use crate::probes;
use crate::state::{Decision, StateManager};
use anyhow::Result;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::egress::EgressManager;

pub async fn run_proxy(
    port: u16,
    state_manager: StateManager,
    mode: String,
    egress_mgr: Arc<EgressManager>,
) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("DFlux proxy listening on {}", addr);

    let semaphore = Arc::new(tokio::sync::Semaphore::new(2000));

    loop {
        let (stream, _) = listener.accept().await?;

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Max proxy connections reached!");
                continue;
            }
        };

        let state_manager = state_manager.clone();
        let mode = mode.clone();
        let egress_mgr = egress_mgr.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_client(stream, state_manager, mode, egress_mgr).await {
                eprintln!("Client error: {}", e);
            }
        });
    }
}

async fn handle_client(
    mut client_stream: TcpStream,
    state_manager: StateManager,
    mode: String,
    egress_mgr: Arc<EgressManager>,
) -> Result<()> {
    let mut buf = [0u8; 4096];
    let n = client_stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let mut lines = request.lines();
    let first_line = lines.next().unwrap_or("");

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() != 3 || parts[0] != "CONNECT" {
        return Ok(()); // We only handle CONNECT for now
    }

    let host_port = parts[1];
    let host = host_port.split(':').next().unwrap_or("").to_string();
    let port: u16 = host_port
        .split(':')
        .nth(1)
        .unwrap_or("443")
        .parse()
        .unwrap_or(443);

    // Make routing decision via single-flight evaluator
    let eval_egress = egress_mgr.clone();
    let eval_host = host.clone();
    let decision = state_manager
        .get_or_evaluate(&host, move || async move {
            probes::evaluate_route(&eval_host, port, eval_egress).await
        })
        .await;

    let mut server_stream = match proxy_connect(
        &mode,
        decision,
        &host,
        port,
        |host, remote| {
            let manager = egress_mgr.clone();
            async move { probes::dns::resolve(&host, remote, manager).await }
        },
        |ips, port, remote| {
            let manager = egress_mgr.clone();
            async move { crate::outbound::connect_tcp_candidates(&ips, port, remote, manager).await }
        },
        |event| {
            tracing::warn!(event = event.event, calculated_policy = event.calculated_policy,
            applied_policy = event.applied_policy, hostname = %event.hostname,
            reason = event.reason, "OBSERVE policy discrepancy")
        },
    )
    .await
    {
        Ok(stream) => stream,
        Err(ProxyConnectFailure::Resolve(e)) => {
            state_manager.record_failure(&host).await;
            tracing::warn!("Proxy resolution failed for {}: {}", host, e);
            return Ok(());
        }
        Err(ProxyConnectFailure::EmptyResolution) => {
            state_manager.record_failure(&host).await;
            return Ok(());
        }
        Err(ProxyConnectFailure::Connect(e)) => {
            state_manager.record_failure(&host).await;
            return Err(e);
        }
    };

    let _ = client_stream.set_nodelay(true);
    let _ = server_stream.set_nodelay(true);

    // Send 200 OK to client
    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Copy bi-directional with 128 KiB buffers
    match tokio::io::copy_bidirectional_with_sizes(
        &mut client_stream,
        &mut server_stream,
        131072,
        131072,
    )
    .await
    {
        Ok((from_client, from_server)) => {
            if from_server > 0 || from_client > 0 {
                state_manager.record_success(&host).await;
            }
            Ok(())
        }
        Err(e) => {
            state_manager.record_failure(&host).await;
            Err(e.into())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PolicyDiscrepancy {
    event: &'static str,
    calculated_policy: &'static str,
    applied_policy: &'static str,
    hostname: String,
    reason: &'static str,
}

#[derive(Debug)]
enum ProxyConnectFailure {
    Resolve(anyhow::Error),
    EmptyResolution,
    Connect(anyhow::Error),
}

/// The proxy's production policy/DNS/connect path. Injected callbacks represent only external
/// operations and event output, leaving OBSERVE selection and control flow shared with runtime.
async fn proxy_connect<T, D, DF, C, CF, E>(
    mode: &str,
    decision: Decision,
    hostname: &str,
    port: u16,
    mut resolve: D,
    mut connect: C,
    mut emit: E,
) -> std::result::Result<T, ProxyConnectFailure>
where
    D: FnMut(String, bool) -> DF,
    DF: Future<Output = Result<Vec<IpAddr>>>,
    C: FnMut(Vec<IpAddr>, u16, bool) -> CF,
    CF: Future<Output = Result<T>>,
    E: FnMut(PolicyDiscrepancy),
{
    let remote = mode == "enforce" && decision == Decision::Remote;
    if mode == "observe" && decision == Decision::Remote {
        emit(PolicyDiscrepancy {
            event: "egress_policy_discrepancy",
            calculated_policy: "REMOTE",
            applied_policy: "DIRECT",
            hostname: hostname.to_string(),
            reason: "decision_engine_selected_remote_in_observe_mode",
        });
    }
    let ips = resolve(hostname.to_string(), remote)
        .await
        .map_err(ProxyConnectFailure::Resolve)?;
    if ips.is_empty() {
        return Err(ProxyConnectFailure::EmptyResolution);
    }
    connect(ips, port, remote)
        .await
        .map_err(ProxyConnectFailure::Connect)
}

#[cfg(test)]
mod observe_behavior_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn observe_calculates_remote_but_resolves_connects_direct_and_emits_event() {
        let resolved = Arc::new(Mutex::new(Vec::new()));
        let connected = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let r = resolved.clone();
        let c = connected.clone();
        let e = events.clone();
        let result = proxy_connect(
            "observe",
            Decision::Remote,
            "observe.example",
            443,
            move |host, remote| {
                r.lock().unwrap().push((host, remote));
                async { Ok(vec!["203.0.113.10".parse().unwrap()]) }
            },
            move |ips, port, remote| {
                c.lock().unwrap().push((ips.clone(), port, remote));
                async move { Ok::<_, anyhow::Error>(ips[0]) }
            },
            move |event| e.lock().unwrap().push(event),
        )
        .await
        .unwrap();
        assert_eq!(result, "203.0.113.10".parse::<IpAddr>().unwrap());
        assert_eq!(
            *resolved.lock().unwrap(),
            vec![("observe.example".to_string(), false)]
        );
        assert_eq!(
            *connected.lock().unwrap(),
            vec![(vec!["203.0.113.10".parse().unwrap()], 443, false)]
        );
        assert_eq!(
            *events.lock().unwrap(),
            vec![PolicyDiscrepancy {
                event: "egress_policy_discrepancy",
                calculated_policy: "REMOTE",
                applied_policy: "DIRECT",
                hostname: "observe.example".into(),
                reason: "decision_engine_selected_remote_in_observe_mode",
            }]
        );
    }
}
