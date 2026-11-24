use crate::probes;
use crate::state::{Decision, StateManager};
use anyhow::Result;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::egress::EgressManager;
use crate::gateway::copy;
use crate::telemetry;
use std::time::{Duration, Instant};

pub async fn run_proxy(
    port: u16,
    state_manager: StateManager,
    mode: String,
    egress_mgr: Arc<EgressManager>,
) -> Result<()> {
    let mut config = crate::config::DFluxConfig::default().gateway;
    config.proxy_port = port;
    run_proxy_with_config(config, state_manager, mode, egress_mgr).await
}

pub async fn run_proxy_with_config(
    config: crate::config::GatewayConfig,
    state_manager: StateManager,
    mode: String,
    egress_mgr: Arc<EgressManager>,
) -> Result<()> {
    let addr = format!("127.0.0.1:{}", config.proxy_port);
    let listener = TcpListener::bind(&addr).await?;
    let max_conns = telemetry::calculate_safe_max_connections(config.max_connections);
    println!(
        "DFlux proxy listening on {} (max connections: {}, idle timeout: {}s, half-close timeout: {}s)",
        addr, max_conns, config.tcp_idle_timeout_secs, config.half_close_timeout_secs
    );

    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_conns));
    let metrics = telemetry::global_metrics();

    let mut backoff = Duration::from_millis(25);
    let mut consecutive_emfile = 0u32;
    let mut emfile_start: Option<Instant> = None;

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => {
                backoff = Duration::from_millis(25);
                consecutive_emfile = 0;
                emfile_start = None;
                conn
            }
            Err(e) => {
                let is_emfile = e.raw_os_error() == Some(libc::EMFILE)
                    || e.raw_os_error() == Some(libc::ENFILE);

                metrics
                    .accept_errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                if is_emfile {
                    metrics
                        .emfile_errors
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    consecutive_emfile += 1;
                    let start = emfile_start.get_or_insert_with(Instant::now);
                    let duration_exhausted = start.elapsed();

                    eprintln!(
                        "CRITICAL: Proxy EMFILE/ENFILE! Open FDs: {}/{}, consecutive: {}, duration: {:?}",
                        telemetry::get_open_fd_count(),
                        telemetry::get_fd_limits().0,
                        consecutive_emfile,
                        duration_exhausted
                    );

                    if duration_exhausted > Duration::from_secs(30) {
                        return Err(anyhow::anyhow!(
                            "Fatal proxy EMFILE exhaustion: descriptor table saturated for {:?}",
                            duration_exhausted
                        ));
                    }

                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_millis(1000));
                    continue;
                }

                if e.kind() == std::io::ErrorKind::ConnectionAborted
                    || e.kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }

                tracing::warn!("Proxy accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        metrics
            .total_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                metrics
                    .rejected_connections
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                eprintln!(
                    "Max proxy connections reached (limit: {})! Shedding traffic from {}",
                    max_conns, peer_addr
                );
                drop(stream);
                continue;
            }
        };

        let state_manager = state_manager.clone();
        let mode = mode.clone();
        let egress_mgr = egress_mgr.clone();
        let conn_config = config.clone();
        let conn_metrics = metrics.clone();

        metrics
            .active_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        tokio::spawn(async move {
            let _permit = permit;
            struct ActiveGuard(Arc<crate::telemetry::GatewayMetrics>);
            impl Drop for ActiveGuard {
                fn drop(&mut self) {
                    self.0
                        .active_connections
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            let _guard = ActiveGuard(conn_metrics);

            if let Err(e) =
                handle_client(stream, state_manager, mode, egress_mgr, conn_config).await
            {
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
    config: crate::config::GatewayConfig,
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

    tracing::info!(hostname = %host, calculated_policy = ?decision,
        applied_policy = if mode == "observe" { "DIRECT" } else if decision == Decision::Remote { "REMOTE" } else { "DIRECT" },
        mode = %mode, "proxy route policy selected");

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

    let idle_timeout = Duration::from_secs(config.tcp_idle_timeout_secs);
    let half_close_timeout = Duration::from_secs(config.half_close_timeout_secs);
    let metrics = telemetry::global_metrics();

    // Copy bi-directional with idle and half-close timeouts
    match copy::copy_bidirectional_with_timeouts(
        &mut client_stream,
        &mut server_stream,
        idle_timeout,
        half_close_timeout,
        131072,
        metrics,
    )
    .await
    {
        Ok((_from_client, _from_server)) => Ok(()),
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
