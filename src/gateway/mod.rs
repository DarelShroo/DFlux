pub mod inspector;

use crate::egress::EgressManager;
use crate::state::{Decision, StateManager};
use anyhow::Result;
use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    // With TPROXY, the local_addr() of the accepted stream IS the original destination
    Ok(stream.local_addr()?)
}

pub async fn run_gateway(
    port: u16,
    state_manager: StateManager,
    egress_mgr: Arc<EgressManager>,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", port).parse::<SocketAddr>()?;
    let socket = tokio::net::TcpSocket::new_v4()?;

    // Set IP_TRANSPARENT so the socket can accept packets destined for external IPs
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&socket);
    unsafe {
        let optval: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "Failed to set IP_TRANSPARENT on gateway listener: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // SO_REUSEADDR is already set by TcpSocket::new_v4() by default in tokio, but we can bind now
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;

    println!("DFlux Transparent Gateway listening on {}", addr);

    // Semaphore to protect against connection floods (Circuit Breaker layer 1)
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2000));

    loop {
        let (stream, peer_addr) = listener.accept().await?;

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                eprintln!(
                    "Max connections reached! Dropping traffic from {}",
                    peer_addr
                );
                continue; // Drop to protect network health
            }
        };

        let state_manager = state_manager.clone();
        let egress_mgr = egress_mgr.clone();

        tokio::spawn(async move {
            let _permit = permit; // Will be dropped automatically when the task finishes
            if let Err(e) =
                handle_gateway_client(stream, peer_addr, state_manager, egress_mgr).await
            {
                eprintln!("Gateway client error: {}", e);
            }
        });
    }
}

async fn handle_gateway_client(
    mut client_stream: TcpStream,
    peer_addr: SocketAddr,
    state_manager: StateManager,
    egress_mgr: Arc<EgressManager>,
) -> Result<()> {
    // 1. Get original destination IP
    let orig_dst = match get_original_dst(&client_stream) {
        Ok(dst) => dst,
        Err(e) => {
            // If we can't get original destination, we can't forward properly unless we have SNI, but we need IP for non-SNI anyway.
            // Wait, for testing directly without iptables redirect, we can fallback to peer_addr just to not crash, or just return.
            // Let's log and return.
            eprintln!(
                "Could not get original destination for {}: {}",
                peer_addr, e
            );
            return Err(e);
        }
    };

    let orig_port = orig_dst.port();

    // 2. Peek for SNI / Host
    let (hostname_opt, _buffered) = inspector::peek_hostname(&mut client_stream).await?;

    let target_host = if let Some(h) = &hostname_opt {
        h.clone()
    } else {
        orig_dst.ip().to_string()
    };

    tracing::debug!(
        "Gateway intercepted {} -> {} (host: {})",
        peer_addr,
        orig_dst,
        target_host
    );

    // 3. Make routing decision via single-flight evaluator
    let eval_egress = egress_mgr.clone();
    let eval_host = target_host.clone();
    let decision = state_manager
        .get_or_evaluate(&target_host, move || async move {
            crate::probes::evaluate_route(&eval_host, orig_port, eval_egress).await
        })
        .await;

    let enforce_remote = decision == Decision::Remote;

    // Resolve identified hostnames through the selected egress policy. A failed
    // DIRECT lookup may use the intercepted destination; REMOTE remains fail-closed.
    let mut server_stream = match gateway_connect(
        hostname_opt.as_deref(),
        orig_dst.ip(),
        orig_port,
        enforce_remote,
        |host, remote| {
            let manager = egress_mgr.clone();
            async move { crate::probes::dns::resolve(&host, remote, manager).await }
        },
        |ips, port, remote| {
            let manager = egress_mgr.clone();
            async move { crate::outbound::connect_tcp_candidates(&ips, port, remote, manager).await }
        },
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            state_manager.record_failure(&target_host).await;
            return Err(error);
        }
    };

    let _ = client_stream.set_nodelay(true);
    let _ = server_stream.set_nodelay(true);

    // 5. High performance bidirectional copy with 128 KiB buffers
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
                state_manager.record_success(&target_host).await;
            }
            Ok(())
        }
        Err(e) => {
            state_manager.record_failure(&target_host).await;
            Err(e.into())
        }
    }
}

/// Complete gateway DNS and connection choice. Tests inject only the external DoH/socket
/// operations; hostname fallback and policy behavior are the production flow below.
async fn gateway_connect<T, D, DF, C, CF>(
    hostname: Option<&str>,
    original_ip: IpAddr,
    port: u16,
    remote: bool,
    mut resolve: D,
    mut connect: C,
) -> Result<T>
where
    D: FnMut(String, bool) -> DF,
    DF: Future<Output = Result<Vec<IpAddr>>>,
    C: FnMut(Vec<IpAddr>, u16, bool) -> CF,
    CF: Future<Output = Result<T>>,
{
    if let Some(host) = hostname {
        match resolve(host.to_string(), remote).await {
            Ok(ips) if !ips.is_empty() => connect(ips, port, remote).await,
            Ok(_) | Err(_) if !remote => {
                tracing::warn!(hostname = %host, policy = "DIRECT", "DoH failed; using original destination IP");
                connect(vec![original_ip], port, false).await
            }
            Ok(_) | Err(_) => Err(anyhow::anyhow!(
                "Cannot route securely: DoH resolution failed for REMOTE target '{}'",
                host
            )),
        }
    } else {
        connect(vec![original_ip], port, remote).await
    }
}

#[cfg(test)]
mod gateway_decision_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn gateway_applies_policy_scoped_resolution_and_fallback_rules() {
        let original = ip("198.51.100.9");
        let direct_ip = ip("203.0.113.10");
        let remote_ip = ip("203.0.113.20");

        let connected = gateway_connect(
            Some("service.example"),
            original,
            443,
            false,
            |_, remote| async move {
                assert!(!remote);
                Ok(vec![direct_ip])
            },
            |ips, _, _| async move { Ok::<_, anyhow::Error>(ips[0]) },
        )
        .await
        .unwrap();
        assert_eq!(
            connected, direct_ip,
            "DIRECT uses DoH answer, not original destination"
        );

        let connected = gateway_connect(
            Some("service.example"),
            original,
            443,
            false,
            |_, _| async { Err(anyhow::anyhow!("DoH unavailable")) },
            |ips, _, _| async move { Ok::<_, anyhow::Error>(ips[0]) },
        )
        .await
        .unwrap();
        assert_eq!(
            connected, original,
            "DIRECT DoH failure falls back to intercepted IP"
        );

        let attempts = Arc::new(Mutex::new(Vec::new()));
        let connect_log = attempts.clone();
        let failed = gateway_connect(
            Some("service.example"),
            original,
            443,
            true,
            |_, remote| async move {
                assert!(remote);
                Err(anyhow::anyhow!("DoH unavailable"))
            },
            move |ips, _, _| {
                let log = connect_log.clone();
                async move {
                    log.lock().unwrap().extend(ips);
                    Ok::<_, anyhow::Error>(())
                }
            },
        )
        .await;
        assert!(failed.is_err());
        assert!(
            attempts.lock().unwrap().is_empty(),
            "REMOTE failure never connects to original destination"
        );

        let dns_calls = Arc::new(Mutex::new(0));
        let dns_log = dns_calls.clone();
        let literal_result = gateway_connect(
            None,
            original,
            8443,
            false,
            move |_, _| {
                *dns_log.lock().unwrap() += 1;
                async move { Ok(vec![direct_ip]) }
            },
            |ips, port, _| async move {
                assert_eq!(port, 8443);
                Ok::<_, anyhow::Error>(ips[0])
            },
        )
        .await
        .unwrap();
        assert_eq!(literal_result, original);
        assert_eq!(
            *dns_calls.lock().unwrap(),
            0,
            "IP literal path does not query DoH"
        );

        for (remote, expected) in [(false, direct_ip), (true, remote_ip)] {
            let actual = gateway_connect(
                Some("service.example"),
                original,
                443,
                remote,
                move |_, policy| async move {
                    assert_eq!(policy, remote);
                    Ok(vec![expected])
                },
                move |ips, _, policy| async move {
                    assert_eq!(policy, remote);
                    Ok::<_, anyhow::Error>(ips[0])
                },
            )
            .await
            .unwrap();
            assert_eq!(actual, expected);
        }
    }
}
