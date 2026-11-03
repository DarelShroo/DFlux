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
    // TPROXY preserves the destination in local_addr(); locally generated connections use
    // nft REDIRECT and expose their original destination via SO_ORIGINAL_DST.
    let fd = std::os::fd::AsRawFd::as_raw_fd(stream);
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            80, // SO_ORIGINAL_DST (Linux)
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if result == 0
        && len as usize >= std::mem::size_of::<libc::sockaddr_in>()
        && addr.sin_family as libc::c_int == libc::AF_INET
        && addr.sin_port != 0
    {
        let ip = std::net::Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
        return Ok(SocketAddr::new(IpAddr::V4(ip), u16::from_be(addr.sin_port)));
    }
    Ok(stream.local_addr()?)
}

pub async fn run_gateway(
    port: u16,
    state_manager: StateManager,
    egress_mgr: Arc<EgressManager>,
) -> Result<()> {
    let listener = bind_gateway(port).await?;
    run_gateway_with_listener(listener, state_manager, egress_mgr).await
}

pub async fn bind_gateway(port: u16) -> Result<tokio::net::TcpListener> {
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
    Ok(listener)
}

pub async fn run_gateway_with_listener(
    listener: tokio::net::TcpListener,
    state_manager: StateManager,
    egress_mgr: Arc<EgressManager>,
) -> Result<()> {
    let addr = listener.local_addr()?;
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
    let inspection = inspector::inspect_hostname(&client_stream).await;
    let hostname_opt = inspection.hostname;

    let target_host = if let Some(h) = &hostname_opt {
        h.trim_end_matches('.').to_ascii_lowercase()
    } else {
        orig_dst.ip().to_string()
    };

    tracing::info!(
        "Gateway intercepted {} -> {} (host: {}, inspection: {:?}, bytes: {})",
        peer_addr,
        orig_dst,
        target_host,
        inspection.status,
        inspection.observed_bytes
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

    // Resolve the hostname independently over any fallback route. Never reuse a DIRECT DNS
    // answer for REMOTE, and never fall back from REMOTE to DIRECT.
    let (mut server_stream, used_remote) = match gateway_connect(
        hostname_opt.as_deref(),
        orig_dst.ip(),
        orig_port,
        enforce_remote,
        egress_mgr.get_remote_interface().is_some(),
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

    tracing::info!(hostname = %target_host, selected = ?decision,
        applied = if used_remote { "REMOTE" } else { "DIRECT" },
        failover = used_remote && !enforce_remote,
        "gateway route established");
    if used_remote && !enforce_remote {
        state_manager
            .record_route_success(&target_host, Decision::Remote)
            .await;
    }

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
        Ok((_from_client, _from_server)) => Ok(()),
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
    remote_available: bool,
    mut resolve: D,
    mut connect: C,
) -> Result<(T, bool)>
where
    D: FnMut(String, bool) -> DF,
    DF: Future<Output = Result<Vec<IpAddr>>>,
    C: FnMut(Vec<IpAddr>, u16, bool) -> CF,
    CF: Future<Output = Result<T>>,
{
    let resolved = if let Some(host) = hostname {
        resolve(host.to_string(), remote).await
    } else {
        Ok(vec![original_ip])
    };
    let ips = match resolved {
        Ok(ips) if !ips.is_empty() => ips,
        Ok(_) | Err(_) if !remote && remote_available => {
            let host =
                hostname.ok_or_else(|| anyhow::anyhow!("REMOTE retry requires a hostname"))?;
            let ips = resolve(host.to_string(), true).await?;
            if ips.is_empty() {
                return Err(anyhow::anyhow!("REMOTE DNS returned no addresses"));
            }
            return connect(ips, port, true).await.map(|stream| (stream, true));
        }
        Ok(ips) if !remote && hostname.is_none() => ips,
        Ok(_) => return Err(anyhow::anyhow!("DNS returned no addresses")),
        Err(error) => return Err(error),
    };

    match connect(ips.clone(), port, remote).await {
        Ok(stream) => Ok((stream, remote)),
        Err(error)
            if !remote
                && remote_available
                && crate::outbound::classify_connect_failure(&error)
                    == crate::outbound::ConnectFailureClass::RecoverableNetwork =>
        {
            let remote_ips = if let Some(host) = hostname {
                resolve(host.to_string(), true).await?
            } else {
                vec![original_ip]
            };
            if remote_ips.is_empty() {
                return Err(anyhow::anyhow!("REMOTE DNS returned no addresses"));
            }
            connect(remote_ips, port, true)
                .await
                .map(|stream| (stream, true))
        }
        Err(error) => Err(error),
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
            false,
            |_, remote| async move {
                assert!(!remote);
                Ok(vec![direct_ip])
            },
            |ips, _, _| async move { Ok::<_, anyhow::Error>(ips[0]) },
        )
        .await
        .unwrap();
        let (connected, used_remote) = connected;
        assert!(!used_remote);
        assert_eq!(
            connected, direct_ip,
            "DIRECT uses DoH answer, not original destination"
        );

        let connected = gateway_connect(
            Some("service.example"),
            original,
            443,
            false,
            false,
            |_, _| async { Err(anyhow::anyhow!("DoH unavailable")) },
            |ips, _, _| async move { Ok::<_, anyhow::Error>(ips[0]) },
        )
        .await
        .unwrap_err();
        assert!(connected.to_string().contains("DoH unavailable"));

        let attempts = Arc::new(Mutex::new(Vec::new()));
        let connect_log = attempts.clone();
        let failed = gateway_connect(
            Some("service.example"),
            original,
            443,
            true,
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
        let (literal_result, used_remote) = literal_result;
        assert!(!used_remote);
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
                true,
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
            assert_eq!(actual.0, expected);
            assert_eq!(actual.1, remote);
        }
    }

    #[tokio::test]
    async fn direct_connect_timeout_fails_over_using_remote_dns_and_route() {
        let original = ip("198.51.100.9");
        let remote_ip = ip("203.0.113.20");
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let dns_log = attempts.clone();
        let connect_log = attempts.clone();
        let (connected, used_remote) = gateway_connect(
            Some("service.example"),
            original,
            443,
            false,
            true,
            move |_, remote| {
                let log = dns_log.clone();
                async move {
                    log.lock()
                        .unwrap()
                        .push(if remote { "dns-remote" } else { "dns-direct" });
                    Ok(vec![if remote {
                        remote_ip
                    } else {
                        ip("203.0.113.10")
                    }])
                }
            },
            move |ips, _, remote| {
                let log = connect_log.clone();
                async move {
                    log.lock().unwrap().push(if remote {
                        "connect-remote"
                    } else {
                        "connect-direct"
                    });
                    if remote {
                        Ok(ips[0])
                    } else {
                        Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into())
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(connected, remote_ip);
        assert!(used_remote);
        assert_eq!(
            *attempts.lock().unwrap(),
            vec![
                "dns-direct",
                "connect-direct",
                "dns-remote",
                "connect-remote"
            ]
        );
    }

    #[tokio::test]
    async fn isolation_failure_never_falls_back_to_remote() {
        let calls = Arc::new(Mutex::new(0));
        let log = calls.clone();
        let err = gateway_connect(
            Some("service.example"),
            ip("198.51.100.9"),
            443,
            false,
            true,
            |_, _| async { Ok(vec![ip("203.0.113.10")]) },
            move |_, _, remote| {
                let log = log.clone();
                async move {
                    *log.lock().unwrap() += 1;
                    if remote {
                        Ok(())
                    } else {
                        Err(crate::outbound::IsolationError::SoMark(
                            std::io::Error::from_raw_os_error(libc::EPERM),
                        )
                        .into())
                    }
                }
            },
        )
        .await
        .unwrap_err();
        assert!(
            err.downcast_ref::<crate::outbound::IsolationError>()
                .is_some()
        );
        assert_eq!(*calls.lock().unwrap(), 1);
    }
}
