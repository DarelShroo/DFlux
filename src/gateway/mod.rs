pub mod copy;
pub mod inspector;

use crate::egress::EgressManager;
use crate::observability::{self, Level};
use crate::state::{Decision, StateManager};
use crate::telemetry;
use anyhow::Result;
use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
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
    let mut config = crate::config::DFluxConfig::default().gateway;
    config.port = port;
    let listener = bind_gateway(port).await?;
    run_gateway_with_listener(listener, state_manager, egress_mgr, config).await
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
    config: crate::config::GatewayConfig,
) -> Result<()> {
    let addr = listener.local_addr()?;
    let max_conns = telemetry::calculate_safe_max_connections(config.max_connections);
    println!(
        "DFlux Transparent Gateway listening on {} (max connections: {}, idle timeout: {}s, half-close timeout: {}s)",
        addr, max_conns, config.tcp_idle_timeout_secs, config.half_close_timeout_secs
    );

    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_conns));
    let metrics = telemetry::global_metrics();

    // Reserve file descriptor to shed connections gracefully on EMFILE
    let mut reserve_fd = std::fs::File::open("/dev/null").ok();

    let mut backoff = Duration::from_millis(25);
    let mut consecutive_emfile = 0u32;
    let mut emfile_start: Option<Instant> = None;

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => {
                backoff = Duration::from_millis(25);
                consecutive_emfile = 0;
                emfile_start = None;
                if reserve_fd.is_none() {
                    reserve_fd = std::fs::File::open("/dev/null").ok();
                }
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

                    let open_fds = telemetry::get_open_fd_count();
                    let (soft, hard) = telemetry::get_fd_limits();

                    let mut event = observability::event(
                        Level::Critical,
                        "gateway_accept_emfile",
                        "gateway",
                        "listener_accept",
                    );
                    event.error_category = Some("fd_exhaustion".into());
                    event.error_message = Some(e.to_string());
                    event
                        .fields
                        .insert("open_fds".into(), serde_json::json!(open_fds));
                    event
                        .fields
                        .insert("soft_limit".into(), serde_json::json!(soft));
                    event
                        .fields
                        .insert("hard_limit".into(), serde_json::json!(hard));
                    event.fields.insert(
                        "consecutive_emfile".into(),
                        serde_json::json!(consecutive_emfile),
                    );
                    event.fields.insert(
                        "exhaustion_duration_ms".into(),
                        serde_json::json!(duration_exhausted.as_millis()),
                    );
                    observability::emit(event);

                    eprintln!(
                        "CRITICAL: Gateway EMFILE/ENFILE (os error {})! Open FDs: {}/{}, consecutive errors: {}, duration: {:?}",
                        e.raw_os_error().unwrap_or(0),
                        open_fds,
                        soft,
                        consecutive_emfile,
                        duration_exhausted
                    );

                    // Use reserve descriptor to shed pending connection if possible
                    if let Some(fd) = reserve_fd.take() {
                        drop(fd);
                        if let Ok(Ok((shed_stream, _))) =
                            tokio::time::timeout(Duration::from_millis(10), listener.accept()).await
                        {
                            drop(shed_stream);
                        }
                        reserve_fd = std::fs::File::open("/dev/null").ok();
                    }

                    // If starvation persists for > 30s without relief, trigger fatal abort so systemd can restart
                    if duration_exhausted > Duration::from_secs(30) {
                        let mut fatal_event = observability::event(
                            Level::Critical,
                            "gateway_fatal_emfile_exhaustion",
                            "gateway",
                            "listener_accept",
                        );
                        fatal_event.outcome = Some("fatal_shutdown".into());
                        fatal_event.error_message =
                            Some("EMFILE persistent for >30s without recovery".into());
                        observability::emit(fatal_event);

                        return Err(anyhow::anyhow!(
                            "Fatal gateway EMFILE exhaustion: descriptor table saturated for {:?}; aborting for systemd restart",
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
                    tracing::debug!("Transient accept error: {}", e);
                    continue;
                }

                tracing::warn!("Gateway accept unexpected error: {}", e);
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
                let mut event = observability::event(
                    Level::Warn,
                    "gateway_connection_rejected",
                    "gateway",
                    "concurrency_limit",
                );
                event.error_category = Some("backpressure".into());
                event
                    .fields
                    .insert("peer".into(), serde_json::json!(peer_addr.to_string()));
                event
                    .fields
                    .insert("limit".into(), serde_json::json!(max_conns));
                observability::emit(event);

                eprintln!(
                    "Max connections reached (limit: {})! Shedding traffic from {}",
                    max_conns, peer_addr
                );
                drop(stream);
                continue;
            }
        };

        let state_manager = state_manager.clone();
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
                handle_gateway_client(stream, peer_addr, state_manager, egress_mgr, conn_config)
                    .await
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
    config: crate::config::GatewayConfig,
) -> Result<()> {
    // 1. Get original destination IP
    let orig_dst = match get_original_dst(&client_stream) {
        Ok(dst) => dst,
        Err(e) => {
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

    let idle_timeout = Duration::from_secs(config.tcp_idle_timeout_secs);
    let half_close_timeout = Duration::from_secs(config.half_close_timeout_secs);
    let metrics = telemetry::global_metrics();

    // 5. Bounded bidirectional copy with idle and half-close timeouts
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
    let started = Instant::now();
    let mut started_event = observability::event(
        Level::Debug,
        "gateway_connection_attempt",
        "gateway",
        "gateway_connect",
    );
    started_event
        .fields
        .insert("remote".into(), serde_json::json!(remote));
    started_event
        .fields
        .insert("port".into(), serde_json::json!(port));
    if let Some(host) = hostname {
        started_event.fields.insert(
            "hostname".into(),
            serde_json::Value::String(observability::redact(host)),
        );
    }
    observability::emit(started_event);

    let resolved = if let Some(host) = hostname {
        resolve(host.to_string(), remote).await
    } else {
        Ok(vec![original_ip])
    };
    let mut dns_event = observability::event(
        if resolved.is_ok() {
            Level::Debug
        } else {
            Level::Warn
        },
        "gateway_dns_result",
        "gateway",
        "gateway_connect",
    );
    dns_event
        .fields
        .insert("remote".into(), serde_json::json!(remote));
    dns_event.fields.insert(
        "addresses".into(),
        serde_json::json!(resolved.as_ref().map(Vec::len).unwrap_or_default()),
    );
    dns_event.fields.insert(
        "duration_ms".into(),
        serde_json::json!(started.elapsed().as_millis()),
    );
    if let Err(error) = &resolved {
        dns_event.error_category = Some("dns".into());
        dns_event.error_message = Some(error.to_string());
    }
    observability::emit(dns_event);
    let ips = match resolved {
        Ok(ips) if !ips.is_empty() => ips,
        Ok(_) | Err(_) if !remote && remote_available => {
            let host =
                hostname.ok_or_else(|| anyhow::anyhow!("REMOTE retry requires a hostname"))?;
            let ips = resolve(host.to_string(), true).await?;
            if ips.is_empty() {
                return Err(anyhow::anyhow!("REMOTE DNS returned no addresses"));
            }
            let result = connect(ips, port, true).await;
            let mut event = observability::event(
                if result.is_ok() {
                    Level::Info
                } else {
                    Level::Error
                },
                "gateway_fallback_result",
                "gateway",
                "gateway_connect",
            );
            event.outcome = Some(if result.is_ok() { "success" } else { "failure" }.into());
            event
                .fields
                .insert("remote".into(), serde_json::json!(true));
            event.fields.insert(
                "duration_ms".into(),
                serde_json::json!(started.elapsed().as_millis()),
            );
            if let Err(error) = &result {
                event.error_category = Some("fallback_connect".into());
                event.error_message = Some(error.to_string());
            }
            observability::emit(event);
            return result.map(|stream| (stream, true));
        }
        Ok(ips) if !remote && hostname.is_none() => ips,
        Ok(_) => return Err(anyhow::anyhow!("DNS returned no addresses")),
        Err(error) => return Err(error),
    };

    let direct_result = connect(ips.clone(), port, remote).await;
    match direct_result {
        Ok(stream) => {
            let mut event = observability::event(
                Level::Info,
                "gateway_connect_result",
                "gateway",
                "gateway_connect",
            );
            event.outcome = Some("success".into());
            event
                .fields
                .insert("remote".into(), serde_json::json!(remote));
            event.fields.insert(
                "duration_ms".into(),
                serde_json::json!(started.elapsed().as_millis()),
            );
            observability::emit(event);
            Ok((stream, remote))
        }
        Err(error)
            if !remote
                && remote_available
                && crate::outbound::classify_connect_failure(&error)
                    == crate::outbound::ConnectFailureClass::RecoverableNetwork =>
        {
            let mut fallback_event = observability::event(
                Level::Warn,
                "gateway_fallback_attempt",
                "gateway",
                "gateway_connect",
            );
            fallback_event.outcome = Some("attempted".into());
            fallback_event.error_category = Some("recoverable_network".into());
            fallback_event.error_message = Some(error.to_string());
            fallback_event
                .fields
                .insert("remote".into(), serde_json::json!(true));
            observability::emit(fallback_event);
            let remote_ips = if let Some(host) = hostname {
                resolve(host.to_string(), true).await?
            } else {
                vec![original_ip]
            };
            if remote_ips.is_empty() {
                return Err(anyhow::anyhow!("REMOTE DNS returned no addresses"));
            }
            let result = connect(remote_ips, port, true).await;
            let mut event = observability::event(
                if result.is_ok() {
                    Level::Info
                } else {
                    Level::Error
                },
                "gateway_fallback_result",
                "gateway",
                "gateway_connect",
            );
            event.outcome = Some(if result.is_ok() { "success" } else { "failure" }.into());
            event
                .fields
                .insert("remote".into(), serde_json::json!(true));
            event.fields.insert(
                "duration_ms".into(),
                serde_json::json!(started.elapsed().as_millis()),
            );
            if let Err(error) = &result {
                event.error_category = Some("fallback_connect".into());
                event.error_message = Some(error.to_string());
            }
            observability::emit(event);
            result.map(|stream| (stream, true))
        }
        Err(error) => {
            let mut event = observability::event(
                Level::Error,
                "gateway_connect_result",
                "gateway",
                "gateway_connect",
            );
            event.outcome = Some("failure".into());
            event.error_category = Some("connect".into());
            event.error_message = Some(error.to_string());
            event
                .fields
                .insert("remote".into(), serde_json::json!(remote));
            event.fields.insert(
                "duration_ms".into(),
                serde_json::json!(started.elapsed().as_millis()),
            );
            observability::emit(event);
            let mut incident = observability::event(
                Level::Critical,
                "incident_connectivity_failure",
                "gateway",
                "gateway_connect",
            );
            incident.outcome = Some("detected".into());
            incident.error_category = Some("connectivity".into());
            incident.error_message = Some(error.to_string());
            incident
                .fields
                .insert("root_cause".into(), serde_json::json!("UNDETERMINED"));
            incident.fields.insert(
                "evidence".into(),
                serde_json::json!(["gateway_connect_result=failure", "no_verified_recovery"]),
            );
            incident.fields.insert(
                "duration_ms".into(),
                serde_json::json!(started.elapsed().as_millis()),
            );
            observability::emit(incident);
            Err(error)
        }
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
