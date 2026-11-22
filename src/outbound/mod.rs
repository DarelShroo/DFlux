use anyhow::{Result, anyhow};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::{future::Future, pin::Pin};
use thiserror::Error;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{Duration, Instant, timeout};

use crate::egress::EgressManager;
use crate::observability::{self, Level};

pub const DFLUX_SO_MARK: u32 = 0x4446;
pub const GLOBAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug, Error)]
pub enum IsolationError {
    #[error("SO_MARK setup failed: {0}")]
    SoMark(#[source] std::io::Error),
    #[error("SO_BINDTODEVICE setup failed: {0}")]
    BindToDevice(#[source] std::io::Error),
}

#[derive(Debug, Error)]
pub enum OutboundError {
    #[error("connection attempt timed out")]
    Timeout,
    #[error("invalid egress configuration: {0}")]
    Configuration(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectFailureClass {
    Isolation,
    Configuration,
    RecoverableNetwork,
    Other,
}

/// Classifies connector failures without parsing display strings. Isolation and policy errors
/// are deliberately never eligible for cross-route fallback.
pub fn classify_connect_failure(error: &anyhow::Error) -> ConnectFailureClass {
    if error.downcast_ref::<IsolationError>().is_some() {
        return ConnectFailureClass::Isolation;
    }
    if error
        .downcast_ref::<OutboundError>()
        .is_some_and(|e| matches!(e, OutboundError::Configuration(_)))
    {
        return ConnectFailureClass::Configuration;
    }
    if error
        .downcast_ref::<OutboundError>()
        .is_some_and(|e| matches!(e, OutboundError::Timeout))
    {
        return ConnectFailureClass::RecoverableNetwork;
    }
    let root = error.root_cause();
    if let Some(io) = root.downcast_ref::<std::io::Error>() {
        return match io.kind() {
            std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable => ConnectFailureClass::RecoverableNetwork,
            _ => ConnectFailureClass::Other,
        };
    }
    ConnectFailureClass::Other
}

/// Connects to a target TCP destination using a single IP address with strict isolation options.
pub async fn connect_tcp(
    ip: IpAddr,
    port: u16,
    enforce_remote: bool,
    egress_mgr: Arc<EgressManager>,
) -> Result<TcpStream> {
    connect_tcp_candidates(&[ip], port, enforce_remote, egress_mgr).await
}

/// Connects to a target TCP destination choosing from up to 3 candidate IP addresses,
/// respecting a cumulative global connection timeout of 4 seconds without resetting the clock.
pub async fn connect_tcp_candidates(
    ips: &[IpAddr],
    port: u16,
    enforce_remote: bool,
    egress_mgr: Arc<EgressManager>,
) -> Result<TcpStream> {
    connect_tcp_candidates_with(ips, port, enforce_remote, egress_mgr, |ip, port, ifname| {
        Box::pin(async move {
            let stream = connect_isolated_socket(ip, port, &ifname).await?;
            let _ = stream.set_nodelay(true);
            Ok(stream)
        })
    })
    .await
}

/// Same candidate-selection flow as the production connector, with only the socket operation
/// injected. This keeps retry and isolation-abort behavior testable without host capabilities.
#[doc(hidden)]
pub async fn connect_tcp_candidates_with<T, F>(
    ips: &[IpAddr],
    port: u16,
    enforce_remote: bool,
    egress_mgr: Arc<EgressManager>,
    mut connect: F,
) -> Result<T>
where
    F: FnMut(IpAddr, u16, String) -> Pin<Box<dyn Future<Output = Result<T>> + Send>>,
{
    if ips.is_empty() {
        return Err(OutboundError::Configuration("no IP addresses provided").into());
    }

    let ifname = if enforce_remote {
        match egress_mgr.get_remote_interface() {
            Some(iface) if !iface.trim().is_empty() => iface.to_string(),
            _ => {
                return Err(
                    OutboundError::Configuration("REMOTE interface is not configured").into(),
                );
            }
        }
    } else {
        let direct = egress_mgr.get_direct_interface();
        if direct.trim().is_empty() {
            return Err(OutboundError::Configuration(
                "DIRECT interface is empty or not configured",
            )
            .into());
        }
        direct.to_string()
    };

    let max_candidates = ips.len().min(3);
    let stream = run_candidates(max_candidates, GLOBAL_CONNECT_TIMEOUT, |idx| {
        let ip = ips[idx];
        let ifname = ifname.clone();
        connect(ip, port, ifname)
    })
    .await?;
    Ok(stream)
}

#[doc(hidden)]
pub async fn run_candidates<T, F>(
    candidate_count: usize,
    budget: Duration,
    mut attempt: F,
) -> Result<T>
where
    F: FnMut(usize) -> Pin<Box<dyn Future<Output = Result<T>> + Send>>,
{
    let start_time = Instant::now();
    let mut started =
        observability::event(Level::Debug, "outbound_attempts", "outbound", "connect");
    started
        .fields
        .insert("candidate_count".into(), serde_json::json!(candidate_count));
    started
        .fields
        .insert("budget_ms".into(), serde_json::json!(budget.as_millis()));
    observability::emit(started);
    let mut last_err = None;
    for idx in 0..candidate_count {
        let elapsed = start_time.elapsed();
        if elapsed >= budget {
            return Err(OutboundError::Timeout.into());
        }
        let remaining = budget - elapsed;
        let attempt_timeout = if idx == 0 {
            remaining.min(Duration::from_secs(2))
        } else {
            remaining
        };
        match timeout(attempt_timeout, attempt(idx)).await {
            Ok(Ok(stream)) => {
                let mut event =
                    observability::event(Level::Info, "outbound_candidate", "outbound", "connect");
                event.outcome = Some("success".into());
                event
                    .fields
                    .insert("candidate_index".into(), serde_json::json!(idx));
                event.fields.insert(
                    "duration_ms".into(),
                    serde_json::json!(start_time.elapsed().as_millis()),
                );
                observability::emit(event);
                return Ok(stream);
            }
            Ok(Err(e)) => {
                // If it's a fatal socket configuration error (SO_MARK or SO_BINDTODEVICE), abort immediately!
                // Security isolation errors MUST NOT fall through to retries.
                if e.downcast_ref::<IsolationError>().is_some() {
                    return Err(e);
                }
                tracing::warn!("Connection candidate {} failed: {}", idx, e);
                let mut event =
                    observability::event(Level::Warn, "outbound_candidate", "outbound", "connect");
                event.outcome = Some("failure".into());
                event.error_category = Some(format!("{:?}", classify_connect_failure(&e)));
                event.error_message = Some(e.to_string());
                event
                    .fields
                    .insert("candidate_index".into(), serde_json::json!(idx));
                event.fields.insert(
                    "duration_ms".into(),
                    serde_json::json!(start_time.elapsed().as_millis()),
                );
                observability::emit(event);
                last_err = Some(e);
            }
            Err(_) => {
                tracing::warn!(
                    "Connection candidate {} timed out after {:?}",
                    idx,
                    attempt_timeout
                );
                let mut event =
                    observability::event(Level::Warn, "outbound_candidate", "outbound", "connect");
                event.outcome = Some("timeout".into());
                event.error_category = Some("timeout".into());
                event
                    .fields
                    .insert("candidate_index".into(), serde_json::json!(idx));
                event.fields.insert(
                    "duration_ms".into(),
                    serde_json::json!(start_time.elapsed().as_millis()),
                );
                observability::emit(event);
                last_err = Some(OutboundError::Timeout.into());
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("All connection attempts failed")))
}

/// Internal primitive: creates a socket, applies SO_MARK and SO_BINDTODEVICE strictly,
/// and executes connect. If any isolation option fails, the function aborts before connect().
async fn connect_isolated_socket(ip: IpAddr, port: u16, ifname: &str) -> Result<TcpStream> {
    let addr = SocketAddr::new(ip, port);

    let socket = if ip.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    let _ = socket.set_nodelay(true);
    let fd = socket.as_raw_fd();

    apply_socket_isolation(fd, ifname)?;

    // 3. Connect to destination address
    socket.connect(addr).await.map_err(|e| e.into())
}

/// Apply both mandatory isolation options in order. Kept as a production helper so
/// tests can inject syscall outcomes without requiring CAP_NET_ADMIN.
fn apply_socket_isolation(fd: std::os::fd::RawFd, ifname: &str) -> Result<()> {
    apply_socket_isolation_with(ifname, |option, value| unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            value.as_ptr() as *const libc::c_void,
            value.len() as libc::socklen_t,
        )
    })
}

#[doc(hidden)]
pub fn apply_socket_isolation_with(
    ifname: &str,
    mut set_option: impl FnMut(libc::c_int, &[u8]) -> libc::c_int,
) -> Result<()> {
    let mark = DFLUX_SO_MARK.to_ne_bytes();
    if set_option(libc::SO_MARK, &mark) != 0 {
        return Err(IsolationError::SoMark(std::io::Error::last_os_error()).into());
    }
    if ifname.trim().is_empty() {
        return Err(OutboundError::Configuration("interface name is empty").into());
    }
    let mut interface = ifname.as_bytes().to_vec();
    interface.push(0);
    if set_option(libc::SO_BINDTODEVICE, &interface) != 0 {
        return Err(IsolationError::BindToDevice(std::io::Error::last_os_error()).into());
    }
    Ok(())
}

#[cfg(test)]
mod isolation_tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn mark_failure_stops_before_bind_or_connect() {
        let calls = RefCell::new(Vec::new());
        let result = apply_socket_isolation_with("eth-test", |option, _| {
            calls.borrow_mut().push(option);
            unsafe { *libc::__errno_location() = libc::EPERM };
            -1
        });
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<IsolationError>()
                .is_some()
        );
        assert_eq!(*calls.borrow(), vec![libc::SO_MARK]);
    }

    #[test]
    fn bind_failure_stops_before_connect() {
        let calls = RefCell::new(Vec::new());
        let result = apply_socket_isolation_with("eth-test", |option, _| {
            calls.borrow_mut().push(option);
            if option == libc::SO_BINDTODEVICE {
                unsafe { *libc::__errno_location() = libc::EPERM };
                -1
            } else {
                0
            }
        });
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<IsolationError>()
                .is_some()
        );
        assert_eq!(*calls.borrow(), vec![libc::SO_MARK, libc::SO_BINDTODEVICE]);
    }

    fn manager() -> Arc<EgressManager> {
        use crate::config::EgressConfig;
        use crate::egress::NetworkInterfaceEgress;
        Arc::new(EgressManager::new(
            Arc::new(EgressConfig {
                direct_interface: "dir0".into(),
                remote_interface: Some("rem0".into()),
            }),
            Some(Arc::new(NetworkInterfaceEgress::new("rem0".into()))),
        ))
    }

    #[test]
    fn classifies_timeout_as_recoverable_and_isolation_as_nonrecoverable() {
        let timeout = anyhow::Error::new(OutboundError::Timeout);
        assert_eq!(
            classify_connect_failure(&timeout),
            ConnectFailureClass::RecoverableNetwork
        );
        let isolation = anyhow::Error::new(IsolationError::SoMark(
            std::io::Error::from_raw_os_error(libc::EPERM),
        ));
        assert_eq!(
            classify_connect_failure(&isolation),
            ConnectFailureClass::Isolation
        );
        let refused =
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert_eq!(
            classify_connect_failure(&refused),
            ConnectFailureClass::RecoverableNetwork
        );
    }

    #[tokio::test]
    async fn real_candidate_flow_aborts_on_mark_and_bind_errors() {
        for fail_option in [libc::SO_MARK, libc::SO_BINDTODEVICE] {
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let log = calls.clone();
            let ips = ["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
            let result: Result<()> =
                connect_tcp_candidates_with(&ips, 443, false, manager(), move |ip, _, _| {
                    let log = log.clone();
                    Box::pin(async move {
                        log.lock().unwrap().push(format!("socket:{ip}"));
                        let isolation = apply_socket_isolation_with("dir0", |option, _| {
                            log.lock().unwrap().push(format!("option:{option}"));
                            if option == fail_option {
                                unsafe { *libc::__errno_location() = libc::EPERM };
                                -1
                            } else {
                                0
                            }
                        });
                        isolation?;
                        log.lock().unwrap().push("connect".into());
                        Err(anyhow!("unexpected"))
                    })
                })
                .await;
            assert!(
                result
                    .unwrap_err()
                    .downcast_ref::<IsolationError>()
                    .is_some()
            );
            let observed = calls.lock().unwrap().clone();
            assert_eq!(
                observed.iter().filter(|s| s.starts_with("socket:")).count(),
                1
            );
            assert!(!observed.iter().any(|s| s == "connect"));
        }
    }

    #[tokio::test]
    async fn real_candidate_flow_retries_tcp_errors_with_one_budget() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = calls.clone();
        let ips = ["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
        let result = connect_tcp_candidates_with(&ips, 443, false, manager(), move |ip, _, _| {
            let log = log.clone();
            Box::pin(async move {
                log.lock().unwrap().push(ip);
                if ip == ips[0] {
                    Err(std::io::Error::from_raw_os_error(libc::ECONNREFUSED).into())
                } else {
                    Ok(ip)
                }
            })
        })
        .await
        .unwrap();
        assert_eq!(result, ips[1]);
        assert_eq!(*calls.lock().unwrap(), ips);
    }

    #[tokio::test]
    async fn real_candidate_flow_stops_after_first_success() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = calls.clone();
        let ips = ["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
        let result = connect_tcp_candidates_with(&ips, 443, false, manager(), move |ip, _, _| {
            let log = log.clone();
            Box::pin(async move {
                log.lock().unwrap().push(ip);
                Ok(ip)
            })
        })
        .await
        .unwrap();
        assert_eq!(result, ips[0]);
        assert_eq!(*calls.lock().unwrap(), vec![ips[0]]);
    }
}
