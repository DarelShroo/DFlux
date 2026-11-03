use crate::config::EgressConfig;
use anyhow::Result;
use std::net::IpAddr;
use std::sync::Arc;

#[allow(dead_code)]
pub trait RemoteEgress: Send + Sync + std::fmt::Debug {
    /// Returns the name of the network interface.
    fn get_interface(&self) -> &str;

    /// Checks if the egress is healthy.
    fn health(
        &self,
        direct_ip: Option<IpAddr>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + '_>>;

    /// Returns a status string.
    fn status(&self) -> &str;
}

#[derive(Debug, Clone)]
pub struct NetworkInterfaceEgress {
    pub interface_name: String,
}

impl NetworkInterfaceEgress {
    pub fn new(interface_name: String) -> Self {
        Self { interface_name }
    }
}

impl RemoteEgress for NetworkInterfaceEgress {
    fn get_interface(&self) -> &str {
        &self.interface_name
    }

    fn health(
        &self,
        direct_ip: Option<IpAddr>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + '_>> {
        Box::pin(async move {
            let path = std::path::Path::new("/sys/class/net").join(&self.interface_name);
            if !path.exists() {
                return Err(anyhow::anyhow!(
                    "egress interface '{}' does not exist",
                    self.interface_name
                ));
            }
            let state = std::fs::read_to_string(path.join("operstate")).unwrap_or_default();
            if !matches!(state.trim(), "up" | "unknown") {
                return Ok(false);
            }
            if let Some(ip) = direct_ip {
                let socket = if ip.is_ipv4() {
                    tokio::net::TcpSocket::new_v4()?
                } else {
                    tokio::net::TcpSocket::new_v6()?
                };
                let name = std::ffi::CString::new(self.interface_name.as_str())?;
                let fd = std::os::fd::AsRawFd::as_raw_fd(&socket);
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        name.as_ptr() as *const libc::c_void,
                        (name.as_bytes_with_nul().len()) as libc::socklen_t,
                    )
                };
                if result != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                return Ok(tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    socket.connect(std::net::SocketAddr::new(ip, 443)),
                )
                .await
                .is_ok_and(|r| r.is_ok()));
            }
            Ok(true)
        })
    }

    fn status(&self) -> &str {
        "Interface status checked; route reachability requires a target probe"
    }
}

#[derive(Debug, Clone)]
pub struct EgressManager {
    config: Arc<EgressConfig>,
    remote_egress: Option<Arc<dyn RemoteEgress>>,
}

#[allow(dead_code)]
impl EgressManager {
    pub fn new(config: Arc<EgressConfig>, remote_egress: Option<Arc<dyn RemoteEgress>>) -> Self {
        Self {
            config,
            remote_egress,
        }
    }

    pub fn get_direct_interface(&self) -> &str {
        &self.config.direct_interface
    }

    pub fn get_remote_interface(&self) -> Option<&str> {
        self.remote_egress.as_ref().map(|re| re.get_interface())
    }

    pub fn get_remote_egress(&self) -> Option<Arc<dyn RemoteEgress>> {
        self.remote_egress.clone()
    }

    /// Checks link presence and administrative/operational state before routing rules are
    /// installed. This does not claim Internet reachability; route probes establish that.
    pub fn validate_interfaces(&self) -> Result<()> {
        let mut names = vec![("DIRECT", self.config.direct_interface.as_str())];
        if let Some(remote) = self.get_remote_interface() {
            names.push(("REMOTE", remote));
        }
        for (policy, name) in names {
            if name.trim().is_empty()
                || unsafe { libc::if_nametoindex(std::ffi::CString::new(name)?.as_ptr()) } == 0
            {
                return Err(anyhow::anyhow!(
                    "{} interface '{}' is unavailable",
                    policy,
                    name
                ));
            }
            let state_path = std::path::Path::new("/sys/class/net")
                .join(name)
                .join("operstate");
            let state = std::fs::read_to_string(state_path)?;
            if !matches!(state.trim(), "up" | "unknown") {
                return Err(anyhow::anyhow!(
                    "{} interface '{}' is present but not operational (state: {})",
                    policy,
                    name,
                    state.trim()
                ));
            }
        }
        Ok(())
    }
}
