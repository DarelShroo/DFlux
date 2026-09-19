use crate::config::EgressConfig;
use std::sync::Arc;
use std::net::IpAddr;
use anyhow::Result;

#[allow(dead_code)]
pub trait RemoteEgress: Send + Sync + std::fmt::Debug {
    /// Returns the name of the network interface.
    fn get_interface(&self) -> &str;

    /// Checks if the egress is healthy.
    fn health(&self, direct_ip: Option<IpAddr>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + '_>>;

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

    fn health(&self, _direct_ip: Option<IpAddr>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + '_>> {
        Box::pin(async move {
            // TODO: Implement actual external IP check.
            // For now, we assume it's healthy if we can bind to it.
            Ok(true)
        })
    }

    fn status(&self) -> &str {
        "Connected via network interface"
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
        Self { config, remote_egress }
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
}
