use crate::config::EgressConfig;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct EgressManager {
    config: Arc<EgressConfig>,
}

impl EgressManager {
    pub fn new(config: Arc<EgressConfig>) -> Self {
        Self { config }
    }

    pub fn get_direct_interface(&self) -> &str {
        &self.config.direct_interface
    }

    pub fn get_remote_interface(&self) -> &str {
        &self.config.remote_interface
    }
}
