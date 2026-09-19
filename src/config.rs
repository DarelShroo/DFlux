use serde::{Deserialize, Serialize};
use std::fs;
use anyhow::{Result, Context};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DFluxConfig {
    pub egress: EgressConfig,
    pub gateway: GatewayConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressConfig {
    pub direct_interface: String,
    pub remote_interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub port: u16,
    pub enable_transparent: bool,
}

impl DFluxConfig {
    pub fn default() -> Self {
        Self {
            egress: EgressConfig {
                direct_interface: "wlp14s0".to_string(), // Will be default unless configured
                remote_interface: "tun0".to_string(),
            },
            gateway: GatewayConfig {
                port: 12345,
                enable_transparent: true,
            },
        }
    }

    #[allow(dead_code)]
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read config file")?;
        let config: DFluxConfig = serde_json::from_str(&content).context("Failed to parse config file")?;
        Ok(config)
    }
}
