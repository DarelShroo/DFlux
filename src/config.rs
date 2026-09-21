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
    pub remote_interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub port: u16,
    pub proxy_port: u16,
    pub enable_transparent: bool,
    pub exclude_subnets: String,
}

impl DFluxConfig {
    pub fn default() -> Self {
        Self {
            egress: EgressConfig {
                direct_interface: std::env::var("DFLUX_DIRECT_IFACE")
                    .unwrap_or_else(|_| Self::detect_default_interface().unwrap_or_else(|| "eth0".to_string())),
                remote_interface: std::env::var("DFLUX_REMOTE_IFACE").ok(),
            },
            gateway: GatewayConfig {
                port: std::env::var("DFLUX_TPROXY_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(12345),
                proxy_port: std::env::var("DFLUX_PROXY_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080),
                enable_transparent: true,
                exclude_subnets: std::env::var("DFLUX_EXCLUDE_SUBNETS")
                    .unwrap_or_else(|_| "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8".to_string()),
            },
        }
    }

    #[allow(dead_code)]
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read config file")?;
        let config: DFluxConfig = serde_json::from_str(&content).context("Failed to parse config file")?;
        Ok(config)
    }

    /// Attempts to auto-detect the default network interface by parsing `ip route show default`
    fn detect_default_interface() -> Option<String> {
        if let Ok(output) = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output() 
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            // output looks like: "default via 192.168.1.1 dev wlp14s0 proto dhcp metric 600"
            for part in output_str.split_whitespace().collect::<Vec<_>>().windows(2) {
                if part[0] == "dev" {
                    return Some(part[1].to_string());
                }
            }
        }
        None
    }
}
