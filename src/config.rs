use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;

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

impl Default for DFluxConfig {
    fn default() -> Self {
        let direct_iface = std::env::var("DFLUX_DIRECT_IFACE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(Self::detect_default_interface)
            .unwrap_or_default();

        Self {
            egress: EgressConfig {
                direct_interface: direct_iface,
                remote_interface: std::env::var("DFLUX_REMOTE_IFACE")
                    .ok()
                    .filter(|s| !s.trim().is_empty()),
            },
            gateway: GatewayConfig {
                port: std::env::var("DFLUX_TPROXY_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(12345),
                proxy_port: std::env::var("DFLUX_PROXY_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(8080),
                enable_transparent: true,
                exclude_subnets: std::env::var("DFLUX_EXCLUDE_SUBNETS").unwrap_or_else(|_| {
                    "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8".to_string()
                }),
            },
        }
    }
}

impl DFluxConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read config file")?;
        let config: DFluxConfig =
            serde_json::from_str(&content).context("Failed to parse config file")?;
        config.validate()?;
        Ok(config)
    }

    /// Validates the configuration to ensure security invariants are met.
    pub fn validate(&self) -> Result<()> {
        self.validate_with_sysfs(std::path::Path::new("/sys/class/net"))
    }

    fn validate_with_sysfs(&self, sysfs: &std::path::Path) -> Result<()> {
        if self.egress.direct_interface.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "direct_interface is required and cannot be empty"
            ));
        }
        if !Self::is_physical_interface_at(&self.egress.direct_interface, sysfs) {
            return Err(anyhow::anyhow!(
                "direct_interface '{}' is not verified as a physical interface in sysfs; configure a valid physical interface",
                self.egress.direct_interface
            ));
        }
        Ok(())
    }

    /// Checks if a network interface is a real physical interface (not a virtual/VPN/bridge).
    pub fn is_physical_interface(iface: &str) -> bool {
        Self::is_physical_interface_at(iface, std::path::Path::new("/sys/class/net"))
    }

    fn is_physical_interface_at(iface: &str, sys_class_net: &std::path::Path) -> bool {
        let iface = iface.trim();
        if iface.is_empty() || iface == "lo" || iface.contains('/') || iface == "." || iface == ".."
        {
            return false;
        }
        sys_class_net.join(iface).join("device").exists()
    }

    /// Attempts to auto-detect the default physical network interface by parsing `ip route show default`
    pub fn detect_default_interface() -> Option<String> {
        if let Ok(output) = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            // output looks like: "default via 192.168.1.1 dev wlp14s0 proto dhcp metric 600"
            for part in output_str.split_whitespace().collect::<Vec<_>>().windows(2) {
                if part[0] == "dev" {
                    let cand = part[1].to_string();
                    if Self::is_physical_interface(&cand) {
                        return Some(cand);
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "dflux-config-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn config(interface: &str) -> DFluxConfig {
        DFluxConfig {
            egress: EgressConfig {
                direct_interface: interface.into(),
                remote_interface: None,
            },
            gateway: GatewayConfig {
                port: 12345,
                proxy_port: 8080,
                enable_transparent: true,
                exclude_subnets: "127.0.0.0/8".into(),
            },
        }
    }

    #[test]
    fn validates_configured_physical_and_rejects_virtual_missing_or_unreadable_sysfs() {
        let root = temp_path("sysfs");
        let physical = root.join("enp-test");
        std::fs::create_dir_all(physical.join("device")).unwrap();
        std::fs::create_dir_all(root.join("tun-test")).unwrap();

        assert!(config("enp-test").validate_with_sysfs(&root).is_ok());
        assert!(config("tun-test").validate_with_sysfs(&root).is_err());
        assert!(config("missing-test").validate_with_sysfs(&root).is_err());
        assert!(config("").validate_with_sysfs(&root).is_err());
        // A non-directory sysfs root models a sysfs lookup that cannot provide an interface.
        let invalid_sysfs = temp_path("not-sysfs");
        std::fs::write(&invalid_sysfs, b"not a sysfs directory").unwrap();
        assert!(config("eth0").validate_with_sysfs(&invalid_sysfs).is_err());

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(invalid_sysfs);
    }
}
