use std::process::{Command, Stdio};
use std::io::Write;
use anyhow::{Result, anyhow};

/// Manages routing rules using nftables and policy routing.
/// Replaces the legacy bash scripts and iptables REDIRECT.
pub struct RoutingEngine {
    port: u16,
    direct_iface: String,
    remote_iface: Option<String>,
    exclude_subnets: String,
}

impl RoutingEngine {
    pub fn new(port: u16, direct_iface: String, remote_iface: Option<String>, exclude_subnets: String) -> Self {
        Self {
            port,
            direct_iface,
            remote_iface,
            exclude_subnets,
        }
    }

    /// Sets up the transparent proxy rules using nftables TPROXY.
    /// It also ensures MASQUERADE is set for the outbound interfaces.
    pub fn start(&self) -> Result<()> {
        println!("Starting Routing Engine (nftables TPROXY)...");
        self.stop().unwrap_or(()); // Clean up previous state if any

        // Enable IP forwarding
        Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).status()?;

        // Write nftables rules to a temporary file
        let rules = format!("
table ip dflux {{
    chain prerouting {{
        type filter hook prerouting priority mangle; policy accept;
        # Exclude private subnets and loopback to prevent intercepting LAN/router traffic
        ip daddr {{ {exclude_subnets} }} accept
        
        # Catch forwarded LAN traffic and locally re-routed traffic
        tcp dport {{ 80, 443 }} tproxy to :{port} meta mark set 1 accept
    }}
    chain output {{
        type route hook output priority mangle; policy accept;
        # Exclude DFlux's own traffic (marked with 0x4446)
        meta mark 0x4446 accept
        
        # Exclude private subnets and loopback
        ip daddr {{ {exclude_subnets} }} accept
        
        # Intercept locally generated traffic and mark it to force routing to 'lo'
        tcp dport {{ 80, 443 }} meta mark set 1 accept
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        # Exclude private subnets from masquerading to prevent breaking local routed traffic (like VPN return paths)
        ip daddr {{ {exclude_subnets} }} return

        # Masquerade traffic leaving through managed interfaces
        oifname \"{direct_iface}\" masquerade
        {remote_masq}
    }}
}}", port = self.port, direct_iface = self.direct_iface, exclude_subnets = self.exclude_subnets, remote_masq = self.remote_iface.as_ref().map_or("".to_string(), |iface| format!("oifname \"{}\" masquerade", iface)));

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(rules.as_bytes())?;
        }

        let status = child.wait()?;
        if !status.success() {
            return Err(anyhow!("Failed to apply nftables rules"));
        }

        // Add local policy routing to deliver marked packets to the socket, with a specific pref for safe rollback
        Command::new("ip").args(["rule", "add", "fwmark", "1", "lookup", "100", "pref", "32000"]).status()?;
        Command::new("ip").args(["route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100"]).status()?;

        println!("Routing Engine rules applied successfully.");
        Ok(())
    }

    /// Safely reverts all changes made by the RoutingEngine
    pub fn stop(&self) -> Result<()> {
        println!("Stopping Routing Engine and reverting changes...");
        // Flush and delete the dflux nftables table
        Command::new("nft").args(["delete", "table", "ip", "dflux"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status().unwrap_or_default();
        
        // Remove policy routing transactionally using the specific pref
        Command::new("ip").args(["rule", "del", "pref", "32000"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status().unwrap_or_default();
        Command::new("ip").args(["route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "100"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status().unwrap_or_default();

        println!("Routing Engine stopped.");
        Ok(())
    }
}

impl Drop for RoutingEngine {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
