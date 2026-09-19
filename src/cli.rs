use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "dflux", about = "Adaptive Egress Gateway", version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Probe a destination directly
    Probe {
        /// The hostname to probe
        hostname: String,
        
        /// Optional: Force use of remote outbound
        #[arg(long)]
        remote: bool,
        
        /// Optional: Override direct interface
        #[arg(long)]
        direct_iface: Option<String>,
        
        /// Optional: Override remote interface
        #[arg(long)]
        remote_iface: Option<String>,
    },
    /// Compare DIRECT and REMOTE outbounds
    Compare {
        /// The hostname to compare
        hostname: String,
        
        /// Optional: Override direct interface
        #[arg(long)]
        direct_iface: Option<String>,
        
        /// Optional: Override remote interface
        #[arg(long)]
        remote_iface: Option<String>,
    },
    /// Run DFlux daemon
    Mode {
        /// Mode type: 'observe' (Local HTTP Proxy on 8080, no routing changes) or 'enforce' (Transparent Gateway on 12345, alters routing)
        #[arg(value_parser = ["observe", "enforce"])]
        mode_type: String,
        
        /// Optional: Override direct interface
        #[arg(long)]
        direct_iface: Option<String>,
        
        /// Optional: Override remote interface
        #[arg(long)]
        remote_iface: Option<String>,
    },
    /// Manually remove DFlux routing rules if the daemon crashed
    Rollback,
}
