mod config;
mod egress;
mod routing;
mod cli;
mod outbound;
mod probes;
mod proxy;
mod state;
mod gateway;

use clap::Parser;
use cli::{Cli, Commands};
use state::StateManager;
use std::sync::Arc;
use config::DFluxConfig;
use egress::EgressManager;
use routing::RoutingEngine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Probe { hostname, remote, direct_iface, remote_iface } => {
            println!("Probing hostname: {}, remote: {}", hostname, remote);
            let config = DFluxConfig::default();
            let mut cfg = config.egress;
            if let Some(d) = direct_iface { cfg.direct_interface = d.clone(); }
            if let Some(r) = remote_iface { cfg.remote_interface = r.clone(); }
            let egress_mgr = Arc::new(EgressManager::new(Arc::new(cfg)));
            probes::run_probe(hostname, *remote, egress_mgr).await?;
        }
        Commands::Compare { hostname, direct_iface, remote_iface } => {
            println!("Comparing routes for hostname: {}", hostname);
            let config = DFluxConfig::default();
            let mut cfg = config.egress;
            if let Some(d) = direct_iface { cfg.direct_interface = d.clone(); }
            if let Some(r) = remote_iface { cfg.remote_interface = r.clone(); }
            let egress_mgr = Arc::new(EgressManager::new(Arc::new(cfg)));
            probes::run_probe_compare(hostname, egress_mgr).await?; // Assume run_compare takes egress_mgr, need to fix name to run_probe_compare or similar if it was run_compare. Oh it's run_compare
        }
        Commands::Mode { mode_type, direct_iface, remote_iface } => {
            let mut config = DFluxConfig::default();
            if let Some(d) = direct_iface { config.egress.direct_interface = d.clone(); }
            if let Some(r) = remote_iface { config.egress.remote_interface = r.clone(); }
            
            let egress_mgr = Arc::new(EgressManager::new(Arc::new(config.egress.clone())));
            let state_manager = StateManager::new(1800); // 30 minutes TTL
            
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let ctrlc_tx = tx.clone();
            ctrlc::set_handler(move || {
                let _ = ctrlc_tx.blocking_send(());
            }).expect("Error setting Ctrl-C handler");

            if mode_type == "observe" {
                println!("Running OBSERVE mode (Local Proxy on :8080). No system routing rules will be modified.");
                println!("Point your test client to HTTP_PROXY=http://127.0.0.1:8080");
                tokio::select! {
                    res = proxy::run_proxy(8080, state_manager, mode_type.clone(), egress_mgr) => {
                        if let Err(e) = res { eprintln!("Proxy error: {}", e); }
                    }
                    _ = rx.recv() => {
                        println!("Received shutdown signal. Stopping proxy.");
                    }
                }
            } else if mode_type == "enforce" {
                println!("WARNING: Running ENFORCE mode. DFlux will intercept system traffic transparently.");
                let routing_engine = RoutingEngine::new(config.gateway.port, config.egress.direct_interface.clone(), config.egress.remote_interface.clone());
                routing_engine.start()?;
                
                let watchdog_tx = tx.clone();
                let watchdog_egress = egress_mgr.clone();
                tokio::spawn(async move {
                    let mut failures = 0;
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                        // Health check DIRECT using an external reliable IP
                        if let Ok(Ok(_)) = tokio::time::timeout(
                            tokio::time::Duration::from_secs(5),
                            outbound::connect_tcp(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 443, false, watchdog_egress.clone())
                        ).await {
                            failures = 0;
                        } else {
                            failures += 1;
                            eprintln!("WATCHDOG: Direct outbound failed ({} / 3)", failures);
                            if failures >= 3 {
                                eprintln!("WATCHDOG: CRITICAL NETWORK FAILURE DETECTED. Triggering emergency rollback!");
                                let _ = watchdog_tx.send(()).await;
                                break;
                            }
                        }
                    }
                });

                println!("Gateway is running. Press Ctrl-C to stop safely.");
                tokio::select! {
                    res = gateway::run_gateway(config.gateway.port, state_manager, egress_mgr) => {
                        if let Err(e) = res { eprintln!("Gateway error: {}", e); }
                    }
                    _ = rx.recv() => {
                        println!("Received shutdown signal. RoutingEngine Drop will clean up.");
                    }
                }
            }
        }
        Commands::Rollback => {
            println!("Manually rolling back DFlux routing rules...");
            // We just instantiate a dummy engine and call stop()
            let routing_engine = RoutingEngine::new(12345, "".to_string(), "".to_string());
            routing_engine.stop()?;
        }
    }

    Ok(())
}
