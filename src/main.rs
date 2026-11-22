use clap::Parser;
use dflux::cli::{Cli, Commands};
use dflux::config::DFluxConfig;
use dflux::egress::{self, EgressManager};
use dflux::routing::RoutingEngine;
use dflux::state::StateManager;
use dflux::{gateway, observability, probes, proxy};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env variables if present
    dotenvy::dotenv().ok();

    // Initialize logging
    tracing_subscriber::fmt::init();
    observability::Observer::install_global(observability::Observer::new(
        observability::ObserverConfig::default(),
    ));

    let cli = Cli::parse();

    match &cli.command {
        Commands::Probe {
            hostname,
            remote,
            direct_iface,
            remote_iface,
        } => {
            println!("Probing hostname: {}, remote: {}", hostname, remote);
            let config = DFluxConfig::default();
            let mut cfg = config.egress;
            if let Some(d) = direct_iface {
                cfg.direct_interface = d.clone();
            }
            if let Some(r) = remote_iface {
                cfg.remote_interface = Some(r.clone());
            }
            let remote_egress: Option<Arc<dyn egress::RemoteEgress>> =
                cfg.remote_interface.as_ref().map(|iface| {
                    Arc::new(egress::NetworkInterfaceEgress::new(iface.clone()))
                        as Arc<dyn egress::RemoteEgress>
                });
            let egress_mgr = Arc::new(EgressManager::new(Arc::new(cfg), remote_egress));
            probes::run_probe(hostname, *remote, egress_mgr).await?;
        }
        Commands::Compare {
            hostname,
            direct_iface,
            remote_iface,
        } => {
            println!("Comparing routes for hostname: {}", hostname);
            let config = DFluxConfig::default();
            let mut cfg = config.egress;
            if let Some(d) = direct_iface {
                cfg.direct_interface = d.clone();
            }
            if let Some(r) = remote_iface {
                cfg.remote_interface = Some(r.clone());
            }
            let remote_egress: Option<Arc<dyn egress::RemoteEgress>> =
                cfg.remote_interface.as_ref().map(|iface| {
                    Arc::new(egress::NetworkInterfaceEgress::new(iface.clone()))
                        as Arc<dyn egress::RemoteEgress>
                });
            let egress_mgr = Arc::new(EgressManager::new(Arc::new(cfg), remote_egress));
            probes::run_probe_compare(hostname, egress_mgr).await?;
        }
        Commands::Mode {
            mode_type,
            direct_iface,
            remote_iface,
        } => {
            let mut config = DFluxConfig::default();
            if let Some(d) = direct_iface {
                config.egress.direct_interface = d.clone();
            }
            if let Some(r) = remote_iface {
                config.egress.remote_interface = Some(r.clone());
            }

            config.validate()?;

            let remote_egress: Option<Arc<dyn egress::RemoteEgress>> =
                config.egress.remote_interface.as_ref().map(|iface| {
                    Arc::new(egress::NetworkInterfaceEgress::new(iface.clone()))
                        as Arc<dyn egress::RemoteEgress>
                });
            let egress_mgr = Arc::new(EgressManager::new(
                Arc::new(config.egress.clone()),
                remote_egress,
            ));
            if mode_type == "enforce" {
                egress_mgr.validate_interfaces()?;
            }
            let state_manager = StateManager::new(1800); // 30 minutes TTL

            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let ctrlc_tx = tx.clone();
            ctrlc::set_handler(move || {
                let _ = ctrlc_tx.blocking_send(());
            })
            .expect("Error setting Ctrl-C handler");

            if mode_type == "observe" {
                println!(
                    "Running OBSERVE mode (Local Proxy on :{}). No system routing rules will be modified.",
                    config.gateway.proxy_port
                );
                println!(
                    "Point your test client to HTTP_PROXY=http://127.0.0.1:{}",
                    config.gateway.proxy_port
                );
                tokio::select! {
                    res = proxy::run_proxy(config.gateway.proxy_port, state_manager, mode_type.clone(), egress_mgr) => {
                        if let Err(e) = res { eprintln!("Proxy error: {}", e); }
                    }
                    _ = rx.recv() => {
                        println!("Received shutdown signal. Stopping proxy.");
                    }
                }
            } else if mode_type == "enforce" {
                println!(
                    "WARNING: Running ENFORCE mode. DFlux will intercept system traffic transparently."
                );
                eprintln!(
                    "IPv6 TCP ports 80/443 are rejected in ENFORCE mode; this build does not proxy IPv6."
                );
                // Prove the transparent listener can bind before changing host routing state.
                let gateway_listener = gateway::bind_gateway(config.gateway.port).await?;
                let mut routing_engine = RoutingEngine::new(
                    config.gateway.port,
                    config.egress.direct_interface.clone(),
                    config.egress.remote_interface.clone(),
                    config.gateway.exclude_subnets.clone(),
                );
                routing_engine.start()?;

                println!("Gateway is running. Press Ctrl-C to stop safely.");
                tokio::select! {
                    res = gateway::run_gateway_with_listener(gateway_listener, state_manager, egress_mgr) => {
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
            let routing_engine = RoutingEngine::new(12345, "".to_string(), None, "".to_string());
            routing_engine.stop()?;
        }
        Commands::Diagnose { export } => {
            let observer = observability::Observer::global()
                .expect("observability is initialized before command dispatch");
            if let Some(path) = export {
                observer.export_json(path)?;
                println!("Diagnostic snapshot exported to {}", path.display());
            } else {
                println!("Buffered events: {}", observer.snapshot().len());
                println!("Dropped events: {}", observer.dropped_events());
                println!("{}", serde_json::to_string_pretty(&observer.snapshot())?);
            }
        }
    }

    Ok(())
}
