use clap::Parser;
use dflux::cli::{Cli, Commands};
use dflux::config::DFluxConfig;
use dflux::egress::{self, EgressManager};
use dflux::observability::{self, Level};
use dflux::routing::RoutingEngine;
use dflux::state::StateManager;
use dflux::{gateway, probes, proxy, systemd_notify, telemetry};
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
            // Automatically raise soft file descriptor limit to 65536 if allowed by hard limit
            let (soft, hard) =
                telemetry::raise_nofile_limit(65536).unwrap_or_else(|_| telemetry::get_fd_limits());
            tracing::info!(
                soft_limit = soft,
                hard_limit = hard,
                "Process file descriptor limits configured"
            );

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
                    res = proxy::run_proxy_with_config(config.gateway.clone(), state_manager, mode_type.clone(), egress_mgr) => {
                        if let Err(e) = res {
                            eprintln!("Proxy fatal error: {}", e);
                            let mut fatal_event = observability::event(
                                Level::Critical,
                                "proxy_fatal_error",
                                "main",
                                "run_proxy",
                            );
                            fatal_event.error_category = Some("fatal_exit".into());
                            fatal_event.error_message = Some(e.to_string());
                            observability::emit(fatal_event);
                            return Err(e);
                        }
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
                let mut routing_engine = RoutingEngine::with_preserve_forwarding(
                    config.gateway.port,
                    config.egress.direct_interface.clone(),
                    config.egress.remote_interface.clone(),
                    config.gateway.exclude_subnets.clone(),
                    config.gateway.preserve_ip_forward,
                );
                routing_engine.start()?;

                // Notify systemd that service is ready
                systemd_notify::notify_ready();

                // Background watchdog supervisor task
                let watchdog_secs = config.gateway.watchdog_secs.unwrap_or(15);
                let watchdog_task = tokio::spawn(async move {
                    let interval = std::time::Duration::from_secs((watchdog_secs / 2).max(1));
                    let mut ticker = tokio::time::interval(interval);
                    loop {
                        ticker.tick().await;
                        let open_fds = telemetry::get_open_fd_count();
                        let (soft, _) = telemetry::get_fd_limits();
                        // Suppress watchdog ping if open FDs exceed 95% of limit (starvation / deadlock)
                        let healthy = soft == 0 || (open_fds as f64 / soft as f64) < 0.95;
                        if healthy {
                            systemd_notify::notify_watchdog();
                        } else {
                            tracing::warn!(
                                open_fds,
                                soft,
                                "Watchdog ping suppressed: critical FD saturation"
                            );
                        }
                    }
                });

                println!("Gateway is running. Press Ctrl-C to stop safely.");
                tokio::select! {
                    res = gateway::run_gateway_with_listener(gateway_listener, state_manager, egress_mgr, config.gateway.clone()) => {
                        watchdog_task.abort();
                        if let Err(e) = res {
                            eprintln!("Gateway fatal error: {}", e);
                            let mut fatal_event = observability::event(
                                Level::Critical,
                                "gateway_fatal_error",
                                "main",
                                "run_gateway",
                            );
                            fatal_event.error_category = Some("fatal_exit".into());
                            fatal_event.error_message = Some(e.to_string());
                            observability::emit(fatal_event);
                            // Return error so main exits with non-zero exit code (restarted by systemd Restart=on-failure)
                            return Err(e);
                        }
                    }
                    _ = rx.recv() => {
                        watchdog_task.abort();
                        systemd_notify::notify_stopping();
                        println!("Received shutdown signal. RoutingEngine Drop will clean up.");
                    }
                }
            }
        }
        Commands::Rollback { restore_sysctls } => {
            println!("Manually rolling back DFlux routing rules...");
            let mut routing_engine =
                RoutingEngine::new(12345, "".to_string(), None, "".to_string());
            routing_engine.preserve_ip_forward = !*restore_sysctls;
            routing_engine.stop()?;
        }
        Commands::Diagnose { export, metrics } => {
            let observer = observability::Observer::global()
                .expect("observability is initialized before command dispatch");
            let snap = telemetry::global_metrics().snapshot();
            if *metrics || export.is_none() {
                println!("=== DFlux Gateway & Resource Metrics ===");
                println!(
                    "  Open FDs:             {} (soft limit: {}, hard limit: {}, {:.1}% used)",
                    snap.open_fds, snap.soft_fd_limit, snap.hard_fd_limit, snap.fd_utilization_pct
                );
                println!("  Active Connections:   {}", snap.active_connections);
                println!("  Idle Connections:     {}", snap.idle_connections);
                println!("  Half-closed Conns:    {}", snap.half_closed_connections);
                println!("  Total Intercepted:    {}", snap.total_connections);
                println!("  Rejected (Shed):      {}", snap.rejected_connections);
                println!(
                    "  Accept Errors:        {} (EMFILE: {})",
                    snap.accept_errors, snap.emfile_errors
                );
                println!(
                    "  Timeouts:             {} idle, {} half-close",
                    snap.idle_timeouts, snap.half_close_timeouts
                );
                println!(
                    "  Traffic Transferred:  {} bytes client->server, {} bytes server->client",
                    snap.bytes_client_to_server, snap.bytes_server_to_client
                );
                println!("========================================");
            }
            if let Some(path) = export {
                let export_data = serde_json::json!({
                    "metrics": snap,
                    "events": observer.snapshot(),
                    "dropped_events": observer.dropped_events(),
                });
                std::fs::write(path, serde_json::to_string_pretty(&export_data)?)?;
                println!("Diagnostic snapshot exported to {}", path.display());
            } else if !*metrics {
                println!("Buffered events: {}", observer.snapshot().len());
                println!("Dropped events: {}", observer.dropped_events());
                println!("{}", serde_json::to_string_pretty(&observer.snapshot())?);
            }
        }
    }

    Ok(())
}
