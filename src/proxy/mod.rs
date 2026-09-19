use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use anyhow::Result;
use crate::state::{StateManager, Decision};
use crate::probes;

use crate::egress::EgressManager;

pub async fn run_proxy(port: u16, state_manager: StateManager, mode: String, egress_mgr: Arc<EgressManager>) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("DFlux proxy listening on {}", addr);

    let semaphore = Arc::new(tokio::sync::Semaphore::new(2000));

    loop {
        let (stream, _) = listener.accept().await?;
        
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Max proxy connections reached!");
                continue;
            }
        };

        let state_manager = state_manager.clone();
        let mode = mode.clone();
        let egress_mgr = egress_mgr.clone();
        
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_client(stream, state_manager, mode, egress_mgr).await {
                eprintln!("Client error: {}", e);
            }
        });
    }
}

async fn handle_client(mut client_stream: TcpStream, state_manager: StateManager, mode: String, egress_mgr: Arc<EgressManager>) -> Result<()> {
    let mut buf = [0u8; 4096];
    let n = client_stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let mut lines = request.lines();
    let first_line = lines.next().unwrap_or("");
    
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() != 3 || parts[0] != "CONNECT" {
        return Ok(()); // We only handle CONNECT for now
    }

    let host_port = parts[1];
    let host = host_port.split(':').next().unwrap_or("");

    // Make routing decision
    let decision = if let Some(d) = state_manager.get_decision(host).await {
        d
    } else {
        println!("Evaluating {}", host);
        // We only evaluate TLS for 443 for now, or assume the probe will handle it.
        // run_probe_silent already tries resolving, tcp, tls.
        let direct = probes::run_probe_silent(host, false, egress_mgr.clone()).await.ok();
        let remote = probes::run_probe_silent(host, true, egress_mgr.clone()).await.ok();
        
        let mut d = Decision::Unknown;
        let mut failed = false;
        if let Some(dir) = direct {
            if dir.cert_valid {
                d = Decision::Direct;
            } else if let Some(rem) = remote {
                if rem.cert_valid {
                    d = Decision::Remote;
                }
            }
        }
        if d == Decision::Unknown {
            d = Decision::Direct; // Fallback to direct
            failed = true;
        }
        
        state_manager.set_decision(host, d, failed).await;
        d
    };

    println!("Routing {} via {:?}", host_port, decision);

    // If observe mode, we just log and route DIRECT.
    let enforce_remote = mode == "enforce" && decision == Decision::Remote;

    // Resolve IPs
    let ips = match probes::dns::resolve(host).await {
        Ok(ips) => ips,
        Err(_) => return Ok(()),
    };
    
    if ips.is_empty() {
        return Ok(());
    }
    
    let port: u16 = host_port.split(':').nth(1).unwrap_or("443").parse().unwrap_or(443);

    // Connect to destination
    let mut server_stream = crate::outbound::connect_tcp(ips[0], port, enforce_remote, egress_mgr).await?;

    // Send 200 OK to client
    client_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    // Copy bi-directional
    tokio::io::copy_bidirectional(&mut client_stream, &mut server_stream).await?;

    Ok(())
}
