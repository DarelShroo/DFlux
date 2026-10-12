use crate::probes;
use crate::state::{Decision, StateManager};
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::egress::EgressManager;

pub async fn run_proxy(
    port: u16,
    state_manager: StateManager,
    mode: String,
    egress_mgr: Arc<EgressManager>,
) -> Result<()> {
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

async fn handle_client(
    mut client_stream: TcpStream,
    state_manager: StateManager,
    mode: String,
    egress_mgr: Arc<EgressManager>,
) -> Result<()> {
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
    let host = host_port.split(':').next().unwrap_or("").to_string();
    let port: u16 = host_port
        .split(':')
        .nth(1)
        .unwrap_or("443")
        .parse()
        .unwrap_or(443);

    // Make routing decision via single-flight evaluator
    let eval_egress = egress_mgr.clone();
    let eval_host = host.clone();
    let decision = state_manager
        .get_or_evaluate(&host, move || async move {
            probes::evaluate_route(&eval_host, port, eval_egress).await
        })
        .await;

    // In observe mode, route Direct unless enforce mode specified
    let enforce_remote = mode == "enforce" && decision == Decision::Remote;

    // Resolve IPs (cached via DnsCache)
    let ips = match probes::dns::resolve(&host).await {
        Ok(ips) => ips,
        Err(_) => return Ok(()),
    };

    if ips.is_empty() {
        return Ok(());
    }

    // Connect to destination
    let mut server_stream =
        match crate::outbound::connect_tcp(ips[0], port, enforce_remote, egress_mgr).await {
            Ok(s) => s,
            Err(e) => {
                state_manager.record_failure(&host).await;
                return Err(e);
            }
        };

    let _ = client_stream.set_nodelay(true);
    let _ = server_stream.set_nodelay(true);

    // Send 200 OK to client
    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Copy bi-directional with 128 KiB buffers
    match tokio::io::copy_bidirectional_with_sizes(
        &mut client_stream,
        &mut server_stream,
        131072,
        131072,
    )
    .await
    {
        Ok((from_client, from_server)) => {
            if from_server > 0 || from_client > 0 {
                state_manager.record_success(&host).await;
            }
            Ok(())
        }
        Err(e) => {
            state_manager.record_failure(&host).await;
            Err(e.into())
        }
    }
}
