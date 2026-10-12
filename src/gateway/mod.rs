pub mod inspector;

use crate::egress::EgressManager;
use crate::state::{Decision, StateManager};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    // With TPROXY, the local_addr() of the accepted stream IS the original destination
    Ok(stream.local_addr()?)
}

pub async fn run_gateway(
    port: u16,
    state_manager: StateManager,
    egress_mgr: Arc<EgressManager>,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", port).parse::<SocketAddr>()?;
    let socket = tokio::net::TcpSocket::new_v4()?;

    // Set IP_TRANSPARENT so the socket can accept packets destined for external IPs
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&socket);
    unsafe {
        let optval: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            eprintln!(
                "Warning: Failed to set IP_TRANSPARENT on listener: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // SO_REUSEADDR is already set by TcpSocket::new_v4() by default in tokio, but we can bind now
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;

    println!("DFlux Transparent Gateway listening on {}", addr);

    // Semaphore to protect against connection floods (Circuit Breaker layer 1)
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2000));

    loop {
        let (stream, peer_addr) = listener.accept().await?;

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                eprintln!(
                    "Max connections reached! Dropping traffic from {}",
                    peer_addr
                );
                continue; // Drop to protect network health
            }
        };

        let state_manager = state_manager.clone();
        let egress_mgr = egress_mgr.clone();

        tokio::spawn(async move {
            let _permit = permit; // Will be dropped automatically when the task finishes
            if let Err(e) =
                handle_gateway_client(stream, peer_addr, state_manager, egress_mgr).await
            {
                eprintln!("Gateway client error: {}", e);
            }
        });
    }
}

async fn handle_gateway_client(
    mut client_stream: TcpStream,
    peer_addr: SocketAddr,
    state_manager: StateManager,
    egress_mgr: Arc<EgressManager>,
) -> Result<()> {
    // 1. Get original destination IP
    let orig_dst = match get_original_dst(&client_stream) {
        Ok(dst) => dst,
        Err(e) => {
            // If we can't get original destination, we can't forward properly unless we have SNI, but we need IP for non-SNI anyway.
            // Wait, for testing directly without iptables redirect, we can fallback to peer_addr just to not crash, or just return.
            // Let's log and return.
            eprintln!(
                "Could not get original destination for {}: {}",
                peer_addr, e
            );
            return Err(e);
        }
    };

    let orig_port = orig_dst.port();

    // 2. Peek for SNI / Host
    let (hostname_opt, _buffered) = inspector::peek_hostname(&mut client_stream).await?;

    let target_host = if let Some(h) = &hostname_opt {
        h.clone()
    } else {
        orig_dst.ip().to_string()
    };

    tracing::debug!(
        "Gateway intercepted {} -> {} (host: {})",
        peer_addr,
        orig_dst,
        target_host
    );

    // 3. Make routing decision via single-flight evaluator
    let eval_egress = egress_mgr.clone();
    let eval_host = target_host.clone();
    let decision = state_manager
        .get_or_evaluate(&target_host, move || async move {
            crate::probes::evaluate_route(&eval_host, orig_port, eval_egress).await
        })
        .await;

    let enforce_remote = decision == Decision::Remote;

    // 4. Connect to destination:
    // When routing DIRECT, use the original destination IP selected by the client.
    // This preserves CDN Anycast optimization, geo-DNS proximity, and eliminates DoH latency completely.
    // Only when routing REMOTE (anti-censorship/anti-poisoning) do we resolve true IP via secure DoH.
    let dest_ip = if enforce_remote {
        if let Some(h) = &hostname_opt {
            match crate::probes::dns::resolve(h).await {
                Ok(ips) if !ips.is_empty() => {
                    let true_ip = ips[0];
                    if true_ip != orig_dst.ip() {
                        tracing::info!(
                            "Gateway anti-poisoning: replacing {} with {}",
                            orig_dst.ip(),
                            true_ip
                        );
                    }
                    true_ip
                }
                _ => orig_dst.ip(),
            }
        } else {
            orig_dst.ip()
        }
    } else {
        orig_dst.ip()
    };

    let _ = client_stream.set_nodelay(true);

    let mut server_stream =
        match crate::outbound::connect_tcp(dest_ip, orig_port, enforce_remote, egress_mgr).await {
            Ok(s) => s,
            Err(e) => {
                state_manager.record_failure(&target_host).await;
                return Err(e);
            }
        };

    let _ = server_stream.set_nodelay(true);

    // 5. High performance bidirectional copy with 128 KiB buffers
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
                state_manager.record_success(&target_host).await;
            }
            Ok(())
        }
        Err(e) => {
            state_manager.record_failure(&target_host).await;
            Err(e.into())
        }
    }
}
