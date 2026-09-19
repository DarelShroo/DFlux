pub mod inspector;

use tokio::net::TcpStream;
use anyhow::Result;
use std::net::SocketAddr;
use crate::state::{StateManager, Decision};
use crate::probes;
use std::sync::Arc;
use crate::egress::EgressManager;

fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    // With TPROXY, the local_addr() of the accepted stream IS the original destination
    Ok(stream.local_addr()?)
}

pub async fn run_gateway(port: u16, state_manager: StateManager, egress_mgr: Arc<EgressManager>) -> Result<()> {
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
            eprintln!("Warning: Failed to set IP_TRANSPARENT on listener: {}", std::io::Error::last_os_error());
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
                eprintln!("Max connections reached! Dropping traffic from {}", peer_addr);
                continue; // Drop to protect network health
            }
        };

        let state_manager = state_manager.clone();
        let egress_mgr = egress_mgr.clone();
        
        tokio::spawn(async move {
            let _permit = permit; // Will be dropped automatically when the task finishes
            if let Err(e) = handle_gateway_client(stream, peer_addr, state_manager, egress_mgr).await {
                eprintln!("Gateway client error: {}", e);
            }
        });
    }
}

async fn handle_gateway_client(mut client_stream: TcpStream, peer_addr: SocketAddr, state_manager: StateManager, egress_mgr: Arc<EgressManager>) -> Result<()> {
    // 1. Get original destination IP
    let orig_dst = match get_original_dst(&client_stream) {
        Ok(dst) => dst,
        Err(e) => {
            // If we can't get original destination, we can't forward properly unless we have SNI, but we need IP for non-SNI anyway.
            // Wait, for testing directly without iptables redirect, we can fallback to peer_addr just to not crash, or just return.
            // Let's log and return.
            eprintln!("Could not get original destination for {}: {}", peer_addr, e);
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

    println!("Gateway intercepted {} -> {} (host: {})", peer_addr, orig_dst, target_host);

    // 3. Make routing decision
    let decision = if let Some(d) = state_manager.get_decision(&target_host).await {
        d
    } else {
        println!("Gateway evaluating {}", target_host);
        let direct = probes::run_probe_silent(&target_host, false, egress_mgr.clone()).await.ok();
        let remote = probes::run_probe_silent(&target_host, true, egress_mgr.clone()).await.ok();
        
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
            d = Decision::Direct; // Fallback
            failed = true;
        }
        
        state_manager.set_decision(&target_host, d, failed).await;
        d
    };

    println!("Gateway routing {} via {:?}", target_host, decision);
    let enforce_remote = decision == Decision::Remote;

    // 4. Connect to destination
    // Anti-DNS Poisoning: If we have SNI, we use our secure DoH to resolve the real IP, 
    // completely ignoring the potentially poisoned IP that the browser connected to.
    let dest_ip = if let Some(h) = &hostname_opt {
        match crate::probes::dns::resolve(h).await {
            Ok(ips) if !ips.is_empty() => {
                let true_ip = ips[0];
                if true_ip != orig_dst.ip() {
                    println!("Gateway anti-poisoning: replacing {} with {}", orig_dst.ip(), true_ip);
                }
                true_ip
            },
            _ => orig_dst.ip(),
        }
    } else {
        orig_dst.ip()
    };

    let mut server_stream = crate::outbound::connect_tcp(dest_ip, orig_port, enforce_remote, egress_mgr).await?;

    // 5. Copy bi-directional
    // Note: since we used `peek` in inspector, client_stream still contains the full original bytes.
    tokio::io::copy_bidirectional(&mut client_stream, &mut server_stream).await?;

    Ok(())
}
