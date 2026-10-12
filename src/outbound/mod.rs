use anyhow::{Result, anyhow};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{Duration, timeout};

use crate::egress::EgressManager;
use std::sync::Arc;

pub async fn connect_tcp(
    ip: IpAddr,
    port: u16,
    enforce_remote: bool,
    egress_mgr: Arc<EgressManager>,
) -> Result<TcpStream> {
    let addr = SocketAddr::new(ip, port);

    let socket = if ip.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    // Enable TCP_NODELAY to avoid 40ms delayed-ACK latency
    let _ = socket.set_nodelay(true);
    // Note: We deliberately do NOT call set_recv_buffer_size / set_send_buffer_size here.
    // In Linux, manually setting SO_RCVBUF disables kernel dynamic TCP window autotuning (tcp_moderate_rcvbuf),
    // which artificially caps the Bandwidth-Delay Product (BDP) on high-latency or fast WAN links.

    let ifname = if enforce_remote {
        match egress_mgr.get_remote_interface() {
            Some(iface) => iface,
            None => {
                return Err(anyhow!(
                    "REMOTE egress requested but no remote interface is configured"
                ));
            }
        }
    } else {
        egress_mgr.get_direct_interface()
    };

    let fd = socket.as_raw_fd();

    // Set SO_MARK to 0x4446 so the nftables rules ignore our own traffic
    unsafe {
        let mark: u32 = 0x4446;
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
    }

    // Bind to the correct interface (remote or direct if specified)
    if !ifname.is_empty() {
        let mut ifname_bytes = ifname.as_bytes().to_vec();
        ifname_bytes.push(0); // null-terminate
        unsafe {
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                ifname_bytes.as_ptr() as *const libc::c_void,
                ifname_bytes.len() as libc::socklen_t,
            );
            if ret != 0 {
                if enforce_remote {
                    return Err(anyhow!(
                        "Failed to bind remote egress to {}: {} (requires CAP_NET_RAW)",
                        ifname,
                        std::io::Error::last_os_error()
                    ));
                } else {
                    // Direct interface: if SO_BINDTODEVICE fails, standard routing table applies
                    tracing::debug!(
                        "SO_BINDTODEVICE on direct interface {} failed, using default route",
                        ifname
                    );
                }
            }
        }
    }

    match timeout(Duration::from_secs(3), socket.connect(addr)).await {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            Ok(stream)
        }
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(anyhow!("TCP connect timeout")),
    }
}
