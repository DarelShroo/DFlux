use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpStream, TcpSocket};
use tokio::time::{timeout, Duration};
use anyhow::{Result, anyhow};
use std::os::unix::io::AsRawFd;

use std::sync::Arc;
use crate::egress::EgressManager;

pub async fn connect_tcp(ip: IpAddr, port: u16, enforce_remote: bool, egress_mgr: Arc<EgressManager>) -> Result<TcpStream> {
    let addr = SocketAddr::new(ip, port);
    
    let socket = if ip.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    let ifname = if enforce_remote {
        egress_mgr.get_remote_interface()
    } else {
        egress_mgr.get_direct_interface()
    };
    
    let fd = socket.as_raw_fd();
    
    // Set SO_MARK to 0x4446 so the nftables rules ignore our own traffic
    unsafe {
        let mark: u32 = 0x4446;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
        if ret != 0 {
            eprintln!("Warning: Failed to set SO_MARK on outbound socket: {}", std::io::Error::last_os_error());
        }
    }

    // Bind to the correct interface (both remote or direct if specified)
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
                return Err(anyhow!("Failed to bind to {}: {} (Are you running with CAP_NET_RAW?)", ifname, std::io::Error::last_os_error()));
            }
        }
    }

    match timeout(Duration::from_secs(5), socket.connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(anyhow!("TCP connect timeout")),
    }
}
