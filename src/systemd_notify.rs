use std::os::unix::net::UnixDatagram;

/// Sends a readiness notification to systemd if NOTIFY_SOCKET is defined.
pub fn notify_ready() -> bool {
    notify("READY=1")
}

/// Sends a watchdog ping to systemd if NOTIFY_SOCKET is defined.
pub fn notify_watchdog() -> bool {
    notify("WATCHDOG=1")
}

/// Sends a stopping notification to systemd if NOTIFY_SOCKET is defined.
pub fn notify_stopping() -> bool {
    notify("STOPPING=1")
}

/// Sends a raw notification string to the socket specified in the NOTIFY_SOCKET environment variable.
/// Supports both standard filesystem pathname sockets and abstract Unix domain sockets (prefixed with '@').
pub fn notify(state: &str) -> bool {
    let Ok(sock_path) = std::env::var("NOTIFY_SOCKET") else {
        return false;
    };
    if sock_path.trim().is_empty() {
        return false;
    }

    // Standard pathname Unix domain socket
    if !sock_path.starts_with('@') {
        if let Ok(socket) = UnixDatagram::unbound()
            && socket.send_to(state.as_bytes(), &sock_path).is_ok()
        {
            return true;
        }
        return false;
    }

    // Abstract Unix domain socket (Linux specific, starts with '\0')
    let abstract_name = &sock_path[1..];
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return false;
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

    let bytes = abstract_name.as_bytes();
    let max_len = addr.sun_path.len() - 1;
    let copy_len = bytes.len().min(max_len);

    // First byte of sun_path is \0 (abstract namespace)
    for (i, byte) in bytes.iter().enumerate().take(copy_len) {
        addr.sun_path[i + 1] = *byte as libc::c_char;
    }

    let addr_len = (std::mem::size_of::<libc::sa_family_t>() + 1 + copy_len) as libc::socklen_t;
    let ret = unsafe {
        libc::sendto(
            fd,
            state.as_ptr() as *const libc::c_void,
            state.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            addr_len,
        )
    };
    unsafe {
        libc::close(fd);
    }
    ret >= 0
}
