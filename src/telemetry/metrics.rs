use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Debug, Default)]
pub struct GatewayMetrics {
    pub active_connections: AtomicUsize,
    pub idle_connections: AtomicUsize,
    pub half_closed_connections: AtomicUsize,
    pub total_connections: AtomicU64,
    pub rejected_connections: AtomicU64,
    pub accept_errors: AtomicU64,
    pub emfile_errors: AtomicU64,
    pub idle_timeouts: AtomicU64,
    pub half_close_timeouts: AtomicU64,
    pub bytes_client_to_server: AtomicU64,
    pub bytes_server_to_client: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayMetricsSnapshot {
    pub open_fds: usize,
    pub soft_fd_limit: u64,
    pub hard_fd_limit: u64,
    pub fd_utilization_pct: f64,
    pub active_connections: usize,
    pub idle_connections: usize,
    pub half_closed_connections: usize,
    pub total_connections: u64,
    pub rejected_connections: u64,
    pub accept_errors: u64,
    pub emfile_errors: u64,
    pub idle_timeouts: u64,
    pub half_close_timeouts: u64,
    pub bytes_client_to_server: u64,
    pub bytes_server_to_client: u64,
}

static GLOBAL_METRICS: OnceLock<Arc<GatewayMetrics>> = OnceLock::new();

pub fn global_metrics() -> Arc<GatewayMetrics> {
    GLOBAL_METRICS
        .get_or_init(|| Arc::new(GatewayMetrics::default()))
        .clone()
}

pub fn get_open_fd_count() -> usize {
    match std::fs::read_dir("/proc/self/fd") {
        Ok(entries) => entries.count().saturating_sub(1),
        Err(_) => 0,
    }
}

pub fn get_fd_limits() -> (u64, u64) {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } == 0 {
        (rlim.rlim_cur, rlim.rlim_max)
    } else {
        (1024, 1024)
    }
}

pub fn raise_nofile_limit(target: u64) -> std::io::Result<(u64, u64)> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let desired = rlim.rlim_max.min(target as libc::rlim_t);
    if desired > rlim.rlim_cur {
        rlim.rlim_cur = desired;
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok((rlim.rlim_cur, rlim.rlim_max))
}

pub fn calculate_safe_max_connections(configured: Option<usize>) -> usize {
    let (soft, _) = get_fd_limits();
    // Reserve 128 FDs for process operations (logging, DNS, epoll, signals, listener)
    let available = (soft as usize).saturating_sub(128);
    // Each connection uses 2 FDs: client + server
    let safe_from_nofile = (available / 2).max(10);
    if let Some(cfg) = configured {
        cfg.min(safe_from_nofile)
    } else {
        safe_from_nofile.min(10000)
    }
}

impl GatewayMetrics {
    pub fn snapshot(&self) -> GatewayMetricsSnapshot {
        let open_fds = get_open_fd_count();
        let (soft, hard) = get_fd_limits();
        let pct = if soft > 0 {
            (open_fds as f64 / soft as f64) * 100.0
        } else {
            0.0
        };
        GatewayMetricsSnapshot {
            open_fds,
            soft_fd_limit: soft,
            hard_fd_limit: hard,
            fd_utilization_pct: pct,
            active_connections: self.active_connections.load(Ordering::Relaxed),
            idle_connections: self.idle_connections.load(Ordering::Relaxed),
            half_closed_connections: self.half_closed_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            rejected_connections: self.rejected_connections.load(Ordering::Relaxed),
            accept_errors: self.accept_errors.load(Ordering::Relaxed),
            emfile_errors: self.emfile_errors.load(Ordering::Relaxed),
            idle_timeouts: self.idle_timeouts.load(Ordering::Relaxed),
            half_close_timeouts: self.half_close_timeouts.load(Ordering::Relaxed),
            bytes_client_to_server: self.bytes_client_to_server.load(Ordering::Relaxed),
            bytes_server_to_client: self.bytes_server_to_client.load(Ordering::Relaxed),
        }
    }
}
