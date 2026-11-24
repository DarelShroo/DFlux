use crate::telemetry::GatewayMetrics;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Sets TCP keepalive parameters on a socket to detect dead peers at the kernel level.
pub fn configure_socket_keepalive(
    stream: &TcpStream,
    idle: Duration,
    interval: Duration,
    retries: u32,
) {
    let sock_ref = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(idle)
        .with_interval(interval)
        .with_retries(retries);
    let _ = sock_ref.set_tcp_keepalive(&keepalive);
}

/// Helper function to copy one direction of a full-duplex TCP stream.
/// When EOF is encountered on the reader, `writer.shutdown().await` is called
/// to signal a TCP FIN (half-close) to the remote peer.
async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    buffer_size: usize,
    last_activity: Arc<AtomicU64>,
    metrics_counter: Arc<AtomicU64>,
) -> io::Result<u64>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = vec![0u8; buffer_size];
    let mut total_bytes = 0u64;

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            // EOF: Remote reader closed their write end. Signal FIN to our writer.
            writer.shutdown().await?;
            return Ok(total_bytes);
        }
        writer.write_all(&buf[..n]).await?;
        total_bytes += n as u64;
        metrics_counter.fetch_add(n as u64, Ordering::Relaxed);
        last_activity.store(coarse_now_millis(), Ordering::Relaxed);
    }
}

#[inline]
fn coarse_now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Bounded bidirectional copy engine.
///
/// Features:
/// 1. Socket-level TCP keepalive probes (idle 60s, interval 10s, retries 3).
/// 2. Active vs Idle differentiation: As long as data flows in either direction,
///    the idle timer resets on every chunk.
/// 3. Inactivity timeout: If no bytes are transferred in either direction for `idle_timeout`,
///    the connection is aborted cleanly with `io::ErrorKind::TimedOut`.
/// 4. Orderly half-close handling: If one side sends FIN (EOF), the other side is given up to
///    `half_close_timeout` to transmit any final response data and close. If it fails to close
///    within the grace window, both streams are torn down to prevent FIN-WAIT-2 / CLOSE-WAIT leaks.
pub async fn copy_bidirectional_with_timeouts(
    client: &mut TcpStream,
    server: &mut TcpStream,
    idle_timeout: Duration,
    half_close_timeout: Duration,
    buffer_size: usize,
    metrics: Arc<GatewayMetrics>,
) -> io::Result<(u64, u64)> {
    // Configure socket-level keepalive on both ends
    configure_socket_keepalive(client, Duration::from_secs(60), Duration::from_secs(10), 3);
    configure_socket_keepalive(server, Duration::from_secs(60), Duration::from_secs(10), 3);

    let (c_read, c_write) = client.split();
    let (s_read, s_write) = server.split();

    let last_activity = Arc::new(AtomicU64::new(coarse_now_millis()));

    let c2s_counter = Arc::new(AtomicU64::new(0));
    let s2c_counter = Arc::new(AtomicU64::new(0));

    let c2s_fut = copy_direction(
        c_read,
        s_write,
        buffer_size,
        last_activity.clone(),
        c2s_counter.clone(),
    );
    let s2c_fut = copy_direction(
        s_read,
        c_write,
        buffer_size,
        last_activity.clone(),
        s2c_counter.clone(),
    );

    tokio::pin!(c2s_fut);
    tokio::pin!(s2c_fut);

    let mut c2s_done = false;
    let mut s2c_done = false;
    let mut c2s_bytes = 0u64;
    let mut s2c_bytes = 0u64;
    let mut half_close_start: Option<Instant> = None;

    let check_interval = (idle_timeout / 4)
        .min(half_close_timeout / 4)
        .clamp(Duration::from_millis(50), Duration::from_millis(1000));

    loop {
        tokio::select! {
            res = &mut c2s_fut, if !c2s_done => {
                c2s_bytes = res?;
                c2s_done = true;
                if s2c_done {
                    break;
                }
                metrics.half_closed_connections.fetch_add(1, Ordering::Relaxed);
                half_close_start = Some(Instant::now());
            }
            res = &mut s2c_fut, if !s2c_done => {
                s2c_bytes = res?;
                s2c_done = true;
                if c2s_done {
                    break;
                }
                metrics.half_closed_connections.fetch_add(1, Ordering::Relaxed);
                half_close_start = Some(Instant::now());
            }
            _ = tokio::time::sleep(check_interval) => {
                // 1. Check half-close timeout
                if let Some(start) = half_close_start {
                    if start.elapsed() >= half_close_timeout {
                        metrics.half_close_timeouts.fetch_add(1, Ordering::Relaxed);
                        metrics.half_closed_connections.fetch_sub(1, Ordering::Relaxed);
                        // Grace period expired for the lingering half; terminate cleanly
                        return Ok((c2s_counter.load(Ordering::Relaxed), s2c_counter.load(Ordering::Relaxed)));
                    }
                } else {
                    // 2. Check idle timeout
                    let now_ms = coarse_now_millis();
                    let last_ms = last_activity.load(Ordering::Relaxed);
                    if now_ms.saturating_sub(last_ms) >= idle_timeout.as_millis() as u64 {
                        metrics.idle_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("TCP connection idle timeout after {:?} of inactivity", idle_timeout),
                        ));
                    }
                }
            }
        }
    }

    if half_close_start.is_some() {
        metrics
            .half_closed_connections
            .fetch_sub(1, Ordering::Relaxed);
    }

    metrics
        .bytes_client_to_server
        .fetch_add(c2s_bytes, Ordering::Relaxed);
    metrics
        .bytes_server_to_client
        .fetch_add(s2c_bytes, Ordering::Relaxed);

    Ok((c2s_bytes, s2c_bytes))
}
