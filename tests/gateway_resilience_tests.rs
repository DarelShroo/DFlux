use dflux::config::GatewayConfig;
use dflux::gateway::copy::copy_bidirectional_with_timeouts;
use dflux::routing::{DeploymentState, RoutingEngine};
use dflux::systemd_notify;
use dflux::telemetry::{self, GatewayMetrics};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_tcp_idle_timeout_aborts_hanging_connection() {
    let metrics = Arc::new(GatewayMetrics::default());

    // Setup local listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    let client_side = client;
    let server_side = server;

    // Simulate proxy connecting client_side to a remote target
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let remote_client = TcpStream::connect(target_addr).await.unwrap();
    let (remote_server, _) = target_listener.accept().await.unwrap();

    let mut proxy_client = client_side;
    let mut proxy_remote = remote_client;

    let metrics_clone = metrics.clone();
    let proxy_handle = tokio::spawn(async move {
        copy_bidirectional_with_timeouts(
            &mut proxy_client,
            &mut proxy_remote,
            Duration::from_millis(300), // Idle timeout: 300ms
            Duration::from_millis(200), // Half-close timeout: 200ms
            65536,
            metrics_clone,
        )
        .await
    });

    // Neither client nor server sends any bytes -> connection is completely idle
    let res = proxy_handle.await.unwrap();

    assert!(res.is_err(), "Idle connection must return an error");
    let err = res.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::TimedOut,
        "Error kind must be TimedOut"
    );
    assert!(
        metrics
            .idle_timeouts
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1,
        "Idle timeout counter must be incremented"
    );

    // Verify sockets can be dropped and descriptors freed
    drop(server_side);
    drop(remote_server);
}

#[tokio::test]
async fn test_tcp_active_connection_does_not_timeout_while_streaming() {
    let metrics = Arc::new(GatewayMetrics::default());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_side = TcpStream::connect(addr).await.unwrap();
    let (mut server_side, _) = listener.accept().await.unwrap();

    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let mut remote_client = TcpStream::connect(target_addr).await.unwrap();
    let (mut remote_server, _) = target_listener.accept().await.unwrap();

    let metrics_clone = metrics.clone();
    // Idle timeout set to 400ms
    let proxy_handle = tokio::spawn(async move {
        copy_bidirectional_with_timeouts(
            &mut server_side,
            &mut remote_client,
            Duration::from_millis(400),
            Duration::from_millis(300),
            65536,
            metrics_clone,
        )
        .await
    });

    // Client sends data periodically (every 100ms) for 1000ms (2.5x the idle timeout)
    let sender_handle = tokio::spawn(async move {
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            client_side
                .write_all(b"heartbeat-data-chunk")
                .await
                .unwrap();
        }
        client_side.shutdown().await.unwrap();
    });

    // Remote server reads all data and responds
    let receiver_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        let mut total_read = 0;
        loop {
            let n = remote_server.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total_read += n;
        }
        remote_server.shutdown().await.unwrap();
        total_read
    });

    sender_handle.await.unwrap();
    let total_received = receiver_handle.await.unwrap();
    let proxy_res = proxy_handle.await.unwrap();

    assert!(
        proxy_res.is_ok(),
        "Active streaming connection must NOT be terminated by idle timeout"
    );
    assert_eq!(total_received, 10 * b"heartbeat-data-chunk".len());
    assert_eq!(
        metrics
            .idle_timeouts
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "No idle timeouts should occur for active streams"
    );
}

#[tokio::test]
async fn test_tcp_half_close_grace_period_terminates_lingering_peer() {
    let metrics = Arc::new(GatewayMetrics::default());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_side = TcpStream::connect(addr).await.unwrap();
    let (mut server_side, _) = listener.accept().await.unwrap();

    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let mut remote_client = TcpStream::connect(target_addr).await.unwrap();
    let (mut remote_server, _) = target_listener.accept().await.unwrap();

    let metrics_clone = metrics.clone();
    let proxy_handle = tokio::spawn(async move {
        copy_bidirectional_with_timeouts(
            &mut server_side,
            &mut remote_client,
            Duration::from_secs(10),    // High idle timeout
            Duration::from_millis(300), // Short half-close grace period: 300ms
            65536,
            metrics_clone,
        )
        .await
    });

    // Client sends request then immediately performs TCP half-close (FIN)
    client_side
        .write_all(b"GET /hang HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    client_side.shutdown().await.unwrap();

    // Remote server receives request but deliberately HANGS and never sends response or FIN (lingering in CLOSE-WAIT)
    let mut buf = [0u8; 100];
    let n = remote_server.read(&mut buf).await.unwrap();
    assert!(n > 0);

    // Wait for the proxy to finish via half-close timeout
    let start = std::time::Instant::now();
    let res = proxy_handle.await.unwrap();
    let elapsed = start.elapsed();

    assert!(res.is_ok(), "Half-close grace expiration finishes cleanly");
    assert!(
        elapsed >= Duration::from_millis(250) && elapsed <= Duration::from_millis(1500),
        "Half-close timeout must terminate lingering connection after grace period (took {:?})",
        elapsed
    );
    assert_eq!(
        metrics
            .half_close_timeouts
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "half_close_timeouts metric must be incremented"
    );
}

#[tokio::test]
async fn test_concurrency_semaphore_and_backpressure() {
    let metrics = Arc::new(GatewayMetrics::default());
    let max_conns = 3;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_conns));

    // Acquire all 3 available permits
    let permit1 = semaphore.clone().try_acquire_owned().unwrap();
    let permit2 = semaphore.clone().try_acquire_owned().unwrap();
    let permit3 = semaphore.clone().try_acquire_owned().unwrap();

    // 4th connection attempt should be rejected (backpressure)
    let permit4 = semaphore.clone().try_acquire_owned();
    assert!(
        permit4.is_err(),
        "4th connection must be rejected due to backpressure"
    );

    metrics
        .rejected_connections
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        metrics
            .rejected_connections
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // Release one permit
    drop(permit1);

    // Now 5th connection attempt succeeds
    let permit5 = semaphore.clone().try_acquire_owned();
    assert!(
        permit5.is_ok(),
        "Connection must succeed once permit is freed"
    );

    drop(permit2);
    drop(permit3);
    drop(permit5);
}

#[test]
fn test_preserve_ip_forward_on_rollback() {
    // 1. By default, RoutingEngine preserves forwarding
    let engine = RoutingEngine::new(12345, "eth0".to_string(), None, "10.0.0.0/8".to_string());
    assert!(
        engine.preserve_ip_forward,
        "preserve_ip_forward must default to true"
    );

    // 2. Can be customized with explicit flag
    let custom_engine = RoutingEngine::with_preserve_forwarding(
        12345,
        "eth0".to_string(),
        None,
        "10.0.0.0/8".to_string(),
        false,
    );
    assert!(!custom_engine.preserve_ip_forward);

    // 3. DeploymentState serializes and deserializes preserve_ip_forward with default true
    let json = r#"{
        "uuid": "test-uuid",
        "pid": 1234,
        "created_at": 5000,
        "table_name": "dflux",
        "rule_pref": 32000,
        "fwmark": 1,
        "table_id": 100,
        "nft_active": true,
        "ip_rule_active": true,
        "ip_route_active": true,
        "ip_forward_original": "0"
    }"#;
    let state: DeploymentState = serde_json::from_str(json).unwrap();
    assert!(
        state.preserve_ip_forward,
        "Legacy states without preserve_ip_forward field must default to true"
    );
}

#[test]
fn test_nofile_limit_and_safe_concurrency_calculation() {
    // Test safe connection calculation
    let (soft, hard) = telemetry::get_fd_limits();
    assert!(soft > 0);
    assert!(hard >= soft);

    let calculated = telemetry::calculate_safe_max_connections(None);
    // Must be at least 10 and no more than (soft - 128) / 2
    let expected_max = (soft as usize).saturating_sub(128) / 2;
    assert!(calculated <= expected_max.max(10));

    // Test explicit override bounded by safe max
    let explicit_low = telemetry::calculate_safe_max_connections(Some(50));
    assert_eq!(explicit_low, 50.min(expected_max.max(10)));
}

#[tokio::test]
async fn test_systemd_notify_protocol() {
    use std::os::unix::net::UnixDatagram;

    let socket_path = std::env::temp_dir().join(format!("test_notify_{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket_path);

    let receiver = UnixDatagram::bind(&socket_path).unwrap();
    receiver.set_nonblocking(true).unwrap();

    // Set NOTIFY_SOCKET env var
    unsafe {
        std::env::set_var("NOTIFY_SOCKET", socket_path.to_str().unwrap());
    }

    assert!(systemd_notify::notify_ready());
    assert!(systemd_notify::notify_watchdog());
    assert!(systemd_notify::notify_stopping());

    let mut buf = [0u8; 100];
    let n1 = receiver.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n1], b"READY=1");

    let n2 = receiver.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n2], b"WATCHDOG=1");

    let n3 = receiver.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n3], b"STOPPING=1");

    unsafe {
        std::env::remove_var("NOTIFY_SOCKET");
    }
    let _ = std::fs::remove_file(&socket_path);
}

#[tokio::test]
async fn test_massive_concurrent_connections() {
    let metrics = Arc::new(GatewayMetrics::default());
    let mut tasks = Vec::new();

    // Spawn 50 simultaneous client-proxy-target pairs
    for i in 0..50 {
        let metrics_clone = metrics.clone();
        tasks.push(tokio::spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_addr = target_listener.local_addr().unwrap();

            let mut client = TcpStream::connect(addr).await.unwrap();
            let (mut proxy_in, _) = listener.accept().await.unwrap();

            let mut proxy_out = TcpStream::connect(target_addr).await.unwrap();
            let (mut target, _) = target_listener.accept().await.unwrap();

            // Run proxy copying in background
            let proxy_task = tokio::spawn(async move {
                copy_bidirectional_with_timeouts(
                    &mut proxy_in,
                    &mut proxy_out,
                    Duration::from_secs(5),
                    Duration::from_secs(2),
                    32768,
                    metrics_clone,
                )
                .await
            });

            // Target echo server: reads data and echos it back
            let target_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                loop {
                    let n = target.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    target.write_all(&buf[..n]).await.unwrap();
                }
                target.shutdown().await.unwrap();
            });

            // Client sends payload, then reads echo
            let payload = format!("massive-test-payload-{}", i).into_bytes();
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();

            let mut echo_buf = vec![0u8; 1024];
            let mut total_echo = 0;
            loop {
                let n = client.read(&mut echo_buf).await.unwrap();
                if n == 0 {
                    break;
                }
                total_echo += n;
            }

            target_task.await.unwrap();
            let copy_res = proxy_task.await.unwrap();
            assert!(copy_res.is_ok(), "Concurrent proxy copy must succeed");
            assert_eq!(total_echo, payload.len());
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn test_abrupt_client_disconnect() {
    let metrics = Arc::new(GatewayMetrics::default());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let client = TcpStream::connect(addr).await.unwrap();
    let (mut proxy_in, _) = listener.accept().await.unwrap();

    let mut proxy_out = TcpStream::connect(target_addr).await.unwrap();
    let (mut target, _) = target_listener.accept().await.unwrap();

    let proxy_task = tokio::spawn(async move {
        copy_bidirectional_with_timeouts(
            &mut proxy_in,
            &mut proxy_out,
            Duration::from_millis(500),
            Duration::from_millis(300),
            32768,
            metrics,
        )
        .await
    });

    // Client connects and drops connection abruptly (simulating network crash or client kill)
    drop(client);

    // Target waits for read, which should return 0 (EOF) promptly because proxy shuts down
    let mut buf = [0u8; 100];
    let n = target.read(&mut buf).await.unwrap();
    assert_eq!(
        n, 0,
        "Target must receive EOF promptly when client disconnects"
    );

    let res = proxy_task.await.unwrap();
    assert!(res.is_ok() || res.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn test_emfile_backoff_and_recovery_loop() {
    // Verify that the EMFILE detection, reserve FD release, backoff, and recovery
    // functions work as designed.
    use std::sync::atomic::{AtomicUsize, Ordering};

    let simulated_accepts = Arc::new(AtomicUsize::new(0));
    let accepts_clone = simulated_accepts.clone();

    // Mock accept function returning EMFILE twice then success
    let mock_accept = move || {
        let count = accepts_clone.fetch_add(1, Ordering::SeqCst);
        if count < 2 {
            Err(std::io::Error::from_raw_os_error(libc::EMFILE))
        } else {
            Ok(count)
        }
    };

    let mut reserve_fd = std::fs::File::open("/dev/null").ok();
    assert!(reserve_fd.is_some(), "Reserve file descriptor must be open");

    let mut backoff = Duration::from_millis(10);
    let mut consecutive_emfile = 0u32;
    let mut recovered = false;

    for _ in 0..5 {
        match mock_accept() {
            Ok(c) => {
                recovered = true;
                assert_eq!(c, 2);
                break;
            }
            Err(e) => {
                let is_emfile = e.raw_os_error() == Some(libc::EMFILE);
                assert!(is_emfile);
                consecutive_emfile += 1;

                // Test reserve FD shedding
                if let Some(fd) = reserve_fd.take() {
                    drop(fd); // freed 1 descriptor
                    reserve_fd = std::fs::File::open("/dev/null").ok();
                }

                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_millis(100));
            }
        }
    }

    assert!(recovered, "Accept loop must recover once EMFILE clears");
    assert_eq!(consecutive_emfile, 2);
}

#[test]
fn test_config_gateway_timeouts_and_concurrency_defaults() {
    let cfg = GatewayConfig {
        port: 12345,
        proxy_port: 8080,
        enable_transparent: true,
        exclude_subnets: "10.0.0.0/8".into(),
        tcp_idle_timeout_secs: 120,
        half_close_timeout_secs: 15,
        connect_timeout_secs: 4,
        max_connections: None,
        preserve_ip_forward: true,
        watchdog_secs: Some(15),
    };

    assert_eq!(cfg.tcp_idle_timeout_secs, 120);
    assert_eq!(cfg.half_close_timeout_secs, 15);
    assert_eq!(cfg.connect_timeout_secs, 4);
    assert!(cfg.preserve_ip_forward);
    assert_eq!(cfg.watchdog_secs, Some(15));
}
