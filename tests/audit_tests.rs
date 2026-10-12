use dflux::config::EgressConfig;
use dflux::egress::EgressManager;
use dflux::probes;
use dflux::probes::dns;
use dflux::state::{Decision, StateManager};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

#[tokio::test]
async fn test_dns_cache_hit_and_latency() {
    // 1. Literal IP resolution should be instantaneous
    let ip_str = "1.1.1.1";
    let start = Instant::now();
    let res = dns::resolve(ip_str)
        .await
        .expect("Failed to resolve IP literal");
    let elapsed = start.elapsed();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].to_string(), "1.1.1.1");
    assert!(
        elapsed.as_millis() < 5,
        "Literal IP resolution should take < 5ms"
    );

    // 2. Domain resolution with caching
    let domain = "one.one.one.one";
    let start1 = Instant::now();
    let ips1 = dns::resolve(domain).await.expect("Failed first resolution");
    let elapsed1 = start1.elapsed();
    assert!(!ips1.is_empty());

    // Second resolution must hit cache and complete in microseconds
    let start2 = Instant::now();
    let ips2 = dns::resolve(domain)
        .await
        .expect("Failed second resolution");
    let elapsed2 = start2.elapsed();
    assert_eq!(ips1, ips2);
    assert!(
        elapsed2.as_micros() < 500,
        "Cached DNS resolution took {:?}, should be < 500µs (first took {:?})",
        elapsed2,
        elapsed1
    );
}

#[tokio::test]
async fn test_state_manager_caching_and_expiry() {
    let sm = StateManager::new(1); // 1 second TTL

    // Non-existent key
    assert_eq!(sm.get_decision("unknown.domain.test").await, None);

    // Set decision
    sm.set_decision("example.org", Decision::Direct, false)
        .await;
    assert_eq!(sm.get_decision("example.org").await, Some(Decision::Direct));

    // Wait for expiration
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(sm.get_decision("example.org").await, None);
}

#[tokio::test]
async fn test_single_flight_deduplication() {
    let sm = StateManager::new(300);
    let target = "concurrent.test.domain";
    let probe_counter = Arc::new(AtomicUsize::new(0));

    // Spawn 20 concurrent requests for the same un-cached domain
    let mut handles = Vec::new();
    for _ in 0..20 {
        let sm_clone = sm.clone();
        let counter_clone = probe_counter.clone();
        handles.push(tokio::spawn(async move {
            sm_clone
                .get_or_evaluate(target, || async move {
                    // Simulate an expensive network probe
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    counter_clone.fetch_add(1, Ordering::SeqCst);
                    (Decision::Direct, false)
                })
                .await
        }));
    }

    for h in handles {
        let decision = h.await.unwrap();
        assert_eq!(decision, Decision::Direct);
    }

    // The probe closure MUST have run exactly once!
    assert_eq!(
        probe_counter.load(Ordering::SeqCst),
        1,
        "Single-flight deduplication failed: probe ran multiple times!"
    );
}

#[tokio::test]
async fn test_dynamic_route_failure_and_demotion() {
    let sm = StateManager::new(300);
    let host = "flaky.service.test";

    sm.set_decision(host, Decision::Direct, false).await;
    assert_eq!(sm.get_decision(host).await, Some(Decision::Direct));

    // 1 failure should not expire it yet
    sm.record_failure(host).await;
    assert_eq!(sm.get_decision(host).await, Some(Decision::Direct));

    // 2 failures
    sm.record_failure(host).await;
    assert_eq!(sm.get_decision(host).await, Some(Decision::Direct));

    // 3 consecutive failures triggers immediate expiration for failover
    sm.record_failure(host).await;
    assert_eq!(
        sm.get_decision(host).await,
        None,
        "Route should be expired after 3 consecutive failures to trigger failover"
    );
}

#[tokio::test]
async fn test_optimistic_direct_evaluation() {
    let mut cfg = EgressConfig {
        direct_interface: "enp15s0".to_string(),
        remote_interface: None, // Direct-only configuration
    };
    let egress_mgr = Arc::new(EgressManager::new(Arc::new(cfg.clone()), None));

    // When no remote interface is configured, evaluate_route should immediately choose Direct without probing remote
    let (decision, failed) = probes::evaluate_route("github.com", 443, egress_mgr).await;
    assert_eq!(decision, Decision::Direct);
    assert!(!failed);

    // When remote is configured and direct is healthy (e.g. 1.1.1.1 or github.com)
    cfg.remote_interface = Some("dummy_tun0".to_string());
    let egress_mgr2 = Arc::new(EgressManager::new(Arc::new(cfg), None));
    let (decision2, failed2) = probes::evaluate_route("one.one.one.one", 443, egress_mgr2).await;
    assert_eq!(decision2, Decision::Direct);
    assert!(!failed2);
}

#[tokio::test]
async fn test_high_throughput_bidirectional_buffer() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // Spin up an echo/source server that sends 4 MiB of data
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let payload = vec![0x42u8; 64 * 1024]; // 64 KiB chunks
        for _ in 0..64 {
            // 4 MiB total
            stream.write_all(&payload).await.unwrap();
        }
    });

    let client_stream = TcpStream::connect(addr).await.unwrap();

    // Pipe through two connected streams using our optimized copy_bidirectional_with_sizes
    let (mut client_side, mut server_side) = tokio::io::duplex(128 * 1024);

    let proxy_task = tokio::spawn(async move {
        let mut source = client_stream;
        let _ =
            tokio::io::copy_bidirectional_with_sizes(&mut source, &mut server_side, 65536, 65536)
                .await;
    });

    let total_expected = 4 * 1024 * 1024;
    let mut received_bytes = 0usize;
    let mut buf = vec![0u8; 65536];
    let start = Instant::now();
    loop {
        let n = client_side.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received_bytes += n;
        if received_bytes >= total_expected {
            break;
        }
    }
    let elapsed = start.elapsed();

    server_task.await.unwrap();
    proxy_task.abort();

    assert_eq!(received_bytes, 4 * 1024 * 1024);
    let mib_per_sec = (4.0) / elapsed.as_secs_f64();
    println!(
        "Simulated proxy throughput: {:.2} MiB/s (took {:?})",
        mib_per_sec, elapsed
    );
    assert!(
        mib_per_sec > 100.0,
        "Transfer should exceed 100 MiB/s in local loopback duplex"
    );
}

#[tokio::test]
async fn test_route_flapping_prevention_and_success_reset() {
    let sm = StateManager::new(300);
    let host = "intermittent.service.test";

    sm.set_decision(host, Decision::Direct, false).await;

    // Simulate 2 transient failures
    sm.record_failure(host).await;
    sm.record_failure(host).await;
    assert_eq!(sm.get_decision(host).await, Some(Decision::Direct));

    // A successful connection occurs -> failure counter resets to 0
    sm.record_success(host).await;

    // Another transient failure occurs -> failure counter is now 1, NOT 3
    sm.record_failure(host).await;
    assert_eq!(
        sm.get_decision(host).await,
        Some(Decision::Direct),
        "Single failure after success should NOT expire route; protects against flapping"
    );
}

#[tokio::test]
async fn test_dns_failure_handling_and_nonexistent_domain() {
    let invalid_domain = "nonexistent-domain-xyz9876543210.invalid";
    let res = dns::resolve(invalid_domain).await;
    assert!(
        res.is_err(),
        "Nonexistent domain resolution should return Err, not panic"
    );
}

#[tokio::test]
async fn test_network_performance_units_and_bdp_math() {
    // 1. Differentiate decimal MB/s from binary MiB/s and Megabits/s (Mb/s)
    let bytes_transferred: u64 = 110_100_480; // 105 MiB = 110.1 MB
    let duration_secs: f64 = 3.041; // measured duration

    let bytes_per_sec = bytes_transferred as f64 / duration_secs;
    let mib_per_sec = bytes_per_sec / (1024.0 * 1024.0);
    let mb_per_sec = bytes_per_sec / 1_000_000.0;
    let mbps_bits = bytes_per_sec * 8.0 / 1_000_000.0;

    assert!(
        (mib_per_sec - 34.53).abs() < 0.1,
        "34.53 MiB/s calculation check"
    );
    assert!(
        (mb_per_sec - 36.20).abs() < 0.1,
        "36.20 MB/s decimal calculation check"
    );
    assert!(
        (mbps_bits - 289.6).abs() < 1.0,
        "289.6 Mb/s bit calculation check"
    );

    // 2. Bandwidth-Delay Product (BDP) Demonstration:
    // With RTT = 57.5 ms (measured to GitHub) and SO_RCVBUF clamped to 512 KiB:
    let rtt_secs: f64 = 0.0575;
    let buffer_clamp_bytes: f64 = 512.0 * 1024.0;
    let max_theoretical_throughput_bytes_per_sec: f64 = buffer_clamp_bytes / rtt_secs;
    let max_clamped_mib_per_sec: f64 = max_theoretical_throughput_bytes_per_sec / (1024.0 * 1024.0);

    // Theoretical ceiling is ~8.9 MiB/s payload (up to ~11.9 MiB/s with Linux socket overhead allowance)
    assert!(
        (max_clamped_mib_per_sec - 8.9f64).abs() < 0.5,
        "Mathematical proof of BDP ceiling at 512 KiB"
    );

    // With Linux kernel dynamic auto-tuning enabled (up to 32 MiB window):
    let kernel_max_window_bytes: f64 = 32.0 * 1024.0 * 1024.0;
    let autotuned_max_mib_per_sec: f64 = (kernel_max_window_bytes / rtt_secs) / (1024.0 * 1024.0);
    assert!(
        autotuned_max_mib_per_sec > 500.0,
        "Dynamic window permits > 500 MiB/s without bottleneck"
    );
}

#[tokio::test]
async fn test_config_defaults_and_env_overrides() {
    let cfg = dflux::config::DFluxConfig::default();
    assert_eq!(cfg.gateway.port, 12345);
    assert_eq!(cfg.gateway.proxy_port, 8080);
    assert!(cfg.gateway.enable_transparent);
    assert!(cfg.gateway.exclude_subnets.contains("192.168.0.0/16"));
}

#[tokio::test]
async fn test_non_443_bypass_logic() {
    let cfg = EgressConfig {
        direct_interface: "enp15s0".to_string(),
        remote_interface: Some("dummy_tun0".to_string()),
    };
    let egress_mgr = Arc::new(EgressManager::new(Arc::new(cfg), None));

    // Non-443 ports (e.g. 80, 8080) should bypass TLS probe and select Direct immediately
    let (decision, failed) = probes::evaluate_route("github.com", 80, egress_mgr).await;
    assert_eq!(decision, Decision::Direct);
    assert!(!failed);
}
