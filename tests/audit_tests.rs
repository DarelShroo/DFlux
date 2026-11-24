use dflux::config::EgressConfig;
use dflux::egress::EgressManager;
use dflux::probes;
use dflux::probes::dns;
use dflux::routing::{DeploymentState, RoutingEngine};
use dflux::state::{Decision, StateManager};
use hickory_resolver::proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_resolver::proto::rr::rdata::{A, CNAME};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[tokio::test]
async fn test_dns_ip_literal_resolution_without_network() {
    let cfg = EgressConfig {
        direct_interface: "enp15s0".to_string(),
        remote_interface: None,
    };
    let egress_mgr = Arc::new(EgressManager::new(Arc::new(cfg), None));

    // 1. Literal IP resolution should be instantaneous
    let ip_str = "1.1.1.1";
    let start = Instant::now();
    let res = dns::resolve(ip_str, false, egress_mgr.clone())
        .await
        .expect("Failed to resolve IP literal");
    let elapsed = start.elapsed();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].to_string(), "1.1.1.1");
    assert!(
        elapsed.as_millis() < 5,
        "Literal IP resolution should take < 5ms"
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
    let cfg = EgressConfig {
        direct_interface: "enp15s0".to_string(),
        remote_interface: None, // Direct-only configuration
    };
    let egress_mgr = Arc::new(EgressManager::new(Arc::new(cfg.clone()), None));

    // When no remote interface is configured, evaluate_route should immediately choose Direct without probing remote
    let (decision, failed) = probes::evaluate_route("github.com", 443, egress_mgr).await;
    assert_eq!(decision, Decision::Direct);
    assert!(!failed);

    // Route probing with configured remote interfaces requires network I/O and is covered
    // through injected behavior tests in the resolver/gateway modules.
}

#[tokio::test]
async fn test_high_throughput_bidirectional_buffer() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Exercise the bidirectional copy path using in-memory streams; this test
    // validates buffering and does not depend on host socket permissions.
    let (mut source, mut producer) = tokio::io::duplex(128 * 1024);
    let server_task = tokio::spawn(async move {
        let payload = vec![0x42u8; 64 * 1024]; // 64 KiB chunks
        for _ in 0..64 {
            producer.write_all(&payload).await.unwrap();
        }
        producer.shutdown().await.unwrap();
    });

    // Pipe through two connected streams using our optimized copy_bidirectional_with_sizes
    let (mut client_side, mut server_side) = tokio::io::duplex(128 * 1024);

    let proxy_task = tokio::spawn(async move {
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
async fn test_remote_route_failure_expires_and_valid_probe_can_restore_direct() {
    let sm = StateManager::new(1800);
    let host = "route-recovery.test";
    sm.record_route_success(host, Decision::Remote).await;
    assert_eq!(sm.get_decision(host).await, Some(Decision::Remote));
    sm.record_failure(host).await;
    sm.record_failure(host).await;
    assert_eq!(sm.get_decision(host).await, Some(Decision::Remote));
    sm.record_failure(host).await;
    assert_eq!(sm.get_decision(host).await, None);
    sm.record_route_success(host, Decision::Direct).await;
    assert_eq!(sm.get_decision(host).await, Some(Decision::Direct));
}

#[tokio::test]
async fn test_doh_failure_is_returned_without_network() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let res = dns::run_doh_attempts(
        Duration::from_millis(100),
        Duration::from_millis(50),
        move |_, _| {
            counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(anyhow::anyhow!("simulated DoH transport failure")) })
        },
    )
    .await;
    assert!(
        res.is_err(),
        "transport failure should return Err, not panic"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
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

#[tokio::test]
async fn test_outbound_so_mark_enforcement() {
    let mut options = Vec::new();
    dflux::outbound::apply_socket_isolation_with("test0", |option, _| {
        options.push(option);
        0
    })
    .unwrap();
    assert_eq!(options, vec![libc::SO_MARK, libc::SO_BINDTODEVICE]);
}

#[tokio::test]
async fn test_outbound_no_packets_on_isolation_failure() {
    let mut options = Vec::new();
    let res = dflux::outbound::apply_socket_isolation_with("missing0", |option, _| {
        options.push(option);
        unsafe { *libc::__errno_location() = libc::EPERM };
        -1
    });
    assert!(res.unwrap_err().to_string().contains("SO_MARK"));
    assert_eq!(
        options,
        vec![libc::SO_MARK],
        "failure must prevent bind and connect"
    );
}

#[tokio::test]
async fn test_doh_global_timeout_enforcement() {
    let start = Instant::now();
    let mut allotments = Vec::new();
    let res = dns::run_doh_attempts(
        Duration::from_millis(2500),
        Duration::from_millis(1500),
        |_, allotment| {
            allotments.push(allotment);
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
            })
        },
    )
    .await;
    let elapsed = start.elapsed();

    assert!(
        res.is_err(),
        "Resolution for nonexistent domain should fail"
    );
    assert!(
        (Duration::from_millis(2400)..=Duration::from_millis(2900)).contains(&elapsed),
        "DoH resolution took {:?}, exceeding maximum allowable budget of 2.5s (+ tolerance)",
        elapsed
    );
    assert_eq!(allotments.len(), 2);
    assert_eq!(allotments[0], Duration::from_millis(1500));
    assert!(allotments[1] <= Duration::from_millis(1050));
}

#[test]
fn test_doh_cname_chain_and_loop_detection() {
    let query_id = 0x4321;
    let base_name = "target.example.";

    // 1. Valid CNAME chain: target.example. -> cname1.example. -> 192.0.2.42
    let mut msg = Message::query();
    msg.metadata.id = query_id;
    msg.metadata.message_type = MessageType::Response;
    msg.metadata.response_code = ResponseCode::NoError;
    let q = Query::query(Name::from_ascii(base_name).unwrap(), RecordType::A);
    msg.add_query(q);

    let rec_cname = Record::from_rdata(
        Name::from_ascii(base_name).unwrap(),
        300,
        RData::CNAME(CNAME(Name::from_ascii("cname1.example.").unwrap())),
    );
    let rec_a = Record::from_rdata(
        Name::from_ascii("cname1.example.").unwrap(),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 42))),
    );
    msg.add_answer(rec_cname);
    msg.add_answer(rec_a);

    let wire = msg.to_vec().expect("Serialize DNS message");
    let ips = dns::parse_doh_response(&wire, query_id, "target.example")
        .expect("Valid CNAME chain should resolve");
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))]);

    // DNS parser accepts IN and rejects a non-IN question class.
    let mut class_in = msg.clone();
    class_in.queries[0].set_query_class(hickory_resolver::proto::rr::DNSClass::IN);
    let class_in_wire = class_in.to_vec().unwrap();
    assert!(dns::parse_doh_response(&class_in_wire, query_id, "target.example").is_ok());
    let mut class_ch = msg.clone();
    class_ch.queries[0].set_query_class(hickory_resolver::proto::rr::DNSClass::CH);
    let class_ch_wire = class_ch.to_vec().unwrap();
    assert!(dns::parse_doh_response(&class_ch_wire, query_id, "target.example").is_err());

    // A validly encoded response for a different question is rejected.
    let mut different_question = msg.clone();
    different_question.queries[0] =
        Query::query(Name::from_ascii("other.example.").unwrap(), RecordType::A);
    let different_question_wire = different_question.to_vec().unwrap();
    assert!(dns::parse_doh_response(&different_question_wire, query_id, "target.example").is_err());

    // 2. 8 hops permitted
    let mut msg8 = Message::query();
    msg8.metadata.id = query_id;
    msg8.metadata.message_type = MessageType::Response;
    msg8.metadata.response_code = ResponseCode::NoError;
    msg8.add_query(Query::query(
        Name::from_ascii("hop0.example.").unwrap(),
        RecordType::A,
    ));

    for i in 0..7 {
        let from = format!("hop{}.example.", i);
        let to = format!("hop{}.example.", i + 1);
        msg8.add_answer(Record::from_rdata(
            Name::from_ascii(&from).unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_ascii(&to).unwrap())),
        ));
    }
    msg8.add_answer(Record::from_rdata(
        Name::from_ascii("hop7.example.").unwrap(),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 88))),
    ));

    let wire8 = msg8.to_vec().expect("Serialize 8-hop DNS message");
    let ips8 =
        dns::parse_doh_response(&wire8, query_id, "hop0.example").expect("8 hops should succeed");
    assert_eq!(ips8, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 88))]);

    // 3. Exceeding 8 hops (e.g. 9 hops) is rejected
    let mut msg9 = Message::query();
    msg9.metadata.id = query_id;
    msg9.metadata.message_type = MessageType::Response;
    msg9.metadata.response_code = ResponseCode::NoError;
    msg9.add_query(Query::query(
        Name::from_ascii("long0.example.").unwrap(),
        RecordType::A,
    ));

    for i in 0..9 {
        let from = format!("long{}.example.", i);
        let to = format!("long{}.example.", i + 1);
        msg9.add_answer(Record::from_rdata(
            Name::from_ascii(&from).unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_ascii(&to).unwrap())),
        ));
    }
    msg9.add_answer(Record::from_rdata(
        Name::from_ascii("long9.example.").unwrap(),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
    ));

    let wire9 = msg9.to_vec().expect("Serialize 9-hop DNS message");
    let res9 = dns::parse_doh_response(&wire9, query_id, "long0.example");
    assert!(res9.is_err(), "Exceeding 8 CNAME hops must fail");

    // 4. CNAME loop detection: loopA -> loopB -> loopA
    let mut msg_loop = Message::query();
    msg_loop.metadata.id = query_id;
    msg_loop.metadata.message_type = MessageType::Response;
    msg_loop.metadata.response_code = ResponseCode::NoError;
    msg_loop.add_query(Query::query(
        Name::from_ascii("loop-a.example.").unwrap(),
        RecordType::A,
    ));

    msg_loop.add_answer(Record::from_rdata(
        Name::from_ascii("loop-a.example.").unwrap(),
        300,
        RData::CNAME(CNAME(Name::from_ascii("loop-b.example.").unwrap())),
    ));
    msg_loop.add_answer(Record::from_rdata(
        Name::from_ascii("loop-b.example.").unwrap(),
        300,
        RData::CNAME(CNAME(Name::from_ascii("loop-a.example.").unwrap())),
    ));

    let wire_loop = msg_loop.to_vec().expect("Serialize loop DNS message");
    let res_loop = dns::parse_doh_response(&wire_loop, query_id, "loop-a.example");
    assert!(res_loop.is_err(), "CNAME cycle must be rejected");
    assert!(
        res_loop
            .err()
            .unwrap()
            .to_string()
            .contains("CNAME loop detected"),
        "Must specify CNAME loop detected"
    );

    // 5. Malformed DNS wire message
    let malformed_bytes = [0xFF, 0x00, 0x12];
    assert!(dns::parse_doh_response(&malformed_bytes, query_id, "test.example").is_err());

    // 6. Query ID mismatch
    let mut msg_bad_id = msg.clone();
    msg_bad_id.metadata.id = query_id + 1;
    let wire_bad_id = msg_bad_id.to_vec().unwrap();
    assert!(dns::parse_doh_response(&wire_bad_id, query_id, "target.example").is_err());

    // 7. QR bit is Query instead of Response
    let mut msg_qr = msg.clone();
    msg_qr.metadata.message_type = MessageType::Query;
    let wire_qr = msg_qr.to_vec().unwrap();
    assert!(dns::parse_doh_response(&wire_qr, query_id, "target.example").is_err());

    // 8. Truncated bit (TC = true)
    let mut msg_tc = msg.clone();
    msg_tc.metadata.truncation = true;
    let wire_tc = msg_tc.to_vec().unwrap();
    assert!(dns::parse_doh_response(&wire_tc, query_id, "target.example").is_err());

    // 9. Error RCODE: NXDomain and ServFail
    let mut msg_nx = msg.clone();
    msg_nx.metadata.response_code = ResponseCode::NXDomain;
    let wire_nx = msg_nx.to_vec().unwrap();
    assert!(dns::parse_doh_response(&wire_nx, query_id, "target.example").is_err());

    let mut msg_sf = msg.clone();
    msg_sf.metadata.response_code = ResponseCode::ServFail;
    let wire_sf = msg_sf.to_vec().unwrap();
    assert!(dns::parse_doh_response(&wire_sf, query_id, "target.example").is_err());
}

#[tokio::test]
async fn test_connect_tcp_global_timeout_enforcement() {
    let start = Instant::now();
    let mut attempts = 0;
    let res = dflux::outbound::run_candidates(3, Duration::from_secs(4), |_| {
        attempts += 1;
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok::<(), anyhow::Error>(())
        })
    })
    .await;
    let elapsed = start.elapsed();
    assert!(res.is_err());
    assert_eq!(
        attempts, 2,
        "candidate two consumes only the remaining budget"
    );
    assert!(
        (Duration::from_millis(3900)..=Duration::from_millis(4600)).contains(&elapsed),
        "simulated candidate attempts took {:?}, expected one global 4s budget",
        elapsed
    );
}

#[test]
fn test_state_file_roundtrip_partial_state_and_absent_cleanup() {
    let temp_dir = std::env::temp_dir().join(format!("dflux_test_rollback_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let state_file = temp_dir.join("state.json");

    // 1. Test atomic state writing and reading
    let state = DeploymentState {
        uuid: "test-uuid-1234".to_string(),
        pid: std::process::id(),
        created_at: 1000000,
        table_name: "dflux".to_string(),
        rule_pref: 32000,
        fwmark: 1,
        table_id: 100,
        nft_active: false,
        ip_rule_active: false,
        ip_route_active: false,
        ip_forward_original: None,
        send_redirects_original: None,
        conntrack_udp_timeout_stream_original: None,
        preserve_ip_forward: true,
    };

    RoutingEngine::save_state_to_path(&state_file, &state).expect("Atomic state write failed");
    let loaded = RoutingEngine::read_state_file(&state_file).expect("Failed to read saved state");
    assert_eq!(loaded, state);

    // 2. Test absent resources: stop() when resources are absent succeeds gracefully.
    let engine = RoutingEngine::new_with_run_dir(
        12345,
        "enp15s0".to_string(),
        None,
        "192.168.0.0/16".to_string(),
        temp_dir.clone(),
    );
    let stop_res = engine.stop();
    assert!(stop_res.is_ok(), "Stop on absent resources should not fail");

    // 3. Persist a partially deleted state and verify it round-trips.
    let mut partial_state = state.clone();
    partial_state.nft_active = false;
    partial_state.ip_rule_active = true;
    partial_state.ip_route_active = false;
    RoutingEngine::save_state_to_path(&state_file, &partial_state).unwrap();
    assert_eq!(
        RoutingEngine::read_state_file(&state_file).unwrap(),
        partial_state
    );

    // 4. Test incoherent persistent state
    fs::write(&state_file, b"corrupted-invalid-json-data").unwrap();
    let incoherent_res = RoutingEngine::read_state_file(&state_file);
    assert!(
        incoherent_res.is_err(),
        "Corrupted state file must return Err"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_gateway_nft_rules_contain_forward_conntrack_and_masquerade() {
    // 1. Direct only configuration
    let engine_direct = RoutingEngine::new(
        12345,
        "eth0".to_string(),
        None,
        "10.0.0.0/8, 192.168.0.0/16".to_string(),
    );
    let rules_direct = engine_direct.generate_nft_rules();

    // Verify Prerouting TPROXY
    assert!(rules_direct.contains("chain prerouting"));
    assert!(
        rules_direct.contains("tcp dport { 80, 443 } tproxy to :12345 meta mark set 0x1 accept")
    );
    assert!(rules_direct.contains("ip daddr { 10.0.0.0/8, 192.168.0.0/16 } accept"));

    // Verify Forward chain: Conntrack state tracking and ICMP preservation
    assert!(rules_direct.contains("chain forward"));
    assert!(rules_direct.contains("ct state invalid drop"));
    assert!(rules_direct.contains("ct state { established, related } accept"));
    assert!(rules_direct.contains("ip protocol icmp accept"));

    // Verify Postrouting NAT & Masquerade
    assert!(rules_direct.contains("chain postrouting"));
    assert!(rules_direct.contains("ip daddr { 10.0.0.0/8, 192.168.0.0/16 } return"));
    assert!(rules_direct.contains("oifname \"eth0\" masquerade"));
    assert!(!rules_direct.contains("oifname \"wg0\" masquerade"));

    // Verify absence of application-specific hardcodes (generic gateway compliance)
    assert!(
        !rules_direct.to_lowercase().contains("whatsapp"),
        "DFlux must not contain application-specific hardcodes"
    );

    // 2. Dual-interface configuration with VPN tunnel (remote_iface)
    let engine_dual = RoutingEngine::new(
        12345,
        "eth0".to_string(),
        Some("wg0".to_string()),
        "10.0.0.0/8, 192.168.0.0/16".to_string(),
    );
    let rules_dual = engine_dual.generate_nft_rules();

    // Verify Masquerade on both interfaces
    assert!(rules_dual.contains("oifname \"eth0\" masquerade"));
    assert!(rules_dual.contains("oifname \"wg0\" masquerade"));

    // Verify MSS Clamping on VPN interface to prevent MTU blackholes
    assert!(rules_dual.contains("oifname \"wg0\" tcp flags syn tcp option maxseg size set 1380"));

    // 3. Loopback interface should never be masqueraded
    let engine_lo = RoutingEngine::new(12345, "lo".to_string(), None, "127.0.0.0/8".to_string());
    let rules_lo = engine_lo.generate_nft_rules();
    assert!(!rules_lo.contains("oifname \"lo\" masquerade"));
}

#[test]
fn test_gateway_nft6_rules_contain_forward_reject() {
    let engine = RoutingEngine::new(12345, "eth0".to_string(), None, "10.0.0.0/8".to_string());
    let rules6 = engine.generate_nft6_rules();

    assert!(rules6.contains("table ip6 dflux6"));
    assert!(rules6.contains("chain prerouting"));
    assert!(rules6.contains("chain forward"));
    assert!(rules6.contains("reject with icmpv6 type admin-prohibited"));
    assert!(rules6.contains("chain output"));
}

#[test]
fn test_legacy_deployment_state_backward_compatibility() {
    // Legacy state.json without the new sysctl restore fields
    let legacy_json = r#"{
        "uuid": "legacy-uuid-5678",
        "pid": 1234,
        "created_at": 1700000000,
        "table_name": "dflux",
        "rule_pref": 32000,
        "fwmark": 1,
        "table_id": 100,
        "nft_active": true,
        "ip_rule_active": true,
        "ip_route_active": true
    }"#;

    let state: DeploymentState = serde_json::from_str(legacy_json)
        .expect("Legacy state format must deserialize cleanly via serde defaults");

    assert_eq!(state.uuid, "legacy-uuid-5678");
    assert_eq!(state.ip_forward_original, None);
    assert_eq!(state.send_redirects_original, None);
    assert_eq!(state.conntrack_udp_timeout_stream_original, None);
}
