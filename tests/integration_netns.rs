use std::process::Command;

#[test]
#[ignore = "requires unshare and network namespace capabilities"]
fn test_netns_output_mark_and_routing_isolation() {
    // Run bash script inside isolated user + network namespace
    let script = r#"
set -e
ip link set lo up

# Apply nftables OUTPUT mangle rules matching DFlux Phase C architecture
nft -f - <<'EOF'
table ip dflux_test {
    chain output {
        type route hook output priority mangle; policy accept;
        meta mark 0x4446 counter accept
        tcp dport { 80, 443 } meta mark set 1 counter accept
    }
}
EOF

# 1. Send packet with SO_MARK = 0x4446
python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, 36, 0x4446)
s.setblocking(False)
s.connect_ex(("127.0.0.1", 80))
'

# Inspect nftables: mark 0x4446 counter must be >= 1, mark set 1 must be 0
out_marked=$(nft list table ip dflux_test)
echo "$out_marked"
echo "$out_marked" | grep "meta mark 0x00004446 counter packets 1"
echo "$out_marked" | grep "tcp dport { 80, 443 } meta mark set 0x00000001 counter packets 0"

# 2. Send unmarked packet
python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setblocking(False)
s.connect_ex(("127.0.0.1", 80))
'

# Inspect nftables: mark set 1 counter must now be 1
out_unmarked=$(nft list table ip dflux_test)
echo "$out_unmarked"
echo "$out_unmarked" | grep "tcp dport { 80, 443 } meta mark set 0x00000001 counter packets 1"
"#;

    let output = Command::new("unshare")
        .args(["-U", "-n", "--map-root-user", "bash", "-c", script])
        .output()
        .expect("Failed to execute unshare command");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "Network namespace output mark test failed!\nStdout:\n{}\nStderr:\n{}",
            stdout, stderr
        );
    }
}

#[test]
#[ignore = "requires unshare and network namespace capabilities"]
fn test_netns_direct_and_remote_interface_binding() {
    let script = r#"
set -e
ip link set lo up
ip link add dev dflux_dir type dummy
ip link add dev dflux_rem type dummy
ip link set dflux_dir up
ip link set dflux_rem up

python3 -c '
import socket

# Test DIRECT connection interface binding
s_dir = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_dir.setsockopt(socket.SOL_SOCKET, 36, 0x4446)
s_dir.setsockopt(socket.SOL_SOCKET, 25, b"dflux_dir\x00")
bound_dir = s_dir.getsockopt(socket.SOL_SOCKET, 25, 32).rstrip(b"\x00").decode()
assert bound_dir == "dflux_dir", f"DIRECT socket bound to wrong interface: {bound_dir}"

# Test REMOTE connection interface binding
s_rem = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_rem.setsockopt(socket.SOL_SOCKET, 36, 0x4446)
s_rem.setsockopt(socket.SOL_SOCKET, 25, b"dflux_rem\x00")
bound_rem = s_rem.getsockopt(socket.SOL_SOCKET, 25, 32).rstrip(b"\x00").decode()
assert bound_rem == "dflux_rem", f"REMOTE socket bound to wrong interface: {bound_rem}"

# Test binding failure on invalid device
s_invalid = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s_invalid.setsockopt(socket.SOL_SOCKET, 25, b"nonexistent_iface\x00")
    assert False, "Should have failed to bind to non-existent device"
except OSError as e:
    assert e.errno in (19, 22), f"Expected ENODEV/EINVAL, got {e}"
'
"#;

    let output = Command::new("unshare")
        .args(["-U", "-n", "--map-root-user", "bash", "-c", script])
        .output()
        .expect("Failed to execute unshare command");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "Network namespace interface binding test failed!\nStdout:\n{}\nStderr:\n{}",
            stdout, stderr
        );
    }
}

/// Exercises the production outbound connector against the kernel. Both policies use `lo` in
/// this minimal topology; nftables counters prove that the production socket's SO_MARK reached
/// the local OUTPUT hook. This does not prove egress separation across two physical links.
#[test]
#[ignore = "requires user/network namespaces, iproute2, nftables and socket mark capability"]
fn test_netns_production_outbound_socket_mark_and_bind() {
    if std::env::var_os("DFLUX_OUTBOUND_NETNS_CHILD").is_some() {
        use dflux::config::EgressConfig;
        use dflux::egress::{EgressManager, NetworkInterfaceEgress};
        use std::sync::Arc;
        use tokio::net::TcpListener;

        assert!(
            Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .unwrap()
                .success()
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let config = Arc::new(EgressConfig {
                direct_interface: "lo".into(),
                remote_interface: Some("lo".into()),
            });
            let manager = Arc::new(EgressManager::new(
                config,
                Some(Arc::new(NetworkInterfaceEgress::new("lo".into()))),
            ));

            for remote in [false, true] {
                let stream = dflux::outbound::connect_tcp(
                    "127.0.0.1".parse().unwrap(),
                    port,
                    remote,
                    manager.clone(),
                )
                .await
                .expect("production isolated connector");
                let (_accepted, _) = listener.accept().await.unwrap();
                drop(stream);
            }
        });

        let counters = Command::new("nft")
            .args(["-n", "-a", "list", "table", "ip", "dflux_prod_socket"])
            .output()
            .unwrap();
        assert!(
            counters.status.success(),
            "nft counter query failed: {}",
            String::from_utf8_lossy(&counters.stderr)
        );
        let text = String::from_utf8_lossy(&counters.stdout);
        assert!(
            text.contains("packets 2"),
            "expected both production sockets to hit marked counter: {text}"
        );
        return;
    }

    let nft_script = "table ip dflux_prod_socket { chain output { type filter hook output priority mangle; policy accept; meta mark 0x4446 counter; } }";
    let child = Command::new("unshare")
        .args(["-U", "-n", "--map-root-user", "sh", "-c"])
        .arg(format!("ip link set lo up && nft -f - <<'EOF'\n{nft_script}\nEOF\nDFLUX_OUTBOUND_NETNS_CHILD=1 exec '{}' --ignored --exact test_netns_production_outbound_socket_mark_and_bind --nocapture", std::env::current_exe().unwrap().display()))
        .output().expect("launch isolated production outbound test");
    assert!(
        child.status.success(),
        "production outbound namespace test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
}

/// Executes the real RoutingEngine lifecycle in an isolated network namespace. Run explicitly
/// as root with `cargo test --test integration_netns test_netns_real_routing_rollback_preserves_third_party -- --ignored --exact --nocapture`.
#[test]
#[ignore = "requires root, nftables, iproute2, and CAP_NET_ADMIN"]
fn test_netns_real_routing_rollback_preserves_third_party() {
    if std::env::var_os("DFLUX_NETNS_ROLLBACK_CHILD").is_some() {
        use dflux::routing::RoutingEngine;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "namespace child must run as root"
        );
        assert!(
            Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("nft")
                .args(["add", "table", "ip", "third_party"])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("ip")
                .args([
                    "route",
                    "add",
                    "198.18.77.0/24",
                    "dev",
                    "lo",
                    "table",
                    "200"
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("ip")
                .args([
                    "rule", "add", "pref", "31000", "fwmark", "0x77", "lookup", "200"
                ])
                .status()
                .unwrap()
                .success()
        );
        let run_dir =
            std::env::temp_dir().join(format!("dflux-netns-rollback-{}", std::process::id()));
        fs::create_dir_all(&run_dir).unwrap();
        fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let mut engine = RoutingEngine::new_with_run_dir(
            12345,
            "lo".into(),
            None,
            "127.0.0.0/8".into(),
            run_dir.clone(),
        );
        engine
            .start()
            .expect("real routing initialization must succeed");
        let route_before = Command::new("ip")
            .args(["route", "show", "198.18.77.0/24", "table", "200"])
            .output()
            .unwrap();
        assert!(route_before.status.success() && !route_before.stdout.is_empty());
        let rule_before = Command::new("ip")
            .args(["rule", "show", "pref", "31000"])
            .output()
            .unwrap();
        assert!(rule_before.status.success() && !rule_before.stdout.is_empty());
        assert!(
            Command::new("nft")
                .args(["list", "table", "ip", "dflux"])
                .status()
                .unwrap()
                .success()
        );
        let third_party_route = Command::new("ip")
            .args(["route", "show", "198.18.77.0/24", "table", "200"])
            .output()
            .unwrap();
        assert!(
            third_party_route.status.success() && !third_party_route.stdout.is_empty(),
            "third-party route was not preserved"
        );
        let third_party_rule = Command::new("ip")
            .args(["rule", "show", "pref", "31000"])
            .output()
            .unwrap();
        assert!(
            third_party_rule.status.success() && !third_party_rule.stdout.is_empty(),
            "third-party rule was not preserved"
        );
        let rule = Command::new("ip")
            .args(["rule", "show", "pref", "32000"])
            .output()
            .unwrap();
        assert!(rule.status.success());
        assert!(
            !rule.stdout.is_empty(),
            "DFlux policy rule exists after initialization"
        );
        let route = Command::new("ip")
            .args(["route", "show", "table", "100"])
            .output()
            .unwrap();
        assert!(route.status.success());
        assert!(
            !route.stdout.is_empty(),
            "DFlux route exists after initialization"
        );

        engine.stop().expect("real rollback must succeed");
        assert!(
            !Command::new("nft")
                .args(["list", "table", "ip", "dflux"])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("nft")
                .args(["list", "table", "ip", "third_party"])
                .status()
                .unwrap()
                .success()
        );
        let rule = Command::new("ip")
            .args(["rule", "show", "pref", "32000"])
            .output()
            .unwrap();
        assert!(rule.status.success());
        assert!(rule.stdout.is_empty(), "DFlux policy rule was rolled back");
        let route = Command::new("ip")
            .args(["route", "show", "table", "100"])
            .output()
            .unwrap();
        assert!(route.status.success());
        assert!(route.stdout.is_empty(), "DFlux route was rolled back");
        drop(engine);
        fs::remove_dir_all(run_dir).unwrap();
        return;
    }

    let binary = std::env::current_exe().expect("integration test executable path");
    let output = Command::new("unshare")
        .args(["-n", "--"])
        .arg("env")
        .arg("DFLUX_NETNS_ROLLBACK_CHILD=1")
        .arg(binary)
        .args([
            "--ignored",
            "--exact",
            "test_netns_real_routing_rollback_preserves_third_party",
            "--nocapture",
        ])
        .output()
        .expect("failed to launch unshare; requires root/CAP_SYS_ADMIN");
    assert!(
        output.status.success(),
        "real RoutingEngine namespace rollback failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
