pub mod dns;
pub mod tcp;
pub mod tls;

use anyhow::Result;

pub struct ProbeReport {
    pub dns_pass: bool,
    pub tcp_pass: bool,
    pub tls_pass: bool,
    pub cert_valid: bool,
    pub error_reason: Option<String>,
}

use crate::egress::EgressManager;
use std::sync::Arc;

use crate::state::Decision;

pub async fn evaluate_route(
    target_host: &str,
    port: u16,
    egress_mgr: Arc<EgressManager>,
) -> (Decision, bool) {
    // 1. If remote interface is not configured, direct is the only choice
    if egress_mgr.get_remote_interface().is_none() {
        return (Decision::Direct, false);
    }

    // 2. Optimistic Direct-first probe: test Direct with a 2-second timeout
    let direct_probe = tokio::time::timeout(
        std::time::Duration::from_millis(2000),
        run_probe_silent_port(target_host, port, false, egress_mgr.clone()),
    )
    .await;

    let direct_ok = match direct_probe {
        Ok(Ok(ref report)) => {
            if port == 443 {
                report.cert_valid
            } else {
                report.tcp_pass
            }
        }
        _ => false,
    };

    // If Direct route works, NEVER waste time/resources probing Remote!
    if direct_ok {
        return (Decision::Direct, false);
    }

    // 3. Direct route failed or has invalid certificate/poisoning: test Remote
    let remote_probe = tokio::time::timeout(
        std::time::Duration::from_millis(2500),
        run_probe_silent_port(target_host, port, true, egress_mgr.clone()),
    )
    .await;

    let remote_ok = match remote_probe {
        Ok(Ok(ref report)) => {
            if port == 443 {
                report.cert_valid
            } else {
                report.tcp_pass
            }
        }
        _ => false,
    };

    if remote_ok {
        (Decision::Remote, false)
    } else {
        // Both failed: fallback to Direct with failure flag (triggers exponential backoff)
        (Decision::Direct, true)
    }
}

pub async fn run_probe_silent(
    hostname: &str,
    remote: bool,
    egress_mgr: Arc<EgressManager>,
) -> Result<ProbeReport> {
    run_probe_silent_port(hostname, 443, remote, egress_mgr).await
}

pub async fn run_probe_silent_port(
    hostname: &str,
    port: u16,
    remote: bool,
    egress_mgr: Arc<EgressManager>,
) -> Result<ProbeReport> {
    let mut report = ProbeReport {
        dns_pass: false,
        tcp_pass: false,
        tls_pass: false,
        cert_valid: false,
        error_reason: None,
    };

    let ips = match dns::resolve(hostname).await {
        Ok(ips) => ips,
        Err(e) => {
            report.error_reason = Some(format!("DNS_FAIL: {}", e));
            return Ok(report);
        }
    };
    report.dns_pass = true;

    if ips.is_empty() {
        report.error_reason = Some("DNS_FAIL_NO_IPS".to_string());
        return Ok(report);
    }

    let ip = ips[0];

    match tcp::connect(ip, port, remote, egress_mgr.clone()).await {
        Ok(_) => {
            report.tcp_pass = true;
        }
        Err(e) => {
            report.error_reason = Some(format!("TCP_FAIL: {}", e));
            return Ok(report);
        }
    }

    if port == 443 {
        match tls::handshake_and_verify(hostname, ip, 443, remote, egress_mgr).await {
            Ok(_) => {
                report.tls_pass = true;
                report.cert_valid = true;
            }
            Err(tls::TlsError::HostnameMismatch {
                expected: _,
                received: _,
            }) => {
                report.tls_pass = true;
                report.error_reason = Some("CERTIFICATE_HOSTNAME_MISMATCH".to_string());
            }
            Err(e) => {
                report.error_reason = Some(format!("TLS_FAIL: {}", e));
            }
        }
    } else {
        // Non-TLS (e.g. port 80): TCP success is sufficient
        report.cert_valid = true;
    }

    Ok(report)
}

pub async fn run_probe(hostname: &str, remote: bool, egress_mgr: Arc<EgressManager>) -> Result<()> {
    println!("DNS:");
    let ips = match dns::resolve(hostname).await {
        Ok(ips) => {
            println!("  PASS");
            for ip in &ips {
                println!("  {}", ip);
            }
            ips
        }
        Err(e) => {
            println!("  FAIL: {}", e);
            return Ok(());
        }
    };

    if ips.is_empty() {
        println!("  FAIL: No IPs found");
        return Ok(());
    }

    let ip = ips[0];

    println!("\nTCP:");
    match tcp::connect(ip, 443, remote, egress_mgr.clone()).await {
        Ok(_) => {
            println!("  PASS");
        }
        Err(e) => {
            println!("  FAIL: {}", e);
            return Ok(());
        }
    }

    println!("\nTLS:");
    match tls::handshake_and_verify(hostname, ip, 443, remote, egress_mgr).await {
        Ok(_) => {
            println!("  PASS handshake");
            println!("\nCERTIFICATE:");
            println!("  VALID");
            println!("\nRESULT:\n  HEALTHY");
        }
        Err(tls::TlsError::HostnameMismatch { expected, received }) => {
            println!("  PASS handshake");
            println!("\nCERTIFICATE:");
            println!("  FAIL hostname mismatch");
            println!("\nEXPECTED:\n  {}", expected);
            println!("\nRECEIVED:\n  {}", received);
            println!("\nRESULT:\n  DIRECT_UNHEALTHY");
        }
        Err(e) => {
            println!("  FAIL: {}", e);
            println!("\nRESULT:\n  DIRECT_UNHEALTHY");
        }
    }

    Ok(())
}

pub async fn run_probe_compare(hostname: &str, egress_mgr: Arc<EgressManager>) -> Result<()> {
    let direct = run_probe_silent(hostname, false, egress_mgr.clone()).await?;
    let remote = run_probe_silent(hostname, true, egress_mgr).await?;

    println!("DIRECT");
    println!("  DNS: {}", if direct.dns_pass { "PASS" } else { "FAIL" });
    if direct.dns_pass {
        println!("  TCP: {}", if direct.tcp_pass { "PASS" } else { "FAIL" });
    }
    if direct.tcp_pass {
        println!("  TLS: {}", if direct.cert_valid { "PASS" } else { "FAIL" });
        if !direct.cert_valid {
            println!(
                "  reason: {}",
                direct.error_reason.as_deref().unwrap_or("UNKNOWN")
            );
        }
    }

    println!("\nREMOTE");
    println!("  DNS: {}", if remote.dns_pass { "PASS" } else { "FAIL" });
    if remote.dns_pass {
        println!("  TCP: {}", if remote.tcp_pass { "PASS" } else { "FAIL" });
    }
    if remote.tcp_pass {
        println!("  TLS: {}", if remote.cert_valid { "PASS" } else { "FAIL" });
        if remote.cert_valid {
            println!("  certificate: VALID");
        } else {
            println!(
                "  reason: {}",
                remote.error_reason.as_deref().unwrap_or("UNKNOWN")
            );
        }
    }

    let decision = if direct.cert_valid {
        "DIRECT"
    } else if remote.cert_valid {
        "REMOTE"
    } else {
        "UNKNOWN"
    };

    println!("\nDECISION:");
    println!("  {}", decision);

    Ok(())
}
