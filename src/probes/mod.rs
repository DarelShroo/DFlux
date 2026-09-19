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

use std::sync::Arc;
use crate::egress::EgressManager;

pub async fn run_probe_silent(hostname: &str, remote: bool, egress_mgr: Arc<EgressManager>) -> Result<ProbeReport> {
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

    match tcp::connect(ip, 443, remote, egress_mgr.clone()).await {
        Ok(_) => {
            report.tcp_pass = true;
        }
        Err(e) => {
            report.error_reason = Some(format!("TCP_FAIL: {}", e));
            return Ok(report);
        }
    }

    match tls::handshake_and_verify(hostname, ip, 443, remote, egress_mgr).await {
        Ok(_) => {
            report.tls_pass = true;
            report.cert_valid = true;
        }
        Err(tls::TlsError::HostnameMismatch { expected: _, received: _ }) => {
            report.tls_pass = true; // Handshake technically worked
            report.error_reason = Some("CERTIFICATE_HOSTNAME_MISMATCH".to_string());
        }
        Err(e) => {
            report.error_reason = Some(format!("TLS_FAIL: {}", e));
        }
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
            println!("  reason: {}", direct.error_reason.as_deref().unwrap_or("UNKNOWN"));
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
            println!("  reason: {}", remote.error_reason.as_deref().unwrap_or("UNKNOWN"));
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
