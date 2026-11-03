use anyhow::Result;
use std::time::Duration;
use tls_parser::{TlsExtension, TlsMessage, TlsMessageHandshake, parse_tls_plaintext};
use tokio::net::TcpStream;

pub const MAX_INSPECTION_BYTES: usize = 65_535;
pub const INSPECTION_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectionStatus {
    TlsSni,
    HttpHost,
    SniUnavailable,
    Incomplete,
    Invalid,
    Unsupported,
    Timeout,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    pub hostname: Option<String>,
    pub status: InspectionStatus,
    pub observed_bytes: usize,
}

pub async fn inspect_hostname(stream: &TcpStream) -> Inspection {
    inspect_inner(stream).await
}

/// Compatibility wrapper. All inspected bytes are peeked and remain on the stream.
pub async fn peek_hostname(stream: &mut TcpStream) -> Result<(Option<String>, Vec<u8>)> {
    Ok((inspect_hostname(stream).await.hostname, Vec::new()))
}

async fn inspect_inner(stream: &TcpStream) -> Inspection {
    let mut data = vec![0u8; MAX_INSPECTION_BYTES];
    let mut observed = 0;
    let deadline = tokio::time::Instant::now() + INSPECTION_TIMEOUT;
    loop {
        if observed > 0
            && let Some(result) = analyze_buffer(&data[..observed])
        {
            return result;
        }
        if observed == MAX_INSPECTION_BYTES {
            return outcome(None, InspectionStatus::Invalid, observed);
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return outcome(None, InspectionStatus::Timeout, observed);
        }
        if observed > 0 {
            tokio::time::sleep(Duration::from_millis(5).min(remaining)).await;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if tokio::time::timeout(Duration::from_millis(100).min(remaining), stream.readable())
            .await
            .is_err()
        {
            if tokio::time::Instant::now() >= deadline {
                return outcome(None, InspectionStatus::Timeout, observed);
            }
            continue;
        }
        match stream.peek(&mut data[..]).await {
            Ok(0) => return outcome(None, InspectionStatus::Incomplete, observed),
            Ok(n) if n > observed => observed = n.min(MAX_INSPECTION_BYTES),
            Ok(_) => continue,
            Err(_) => return outcome(None, InspectionStatus::Invalid, observed),
        }
    }
}

fn analyze_buffer(buf: &[u8]) -> Option<Inspection> {
    if let Some(host) = extract_http_host(buf) {
        return Some(outcome(Some(host), InspectionStatus::HttpHost, buf.len()));
    }
    if is_http_prefix(buf) && buf.windows(4).any(|w| w == b"\r\n\r\n") {
        return Some(outcome(None, InspectionStatus::SniUnavailable, buf.len()));
    }
    if buf.first() == Some(&0x16) {
        if buf.len() < 5 {
            return None;
        }
        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf[1] != 0x03 || buf[2] > 0x04 || record_len < 4 {
            return Some(outcome(None, InspectionStatus::Invalid, buf.len()));
        }
        if record_len + 5 > MAX_INSPECTION_BYTES {
            return Some(outcome(None, InspectionStatus::Invalid, buf.len()));
        }
        if buf.len() < record_len + 5 {
            return None;
        }
        return Some(match parse_tls_sni(&buf[..record_len + 5]) {
            Ok(Some(host)) => outcome(Some(host), InspectionStatus::TlsSni, buf.len()),
            Ok(None) => outcome(None, InspectionStatus::SniUnavailable, buf.len()),
            Err(()) => outcome(None, InspectionStatus::Invalid, buf.len()),
        });
    }
    if !could_be_http(buf) {
        return Some(outcome(None, InspectionStatus::Unsupported, buf.len()));
    }
    None
}

fn outcome(
    hostname: Option<String>,
    status: InspectionStatus,
    observed_bytes: usize,
) -> Inspection {
    Inspection {
        hostname,
        status,
        observed_bytes,
    }
}

fn could_be_http(buf: &[u8]) -> bool {
    [
        b"GET ".as_slice(),
        b"POST ",
        b"CONNECT ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
    ]
    .iter()
    .any(|prefix| prefix.starts_with(buf) || buf.starts_with(prefix))
}
fn is_http_prefix(buf: &[u8]) -> bool {
    [
        b"GET ".as_slice(),
        b"POST ",
        b"CONNECT ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
    ]
    .iter()
    .any(|prefix| buf.starts_with(prefix))
}

fn parse_tls_sni(buf: &[u8]) -> Result<Option<String>, ()> {
    let (_, record) = parse_tls_plaintext(buf).map_err(|_| ())?;
    for msg in record.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)) = msg
            && let Some(exts) = hello.ext
            && let Ok((_, extensions)) = tls_parser::parse_tls_extensions(exts)
        {
            for ext in extensions {
                if let TlsExtension::SNI(names) = ext
                    && let Some((_, name)) = names.first()
                    && let Ok(name) = std::str::from_utf8(name)
                {
                    return Ok(Some(name.to_string()));
                }
            }
        }
    }
    Ok(None)
}

fn extract_http_host(buf: &[u8]) -> Option<String> {
    if !is_http_prefix(buf) || !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        return None;
    }
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("host")
        {
            let value = value.trim();
            let host = value
                .strip_prefix('[')
                .and_then(|v| v.split_once(']'))
                .map(|(h, _)| h)
                .unwrap_or_else(|| {
                    value
                        .rsplit_once(':')
                        .filter(|(_, p)| p.parse::<u16>().is_ok())
                        .map_or(value, |(h, _)| h)
                });
            return (!host.is_empty()).then(|| host.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fragmented_http_host_after_incremental_accumulation() {
        let first = b"GET / HTTP/1.1\r\nHo";
        assert!(analyze_buffer(first).is_none());
        let second = b"GET / HTTP/1.1\r\nHost: wolftorrent.com\r\n\r\n";
        let result = analyze_buffer(second).unwrap();
        assert_eq!(result.hostname.as_deref(), Some("wolftorrent.com"));
        assert_eq!(result.status, InspectionStatus::HttpHost);
    }

    #[test]
    fn parses_host_after_more_than_four_kib_of_headers() {
        let mut request = b"GET / HTTP/1.1\r\nX-Padding: ".to_vec();
        request.extend(vec![b'x'; 5_000]);
        request.extend(b"\r\nHost: wolftorrent.com\r\n\r\n");
        let result = analyze_buffer(&request).unwrap();
        assert_eq!(result.hostname.as_deref(), Some("wolftorrent.com"));
        assert!(result.observed_bytes > 4096);
    }

    #[test]
    fn reports_invalid_and_incomplete_payloads_explicitly() {
        let invalid = analyze_buffer(&[0, 1, 2, 3]).unwrap();
        assert_eq!(invalid.status, InspectionStatus::Unsupported);
        assert!(analyze_buffer(&[0x16, 0x03, 0x03, 0x10, 0x00]).is_none());
    }

    #[test]
    fn tls_client_hello_sni_parser_handles_complete_and_missing_sni() {
        let mut hello = vec![0x01, 0, 0, 0];
        let mut body = vec![0x03, 0x03];
        body.extend([0u8; 32]);
        body.extend([0, 0, 2, 0x13, 0x01, 1, 0]);
        let name = b"wolftorrent.com";
        let mut sni_body = Vec::new();
        sni_body.extend(((name.len() + 3) as u16).to_be_bytes());
        sni_body.push(0);
        sni_body.extend((name.len() as u16).to_be_bytes());
        sni_body.extend(name);
        let mut extensions = vec![0, 0];
        extensions.extend((sni_body.len() as u16).to_be_bytes());
        extensions.extend(sni_body);
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        hello[1..4].copy_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hello.extend(body);
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend((hello.len() as u16).to_be_bytes());
        record.extend(hello);
        assert_eq!(
            parse_tls_sni(&record).unwrap().as_deref(),
            Some("wolftorrent.com")
        );
        assert!(analyze_buffer(&record[..20]).is_none());
        assert_eq!(
            analyze_buffer(&record).unwrap().status,
            InspectionStatus::TlsSni
        );

        let mut no_sni_body = vec![0x03, 0x03];
        no_sni_body.extend([0u8; 32]);
        no_sni_body.extend([0, 0, 2, 0x13, 0x01, 1, 0, 0, 0]);
        let mut no_sni_handshake = vec![0x01, 0, 0, 0];
        no_sni_handshake[1..4].copy_from_slice(&(no_sni_body.len() as u32).to_be_bytes()[1..]);
        no_sni_handshake.extend(no_sni_body);
        let mut no_sni_record = vec![0x16, 0x03, 0x03];
        no_sni_record.extend((no_sni_handshake.len() as u16).to_be_bytes());
        no_sni_record.extend(no_sni_handshake);
        assert_eq!(
            analyze_buffer(&no_sni_record).unwrap().status,
            InspectionStatus::SniUnavailable
        );
    }
}
