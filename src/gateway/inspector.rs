use tokio::net::TcpStream;
use anyhow::Result;
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsExtension};

/// Peeks at the stream to extract SNI or Host header without consuming the bytes
/// returns the hostname and the buffered bytes that were read.
pub async fn peek_hostname(stream: &mut TcpStream) -> Result<(Option<String>, Vec<u8>)> {
    let mut buf = vec![0u8; 4096];
    
    // We only peek so we don't consume, but wait, TcpStream peek is supported.
    // However, if it's TLS, the ClientHello might not be entirely in the first peek,
    // though usually it is. Let's use `peek` to read into buf.
    let n = match stream.peek(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return Ok((None, Vec::new())),
    };

    buf.truncate(n);
    let hostname = extract_sni(&buf).or_else(|| extract_http_host(&buf));

    // If we used peek, the bytes are still in the stream, so we don't need to return them to be prepended later,
    // but in case we switch to read() and reconstruct, returning them is safer. 
    // Since we used peek, we return an empty vec so the caller just copies bidirectionally.
    Ok((hostname, Vec::new()))
}

fn extract_sni(buf: &[u8]) -> Option<String> {
    if let Ok((_, record)) = parse_tls_plaintext(buf) {
        for msg in record.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) = msg {
                if let Some(exts) = client_hello.ext {
                    if let Ok((_, extensions)) = tls_parser::parse_tls_extensions(exts) {
                        for ext in extensions {
                            if let TlsExtension::SNI(sni_list) = ext {
                                if let Some(sni) = sni_list.first() {
                                    if let Ok(name) = std::str::from_utf8(sni.1) {
                                        return Some(name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn extract_http_host(buf: &[u8]) -> Option<String> {
    // Basic HTTP header extraction
    let text = String::from_utf8_lossy(buf);
    if !text.starts_with("GET ") && !text.starts_with("POST ") && !text.starts_with("CONNECT ") &&
       !text.starts_with("PUT ") && !text.starts_with("DELETE ") && !text.starts_with("HEAD ") &&
       !text.starts_with("OPTIONS ") {
        return None;
    }

    for line in text.lines() {
        if line.to_lowercase().starts_with("host:") {
            let host_part = line[5..].trim();
            // Remove port if present
            let host = host_part.split(':').next().unwrap_or(host_part);
            return Some(host.to_string());
        }
    }
    None
}
