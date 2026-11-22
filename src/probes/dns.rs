use anyhow::{Result, anyhow};
use hickory_resolver::proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, RecordType};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::egress::EgressManager;
use crate::observability::{self, Level};

pub const GLOBAL_DOH_TIMEOUT: Duration = Duration::from_millis(2500);
pub const MAX_HTTP_HEADERS_SIZE: usize = 8192;
pub const MAX_DNS_MESSAGE_SIZE: usize = 65535;
pub const MAX_CNAME_DEPTH: usize = 8;

struct CacheEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

type DnsCacheKey = (String, bool);
type DnsFlight = Arc<tokio::sync::Mutex<()>>;

pub struct DnsCache {
    entries: RwLock<HashMap<DnsCacheKey, CacheEntry>>,
    flights: RwLock<HashMap<DnsCacheKey, DnsFlight>>,
    ttl: Duration,
}

#[cfg(test)]
mod resolver_behavior_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn policy_scoped_cache_and_singleflight_use_independent_transports() {
        let cache = Arc::new(DnsCache::new(30));
        let calls = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let mut tasks = Vec::new();
        for remote in [false, true].into_iter().cycle().take(20) {
            let cache = cache.clone();
            let calls = calls.clone();
            tasks.push(tokio::spawn(async move {
                resolve_cached(&cache, "same.example.test", remote, || async move {
                    calls[usize::from(remote)].fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok(vec![
                        if remote {
                            "203.0.113.20"
                        } else {
                            "203.0.113.10"
                        }
                        .parse()
                        .unwrap(),
                    ])
                })
                .await
                .unwrap()
            }));
        }
        for (index, task) in tasks.into_iter().enumerate() {
            let result = task.await.unwrap();
            let expected: IpAddr = if index % 2 == 0 {
                "203.0.113.10"
            } else {
                "203.0.113.20"
            }
            .parse()
            .unwrap();
            assert_eq!(result, vec![expected]);
        }
        assert_eq!(
            calls[0].load(Ordering::SeqCst),
            1,
            "DIRECT concurrent requests share one DoH exchange"
        );
        assert_eq!(
            calls[1].load(Ordering::SeqCst),
            1,
            "REMOTE concurrent requests share one DoH exchange"
        );

        // Cached values remain policy scoped; neither policy can observe the other's answer.
        let direct: IpAddr = "203.0.113.10".parse().unwrap();
        let remote: IpAddr = "203.0.113.20".parse().unwrap();
        assert_eq!(
            resolve_cached(&cache, "same.example.test", false, || async {
                Ok(vec![remote])
            })
            .await
            .unwrap(),
            vec![direct]
        );
        assert_eq!(
            resolve_cached(&cache, "same.example.test", true, || async {
                Ok(vec![direct])
            })
            .await
            .unwrap(),
            vec![remote]
        );
        assert_eq!(calls[0].load(Ordering::SeqCst), 1);
        assert_eq!(calls[1].load(Ordering::SeqCst), 1);
    }
}

impl DnsCache {
    fn new(ttl_secs: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            flights: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    async fn get(&self, hostname: &str, remote: bool) -> Option<Vec<IpAddr>> {
        let read = self.entries.read().await;
        if let Some(entry) = read.get(&(hostname.to_string(), remote))
            && Instant::now() < entry.expires_at
        {
            return Some(entry.ips.clone());
        }
        None
    }

    async fn insert(&self, hostname: &str, remote: bool, ips: Vec<IpAddr>) {
        let mut write = self.entries.write().await;
        if write.len() > 2000 {
            let now = Instant::now();
            write.retain(|_, v| v.expires_at > now);
        }
        write.insert(
            (hostname.to_string(), remote),
            CacheEntry {
                ips,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    async fn flight(&self, hostname: &str, remote: bool) -> Arc<tokio::sync::Mutex<()>> {
        let key = (hostname.to_string(), remote);
        if let Some(lock) = self.flights.read().await.get(&key) {
            return lock.clone();
        }
        let mut flights = self.flights.write().await;
        if flights.len() > 2000 {
            flights.retain(|_, lock| Arc::strong_count(lock) > 1);
        }
        flights
            .entry(key)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

static DNS_CACHE: LazyLock<DnsCache> = LazyLock::new(|| DnsCache::new(300));

static DOH_TLS_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Arc::new(config)
});

/// Resolves a hostname using strict RFC 8484 DoH without system DNS fallback,
/// respecting a cumulative global timeout of 2.5 seconds and the caller's DIRECT/REMOTE policy.
pub async fn resolve(
    hostname: &str,
    enforce_remote: bool,
    egress_mgr: Arc<EgressManager>,
) -> Result<Vec<IpAddr>> {
    let hostname = hostname.trim();
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let hostname = hostname.to_string();
    let lookup_key = hostname.clone();
    let started = Instant::now();
    let transport_mgr = egress_mgr.clone();
    let result = resolve_cached(
        &DNS_CACHE,
        &lookup_key,
        enforce_remote,
        move || async move {
            // Use kernel entropy; Instant::now().elapsed() is almost always near zero and
            // would otherwise make the transaction ID effectively constant.
            let mut id_bytes = [0u8; 2];
            let count = unsafe {
                libc::getrandom(
                    id_bytes.as_mut_ptr() as *mut libc::c_void,
                    id_bytes.len(),
                    0,
                )
            };
            if count != id_bytes.len() as isize {
                let fallback = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos()
                    ^ std::process::id() as u128;
                id_bytes.copy_from_slice(&(fallback as u16).to_be_bytes());
            }
            let query_id = u16::from_be_bytes(id_bytes);
            let query_wire = build_dns_query(&hostname, query_id)?;
            run_doh_attempts(
                GLOBAL_DOH_TIMEOUT,
                Duration::from_millis(1500),
                |index, limit| {
                    let query_wire = query_wire.clone();
                    let hostname = hostname.clone();
                    let egress_mgr = transport_mgr.clone();
                    Box::pin(async move {
                        let (server_ip, server_name) = if index == 0 {
                            (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "cloudflare-dns.com")
                        } else {
                            (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), "dns.google")
                        };
                        let response = doh_exchange(
                            server_ip,
                            server_name,
                            &query_wire,
                            enforce_remote,
                            egress_mgr,
                            limit,
                        )
                        .await?;
                        let ips = parse_doh_response(&response, query_id, &hostname)?;
                        if ips.is_empty() {
                            Err(anyhow!("DoH returned no addresses"))
                        } else {
                            Ok(ips)
                        }
                    })
                },
            )
            .await
        },
    )
    .await;
    match &result {
        Ok(ips) => {
            let mut event = observability::event(Level::Info, "dns_resolution", "dns", "resolve");
            event.outcome = Some("success".into());
            event
                .fields
                .insert("hostname".into(), serde_json::json!(lookup_key));
            event
                .fields
                .insert("remote".into(), serde_json::json!(enforce_remote));
            event
                .fields
                .insert("addresses".into(), serde_json::json!(ips.len()));
            event.fields.insert(
                "duration_ms".into(),
                serde_json::json!(started.elapsed().as_millis()),
            );
            observability::emit(event);
            tracing::debug!(hostname = %lookup_key, route = if enforce_remote { "REMOTE" } else { "DIRECT" }, addresses = ?ips, "DoH resolution completed")
        }
        Err(error) => {
            let mut event = observability::event(Level::Warn, "dns_resolution", "dns", "resolve");
            event.outcome = Some("failure".into());
            event.error_category = Some("dns".into());
            event.error_message = Some(error.to_string());
            event
                .fields
                .insert("hostname".into(), serde_json::json!(lookup_key));
            event
                .fields
                .insert("remote".into(), serde_json::json!(enforce_remote));
            event.fields.insert(
                "duration_ms".into(),
                serde_json::json!(started.elapsed().as_millis()),
            );
            observability::emit(event);
            tracing::warn!(hostname = %lookup_key, route = if enforce_remote { "REMOTE" } else { "DIRECT" }, error = %error, "DoH resolution failed")
        }
    }
    result
}

/// Runs one policy-scoped lookup through the same cache and single-flight path used by DoH.
/// `transport` is the DoH exchange and is injectable so tests need no network access.
#[doc(hidden)]
pub async fn resolve_cached<F, Fut>(
    cache: &DnsCache,
    hostname: &str,
    remote: bool,
    transport: F,
) -> Result<Vec<IpAddr>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Vec<IpAddr>>>,
{
    let flight = cache.flight(hostname, remote).await;
    let _flight_guard = flight.lock().await;
    if let Some(cached_ips) = cache.get(hostname, remote).await {
        let mut event = observability::event(Level::Debug, "dns_cache", "dns", "resolve");
        event.outcome = Some("hit".into());
        event
            .fields
            .insert("hostname".into(), serde_json::json!(hostname));
        event
            .fields
            .insert("remote".into(), serde_json::json!(remote));
        observability::emit(event);
        return Ok(cached_ips);
    }
    let mut event = observability::event(Level::Debug, "dns_cache", "dns", "resolve");
    event.outcome = Some("miss".into());
    event
        .fields
        .insert("hostname".into(), serde_json::json!(hostname));
    event
        .fields
        .insert("remote".into(), serde_json::json!(remote));
    observability::emit(event);
    let result = transport().await;
    if let Ok(resolved) = &result {
        if resolved.is_empty() {
            return Err(anyhow!("DoH returned no addresses"));
        }
        cache.insert(hostname, remote, resolved.clone()).await;
    }
    result
}

#[doc(hidden)]
pub async fn run_doh_attempts<F>(
    budget: Duration,
    first_cap: Duration,
    mut attempt: F,
) -> Result<Vec<IpAddr>>
where
    F: FnMut(usize, Duration) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send>>,
{
    let started = Instant::now();
    for index in 0..2 {
        let elapsed = started.elapsed();
        if elapsed >= budget {
            break;
        }
        let remaining = budget - elapsed;
        let allotment = if index == 0 {
            remaining.min(first_cap)
        } else {
            remaining
        };
        match timeout(allotment, attempt(index, allotment)).await {
            Ok(Ok(ips)) if !ips.is_empty() => return Ok(ips),
            _ => {}
        }
    }
    Err(anyhow!(
        "All DoH providers failed within global budget ({:?})",
        budget
    ))
}

/// Builds an RFC 1035 wire format DNS query for an A record.
pub fn build_dns_query(hostname: &str, query_id: u16) -> Result<Vec<u8>> {
    let mut normalized = hostname.trim().to_ascii_lowercase();
    if !normalized.ends_with('.') {
        normalized.push('.');
    }
    let name = Name::from_ascii(&normalized)
        .map_err(|e| anyhow!("Invalid DNS hostname '{}': {}", hostname, e))?;

    let mut msg = Message::query();
    msg.metadata.id = query_id;
    msg.metadata.recursion_desired = true;
    let query = Query::query(name, RecordType::A);
    msg.add_query(query);

    let wire_bytes = msg.to_vec()?;
    Ok(wire_bytes)
}

/// Performs a DoH HTTP/1.1 wire exchange over a strictly isolated TLS socket.
async fn doh_exchange(
    server_ip: IpAddr,
    sni_host: &str,
    query_wire: &[u8],
    enforce_remote: bool,
    egress_mgr: Arc<EgressManager>,
    attempt_timeout: Duration,
) -> Result<Vec<u8>> {
    timeout(
        attempt_timeout,
        doh_exchange_inner(server_ip, sni_host, query_wire, enforce_remote, egress_mgr),
    )
    .await
    .map_err(|_| anyhow!("DoH exchange timed out"))?
}

async fn doh_exchange_inner(
    server_ip: IpAddr,
    sni_host: &str,
    query_wire: &[u8],
    enforce_remote: bool,
    egress_mgr: Arc<EgressManager>,
) -> Result<Vec<u8>> {
    // 1. Establish isolated TCP stream with mandatory SO_MARK and SO_BINDTODEVICE
    let tcp_stream =
        crate::outbound::connect_tcp(server_ip, 443, enforce_remote, egress_mgr).await?;

    // 2. Perform strict TLS handshake against webpki root certificates
    let server_name = ServerName::try_from(sni_host.to_string())
        .map_err(|e| anyhow!("Invalid TLS SNI hostname '{}': {}", sni_host, e))?;

    let connector = TlsConnector::from(DOH_TLS_CONFIG.clone());
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

    // 3. Send HTTP/1.1 POST /dns-query
    let request_head = format!(
        "POST /dns-query HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        sni_host,
        query_wire.len()
    );

    tls_stream.write_all(request_head.as_bytes()).await?;
    tls_stream.write_all(query_wire).await?;
    tls_stream.flush().await?;

    // 4. Read HTTP/1.1 response with strict memory and header limits
    let mut buffer = Vec::with_capacity(4096);
    let mut temp = [0u8; 1024];
    let mut headers_end = None;

    while buffer.len() < MAX_HTTP_HEADERS_SIZE {
        let n = tls_stream.read(&mut temp).await?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..n]);
        if let Some(pos) = find_subsequence(&buffer, b"\r\n\r\n") {
            headers_end = Some(pos);
            break;
        }
    }

    let header_boundary = headers_end.ok_or_else(|| {
        anyhow!("HTTP headers exceeded maximum limit of 8 KiB or stream ended prematurely")
    })?;

    let header_bytes = &buffer[..header_boundary];
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.lines();

    // Validate Status-Line (RFC 7230 §3.1.2)
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow!("Missing HTTP Status-Line in DoH response"))?;
    let status_parts: Vec<&str> = status_line.split_whitespace().collect();
    if status_parts.len() < 2 {
        return Err(anyhow!("Malformed HTTP Status-Line: '{}'", status_line));
    }
    if !status_parts[0].starts_with("HTTP/1.") {
        return Err(anyhow!("Unsupported HTTP version in: '{}'", status_line));
    }
    let status_code: u16 = status_parts[1]
        .parse()
        .map_err(|_| anyhow!("Invalid status code in: '{}'", status_line))?;
    if status_code != 200 {
        return Err(anyhow!("DoH server returned HTTP status {}", status_code));
    }

    // Parse and validate headers
    let mut content_type_valid = false;
    let mut content_length: Option<usize> = None;
    let mut has_transfer_encoding = false;

    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let name = name.trim();
            let val = val.trim();
            if name.eq_ignore_ascii_case("content-type") {
                // Ignore optional MIME parameters after ';'
                let mime_type = val.split(';').next().unwrap_or("").trim();
                if mime_type.eq_ignore_ascii_case("application/dns-message") {
                    content_type_valid = true;
                }
            } else if name.eq_ignore_ascii_case("content-length") {
                if let Ok(len) = val.parse::<usize>() {
                    content_length = Some(len);
                }
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                has_transfer_encoding = true;
            }
        }
    }

    // RFC 7230 §3.3.3: Reject ambiguous responses containing both Content-Length and Transfer-Encoding
    if has_transfer_encoding && content_length.is_some() {
        return Err(anyhow!(
            "Rejecting ambiguous HTTP response: both Transfer-Encoding and Content-Length present"
        ));
    }

    if has_transfer_encoding {
        return Err(anyhow!(
            "Transfer-Encoding: chunked is rejected for DoH responses"
        ));
    }

    if !content_type_valid {
        return Err(anyhow!("Invalid or missing Content-Type in DoH response"));
    }

    let expected_len =
        content_length.ok_or_else(|| anyhow!("Missing Content-Length in DoH response"))?;

    if expected_len > MAX_DNS_MESSAGE_SIZE {
        return Err(anyhow!(
            "DoH response Content-Length {} exceeds limit of {} bytes",
            expected_len,
            MAX_DNS_MESSAGE_SIZE
        ));
    }

    // Extract already buffered body bytes
    let body_start = header_boundary + 4;
    let mut body = buffer[body_start..].to_vec();

    // Read remaining body bytes up to expected_len using take()
    if body.len() < expected_len {
        let remaining_needed = expected_len - body.len();
        let mut limited_reader = tls_stream.take(remaining_needed as u64);
        let mut read_chunk = Vec::new();
        limited_reader.read_to_end(&mut read_chunk).await?;
        body.extend_from_slice(&read_chunk);
    }

    if body.len() != expected_len {
        return Err(anyhow!(
            "Incomplete HTTP body: read {} bytes, expected {}",
            body.len(),
            expected_len
        ));
    }

    Ok(body)
}

/// Parses an RFC 1035 / RFC 8484 binary DNS response, validates query ID, QR,
/// RCODE, and follows CNAME chains up to 8 hops with loop detection.
pub fn parse_doh_response(
    body: &[u8],
    query_id: u16,
    expected_hostname: &str,
) -> Result<Vec<IpAddr>> {
    if body.len() > MAX_DNS_MESSAGE_SIZE {
        return Err(anyhow!("DNS wire message exceeds maximum size of 64 KiB"));
    }

    let message = Message::from_vec(body)
        .map_err(|e| anyhow!("Failed to parse DNS response wire message: {}", e))?;

    // 1. Validate Transaction ID
    if message.id != query_id {
        return Err(anyhow!(
            "DNS transaction ID mismatch: expected {}, received {}",
            query_id,
            message.id
        ));
    }

    // 2. Validate QR bit (must be Response)
    if message.message_type != MessageType::Response {
        return Err(anyhow!("DNS message QR bit is not Response"));
    }

    // 3. Validate Truncation
    if message.truncation {
        return Err(anyhow!("DNS response message is truncated"));
    }

    // 4. Validate RCODE
    match message.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => {
            return Err(anyhow!(
                "Domain does not exist (NXDOMAIN): {}",
                expected_hostname
            ));
        }
        ResponseCode::ServFail => {
            return Err(anyhow!(
                "DNS server failure (SERVFAIL): {}",
                expected_hostname
            ));
        }
        other => {
            return Err(anyhow!("DNS server returned error RCODE: {:?}", other));
        }
    }

    // 5. Validate question
    if message.queries.len() != 1 {
        return Err(anyhow!("DNS response must contain exactly one question"));
    }
    let query = &message.queries[0];
    let query_name_norm = normalize_dns_name(&query.name().to_string());
    let expected_norm = normalize_dns_name(expected_hostname);
    if query_name_norm != expected_norm {
        return Err(anyhow!(
            "DNS response question mismatch: expected '{}', received '{}'",
            expected_norm,
            query_name_norm
        ));
    }
    if query.query_type() != RecordType::A {
        return Err(anyhow!("DNS query type was not A"));
    }
    if query.query_class() != DNSClass::IN {
        return Err(anyhow!("DNS question class was not IN"));
    }

    // 6. CNAME chain traversal with loop detection and max depth 8
    let mut current_target = expected_norm.clone();
    let mut visited = Vec::new();

    for _ in 0..MAX_CNAME_DEPTH {
        visited.push(current_target.clone());

        // Look for A records matching current_target
        let mut ips = Vec::new();
        for record in &message.answers {
            let record_name_norm = normalize_dns_name(&record.name.to_string());
            if record_name_norm == current_target
                && let RData::A(a) = &record.data
            {
                ips.push(IpAddr::V4(a.0));
            }
        }

        if !ips.is_empty() {
            return Ok(ips);
        }

        // No direct A record found, look for CNAME matching current_target
        let mut next_target = None;
        for record in &message.answers {
            let record_name_norm = normalize_dns_name(&record.name.to_string());
            if record_name_norm == current_target
                && let RData::CNAME(cname) = &record.data
            {
                let target_str = normalize_dns_name(&cname.0.to_string());
                if visited.contains(&target_str) {
                    return Err(anyhow!(
                        "CNAME loop detected in DoH response at '{}'",
                        target_str
                    ));
                }
                next_target = Some(target_str);
                break;
            }
        }

        match next_target {
            Some(target) => current_target = target,
            None => break,
        }
    }

    if visited.len() >= MAX_CNAME_DEPTH {
        return Err(anyhow!("CNAME chain exceeded maximum depth of 8"));
    }

    Err(anyhow!(
        "No usable A records found in DoH response for '{}'",
        expected_hostname
    ))
}

fn normalize_dns_name(name: &str) -> String {
    let mut s = name.trim().to_ascii_lowercase();
    if s.ends_with('.') {
        s.pop();
    }
    s
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_and_remote_cache_and_flights_are_independent() {
        let cache = DnsCache::new(30);
        let direct_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let remote_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        cache.insert("example.test", false, vec![direct_ip]).await;
        cache.insert("example.test", true, vec![remote_ip]).await;

        assert_eq!(
            cache.get("example.test", false).await,
            Some(vec![direct_ip])
        );
        assert_eq!(cache.get("example.test", true).await, Some(vec![remote_ip]));
        assert!(!Arc::ptr_eq(
            &cache.flight("example.test", false).await,
            &cache.flight("example.test", true).await
        ));
        assert!(Arc::ptr_eq(
            &cache.flight("example.test", false).await,
            &cache.flight("example.test", false).await
        ));
    }
}
