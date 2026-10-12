use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(serde::Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(serde::Deserialize)]
struct DohAnswer {
    r#type: u16,
    data: String,
}

struct CacheEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

struct DnsCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

impl DnsCache {
    fn new(ttl_secs: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    async fn get(&self, hostname: &str) -> Option<Vec<IpAddr>> {
        let read = self.entries.read().await;
        if let Some(entry) = read.get(hostname)
            && Instant::now() < entry.expires_at
        {
            return Some(entry.ips.clone());
        }
        None
    }

    async fn insert(&self, hostname: &str, ips: Vec<IpAddr>) {
        let mut write = self.entries.write().await;
        if write.len() > 2000 {
            let now = Instant::now();
            write.retain(|_, v| v.expires_at > now);
        }
        write.insert(
            hostname.to_string(),
            CacheEntry {
                ips,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}

static DNS_CACHE: LazyLock<DnsCache> = LazyLock::new(|| DnsCache::new(300));
static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .pool_idle_timeout(Duration::from_secs(60))
        .tcp_nodelay(true)
        .build()
        .unwrap_or_default()
});

pub async fn resolve(hostname: &str) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    if let Some(cached_ips) = DNS_CACHE.get(hostname).await {
        return Ok(cached_ips);
    }

    // 1. Try Cloudflare DoH (1.1.1.1)
    let cf_url = format!("https://1.1.1.1/dns-query?name={}&type=A", hostname);
    if let Ok(resp) = HTTP_CLIENT
        .get(&cf_url)
        .header("accept", "application/dns-json")
        .send()
        .await
        && let Ok(doh) = resp.json::<DohResponse>().await
    {
        let mut ips = Vec::new();
        if let Some(answers) = doh.answer {
            for ans in answers {
                if ans.r#type == 1
                    && let Ok(ip) = ans.data.parse::<IpAddr>()
                {
                    ips.push(ip);
                }
            }
        }
        if !ips.is_empty() {
            DNS_CACHE.insert(hostname, ips.clone()).await;
            return Ok(ips);
        }
    }

    // 2. Try Google DoH (8.8.8.8)
    let g_url = format!("https://8.8.8.8/resolve?name={}&type=A", hostname);
    if let Ok(resp) = HTTP_CLIENT.get(&g_url).send().await
        && let Ok(doh) = resp.json::<DohResponse>().await
    {
        let mut ips = Vec::new();
        if let Some(answers) = doh.answer {
            for ans in answers {
                if ans.r#type == 1
                    && let Ok(ip) = ans.data.parse::<IpAddr>()
                {
                    ips.push(ip);
                }
            }
        }
        if !ips.is_empty() {
            DNS_CACHE.insert(hostname, ips.clone()).await;
            return Ok(ips);
        }
    }

    // 3. Fallback to system DNS
    let mut ips = Vec::new();
    if let Ok(addrs) = tokio::net::lookup_host(format!("{}:443", hostname)).await {
        for addr in addrs {
            ips.push(addr.ip());
        }
    }

    if ips.is_empty() {
        return Err(anyhow!("No IPs found via DoH or system DNS"));
    }

    DNS_CACHE.insert(hostname, ips.clone()).await;
    Ok(ips)
}
