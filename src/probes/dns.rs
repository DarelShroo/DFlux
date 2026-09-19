use std::net::IpAddr;
use anyhow::{Result, anyhow};

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

pub async fn resolve(hostname: &str) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let client = reqwest::Client::builder().build()?;
    
    // 1. Try Cloudflare DoH (1.1.1.1)
    let cf_url = format!("https://1.1.1.1/dns-query?name={}&type=A", hostname);
    if let Ok(resp) = client.get(&cf_url).header("accept", "application/dns-json").send().await {
        if let Ok(doh) = resp.json::<DohResponse>().await {
            let mut ips = Vec::new();
            if let Some(answers) = doh.answer {
                for ans in answers {
                    if ans.r#type == 1 {
                        if let Ok(ip) = ans.data.parse::<IpAddr>() {
                            ips.push(ip);
                        }
                    }
                }
            }
            if !ips.is_empty() {
                return Ok(ips);
            }
        }
    }

    // 2. Try Google DoH (8.8.8.8)
    let g_url = format!("https://8.8.8.8/resolve?name={}&type=A", hostname);
    if let Ok(resp) = client.get(&g_url).send().await {
        if let Ok(doh) = resp.json::<DohResponse>().await {
            let mut ips = Vec::new();
            if let Some(answers) = doh.answer {
                for ans in answers {
                    if ans.r#type == 1 {
                        if let Ok(ip) = ans.data.parse::<IpAddr>() {
                            ips.push(ip);
                        }
                    }
                }
            }
            if !ips.is_empty() {
                return Ok(ips);
            }
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
    
    Ok(ips)
}
