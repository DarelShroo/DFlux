use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Instant, Duration};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Decision {
    Direct,
    Remote,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct RouteState {
    pub decision: Decision,
    pub expires_at: Instant,
    pub failures: u32,
}

#[derive(Clone)]
pub struct StateManager {
    cache: Arc<RwLock<HashMap<String, RouteState>>>,
    base_ttl: Duration,
}

impl StateManager {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            base_ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub async fn get_decision(&self, hostname: &str) -> Option<Decision> {
        let cache = self.cache.read().await;
        if let Some(state) = cache.get(hostname) {
            if Instant::now() < state.expires_at {
                return Some(state.decision);
            }
        }
        None
    }

    pub async fn set_decision(&self, hostname: &str, decision: Decision, failed: bool) {
        let mut cache = self.cache.write().await;
        
        let mut failures = 0;
        if failed {
            if let Some(existing) = cache.get(hostname) {
                failures = existing.failures + 1;
            } else {
                failures = 1;
            }
        }
        
        // Exponential backoff for failures: 15s, 30s, 60s, max 5 mins
        let ttl = if failed {
            let backoff = 15 * (2_u64.pow(failures.min(4) as u32));
            Duration::from_secs(backoff)
        } else {
            self.base_ttl
        };

        cache.insert(
            hostname.to_string(),
            RouteState {
                decision,
                expires_at: Instant::now() + ttl,
                failures,
            },
        );
    }
}
