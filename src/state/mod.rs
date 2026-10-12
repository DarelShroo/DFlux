use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock, watch};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Decision {
    Direct,
    Remote,
    #[allow(dead_code)]
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
    inflight: Arc<Mutex<HashMap<String, watch::Receiver<Option<Decision>>>>>,
    base_ttl: Duration,
}

impl StateManager {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            inflight: Arc::new(Mutex::new(HashMap::new())),
            base_ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub async fn get_decision(&self, hostname: &str) -> Option<Decision> {
        let cache = self.cache.read().await;
        if let Some(state) = cache.get(hostname)
            && Instant::now() < state.expires_at
        {
            return Some(state.decision);
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

        // Clean up expired entries if cache is large
        if cache.len() > 5000 {
            let now = Instant::now();
            cache.retain(|_, v| v.expires_at > now);
        }

        // Exponential backoff for failures: 15s, 30s, 60s, max 4 mins
        let ttl = if failed {
            let backoff = 15 * (2_u64.pow(failures.min(4)));
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

    /// Single-flight wrapper: If a probe is already running for `hostname`,
    /// wait for its result instead of running duplicate concurrent probes.
    pub async fn get_or_evaluate<F, Fut>(&self, hostname: &str, eval_fn: F) -> Decision
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = (Decision, bool)>,
    {
        // 1. Fast path: check cache
        if let Some(d) = self.get_decision(hostname).await {
            return d;
        }

        // 2. Check inflight map
        let mut rx = {
            let mut inflight = self.inflight.lock().await;
            // Double check cache
            if let Some(d) = self.get_decision(hostname).await {
                return d;
            }

            if let Some(existing_rx) = inflight.get(hostname) {
                existing_rx.clone()
            } else {
                // We are the leader for this hostname
                let (tx, rx) = watch::channel(None);
                inflight.insert(hostname.to_string(), rx);
                drop(inflight);

                // Run evaluation
                let (decision, failed) = eval_fn().await;
                self.set_decision(hostname, decision, failed).await;

                // Notify all waiters
                let _ = tx.send(Some(decision));

                // Remove from inflight
                let mut inflight = self.inflight.lock().await;
                inflight.remove(hostname);

                return decision;
            }
        };

        // 3. Wait for leader to finish
        while rx.borrow().is_none() {
            if rx.changed().await.is_err() {
                break;
            }
        }

        rx.borrow().unwrap_or(Decision::Direct)
    }

    /// Reports that a connection failed on a route.
    /// If consecutive failures reach threshold, invalidates cached decision.
    pub async fn record_failure(&self, hostname: &str) {
        let mut cache = self.cache.write().await;
        if let Some(state) = cache.get_mut(hostname) {
            state.failures += 1;
            if state.failures >= 3 && state.decision == Decision::Direct {
                // Demote from Direct or expire early to force re-evaluation
                state.expires_at = Instant::now();
            }
        }
    }

    /// Reports successful data transfer on a route to reset failure counters.
    pub async fn record_success(&self, hostname: &str) {
        let mut cache = self.cache.write().await;
        if let Some(state) = cache.get_mut(hostname)
            && state.failures > 0
        {
            state.failures = 0;
        }
    }
}
