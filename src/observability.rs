use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: u8 = 1;
const DEFAULT_BUFFER_CAPACITY: usize = 2048;
const DEFAULT_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub schema_version: u8,
    pub timestamp_ms: u128,
    pub level: Level,
    pub event_id: String,
    pub event_type: String,
    pub component: String,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct ObserverConfig {
    pub directory: Option<PathBuf>,
    pub buffer_capacity: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}

impl Default for ObserverConfig {
    fn default() -> Self {
        Self {
            directory: std::env::var_os("DFLUX_LOG_DIR").map(PathBuf::from),
            buffer_capacity: std::env::var("DFLUX_LOG_BUFFER_CAPACITY")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(DEFAULT_BUFFER_CAPACITY),
            max_file_bytes: std::env::var("DFLUX_LOG_MAX_FILE_BYTES")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(DEFAULT_MAX_FILE_BYTES),
            max_total_bytes: std::env::var("DFLUX_LOG_MAX_TOTAL_BYTES")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(DEFAULT_MAX_TOTAL_BYTES),
        }
    }
}

struct Inner {
    events: VecDeque<Event>,
    next_id: u64,
    dropped_events: u64,
}

pub struct Observer {
    config: ObserverConfig,
    inner: Mutex<Inner>,
}

static GLOBAL: OnceLock<Arc<Observer>> = OnceLock::new();

impl Observer {
    pub fn new(config: ObserverConfig) -> Arc<Self> {
        let max_file_bytes = config.max_file_bytes.max(1);
        let observer = Arc::new(Self {
            config: ObserverConfig {
                buffer_capacity: config.buffer_capacity.max(1),
                max_file_bytes,
                max_total_bytes: config.max_total_bytes.max(max_file_bytes),
                ..config
            },
            inner: Mutex::new(Inner {
                events: VecDeque::new(),
                next_id: 1,
                dropped_events: 0,
            }),
        });
        observer.load_existing_events();
        observer
    }

    pub fn install_global(observer: Arc<Self>) -> Arc<Self> {
        let _ = GLOBAL.set(observer.clone());
        observer
    }

    pub fn global() -> Option<Arc<Self>> {
        GLOBAL.get().cloned()
    }

    pub fn emit(&self, mut event: Event) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        event.schema_version = SCHEMA_VERSION;
        if event.event_id.is_empty() {
            event.event_id = format!("{}-{}", std::process::id(), inner.next_id);
            inner.next_id = inner.next_id.saturating_add(1);
        }
        if inner.events.len() >= self.config.buffer_capacity {
            inner.events.pop_front();
            inner.dropped_events = inner.dropped_events.saturating_add(1);
        }
        if let Some(directory) = &self.config.directory {
            if let Err(error) = self.append_to_disk(directory, &event) {
                tracing::warn!(error = %error, "observability disk write failed");
            }
        }
        inner.events.push_back(event);
    }

    pub fn snapshot(&self) -> Vec<Event> {
        self.inner
            .lock()
            .map(|inner| inner.events.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn dropped_events(&self) -> u64 {
        self.inner
            .lock()
            .map(|inner| inner.dropped_events)
            .unwrap_or_default()
    }

    pub fn export_json(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let report = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "exported_at_ms": now_ms(),
            "dropped_events": self.dropped_events(),
            "events": self.snapshot(),
        });
        let mut file = File::create(path)?;
        serde_json::to_writer_pretty(&mut file, &report)?;
        file.write_all(b"\n")
    }

    fn append_to_disk(&self, directory: &Path, event: &Event) -> std::io::Result<()> {
        fs::create_dir_all(directory)?;
        let path = directory.join("events.jsonl");
        let encoded = serde_json::to_vec(event)?;
        let current_size = fs::metadata(&path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if current_size.saturating_add(encoded.len() as u64 + 1) > self.config.max_file_bytes {
            let rotated = directory.join(format!("events-{}-{}.jsonl", now_ms(), event.event_id));
            if path.exists() {
                fs::rename(&path, rotated)?;
            }
        }
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.write_all(&encoded)?;
        file.write_all(b"\n")?;
        self.enforce_total_limit(directory)
    }

    fn load_existing_events(&self) {
        let Some(directory) = &self.config.directory else {
            return;
        };
        let path = directory.join("events.jsonl");
        let Ok(content) = fs::read_to_string(path) else {
            return;
        };
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        for line in content.lines() {
            let Ok(event) = serde_json::from_str::<Event>(line) else {
                continue;
            };
            if inner.events.len() >= self.config.buffer_capacity {
                inner.events.pop_front();
                inner.dropped_events = inner.dropped_events.saturating_add(1);
            }
            inner.events.push_back(event);
        }
    }

    fn enforce_total_limit(&self, directory: &Path) -> std::io::Result<()> {
        let mut files = fs::read_dir(directory)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("events"))
            .filter_map(|entry| {
                let size = entry.metadata().ok()?.len();
                Some((entry.path(), size))
            })
            .collect::<Vec<_>>();
        let mut total = files.iter().map(|(_, size)| *size).sum::<u64>();
        files.sort_by_key(|(path, _)| path.clone());
        for (path, size) in files {
            if total <= self.config.max_total_bytes
                || path.file_name().is_some_and(|name| name == "events.jsonl")
            {
                continue;
            }
            fs::remove_file(path)?;
            total = total.saturating_sub(size);
        }
        Ok(())
    }
}

pub fn event(level: Level, event_type: &str, component: &str, operation: &str) -> Event {
    Event {
        schema_version: SCHEMA_VERSION,
        timestamp_ms: now_ms(),
        level,
        event_id: String::new(),
        event_type: event_type.to_string(),
        component: component.to_string(),
        operation: operation.to_string(),
        correlation_id: None,
        outcome: None,
        error_code: None,
        error_category: None,
        error_message: None,
        fields: BTreeMap::new(),
    }
}

pub fn emit(event: Event) {
    if let Some(observer) = Observer::global() {
        observer.emit(event);
    }
}

pub fn redact(value: &str) -> String {
    let mut object = Map::new();
    object.insert("value".to_string(), Value::String(value.to_string()));
    redact_value(Value::Object(object))
        .get("value")
        .and_then(Value::as_str)
        .unwrap_or("[REDACTED]")
        .to_string()
}

fn redact_value(value: Value) -> Value {
    match value {
        Value::Object(mut object) => {
            for (key, value) in object.iter_mut() {
                let sensitive = [
                    "password",
                    "token",
                    "secret",
                    "cookie",
                    "authorization",
                    "private_key",
                ]
                .iter()
                .any(|name| key.to_ascii_lowercase().contains(name));
                if sensitive {
                    *value = Value::String("[REDACTED]".to_string());
                }
            }
            Value::Object(object)
        }
        other => other,
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_is_bounded_and_exports_schema() {
        let observer = Observer::new(ObserverConfig {
            directory: None,
            buffer_capacity: 2,
            max_file_bytes: 100,
            max_total_bytes: 200,
        });
        observer.emit(event(Level::Info, "one", "test", "run"));
        observer.emit(event(Level::Info, "two", "test", "run"));
        observer.emit(event(Level::Warn, "three", "test", "run"));
        assert_eq!(observer.snapshot().len(), 2);
        assert_eq!(observer.dropped_events(), 1);
    }

    #[test]
    fn redacts_secret_field_names() {
        let value = redact("not-a-secret");
        assert_eq!(value, "not-a-secret");
        let object = serde_json::json!({"token": "hidden", "safe": "visible"});
        let redacted = redact_value(object);
        assert_eq!(redacted["token"], "[REDACTED]");
        assert_eq!(redacted["safe"], "visible");
    }

    #[test]
    fn rotates_files_without_exceeding_configured_total() {
        let directory = std::env::temp_dir().join(format!("dflux-observability-{}", now_ms()));
        let observer = Observer::new(ObserverConfig {
            directory: Some(directory.clone()),
            buffer_capacity: 32,
            max_file_bytes: 100,
            max_total_bytes: 200,
        });
        for index in 0..20 {
            let mut event = event(Level::Info, "rotation", "test", "run");
            event
                .fields
                .insert("index".into(), serde_json::json!(index));
            event.fields.insert(
                "padding".into(),
                serde_json::json!("xxxxxxxxxxxxxxxxxxxxxxxx"),
            );
            observer.emit(event);
        }
        let total = fs::read_dir(&directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| entry.metadata().ok())
            .map(|metadata| metadata.len())
            .sum::<u64>();
        assert!(
            total <= 200,
            "event files exceeded configured total: {total}"
        );
        let _ = fs::remove_dir_all(directory);
    }
}
