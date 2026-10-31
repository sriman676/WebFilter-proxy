//! Structured JSON-lines logging (LOG_SCHEMA.md, D-17, D-18).
//!
//! Events go through a bounded channel to one writer thread; the request path never blocks on
//! logging (full queue = drop + count). Every line is one `write_all`, so rotation never splits a
//! line. Free-text fields are stripped of control characters and truncated here, not by callers.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};

use crate::config::LoggingConfig;
use crate::filter::Action;

/// Request log file name.
pub const REQUEST_FILE: &str = "webfilter.jsonl";
/// System/audit log file name.
pub const SYSTEM_FILE: &str = "webfilter_system.jsonl";
/// Stats log file name.
pub const STATS_FILE: &str = "webfilter_stats.jsonl";
/// How often dropped events are reported (D-17).
pub const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// UTC ISO-8601 timestamp with milliseconds: `2026-10-28T14:03:22.114Z`.
pub fn now_timestamp() -> String {
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    time::OffsetDateTime::now_utc().format(&format).unwrap_or_default()
}

/// Characters that reorder or break displayed text: bidi controls and line/paragraph separators.
fn is_display_control(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}')
}

/// Strip C0/C1 controls (including ESC), DEL, bidi controls and U+2028/2029; truncate to `max`
/// chars with `…`.
pub fn clean(s: &str, max: usize) -> String {
    let filtered = s.chars().filter(|c| !c.is_control() && !is_display_control(*c));
    if s.chars().count() <= max {
        return filtered.collect();
    }
    let mut out: String = filtered.take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn clean_opt(s: &mut Option<String>, max: usize) {
    if let Some(v) = s {
        *v = clean(v, max);
    }
}

/// One request event. Every key is always serialized (null when unknown).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[allow(missing_docs)] // fields are documented in LOG_SCHEMA.md
pub struct RequestEvent {
    pub timestamp: String,
    pub event_id: String,
    pub event_type: &'static str,
    pub src_ip: String,
    pub src_port: u16,
    pub http_method: String,
    pub url: String,
    pub url_scheme: String,
    pub dest_host: String,
    pub dest_ip: Option<String>,
    pub dest_port: u16,
    pub uri_path: String,
    pub uri_query_keys: Vec<String>,
    pub status: u16,
    pub action: &'static str,
    pub would_block: bool,
    pub reason: &'static str,
    pub rule_id: Option<String>,
    pub rule_list: Option<String>,
    pub user_agent: Option<String>,
    pub http_content_type: Option<String>,
    pub http_version: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration_ms: u64,
    pub tls_intercepted: bool,
    pub tls_sni: Option<String>,
    pub ech_present: bool,
    pub alpn: Option<String>,
    pub h2_stream_id: Option<u32>,
    pub transparent: bool,
    pub orig_dst_ip: Option<String>,
    pub orig_dst_port: Option<u16>,
    pub host_verified: Option<bool>,
    pub upgrade: Option<String>,
    pub suspicious_encoding: bool,
    pub client_id: Option<String>,
    pub profile: Option<String>,
    pub throttled: bool,
    pub scan_status: Option<String>,
    pub scan_engine: Option<String>,
    pub scan_signature: Option<String>,
    pub body_sha256: Option<String>,
    pub body_bytes: Option<u64>,
    pub download_name: Option<String>,
    pub proxy_user: Option<String>,
    pub error: Option<String>,
    pub proxy_mode: &'static str,
}

impl Default for RequestEvent {
    fn default() -> Self {
        Self {
            timestamp: now_timestamp(),
            event_id: uuid::Uuid::now_v7().to_string(),
            event_type: "request",
            src_ip: String::new(),
            src_port: 0,
            http_method: String::new(),
            url: String::new(),
            url_scheme: String::new(),
            dest_host: String::new(),
            dest_ip: None,
            dest_port: 0,
            uri_path: String::new(),
            uri_query_keys: Vec::new(),
            status: 0,
            action: Action::Allow.as_str(),
            would_block: false,
            reason: "none",
            rule_id: None,
            rule_list: None,
            user_agent: None,
            http_content_type: None,
            http_version: "1.1".to_owned(),
            bytes_in: 0,
            bytes_out: 0,
            duration_ms: 0,
            tls_intercepted: false,
            tls_sni: None,
            ech_present: false,
            alpn: None,
            h2_stream_id: None,
            transparent: false,
            orig_dst_ip: None,
            orig_dst_port: None,
            host_verified: None,
            upgrade: None,
            suspicious_encoding: false,
            client_id: None,
            profile: None,
            throttled: false,
            scan_status: None,
            scan_engine: None,
            scan_signature: None,
            body_sha256: None,
            body_bytes: None,
            download_name: None,
            proxy_user: None,
            error: None,
            proxy_mode: "enforce",
        }
    }
}

/// Default cap for free-text fields without a specific LOG_SCHEMA cap.
const DEFAULT_CAP: usize = 2048;

impl RequestEvent {
    /// Apply LOG_SCHEMA caps and control-character stripping to every free-text field.
    pub fn sanitize(&mut self) {
        for s in [
            &mut self.src_ip,
            &mut self.http_method,
            &mut self.url_scheme,
            &mut self.dest_host,
            &mut self.http_version,
        ] {
            *s = clean(s, DEFAULT_CAP);
        }
        let url_without_query = self.url.split('?').next().unwrap_or(""); // never log query values (D-18)
        self.url = clean(url_without_query, 2048);
        self.uri_path = clean(&self.uri_path, 2048);
        self.uri_query_keys.truncate(50);
        for k in &mut self.uri_query_keys {
            *k = clean(k, 64);
        }
        clean_opt(&mut self.user_agent, 512);
        clean_opt(&mut self.error, 256);
        clean_opt(&mut self.proxy_user, 64);
        clean_opt(&mut self.download_name, 128);
        for s in [
            &mut self.dest_ip,
            &mut self.rule_id,
            &mut self.rule_list,
            &mut self.http_content_type,
            &mut self.tls_sni,
            &mut self.alpn,
            &mut self.orig_dst_ip,
            &mut self.upgrade,
            &mut self.client_id,
            &mut self.profile,
            &mut self.scan_status,
            &mut self.scan_engine,
            &mut self.scan_signature,
            &mut self.body_sha256,
        ] {
            clean_opt(s, DEFAULT_CAP);
        }
    }
}

/// System event kinds (LOG_SCHEMA "System event").
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SysEvent {
    ProxyStart,
    ProxyStop,
    ConfigLoaded,
    BlocklistLoaded,
    BlocklistReloadFailed,
    CaGenerated,
    CaLoaded,
    CaPermissionError,
    LogDropped,
    LogRotated,
    PanicIsolated,
    AuthLockout,
    ListenerError,
    FeedUpdated,
    FeedFailed,
    FeedRejected,
    FeedStale,
    MalwareDetected,
    ScannerDown,
    AccessRequestCreated,
    AccessRequestDecided,
    TempAllowAdded,
    TempAllowExpired,
    PolicyReloaded,
    H2Flood,
    OrigDstFailed,
    InsecurePermissions,
}

/// Recursively clean every string in a JSON value (keys and values).
fn clean_value(v: Value) -> Value {
    match v {
        Value::String(s) => Value::String(clean(&s, 512)),
        Value::Array(a) => Value::Array(a.into_iter().take(100).map(clean_value).collect()),
        Value::Object(o) => Value::Object(
            o.into_iter().take(100).map(|(k, v)| (clean(&k, 64), clean_value(v))).collect(),
        ),
        other => other,
    }
}

fn system_line(kind: SysEvent, detail: Value) -> String {
    json!({"timestamp": now_timestamp(), "event_type": "system", "kind": kind, "detail": clean_value(detail)})
        .to_string()
}

#[derive(Clone, Copy)]
enum Target {
    Requests = 0,
    System = 1,
    Stats = 2,
}

enum Msg {
    Line(Target, String),
    Reopen,
    Shutdown(SyncSender<()>),
}

#[derive(Clone)]
struct Sender {
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
}

impl Sender {
    fn send(&self, target: Target, mut line: String) {
        line.push('\n');
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.tx.try_send(Msg::Line(target, line))
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Handle for system/audit events; cheap to clone.
#[derive(Clone)]
pub struct SystemLog(Sender);

impl SystemLog {
    /// Log a system event (never blocks; dropped and counted when the queue is full).
    pub fn event(&self, kind: SysEvent, detail: Value) {
        self.0.send(Target::System, system_line(kind, detail));
    }

    /// Emit `insecure_permissions` when any of `files` is world-writable (PT-5.4).
    pub fn insecure_files<'a>(&self, files: impl IntoIterator<Item = &'a std::path::Path>) {
        let bad = crate::config::world_writable(files);
        if !bad.is_empty() {
            self.event(SysEvent::InsecurePermissions, json!({ "files": bad }));
        }
    }
}

/// The request/system/stats logger.
pub struct EventLogger {
    sender: Sender,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl EventLogger {
    /// Create the log directory and start the writer thread.
    pub fn start(cfg: &LoggingConfig) -> std::io::Result<Self> {
        std::fs::create_dir_all(&cfg.dir)?;
        let (tx, rx) = mpsc::sync_channel(cfg.queue_capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let mut writer =
            Writer::new(&cfg.dir, cfg.max_bytes, cfg.backup_count, Arc::clone(&dropped));
        let thread = std::thread::Builder::new()
            .name("webfilter-log".into())
            .spawn(move || writer.run(&rx))?;
        Ok(Self { sender: Sender { tx, dropped }, thread: Mutex::new(Some(thread)) })
    }

    /// Log a request event; never blocks and never panics. Caps are applied here.
    pub fn log(&self, mut e: RequestEvent) {
        e.sanitize();
        match serde_json::to_string(&e) {
            Ok(line) => self.sender.send(Target::Requests, line),
            Err(_) => {
                self.sender.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Log a stats summary.
    pub fn log_stats(&self, s: &StatsEvent) {
        if let Ok(line) = serde_json::to_string(s) {
            self.sender.send(Target::Stats, line);
        }
    }

    /// Handle for system events.
    pub fn system(&self) -> SystemLog {
        SystemLog(self.sender.clone())
    }

    /// Events dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.sender.dropped.load(Ordering::Relaxed)
    }

    /// Reopen log files (SIGUSR1, for external rotation tools; D-67).
    pub fn reopen(&self) {
        if self.sender.tx.try_send(Msg::Reopen).is_err() {
            self.sender.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Flush queued events and stop the writer, waiting at most `deadline`.
    pub fn shutdown(&self, deadline: Duration) {
        let end = Instant::now() + deadline;
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        let mut msg = Msg::Shutdown(ack_tx);
        loop {
            match self.sender.tx.try_send(msg) {
                Ok(()) => break,
                Err(TrySendError::Full(m)) if Instant::now() < end => {
                    msg = m;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
        if ack_rx.recv_timeout(end.saturating_duration_since(Instant::now())).is_ok()
            && let Some(t) = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take()
        {
            let _ = t.join();
        }
    }
}

/// One size-rotated append-only file.
struct RotatingFile {
    path: PathBuf,
    file: Option<File>,
    size: u64,
    max: u64,
    backups: u32,
}

impl RotatingFile {
    fn open(&mut self) -> std::io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o640);
        let file = opts.open(&self.path)?;
        self.size = file.metadata()?.len();
        self.file = Some(file);
        Ok(())
    }

    /// Shift `X.(n-1)` -> `X.n` ... `X` -> `X.1`, then start a new `X`.
    fn rotate(&mut self) -> std::io::Result<()> {
        self.file = None;
        let numbered = |i: u32| PathBuf::from(format!("{}.{i}", self.path.display()));
        if self.backups == 0 {
            std::fs::remove_file(&self.path)?;
        } else {
            for i in (1..self.backups).rev() {
                if numbered(i).exists() {
                    std::fs::rename(numbered(i), numbered(i + 1))?;
                }
            }
            std::fs::rename(&self.path, numbered(1))?;
        }
        self.open()
    }

    /// Write one complete line; returns whether the file was rotated first.
    fn write_line(&mut self, line: &str) -> std::io::Result<bool> {
        if self.file.is_none() {
            self.open()?;
        }
        let len = line.len() as u64;
        let rotated = self.size > 0 && self.size + len > self.max;
        if rotated {
            self.rotate()?;
        }
        let file = self.file.as_mut().ok_or_else(|| std::io::Error::other("log file not open"))?;
        file.write_all(line.as_bytes())?;
        self.size += len;
        Ok(rotated)
    }
}

struct Writer {
    files: [RotatingFile; 3],
    dropped: Arc<AtomicU64>,
    reported: u64,
    write_errors: u64,
}

impl Writer {
    fn new(dir: &Path, max: u64, backups: u32, dropped: Arc<AtomicU64>) -> Self {
        let file = |name| RotatingFile { path: dir.join(name), file: None, size: 0, max, backups };
        Self {
            files: [file(REQUEST_FILE), file(SYSTEM_FILE), file(STATS_FILE)],
            dropped,
            reported: 0,
            write_errors: 0,
        }
    }

    /// Disk errors are counted and reported on stderr, never panics.
    fn write(&mut self, target: Target, line: &str) {
        let idx = target as usize;
        let Some(file) = self.files.get_mut(idx) else { return };
        match file.write_line(line) {
            Ok(true) => {
                let name = file
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let note = system_line(SysEvent::LogRotated, json!({ "file": name }));
                if let Some(sys) = self.files.get_mut(Target::System as usize) {
                    let _ = sys.write_line(&format!("{note}\n"));
                }
            }
            Ok(false) => {}
            Err(e) => {
                self.write_errors += 1;
                if self.write_errors.is_power_of_two() {
                    eprintln!("webfilter: log write error ({} so far): {e}", self.write_errors);
                }
                file.file = None; // retry opening on the next line
            }
        }
    }

    fn report_drops(&mut self) {
        let dropped = self.dropped.load(Ordering::Relaxed);
        if dropped > self.reported {
            eprintln!("webfilter: {} log events dropped (queue full)", dropped - self.reported);
            let line = system_line(
                SysEvent::LogDropped,
                json!({ "count": dropped - self.reported, "total": dropped }),
            );
            self.write(Target::System, &format!("{line}\n"));
            self.reported = dropped;
        }
    }

    fn run(&mut self, rx: &mpsc::Receiver<Msg>) {
        let mut last_report = Instant::now();
        loop {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(Msg::Line(target, line)) => self.write(target, &line),
                Ok(Msg::Reopen) => self.files.iter_mut().for_each(|f| f.file = None),
                Ok(Msg::Shutdown(ack)) => {
                    while let Ok(msg) = rx.try_recv() {
                        if let Msg::Line(target, line) = msg {
                            self.write(target, &line);
                        }
                    }
                    self.report_drops();
                    let _ = ack.send(());
                    return;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if last_report.elapsed() >= DROP_REPORT_INTERVAL {
                self.report_drops();
                last_report = Instant::now();
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Stats

/// Host count shown in `top_blocked`.
pub const TOP_BLOCKED: usize = 10;
/// Distinct blocked hosts tracked per window (bounded memory).
pub const MAX_TRACKED_HOSTS: usize = 10_000;

/// Live counters for the 60 s stats summary.
#[derive(Debug, Default)]
pub struct Stats {
    requests: AtomicU64,
    allowed: AtomicU64,
    blocked: AtomicU64,
    errors: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    h2_flood: AtomicU64,
    limits: Mutex<std::collections::BTreeMap<String, LimitCounts>>,
    /// Currently open client connections.
    pub active_connections: AtomicU64,
    top: Mutex<HashMap<String, u64>>,
}

/// Limit rejections of one profile in a stats window.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct LimitCounts {
    /// 429 `rate_limited` (rate, in-flight, tunnels).
    pub rate_limited: u64,
    /// 429 `quota_exceeded`.
    pub quota_exceeded: u64,
    /// 503 `too_many_connections`.
    pub too_many_connections: u64,
}

/// `top_blocked` entry.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostCount {
    /// Host.
    pub host: String,
    /// Blocks in the window.
    pub count: u64,
}

/// List sizes for the stats event.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct ListCounts {
    /// Domain entries.
    pub domains: usize,
    /// Regexes.
    pub regexes: usize,
    /// IP networks.
    pub ips: usize,
}

/// Stats line (LOG_SCHEMA "Stats event").
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct StatsEvent {
    pub timestamp: String,
    pub event_type: &'static str,
    pub window_secs: u64,
    pub requests: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub errors: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub active_connections: u64,
    pub dropped_log_events: u64,
    pub h2_flood: u64,
    pub limits: std::collections::BTreeMap<String, LimitCounts>,
    pub top_blocked: Vec<HostCount>,
    pub lists: ListCounts,
}

impl Stats {
    /// Count a finished request.
    pub fn record(&self, action: Action, host: &str, bytes_in: u64, bytes_out: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
        if action == Action::Allow {
            self.allowed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.blocked.fetch_add(1, Ordering::Relaxed);
        let host = clean(host, 253);
        let mut top = self.top.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = top.get_mut(&host) {
            *n += 1;
        } else if top.len() < MAX_TRACKED_HOSTS {
            top.insert(host, 1);
        }
    }

    /// Count an error response.
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a limit rejection for `profile` (SPEC_EXT_POLICY P2; profiles are bounded, <= 100).
    pub fn record_limit(&self, profile: &str, reason: crate::reason::Reason) {
        use crate::reason::Reason as R;
        let mut map = self.limits.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= 128 && !map.contains_key(profile) {
            return;
        }
        let c = map.entry(clean(profile, 32)).or_default();
        match reason {
            R::QuotaExceeded => c.quota_exceeded += 1,
            R::TooManyConnections => c.too_many_connections += 1,
            _ => c.rate_limited += 1,
        }
    }

    /// Count an HTTP/2 connection closed by the flood guard (D-45).
    pub fn record_h2_flood(&self) {
        self.h2_flood.fetch_add(1, Ordering::Relaxed);
    }

    /// Build the window summary and reset the window counters.
    pub fn take_window(&self, window_secs: u64, dropped: u64, lists: ListCounts) -> StatsEvent {
        let take = |a: &AtomicU64| a.swap(0, Ordering::Relaxed);
        let mut top: Vec<HostCount> =
            std::mem::take(&mut *self.top.lock().unwrap_or_else(|e| e.into_inner()))
                .into_iter()
                .map(|(host, count)| HostCount { host, count })
                .collect();
        top.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.host.cmp(&b.host)));
        top.truncate(TOP_BLOCKED);
        StatsEvent {
            timestamp: now_timestamp(),
            event_type: "stats",
            window_secs,
            requests: take(&self.requests),
            allowed: take(&self.allowed),
            blocked: take(&self.blocked),
            errors: take(&self.errors),
            bytes_in: take(&self.bytes_in),
            bytes_out: take(&self.bytes_out),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            dropped_log_events: dropped,
            h2_flood: take(&self.h2_flood),
            limits: std::mem::take(&mut *self.limits.lock().unwrap_or_else(|e| e.into_inner())),
            top_blocked: top,
            lists,
        }
    }
}
