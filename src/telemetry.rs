//! In-memory views for the admin API and `/metrics` (SPEC_EXT_OPS O2/O3, D-56): a ring of the last
//! 1,000 request events (already redacted like the logs), space-saving heavy hitters for blocked
//! hosts (50,000 keys), active clients, and cumulative counters with bounded label sets only.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Write as _;
use std::sync::Mutex;

use crate::logger::RequestEvent;

/// Events kept for `events/recent`.
pub const RING: usize = 1000;
/// Heavy-hitter capacity.
pub const TOP_KEYS: usize = 50_000;
/// Tracked clients.
pub const CLIENT_KEYS: usize = 10_000;
/// Request-duration histogram bounds (seconds).
pub const BUCKETS: [f64; 10] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0];

/// Space-saving heavy hitters (Metwally et al.): at most `cap` keys; a new key replaces the
/// smallest counter and inherits its count as error bound.
#[derive(Debug, Default)]
pub struct SpaceSaving {
    cap: usize,
    counts: HashMap<String, u64>,
}

impl SpaceSaving {
    /// Empty, with capacity `cap`.
    pub fn new(cap: usize) -> Self {
        Self { cap: cap.max(1), counts: HashMap::new() }
    }

    /// Count one occurrence.
    pub fn add(&mut self, key: &str) {
        if let Some(c) = self.counts.get_mut(key) {
            *c += 1;
            return;
        }
        if self.counts.len() < self.cap {
            self.counts.insert(key.to_owned(), 1);
            return;
        }
        if let Some((min_key, min)) =
            self.counts.iter().min_by_key(|(_, c)| **c).map(|(k, c)| (k.clone(), *c))
        {
            self.counts.remove(&min_key);
            self.counts.insert(key.to_owned(), min + 1);
        }
    }

    /// The `n` largest counters.
    pub fn top(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self.counts.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
}

/// Cumulative counters behind `/metrics`; every label set is bounded (D-56).
#[derive(Debug, Default)]
pub struct Counters {
    /// (action, reason, scheme) -> count.
    pub requests: BTreeMap<(String, String, String), u64>,
    /// scheme -> (bucket counts, sum seconds, count).
    pub duration: BTreeMap<String, ([u64; BUCKETS.len()], f64, u64)>,
    /// direction -> bytes.
    pub bytes: BTreeMap<&'static str, u64>,
    /// (profile, kind) -> rejections.
    pub limited: BTreeMap<(String, String), u64>,
    /// profile -> seconds of throttled requests.
    pub throttled_secs: BTreeMap<String, f64>,
    /// (status, engine) -> scans.
    pub scans: BTreeMap<(String, String), u64>,
    /// violation -> GOAWAYs.
    pub h2_flood: BTreeMap<String, u64>,
}

/// Admin-facing telemetry.
#[derive(Debug)]
pub struct Telemetry {
    ring: Mutex<VecDeque<RequestEvent>>,
    blocked: Mutex<SpaceSaving>,
    clients: Mutex<HashMap<String, (u64, u64, String)>>,
    /// Counters.
    pub counters: Mutex<Counters>,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self {
            ring: Mutex::new(VecDeque::with_capacity(RING)),
            blocked: Mutex::new(SpaceSaving::new(TOP_KEYS)),
            clients: Mutex::new(HashMap::new()),
            counters: Mutex::new(Counters::default()),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Telemetry {
    /// Record a finished request (the same redacted event that is logged).
    pub fn record(&self, ev: &RequestEvent) {
        let blocked = ev.action == "blocked";
        {
            let mut c = lock(&self.counters);
            let scheme = if ev.url_scheme.is_empty() { "http" } else { ev.url_scheme.as_str() };
            *c.requests.entry((ev.action.into(), ev.reason.into(), scheme.into())).or_default() +=
                1;
            let secs = ev.duration_ms as f64 / 1000.0;
            let d = c.duration.entry(scheme.into()).or_insert(([0; BUCKETS.len()], 0.0, 0));
            for (i, bound) in BUCKETS.iter().enumerate() {
                if secs <= *bound
                    && let Some(b) = d.0.get_mut(i)
                {
                    *b += 1;
                }
            }
            d.1 += secs;
            d.2 += 1;
            *c.bytes.entry("in").or_default() += ev.bytes_in;
            *c.bytes.entry("out").or_default() += ev.bytes_out;
            let profile = ev.profile.clone().unwrap_or_else(|| "default".into());
            if matches!(ev.reason, "rate_limited" | "quota_exceeded" | "too_many_connections") {
                *c.limited.entry((profile.clone(), ev.reason.into())).or_default() += 1;
            }
            if ev.throttled {
                *c.throttled_secs.entry(profile).or_default() += secs;
            }
            if let Some(status) = &ev.scan_status {
                let engine = ev.scan_engine.clone().unwrap_or_else(|| "none".into());
                *c.scans.entry((status.clone(), engine)).or_default() += 1;
            }
        }
        if blocked && !ev.dest_host.is_empty() {
            lock(&self.blocked).add(&ev.dest_host);
        }
        if let Some(id) = &ev.client_id {
            let mut clients = lock(&self.clients);
            if clients.len() >= CLIENT_KEYS
                && !clients.contains_key(id)
                && let Some(k) = clients.iter().min_by_key(|(_, v)| v.0).map(|(k, _)| k.clone())
            {
                clients.remove(&k);
            }
            let e = clients.entry(id.clone()).or_insert((0, 0, String::new()));
            e.0 += 1;
            e.1 += u64::from(blocked);
            e.2.clone_from(&ev.timestamp);
        }
        let mut ring = lock(&self.ring);
        if ring.len() >= RING {
            ring.pop_front();
        }
        ring.push_back(ev.clone());
    }

    /// Count an h2 flood close by violation type.
    pub fn h2_flood(&self, kind: &str) {
        *lock(&self.counters).h2_flood.entry(kind.into()).or_default() += 1;
    }

    /// Newest-first recent events, optionally filtered by action and reason.
    pub fn recent(
        &self,
        limit: usize,
        action: Option<&str>,
        reason: Option<&str>,
    ) -> Vec<RequestEvent> {
        lock(&self.ring)
            .iter()
            .rev()
            .filter(|e| {
                action.is_none_or(|a| e.action == a) && reason.is_none_or(|r| e.reason == r)
            })
            .take(limit.min(500))
            .cloned()
            .collect()
    }

    /// Top blocked hosts.
    pub fn top_blocked(&self, n: usize) -> Vec<(String, u64)> {
        lock(&self.blocked).top(n.min(100))
    }

    /// Top 50 clients by requests: (client_id, requests, blocked, last seen).
    pub fn clients(&self) -> Vec<(String, u64, u64, String)> {
        let mut v: Vec<_> = lock(&self.clients)
            .iter()
            .map(|(k, (r, b, t))| (k.clone(), *r, *b, t.clone()))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(50);
        v
    }
}

/// Escape a label value for the text exposition format.
pub fn label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Append one `# HELP`/`# TYPE` header.
pub fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

/// Render the counters (the caller adds gauges that live elsewhere).
pub fn render_counters(c: &Counters, out: &mut String) {
    header(out, "webfilter_requests_total", "counter", "Requests by action, reason and scheme.");
    for ((a, r, s), n) in &c.requests {
        let _ = writeln!(
            out,
            "webfilter_requests_total{{action=\"{}\",reason=\"{}\",scheme=\"{}\"}} {n}",
            label(a),
            label(r),
            label(s)
        );
    }
    header(out, "webfilter_request_duration_seconds", "histogram", "Request duration.");
    for (scheme, (buckets, sum, count)) in &c.duration {
        let s = label(scheme);
        for (bound, n) in BUCKETS.iter().zip(buckets) {
            let _ = writeln!(
                out,
                "webfilter_request_duration_seconds_bucket{{scheme=\"{s}\",le=\"{bound}\"}} {n}"
            );
        }
        let _ = writeln!(
            out,
            "webfilter_request_duration_seconds_bucket{{scheme=\"{s}\",le=\"+Inf\"}} {count}"
        );
        let _ = writeln!(out, "webfilter_request_duration_seconds_sum{{scheme=\"{s}\"}} {sum}");
        let _ = writeln!(out, "webfilter_request_duration_seconds_count{{scheme=\"{s}\"}} {count}");
    }
    header(out, "webfilter_bytes_total", "counter", "Body bytes by direction.");
    for (d, n) in &c.bytes {
        let _ = writeln!(out, "webfilter_bytes_total{{direction=\"{d}\"}} {n}");
    }
    header(out, "webfilter_rate_limited_total", "counter", "Limit rejections by profile and kind.");
    for ((p, k), n) in &c.limited {
        let _ = writeln!(
            out,
            "webfilter_rate_limited_total{{profile=\"{}\",kind=\"{}\"}} {n}",
            label(p),
            label(k)
        );
    }
    header(
        out,
        "webfilter_throttled_seconds_total",
        "counter",
        "Duration of bandwidth-throttled requests.",
    );
    for (p, s) in &c.throttled_secs {
        let _ = writeln!(out, "webfilter_throttled_seconds_total{{profile=\"{}\"}} {s}", label(p));
    }
    header(out, "webfilter_scans_total", "counter", "Download scans by status and engine.");
    for ((s, e), n) in &c.scans {
        let _ = writeln!(
            out,
            "webfilter_scans_total{{status=\"{}\",engine=\"{}\"}} {n}",
            label(s),
            label(e)
        );
    }
    header(
        out,
        "webfilter_h2_flood_total",
        "counter",
        "HTTP/2 connections closed by the flood guard.",
    );
    for (t, n) in &c.h2_flood {
        let _ = writeln!(out, "webfilter_h2_flood_total{{type=\"{}\"}} {n}", label(t));
    }
}
