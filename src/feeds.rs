//! Threat feeds (SPEC_EXT_POLICY P3, D-52): verified HTTPS fetch with destination policy and caps,
//! strict per-format parsing, poisoning guards, a versioned on-disk store with atomic promotion,
//! five kept versions, rollback and expiry. Matching joins filter rules 2 (domains/hosts), 3 (IPs)
//! and 4 (exact canonical URLs as 128-bit SHA-256 digests).
#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use ipnet::IpNet;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};

use crate::blocklist::{
    DomainForm, DomainSet, IpSet, parse_domain_entry, parse_domains, parse_ips,
};
use crate::config::{FeedConfig, FeedFormat};
use crate::filter::{Decision, Phase};
use crate::logger::{SysEvent, SystemLog};
use crate::normalize::{NormalizedTarget, TargetContext, canonicalize, fold_ip};
use crate::policy::{DestPolicy, Resolver, is_private};
use crate::reason::Reason;

/// Kept versions per feed.
pub const KEEP_VERSIONS: usize = 5;
/// Longest accepted line.
pub const MAX_LINE: usize = 4096;
/// Always protected (P3).
pub const ALWAYS_PROTECTED: [&str; 2] = ["localhost", "webfilter.local"];

/// Feed failures (never contain the API key).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    /// Download/transport problem (`feed_failed`).
    #[error("fetch failed: {0}")]
    Fetch(String),
    /// The new version was refused (`feed_rejected`).
    #[error("rejected: {0}")]
    Rejected(String),
    /// Store I/O.
    #[error("store: {0}")]
    Store(String),
    /// No such feed or version.
    #[error("{0}")]
    NotFound(String),
}

/// 128-bit truncated SHA-256 of a canonical URL (P3).
pub fn url_digest(canonical: &str) -> [u8; 16] {
    let full = Sha256::digest(canonical.as_bytes());
    let mut out = [0u8; 16];
    for (o, b) in out.iter_mut().zip(full.iter()) {
        *o = *b;
    }
    out
}

/// One accepted entry, in its stored normalized text form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Entry {
    /// Domain-list entry (apex+subdomains, `*.` subdomains, `=` exact).
    Domain(String),
    /// Exact host.
    Host(String),
    /// URL digest (hex).
    Url(String),
    /// IP network.
    Ip(String),
}

impl Entry {
    fn line(&self) -> String {
        match self {
            Self::Domain(d) => format!("d {d}"),
            Self::Host(h) => format!("h {h}"),
            Self::Url(u) => format!("u {u}"),
            Self::Ip(i) => format!("i {i}"),
        }
    }

    fn from_line(line: &str) -> Option<Self> {
        let (kind, value) = line.split_once(' ')?;
        let v = value.to_owned();
        Some(match kind {
            "d" => Self::Domain(v),
            "h" => Self::Host(v),
            "u" => Self::Url(v),
            "i" => Self::Ip(v),
            _ => return None,
        })
    }
}

/// Parse statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseReport {
    /// Non-empty, non-comment lines.
    pub lines: usize,
    /// Accepted entries.
    pub entries: usize,
    /// Skipped lines.
    pub invalid: usize,
}

fn protected(host: &str, protected: &[String]) -> bool {
    let host = host.trim_end_matches('.');
    ALWAYS_PROTECTED.iter().map(|s| (*s).to_owned()).chain(protected.iter().cloned()).any(|p| {
        let p = p.trim_end_matches('.').to_ascii_lowercase();
        host == p || host.ends_with(&format!(".{p}")) || p.ends_with(&format!(".{host}"))
    })
}

/// A domain-list entry acceptable from a feed (normalized, its form kept): valid, at least two
/// labels, not protected, not an IP.
fn feed_host(raw: &str, protect: &[String]) -> Option<String> {
    let (form, host) = parse_domain_entry(raw).ok()?;
    let ok = host.contains('.') && !protected(&host, protect) && host.parse::<IpAddr>().is_err();
    let prefix = match form {
        DomainForm::Apex => "",
        DomainForm::Subdomains => "*.",
        DomainForm::Exact => "=",
    };
    ok.then(|| format!("{prefix}{host}"))
}

fn csv_url(row: &str) -> Option<String> {
    // URLhaus CSV: "id","dateadded","url","url_status",...; quoted fields, no embedded quotes in URLs.
    let mut fields = Vec::new();
    let mut rest = row;
    while !rest.is_empty() {
        let field = rest.strip_prefix('"')?;
        let end = field.find('"')?;
        fields.push(field.get(..end)?);
        rest = field.get(end + 1..)?.trim_start_matches(',');
    }
    fields.get(2).map(|u| (*u).to_owned())
}

fn url_entry(raw: &str) -> Option<Entry> {
    let lower = raw.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return None;
    }
    let t = canonicalize(raw, TargetContext::PlainAbsolute).ok()?;
    let host = t.host.to_string();
    if host.contains('.') || t.host.ip().is_some() {
        Some(Entry::Url(hex::encode(url_digest(&t.url_norm))))
    } else {
        None
    }
}

fn ip_entry(raw: &str) -> Option<Entry> {
    let net: IpNet = raw.parse().or_else(|_| raw.parse::<IpAddr>().map(IpNet::from)).ok()?;
    let min_prefix = if net.addr().is_ipv4() { 8 } else { 16 };
    let ok =
        net.prefix_len() >= min_prefix && !is_private(net.addr()) && !is_private(net.broadcast());
    ok.then(|| Entry::Ip(net.trunc().to_string()))
}

/// Parse a feed body (P3 grammar and guards, `tests/corpus/feed_cases.md`). Duplicates collapse.
pub fn parse_feed(
    format: FeedFormat,
    text: &str,
    protect: &[String],
    max_entries: usize,
) -> Result<(Vec<Entry>, ParseReport), FeedError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut report = ParseReport::default();
    let mut out = HashSet::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        report.lines += 1;
        let entry = if line.len() > MAX_LINE || line.contains('\0') {
            None
        } else {
            match format {
                FeedFormat::DomainsText => feed_host(line, protect).map(Entry::Domain),
                FeedFormat::Hostfile => line
                    .split_ascii_whitespace()
                    .nth(1)
                    .filter(|h| !h.starts_with('*') && !h.starts_with('='))
                    .and_then(|h| feed_host(&format!("={h}"), protect))
                    .map(|h| Entry::Host(h.trim_start_matches('=').to_owned())),
                FeedFormat::UrlsText => url_entry(line),
                FeedFormat::CsvUrlhaus => csv_url(line).and_then(|u| url_entry(&u)),
                FeedFormat::IpsText => ip_entry(line),
            }
        };
        match entry {
            Some(e) => {
                out.insert(e);
            }
            None => report.invalid += 1,
        }
        if out.len() > max_entries {
            return Err(FeedError::Rejected(format!("more than {max_entries} entries")));
        }
    }
    if report.lines > 0 && report.invalid * 2 > report.lines {
        return Err(FeedError::Rejected(format!(
            "{} of {} lines invalid (more than 50 percent)",
            report.invalid, report.lines
        )));
    }
    let mut entries: Vec<Entry> = out.into_iter().collect();
    entries.sort();
    report.entries = entries.len();
    Ok((entries, report))
}

/// The sanity guard: a new version must stay within 50 %..200 % of the active one.
pub fn sanity(previous: Option<usize>, new: usize, force: bool) -> Result<(), FeedError> {
    match previous {
        Some(prev) if !force && prev > 0 && (new * 2 < prev || new > prev * 2) => {
            Err(FeedError::Rejected(format!(
                "entry count changed from {prev} to {new} (allowed 50-200 percent)"
            )))
        }
        _ => Ok(()),
    }
}

/// In-memory lookup structures of one feed version.
#[derive(Debug, Default)]
pub struct FeedSet {
    domains: DomainSet,
    hosts: HashSet<String>,
    urls: HashSet<[u8; 16]>,
    ips: IpSet,
    /// Entries in this version.
    pub entries: usize,
}

impl FeedSet {
    /// Build from parsed entries.
    pub fn build(entries: &[Entry]) -> Result<Self, FeedError> {
        let bad = |e: crate::blocklist::ListError| FeedError::Store(e.to_string());
        let mut domains = Vec::new();
        let mut ips = Vec::new();
        let mut set = Self { entries: entries.len(), ..Self::default() };
        for e in entries {
            match e {
                Entry::Domain(d) => domains.push(d.as_str()),
                Entry::Host(h) => {
                    set.hosts.insert(h.clone());
                }
                Entry::Url(u) => {
                    let mut d = [0u8; 16];
                    hex::decode_to_slice(u, &mut d).map_err(|e| FeedError::Store(e.to_string()))?;
                    set.urls.insert(d);
                }
                Entry::Ip(i) => ips.push(i.as_str()),
            }
        }
        set.domains = parse_domains(&domains.join("\n")).map_err(bad)?.list;
        set.ips = parse_ips(&ips.join("\n")).map_err(bad)?.list;
        Ok(set)
    }

    /// Match one target in one phase (rules 2, 3, 4).
    pub fn matches(&self, t: &NormalizedTarget, phase: Phase<'_>) -> Option<(Reason, String)> {
        match phase {
            Phase::PreDns | Phase::ConnectPreDns => {
                if let Some(d) = t.host.domain() {
                    let d = d.trim_end_matches('.');
                    if self.hosts.contains(d) {
                        return Some((Reason::FeedDomain, d.to_owned()));
                    }
                    if let Some(entry) = self.domains.matches(d) {
                        return Some((Reason::FeedDomain, entry.to_owned()));
                    }
                }
                let url = matches!(phase, Phase::PreDns).then(|| url_digest(&t.url_norm));
                if let Some(digest) = url.filter(|d| self.urls.contains(d)) {
                    return Some((Reason::FeedUrl, hex::encode(digest)));
                }
                None
            }
            Phase::Resolved { ip } => {
                self.ips.matches(fold_ip(ip)).map(|net| (Reason::FeedIp, net.to_string()))
            }
            Phase::ResponseHeaders { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Versioned store: feeds/<name>/v<unix>.list, feeds/<name>/active, feeds/<name>/meta

/// On-disk versions of one feed.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn store_err(e: std::io::Error) -> FeedError {
    FeedError::Store(e.to_string())
}

impl Store {
    /// The store of feed `name` under `root`.
    pub fn new(root: &Path, name: &str) -> Self {
        Self { dir: root.join(name) }
    }

    /// Version file names, newest first.
    pub fn versions(&self) -> Vec<String> {
        let mut v: Vec<(u64, String)> = std::fs::read_dir(&self.dir)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter_map(|e| {
                        let n = e.file_name().to_string_lossy().into_owned();
                        let ts = n.strip_prefix('v')?.strip_suffix(".list")?.parse().ok()?;
                        Some((ts, n))
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort_unstable_by(|a, b| b.cmp(a));
        v.into_iter().map(|(_, n)| n).collect()
    }

    /// The active version's file name.
    pub fn active(&self) -> Option<String> {
        let name = std::fs::read_to_string(self.dir.join("active")).ok()?;
        let name = name.trim();
        (name.starts_with('v') && name.ends_with(".list") && !name.contains('/'))
            .then(|| name.to_owned())
    }

    /// Load a version's entries.
    pub fn load(&self, version: &str) -> Result<Vec<Entry>, FeedError> {
        let text = std::fs::read_to_string(self.dir.join(version)).map_err(store_err)?;
        Ok(text.lines().filter_map(Entry::from_line).collect())
    }

    fn write_atomic(&self, name: &str, data: &[u8]) -> Result<(), FeedError> {
        let tmp = self.dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, data).map_err(store_err)?;
        std::fs::rename(&tmp, self.dir.join(name)).map_err(store_err)
    }

    /// Write `candidate`, promote it to a new version, point `active` at it, prune old versions.
    pub fn promote(&self, entries: &[Entry]) -> Result<String, FeedError> {
        std::fs::create_dir_all(&self.dir).map_err(store_err)?;
        let body: String = entries.iter().map(|e| e.line() + "\n").collect();
        self.write_atomic("candidate", body.as_bytes())?;
        // Always after the newest version, so a pruned name is never reused and order holds.
        let newest = self
            .versions()
            .first()
            .and_then(|v| v.strip_prefix('v')?.strip_suffix(".list")?.parse::<u64>().ok());
        let ts = newest.map_or(unix_now(), |n| unix_now().max(n + 1));
        let version = format!("v{ts}.list");
        std::fs::rename(self.dir.join("candidate"), self.dir.join(&version)).map_err(store_err)?;
        self.write_atomic("active", version.as_bytes())?;
        for old in self.versions().into_iter().skip(KEEP_VERSIONS) {
            let _ = std::fs::remove_file(self.dir.join(old));
        }
        Ok(version)
    }

    /// Point `active` at the version before the current one.
    pub fn rollback(&self) -> Result<String, FeedError> {
        let active =
            self.active().ok_or_else(|| FeedError::NotFound("no active version".into()))?;
        let versions = self.versions();
        let pos = versions.iter().position(|v| *v == active).unwrap_or(0);
        let prev = versions
            .get(pos + 1)
            .cloned()
            .ok_or_else(|| FeedError::NotFound("no older version to roll back to".into()))?;
        self.write_atomic("active", prev.as_bytes())?;
        Ok(prev)
    }

    /// Fetch metadata (ETag, Last-Modified, last success).
    pub fn meta(&self) -> HashMap<String, String> {
        std::fs::read_to_string(self.dir.join("meta"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
            .collect()
    }

    fn set_meta(&self, meta: &HashMap<String, String>) -> Result<(), FeedError> {
        std::fs::create_dir_all(&self.dir).map_err(store_err)?;
        let mut keys: Vec<_> = meta.iter().collect();
        keys.sort();
        let text: String = keys.into_iter().map(|(k, v)| format!("{k}={v}\n")).collect();
        self.write_atomic("meta", text.as_bytes())
    }
}

// ---------------------------------------------------------------------------------------------
// Fetch

/// Feed transport (P3 "Fetch").
pub struct Fetcher {
    /// Verified TLS (webpki + `upstream_ca_bundle`).
    pub tls: Arc<rustls::ClientConfig>,
    /// Resolve once.
    pub resolver: Arc<dyn Resolver>,
    /// Public destinations only; loopback only in `insecure-test` builds with
    /// `WEBFILTER_TEST_FEED_ALLOW_LOOPBACK=1`.
    pub policy: DestPolicy,
}

/// What a fetch returned.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Fetched {
    /// 304: the active version is current.
    NotModified,
    /// New body and validators.
    Body { text: String, etag: Option<String>, last_modified: Option<String> },
}

const UA: &str = concat!("webfilter-proxy/", env!("CARGO_PKG_VERSION"));

impl Fetcher {
    /// GET `url` with conditional headers; https only, <= 3 redirects (https only, key only on the
    /// original host), destination policy on every hop, `max_bytes` cap, 30 s connect / 120 s total.
    pub async fn fetch(
        &self,
        url: &str,
        api_key: Option<&str>,
        meta: &HashMap<String, String>,
        max_bytes: u64,
    ) -> Result<Fetched, FeedError> {
        let fail = |e: String| FeedError::Fetch(e);
        tokio::time::timeout(
            Duration::from_secs(120),
            self.fetch_inner(url, api_key, meta, max_bytes),
        )
        .await
        .map_err(|_| fail("timeout".into()))?
    }

    async fn fetch_inner(
        &self,
        url: &str,
        api_key: Option<&str>,
        meta: &HashMap<String, String>,
        max_bytes: u64,
    ) -> Result<Fetched, FeedError> {
        let fail = |e: &str| FeedError::Fetch(e.to_owned());
        let first = url::Url::parse(url).map_err(|_| fail("invalid URL"))?;
        // Credentials and validators go only to the configured origin (scheme + host + port),
        // never to the same hostname on another port or scheme (review L7).
        let first_origin = first.origin();
        let mut current = first;
        for _ in 0..=3 {
            if current.scheme() != "https" {
                return Err(fail("non-https URL or redirect"));
            }
            let host = current.host_str().ok_or_else(|| fail("no host"))?.to_ascii_lowercase();
            let port = current.port_or_known_default().unwrap_or(443);
            let ips = match host.parse::<IpAddr>() {
                Ok(ip) => vec![ip],
                Err(_) => self
                    .resolver
                    .resolve(&host, port)
                    .await
                    .map_err(|_| fail("resolution failed"))?,
            };
            let ip = *ips.first().ok_or_else(|| fail("no address"))?;
            for a in &ips {
                self.policy
                    .check_ip(*a, port)
                    .map_err(|_| fail("feed host is not a public address"))?;
            }
            let tcp = tokio::time::timeout(
                Duration::from_secs(30),
                tokio::net::TcpStream::connect((ip, port)),
            )
            .await
            .map_err(|_| fail("connect timeout"))?
            .map_err(|_| fail("connect failed"))?;
            let name = ServerName::try_from(host.clone()).map_err(|_| fail("bad server name"))?;
            let tls = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls))
                .connect(name, tcp)
                .await
                .map_err(|_| fail("TLS verification failed"))?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .map_err(|_| fail("HTTP handshake failed"))?;
            tokio::spawn(conn);
            let target = match current.query() {
                Some(q) => format!("{}?{q}", current.path()),
                None => current.path().to_owned(),
            };
            let mut req = http::Request::get(target)
                .header("host", current.host_str().unwrap_or(&host))
                .header("user-agent", UA)
                .header("accept-encoding", "identity")
                .header("connection", "close");
            if current.origin() == first_origin && first_origin.is_tuple() {
                if let Some(key) = api_key {
                    req = req.header("auth-key", key);
                }
                if let Some(e) = meta.get("etag") {
                    req = req.header("if-none-match", e.as_str());
                }
                if let Some(l) = meta.get("last_modified") {
                    req = req.header("if-modified-since", l.as_str());
                }
            }
            let req = req.body(Empty::<Bytes>::new()).map_err(|_| fail("bad request"))?;
            let resp = sender.send_request(req).await.map_err(|_| fail("request failed"))?;
            let status = resp.status().as_u16();
            let header =
                |n: &str| resp.headers().get(n).and_then(|v| v.to_str().ok()).map(str::to_owned);
            match status {
                304 => return Ok(Fetched::NotModified),
                301 | 302 | 303 | 307 | 308 => {
                    let loc =
                        header("location").ok_or_else(|| fail("redirect without location"))?;
                    current = current.join(&loc).map_err(|_| fail("bad redirect"))?;
                    continue;
                }
                200 => {}
                _ => return Err(FeedError::Fetch(format!("HTTP {status}"))),
            }
            if header("content-length")
                .and_then(|l| l.parse::<u64>().ok())
                .is_some_and(|l| l > max_bytes)
            {
                return Err(fail("feed larger than max_bytes"));
            }
            let (etag, last_modified) = (header("etag"), header("last-modified"));
            let mut body = resp.into_body();
            let mut data = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| fail("body read failed"))?;
                if let Some(chunk) = frame.data_ref() {
                    if (data.len() + chunk.len()) as u64 > max_bytes {
                        return Err(fail("feed larger than max_bytes"));
                    }
                    data.extend_from_slice(chunk);
                }
            }
            let text = String::from_utf8(data).map_err(|_| fail("feed is not UTF-8"))?;
            return Ok(Fetched::Body { text, etag, last_modified });
        }
        Err(fail("too many redirects"))
    }
}

// ---------------------------------------------------------------------------------------------
// Manager

/// Status of one feed (`feeds status`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct FeedStatus {
    /// Feed name.
    pub name: String,
    /// Enabled in config.
    pub enabled: bool,
    /// Active version.
    pub active: Option<String>,
    /// Entries in memory.
    pub entries: usize,
    /// Last successful update (unix seconds).
    pub last_success: Option<u64>,
    /// Kept versions.
    pub versions: usize,
}

/// Outcome of a successful update.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedUpdate {
    /// New version promoted.
    Updated { version: String, entries: usize, delta: i64 },
    /// 304.
    NotModified,
}

/// All feeds (INTERFACES `FeedManager`).
pub struct FeedManager {
    feeds: Vec<FeedConfig>,
    root: PathBuf,
    protect: Vec<String>,
    active: ArcSwap<HashMap<String, Arc<FeedSet>>>,
    fetcher: Option<Fetcher>,
    sys: Option<SystemLog>,
    updates: std::sync::Mutex<std::collections::BTreeMap<(String, &'static str), u64>>,
}

impl FeedManager {
    /// A manager over `feeds` stored under `root`; loads active, non-expired versions.
    pub fn new(
        feeds: Vec<FeedConfig>,
        root: PathBuf,
        protect: Vec<String>,
        fetcher: Option<Fetcher>,
        sys: Option<SystemLog>,
    ) -> Self {
        let me = Self {
            feeds,
            root,
            protect,
            active: ArcSwap::from_pointee(HashMap::new()),
            fetcher,
            sys,
            updates: std::sync::Mutex::default(),
        };
        let mut map = HashMap::new();
        for f in me.feeds.iter().filter(|f| f.enabled) {
            if me.expired(f) {
                continue;
            }
            let store = Store::new(&me.root, &f.name);
            if let Some(set) = store
                .active()
                .and_then(|v| store.load(&v).ok())
                .and_then(|e| FeedSet::build(&e).ok())
            {
                map.insert(f.name.clone(), Arc::new(set));
            }
        }
        me.active.store(Arc::new(map));
        me
    }

    fn count(&self, name: &str, result: &'static str) {
        let mut u = self.updates.lock().unwrap_or_else(|e| e.into_inner());
        *u.entry((name.to_owned(), result)).or_default() += 1;
    }

    /// Update attempts per (feed, result) for `/metrics`.
    pub fn update_counts(&self) -> Vec<((String, &'static str), u64)> {
        let u = self.updates.lock().unwrap_or_else(|e| e.into_inner());
        u.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }

    fn event(&self, kind: SysEvent, detail: serde_json::Value) {
        if let Some(s) = &self.sys {
            s.event(kind, detail);
        }
    }

    fn config(&self, name: &str) -> Result<&FeedConfig, FeedError> {
        self.feeds
            .iter()
            .find(|f| f.name == name)
            .ok_or_else(|| FeedError::NotFound(format!("unknown feed {name:?}")))
    }

    fn expired(&self, f: &FeedConfig) -> bool {
        let last = Store::new(&self.root, &f.name)
            .meta()
            .get("last_success")
            .and_then(|v| v.parse::<u64>().ok());
        last.is_some_and(|t| unix_now().saturating_sub(t) > f.expire_after_secs)
    }

    /// The active sets.
    pub fn active(&self) -> Arc<HashMap<String, Arc<FeedSet>>> {
        self.active.load_full()
    }

    fn swap(&self, name: &str, set: Option<FeedSet>) {
        let mut map = (*self.active.load_full()).clone();
        match set {
            Some(s) => map.insert(name.to_owned(), Arc::new(s)),
            None => map.remove(name),
        };
        self.active.store(Arc::new(map));
    }

    /// Apply a fetched body: parse, guard, promote, swap (P3 "Apply").
    pub fn apply(&self, name: &str, text: &str, force: bool) -> Result<FeedUpdate, FeedError> {
        let f = self.config(name)?;
        let result = (|| {
            let (entries, _) = parse_feed(f.format, text, &self.protect, f.max_entries)?;
            let previous = self.active().get(name).map(|s| s.entries);
            sanity(previous, entries.len(), force)?;
            let set = FeedSet::build(&entries)?;
            let version = Store::new(&self.root, name).promote(&entries)?;
            let delta = entries.len() as i64 - previous.unwrap_or(0) as i64;
            self.swap(name, Some(set));
            Ok(FeedUpdate::Updated { version, entries: entries.len(), delta })
        })();
        match &result {
            Ok(FeedUpdate::Updated { entries, delta, .. }) => {
                self.count(name, "updated");
                self.event(
                    SysEvent::FeedUpdated,
                    serde_json::json!({ "name": name, "entries": entries, "delta": delta }),
                );
            }
            Ok(FeedUpdate::NotModified) => {}
            Err(e @ FeedError::Rejected(_)) => {
                self.count(name, "rejected");
                self.event(
                    SysEvent::FeedRejected,
                    serde_json::json!({ "name": name, "error": e.to_string() }),
                );
            }
            Err(e) => {
                self.count(name, "failed");
                self.event(
                    SysEvent::FeedFailed,
                    serde_json::json!({ "name": name, "error": e.to_string() }),
                );
            }
        }
        result
    }

    /// Fetch and apply one feed.
    pub async fn update(&self, name: &str, force: bool) -> Result<FeedUpdate, FeedError> {
        let f = self.config(name)?.clone();
        let fetcher = self.fetcher.as_ref().ok_or_else(|| FeedError::Fetch("no fetcher".into()))?;
        let store = Store::new(&self.root, name);
        let mut meta = store.meta();
        let key = if f.auth_header_file.as_os_str().is_empty() {
            None
        } else {
            let k = std::fs::read_to_string(&f.auth_header_file)
                .map_err(|_| FeedError::Fetch("cannot read the API key file".into()))?;
            Some(k.lines().next().unwrap_or("").trim().to_owned())
        };
        let fetched = match fetcher.fetch(&f.url, key.as_deref(), &meta, f.max_bytes).await {
            Ok(x) => x,
            Err(e) => {
                self.count(name, "failed");
                self.event(
                    SysEvent::FeedFailed,
                    serde_json::json!({ "name": name, "error": e.to_string() }),
                );
                return Err(e);
            }
        };
        let result = match fetched {
            Fetched::NotModified => Ok(FeedUpdate::NotModified),
            Fetched::Body { text, etag, last_modified } => {
                let r = self.apply(name, &text, force);
                if r.is_ok() {
                    meta.remove("etag");
                    meta.remove("last_modified");
                    if let Some(e) = etag {
                        meta.insert("etag".into(), e);
                    }
                    if let Some(l) = last_modified {
                        meta.insert("last_modified".into(), l);
                    }
                }
                r
            }
        };
        if result.is_ok() {
            meta.insert("last_success".into(), unix_now().to_string());
            store.set_meta(&meta)?;
        }
        result
    }

    /// Restore the previous version.
    pub fn rollback(&self, name: &str) -> Result<String, FeedError> {
        self.config(name)?;
        let store = Store::new(&self.root, name);
        let version = store.rollback()?;
        self.swap(name, Some(FeedSet::build(&store.load(&version)?)?));
        self.event(SysEvent::FeedUpdated, serde_json::json!({ "name": name, "rollback": version }));
        Ok(version)
    }

    /// Stale/expiry check (run periodically): `feed_stale` after 3x refresh, deactivation after expiry.
    pub fn check_age(&self) {
        for f in self.feeds.iter().filter(|f| f.enabled) {
            let last = Store::new(&self.root, &f.name)
                .meta()
                .get("last_success")
                .and_then(|v| v.parse::<u64>().ok());
            let age = last.map(|t| unix_now().saturating_sub(t));
            if age.is_some_and(|a| a > f.expire_after_secs) && self.active().contains_key(&f.name) {
                self.swap(&f.name, None);
                self.event(
                    SysEvent::FeedStale,
                    serde_json::json!({ "name": f.name, "deactivated": true }),
                );
            } else if age.is_some_and(|a| a > f.refresh_secs.saturating_mul(3)) {
                self.event(
                    SysEvent::FeedStale,
                    serde_json::json!({ "name": f.name, "age_secs": age }),
                );
            }
        }
    }

    /// Status of every configured feed.
    pub fn status(&self) -> Vec<FeedStatus> {
        let active = self.active();
        self.feeds
            .iter()
            .map(|f| {
                let store = Store::new(&self.root, &f.name);
                FeedStatus {
                    name: f.name.clone(),
                    enabled: f.enabled,
                    active: store.active(),
                    entries: active.get(&f.name).map_or(0, |s| s.entries),
                    last_success: store.meta().get("last_success").and_then(|v| v.parse().ok()),
                    versions: store.versions().len(),
                }
            })
            .collect()
    }

    /// First feed hit among `names` (a profile's feeds) for this phase.
    pub fn check(
        &self,
        t: &NormalizedTarget,
        phase: Phase<'_>,
        names: &[String],
        mode: crate::config::Mode,
    ) -> Option<Decision> {
        let active = self.active();
        names.iter().find_map(|n| {
            let (reason, entry) = active.get(n)?.matches(t, phase)?;
            Some(Decision::block(mode, reason, format!("feed:{n}:{entry}"), n))
        })
    }

    /// Background refresh: jitter +/-10 %, exponential backoff up to 6 h, age checks.
    pub fn spawn(self: &Arc<Self>) -> Vec<tokio::task::JoinHandle<()>> {
        let mut tasks = Vec::new();
        for f in self.feeds.iter().filter(|f| f.enabled).cloned() {
            let me = Arc::clone(self);
            tasks.push(tokio::spawn(async move {
                let mut backoff = Duration::from_secs(60);
                loop {
                    let ok = me.update(&f.name, false).await.is_ok();
                    let base = if ok {
                        backoff = Duration::from_secs(60);
                        Duration::from_secs(f.refresh_secs)
                    } else {
                        backoff = (backoff * 2).min(Duration::from_secs(6 * 3600));
                        backoff
                    };
                    let mut r = [0u8; 2];
                    let _ = getrandom::fill(&mut r);
                    let jitter = f64::from(u16::from_be_bytes(r)) / f64::from(u16::MAX) * 0.2 - 0.1;
                    tokio::time::sleep(base.mul_f64(1.0 + jitter)).await;
                    me.check_age();
                }
            }));
        }
        tasks
    }
}
