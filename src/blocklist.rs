//! Blocklists (SPEC 4.6): file grammar, limits, lock-free snapshots and hot reload (D-15, D-16).
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use ipnet::IpNet;
use regex::RegexBuilder;
use regex_automata::meta::Regex as MultiRegex;
use regex_automata::util::syntax;

use crate::config::BlocklistConfig;
use crate::logger::{SysEvent, SystemLog};
use crate::normalize::fold_ip;

/// Maximum list file size.
pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
/// Maximum entries per list.
pub const MAX_ENTRIES: usize = 1_000_000;
/// Maximum regex pattern length in characters.
pub const MAX_PATTERN_CHARS: usize = 1024;
/// Compiled size limit per regex (D-15).
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// Compiled size limit for the whole pattern set.
pub const REGEX_SET_SIZE_LIMIT: usize = 512 << 20;
/// Lazy-DFA cache for the pattern set.
pub const REGEX_CACHE_BYTES: usize = 32 << 20;
const MAX_WARNINGS: usize = 20;

/// A list file that cannot be used; the previous list is kept.
#[derive(Debug, thiserror::Error)]
pub enum ListError {
    /// Read failure.
    #[error("{path}: {source}")]
    Io {
        /// File.
        path: PathBuf,
        /// Cause.
        #[source]
        source: std::io::Error,
    },
    /// File larger than [`MAX_FILE_BYTES`].
    #[error("{0}: larger than {MAX_FILE_BYTES} bytes")]
    TooLarge(PathBuf),
    /// Not UTF-8.
    #[error("{0}: not valid UTF-8")]
    NotUtf8(PathBuf),
    /// More than [`MAX_ENTRIES`] entries.
    #[error("more than {MAX_ENTRIES} entries")]
    TooManyEntries,
    /// More than half of the lines are invalid.
    #[error("{invalid} of {total} lines invalid (more than 50%)")]
    TooManyInvalid {
        /// Invalid lines.
        invalid: usize,
        /// Non-blank, non-comment lines.
        total: usize,
    },
    /// A category schedule or the UTC offset is invalid.
    #[error("schedule: {0}")]
    Schedule(String),
    /// The combined regex set failed to compile.
    #[error("regex set: {0}")]
    RegexSet(String),
}

/// Result of parsing one list file.
#[derive(Debug)]
pub struct Parsed<T> {
    /// The parsed list.
    pub list: T,
    /// Unique entries.
    pub entries: usize,
    /// Duplicate entries dropped.
    pub duplicates: usize,
    /// Invalid lines skipped.
    pub invalid: usize,
    /// First invalid lines, with line numbers.
    pub warnings: Vec<String>,
}

impl<T> Parsed<T> {
    fn map<U>(self, f: impl FnOnce(T) -> U) -> Parsed<U> {
        let Parsed { list, entries, duplicates, invalid, warnings } = self;
        Parsed { list: f(list), entries, duplicates, invalid, warnings }
    }
}

/// `#` starts a comment at line start or when preceded by whitespace.
fn strip_comment(line: &str) -> &str {
    let mut prev_ws = true;
    for (i, c) in line.char_indices() {
        if c == '#' && prev_ws {
            return line.get(..i).unwrap_or("");
        }
        prev_ws = c.is_whitespace();
    }
    line
}

/// Shared loop: BOM/CR/comments, limits, dedup, first warnings and the 50%-invalid rule.
/// `parse` receives the 1-based line number and the trimmed line.
fn parse_lines<K: Eq + Hash + Clone>(
    text: &str,
    inline_comments: bool,
    parse: impl Fn(usize, &str) -> Result<K, String>,
) -> Result<Parsed<Vec<K>>, ListError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let (mut seen, mut list, mut warnings) = (HashSet::new(), Vec::new(), Vec::new());
    let (mut total, mut invalid, mut duplicates) = (0usize, 0usize, 0usize);
    for (i, line) in text.lines().enumerate() {
        let line = if inline_comments { strip_comment(line) } else { line }.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        total += 1;
        match parse(i + 1, line) {
            Ok(k) if !seen.insert(k.clone()) => duplicates += 1,
            Ok(_) if list.len() >= MAX_ENTRIES => return Err(ListError::TooManyEntries),
            Ok(k) => list.push(k),
            Err(e) => {
                invalid += 1;
                if warnings.len() < MAX_WARNINGS {
                    warnings.push(format!("line {}: {e}", i + 1));
                }
            }
        }
    }
    if invalid * 2 > total {
        return Err(ListError::TooManyInvalid { invalid, total });
    }
    Ok(Parsed { entries: list.len(), list, duplicates, invalid, warnings })
}

// ---------------------------------------------------------------------------------------------
// Domains

/// Entry form in `domains.txt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainForm {
    /// `evil.com`: apex and all subdomains.
    Apex,
    /// `*.evil.com`: subdomains only.
    Subdomains,
    /// `=evil.com`: exact name only.
    Exact,
}

/// Parse one `domains.txt` entry into `(form, ascii_domain)`.
pub fn parse_domain_entry(entry: &str) -> Result<(DomainForm, String), String> {
    let (form, name) = if let Some(n) = entry.strip_prefix("*.") {
        (DomainForm::Subdomains, n)
    } else if let Some(n) = entry.strip_prefix('=') {
        (DomainForm::Exact, n)
    } else {
        (DomainForm::Apex, entry)
    };
    let invalid = || format!("invalid domain {name:?}");
    let name = name.strip_suffix('.').unwrap_or(name); // one trailing dot allowed
    let ascii = idna::domain_to_ascii_strict(name).map_err(|_| invalid())?;
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if ascii.len() > 253 || !ascii.split('.').all(label_ok) {
        return Err(invalid());
    }
    if !ascii.contains('.') && ascii != "localhost" {
        return Err(format!("single-label entry {name:?} not allowed"));
    }
    Ok((form, ascii))
}

/// Domain rules indexed by name; matching walks label suffixes.
#[derive(Debug, Default)]
pub struct DomainSet {
    map: HashMap<String, HashSet<DomainForm>>,
    len: usize,
}

impl DomainSet {
    /// Build from parsed entries.
    pub fn from_entries(entries: impl IntoIterator<Item = (DomainForm, String)>) -> Self {
        let mut set = Self::default();
        for (form, name) in entries {
            if set.map.entry(name).or_default().insert(form) {
                set.len += 1;
            }
        }
        set
    }

    fn has(&self, name: &str, form: DomainForm) -> bool {
        self.map.get(name).is_some_and(|forms| forms.contains(&form))
    }

    /// The matching entry as written (`evil.com`, `*.evil.com`, `=evil.com`), if any.
    /// `notevil.com` never matches `evil.com`.
    pub fn matches(&self, host: &str) -> Option<String> {
        if self.has(host, DomainForm::Apex) {
            return Some(host.to_owned());
        }
        if self.has(host, DomainForm::Exact) {
            return Some(format!("={host}"));
        }
        let mut rest = host;
        while let Some((_, parent)) = rest.split_once('.') {
            if self.has(parent, DomainForm::Apex) {
                return Some(parent.to_owned());
            }
            if self.has(parent, DomainForm::Subdomains) {
                return Some(format!("*.{parent}"));
            }
            rest = parent;
        }
        None
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// No entries.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Parse `domains.txt`.
pub fn parse_domains(text: &str) -> Result<Parsed<DomainSet>, ListError> {
    Ok(parse_lines(text, true, |_, l| parse_domain_entry(l))?.map(DomainSet::from_entries))
}

// ---------------------------------------------------------------------------------------------
// URL patterns

/// Compiled URL patterns with their ids (case-insensitive, linear-time engine, D-15).
///
/// One multi-pattern regex searched leftmost-first: unlike an overlapping "which patterns
/// match" search, its cost does not explode with thousands of patterns (PF-1-01).
#[derive(Debug)]
pub struct PatternSet {
    re: MultiRegex,
    ids: Vec<String>,
}

impl PatternSet {
    fn build(patterns: Vec<String>, ids: Vec<String>) -> Result<Self, ListError> {
        let re = MultiRegex::builder()
            .configure(
                MultiRegex::config()
                    .nfa_size_limit(Some(REGEX_SET_SIZE_LIMIT))
                    .hybrid_cache_capacity(REGEX_CACHE_BYTES),
            )
            .syntax(syntax::Config::new().case_insensitive(true))
            .build_many(&patterns)
            .map_err(|e| ListError::RegexSet(e.to_string()))?;
        Ok(Self { re, ids })
    }

    /// Id of the pattern matching the first view that matches (leftmost match; on a tie the
    /// lower pattern number wins).
    pub fn matches(&self, views: &[String]) -> Option<&str> {
        let m = views.iter().find_map(|v| self.re.find(v.as_str()))?;
        self.ids.get(m.pattern().as_usize()).map(String::as_str)
    }

    /// Number of patterns.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// No patterns.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

/// One `url_patterns.txt` line: optional `[id=...] ` prefix, then a regex. Without an id the
/// pattern is named `line-<n>` (A-20). Returns `(pattern, id)`.
pub fn parse_pattern_line(line_no: usize, line: &str) -> Result<(String, String), String> {
    let (id, pattern) = match line.strip_prefix("[id=") {
        Some(rest) => {
            let (id, pat) = rest.split_once("] ").ok_or("malformed [id=...] prefix")?;
            let id_ok = (1..=64).contains(&id.len())
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
            if !id_ok {
                return Err(format!("invalid id {id:?}"));
            }
            (id.to_owned(), pat.trim())
        }
        None => (format!("line-{line_no}"), line),
    };
    if pattern.chars().count() > MAX_PATTERN_CHARS {
        return Err(format!("pattern longer than {MAX_PATTERN_CHARS} chars"));
    }
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| format!("invalid regex: {}", e.to_string().lines().last().unwrap_or("")))?;
    Ok((pattern.to_owned(), id))
}

/// Parse `url_patterns.txt` (only lines starting with `#` are comments: `#` is valid in regexes).
pub fn parse_patterns(text: &str) -> Result<Parsed<PatternSet>, ListError> {
    let parsed = parse_lines(text, false, parse_pattern_line)?;
    let mut seen = HashSet::new(); // same pattern under different ids: keep the first id
    let (patterns, ids): (Vec<String>, Vec<String>) =
        parsed.list.iter().filter(|(p, _)| seen.insert(p.clone())).cloned().unzip();
    let set = PatternSet::build(patterns, ids)?;
    let dupes = parsed.list.len() - set.len();
    let mut out = parsed.map(|_| set);
    out.duplicates += dupes;
    out.entries -= dupes;
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// IP list

/// IP networks grouped by prefix length; lookup is one hash probe per present length.
#[derive(Debug, Default)]
pub struct IpSet {
    by_len: BTreeMap<(bool, u8), HashSet<IpNet>>, // (is_v6, prefix_len)
    len: usize,
}

/// Parse one `ip_blocklist.txt` entry (address or CIDR; host bits are cleared, mapped IPv6 folded).
pub fn parse_ip_entry(entry: &str) -> Result<IpNet, String> {
    let net = match entry.parse::<IpNet>() {
        // Mapped IPv6 networks (`::ffff:a.b.c.d/104`) fold to IPv4, like lookups (PF-1-08).
        Ok(IpNet::V6(v6)) => match (v6.prefix_len().checked_sub(96), v6.addr().to_ipv4_mapped()) {
            (Some(len), Some(v4)) => IpNet::new(IpAddr::V4(v4), len).map_err(|e| e.to_string())?,
            _ => IpNet::V6(v6),
        },
        Ok(net) => net,
        Err(_) => {
            let ip: IpAddr = entry.parse().map_err(|_| format!("invalid IP or CIDR {entry:?}"))?;
            IpNet::from(fold_ip(ip))
        }
    };
    Ok(net.trunc())
}

impl IpSet {
    /// Build from networks.
    pub fn from_nets(nets: impl IntoIterator<Item = IpNet>) -> Self {
        let mut set = Self::default();
        for net in nets {
            let key = (matches!(net, IpNet::V6(_)), net.prefix_len());
            if set.by_len.entry(key).or_default().insert(net) {
                set.len += 1;
            }
        }
        set
    }

    /// The most specific network containing `ip` (IPv4-mapped IPv6 folded first).
    pub fn matches(&self, ip: IpAddr) -> Option<IpNet> {
        let ip = fold_ip(ip);
        let v6 = ip.is_ipv6();
        self.by_len.iter().rev().filter(|((is_v6, _), _)| *is_v6 == v6).find_map(
            |((_, len), set)| {
                let net = IpNet::new(ip, *len).ok()?.trunc();
                set.contains(&net).then_some(net)
            },
        )
    }

    /// Number of networks.
    pub fn len(&self) -> usize {
        self.len
    }

    /// No networks.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Parse `ip_blocklist.txt`.
pub fn parse_ips(text: &str) -> Result<Parsed<IpSet>, ListError> {
    Ok(parse_lines(text, true, |_, l| parse_ip_entry(l))?.map(IpSet::from_nets))
}

// ---------------------------------------------------------------------------------------------
// Loaded lists and hot reload

/// One list triple plus the file names used as `rule_list` in logs.
#[derive(Debug)]
pub struct ListSet {
    /// Domain entries.
    pub domains: DomainSet,
    /// URL patterns.
    pub patterns: PatternSet,
    /// IP networks.
    pub ips: IpSet,
    /// File names: domains, url patterns, ip list.
    pub files: [String; 3],
}

/// A named category (A-27).
#[derive(Debug)]
pub struct Category {
    /// Name (block page, logs).
    pub name: String,
    /// Switched on in config.
    pub enabled: bool,
    /// When it blocks.
    pub schedule: crate::schedule::Schedule,
    /// Its lists.
    pub lists: ListSet,
}

/// The default lists and the categories, immutable once built.
#[derive(Debug)]
pub struct Blocklists {
    /// `domains.txt`.
    pub domains: DomainSet,
    /// `url_patterns.txt`.
    pub patterns: PatternSet,
    /// `ip_blocklist.txt`.
    pub ips: IpSet,
    /// Named categories, in config order.
    pub categories: Vec<Category>,
}

/// Counts and warnings from a load.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadReport {
    /// Domain entries.
    pub domains: usize,
    /// Regexes.
    pub regexes: usize,
    /// IP networks.
    pub ips: usize,
    /// Invalid lines (first per file), prefixed with the file name.
    pub warnings: Vec<String>,
    /// Duplicates dropped across all files.
    pub duplicates: usize,
}

fn read_list(path: &Path) -> Result<String, ListError> {
    let io = |source| ListError::Io { path: path.to_path_buf(), source };
    if std::fs::metadata(path).map_err(io)?.len() > MAX_FILE_BYTES {
        return Err(ListError::TooLarge(path.to_path_buf()));
    }
    let bytes = std::fs::read(path).map_err(io)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(ListError::TooLarge(path.to_path_buf())); // grew between stat and read
    }
    String::from_utf8(bytes).map_err(|_| ListError::NotUtf8(path.to_path_buf()))
}

impl Blocklists {
    /// Read and parse all three files; any unusable file fails the whole load.
    pub fn load(cfg: &BlocklistConfig) -> Result<(Self, LoadReport), ListError> {
        let mut report = LoadReport::default();
        let main = load_set([&cfg.domains, &cfg.url_patterns, &cfg.ip_blocklist], &mut report)?;
        let offset = crate::schedule::parse_offset(&cfg.utc_offset).map_err(ListError::Schedule)?;
        let categories = cfg
            .categories
            .iter()
            .map(|c| {
                Ok(Category {
                    name: c.name.clone(),
                    enabled: c.enabled,
                    schedule: crate::schedule::Schedule::parse(&c.active, offset)
                        .map_err(ListError::Schedule)?,
                    lists: load_set(c.files(), &mut report)?,
                })
            })
            .collect::<Result<Vec<_>, ListError>>()?;
        Ok((
            Self { domains: main.domains, patterns: main.patterns, ips: main.ips, categories },
            report,
        ))
    }
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Load one triple of list files (an empty path = an empty list) and add to `report`.
fn load_set(files: [&PathBuf; 3], report: &mut LoadReport) -> Result<ListSet, ListError> {
    let read =
        |p: &PathBuf| if p.as_os_str().is_empty() { Ok(String::new()) } else { read_list(p) };
    let [d, u, i] = files;
    let domains = parse_domains(&read(d)?)?;
    let patterns = parse_patterns(&read(u)?)?;
    let ips = parse_ips(&read(i)?)?;
    for (file, w) in [(d, &domains.warnings), (u, &patterns.warnings), (i, &ips.warnings)] {
        let name = file_name(file);
        report.warnings.extend(w.iter().map(|w| format!("{name}: {w}")));
    }
    report.domains += domains.entries;
    report.regexes += patterns.entries;
    report.ips += ips.entries;
    report.duplicates += domains.duplicates + patterns.duplicates + ips.duplicates;
    Ok(ListSet {
        domains: domains.list,
        patterns: patterns.list,
        ips: ips.list,
        files: files.map(|p| file_name(p)),
    })
}

/// Outcome of a reload attempt.
#[derive(Debug)]
pub enum ReloadOutcome {
    /// New lists are active.
    Reloaded(LoadReport),
    /// Load failed; the previous lists stay active.
    Failed(String),
}

type Stamp = Vec<Option<(u64, SystemTime)>>;

/// Atomically swappable lists (D-16): readers take lock-free snapshots.
pub struct BlocklistHandle {
    cfg: BlocklistConfig,
    current: ArcSwap<Blocklists>,
    stamp: Mutex<Stamp>,
}

impl BlocklistHandle {
    /// Initial load; fails if any file is unusable.
    pub fn load(cfg: &BlocklistConfig) -> Result<(Self, LoadReport), ListError> {
        let stamp = Self::stamp_of(cfg);
        let (lists, report) = Blocklists::load(cfg)?;
        let handle = Self {
            cfg: cfg.clone(),
            current: ArcSwap::from_pointee(lists),
            stamp: Mutex::new(stamp),
        };
        Ok((handle, report))
    }

    /// Lock-free read of the active lists.
    pub fn snapshot(&self) -> Arc<Blocklists> {
        self.current.load_full()
    }

    fn stamp_of(cfg: &BlocklistConfig) -> Stamp {
        [&cfg.domains, &cfg.url_patterns, &cfg.ip_blocklist]
            .into_iter()
            .chain(cfg.categories.iter().flat_map(|c| c.files()))
            .map(|p| std::fs::metadata(p).ok().and_then(|m| Some((m.len(), m.modified().ok()?))))
            .collect()
    }

    /// Reload now (SIGHUP); on failure the previous lists stay active.
    pub fn reload(&self) -> ReloadOutcome {
        // Holding the stamp lock for the whole load serializes reloads (SIGHUP vs watcher), so an
        // older load can never overwrite a newer one. A failed load is not retried until changed.
        let mut stamp = self.stamp.lock().unwrap_or_else(|e| e.into_inner());
        *stamp = Self::stamp_of(&self.cfg);
        match Blocklists::load(&self.cfg) {
            Ok((lists, report)) => {
                self.current.store(Arc::new(lists));
                ReloadOutcome::Reloaded(report)
            }
            Err(e) => ReloadOutcome::Failed(e.to_string()),
        }
    }

    /// Reload only if any file's size or mtime changed.
    pub fn reload_if_changed(&self) -> Option<ReloadOutcome> {
        let changed =
            *self.stamp.lock().unwrap_or_else(|e| e.into_inner()) != Self::stamp_of(&self.cfg);
        changed.then(|| self.reload())
    }

    /// Poll for changes every `interval` and log the outcome (SPEC 4.6 hot reload).
    pub fn spawn_watcher(
        self: &Arc<Self>,
        interval: Duration,
        sys: SystemLog,
    ) -> tokio::task::JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                match me.reload_if_changed() {
                    Some(ReloadOutcome::Reloaded(r)) => sys.event(
                        SysEvent::BlocklistLoaded,
                        serde_json::json!({"domains": r.domains, "regexes": r.regexes, "ips": r.ips,
                            "duplicates": r.duplicates, "warnings": r.warnings}),
                    ),
                    Some(ReloadOutcome::Failed(e)) => {
                        sys.event(SysEvent::BlocklistReloadFailed, serde_json::json!({"error": e}))
                    }
                    None => {}
                }
            }
        })
    }
}
