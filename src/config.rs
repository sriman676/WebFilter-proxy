//! Configuration file loading and validation (SPEC 6).
//!
//! Rules: unknown keys are errors; missing keys take the defaults shown in
//! `config/config.example.toml`; relative paths resolve against the config file's directory;
//! a leading `~` expands to `$HOME`; invalid values map to exit code 2.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

/// Process exit code for an invalid configuration (SPEC 6).
pub const EXIT_INVALID_CONFIG: u8 = 2;

/// Configuration errors. Every message names the offending file or key.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("cannot read config file {path}: {source}")]
    Read {
        /// Path that failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// TOML syntax error, unknown key or wrongly typed value.
    #[error("config parse error: {0}")]
    Parse(String),
    /// A value parsed but is not acceptable.
    #[error("invalid config value `{key}`: {reason}")]
    Invalid {
        /// Dotted key path, e.g. `limits.max_connections`.
        key: String,
        /// Human-readable reason.
        reason: String,
    },
}

fn invalid(key: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid { key: key.to_owned(), reason: reason.into() }
}

/// Enforcement mode (D-33).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Block matching requests.
    #[default]
    Enforce,
    /// Never block; log `would_block`.
    Monitor,
}

/// Behaviour when the filter itself fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnError {
    /// Allow the request (always logged).
    #[default]
    Allow,
    /// Block the request.
    Block,
}

/// Root configuration.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Absolute path of the file this config was loaded from (set by `load`).
    #[serde(skip)]
    pub source: Option<PathBuf>,
    /// Enforcement mode.
    pub mode: Mode,
    /// Proxy listen address; non-loopback requires `proxy_auth` (D-13).
    pub listen: SocketAddr,
    /// Tokio worker threads; 0 = number of CPUs (D-04).
    pub worker_threads: usize,
    /// Filter internal-error behaviour.
    pub on_error: OnError,
    /// Log query values (D-18; default false).
    pub log_query_values: bool,
    /// Reuse upstream connections for the same client connection and authority only (D-07).
    pub upstream_keepalive: bool,
    /// Reject CONNECT tunnels that do not start with TLS.
    pub block_non_tls_connect: bool,
    /// Size and connection limits.
    pub limits: LimitsConfig,
    /// Timeouts in seconds.
    pub timeouts: TimeoutsConfig,
    /// Port policy (D-12).
    pub ports: PortConfig,
    /// Destination policy (D-11, D-36).
    pub destination: DestinationConfig,
    /// Log files.
    pub logging: LoggingConfig,
    /// Blocklist files.
    pub blocklists: BlocklistConfig,
    /// Allow domains, extension and content-type rules.
    pub rules: RuleConfig,
    /// TLS interception.
    pub tls: TlsConfig,
    /// Proxy authentication (D-14); required for non-loopback listen.
    pub proxy_auth: Option<ProxyAuthConfig>,
    /// HTTP/1 parser options (A-25).
    pub http: HttpConfig,
    /// Block page template (A-26).
    pub block_page: BlockPageConfig,
    /// HTTP/2 flood limits (D-45).
    pub http2: Http2Config,
    /// Transparent mode (D-41..D-43).
    pub transparent: TransparentConfig,
    /// Admin listener (D-55).
    pub admin: AdminConfig,
    /// Profiles (SPEC_EXT_POLICY P1); `default` always exists.
    pub profiles: Vec<ProfileConfig>,
    /// CIDR -> profile.
    pub clients: Vec<ClientConfig>,
    /// Proxy users (D-50); `[proxy_auth]` stays valid as one user in `default`.
    pub users: Vec<UserConfig>,
    /// Threat feeds (SPEC_EXT_POLICY P3); all disabled by default.
    pub feeds: Vec<FeedConfig>,
    /// Feed store and protected domains.
    pub feeds_global: FeedsGlobalConfig,
    /// Download hashing and scanning (P4); off by default.
    pub scan: ScanConfig,
    /// v1.1 placeholder, typed in Phase 11.
    pub access_requests: Option<RawSection>,
    /// v1.1 placeholder, typed in Phase 11.
    pub state: Option<RawSection>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Enforce,
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            worker_threads: 0,
            on_error: OnError::Allow,
            log_query_values: false,
            upstream_keepalive: false,
            block_non_tls_connect: true,
            source: None,
            limits: LimitsConfig::default(),
            timeouts: TimeoutsConfig::default(),
            ports: PortConfig::default(),
            destination: DestinationConfig::default(),
            logging: LoggingConfig::default(),
            blocklists: BlocklistConfig::default(),
            rules: RuleConfig::default(),
            tls: TlsConfig::default(),
            proxy_auth: None,
            http: HttpConfig::default(),
            block_page: BlockPageConfig::default(),
            http2: Http2Config::default(),
            transparent: TransparentConfig::default(),
            admin: AdminConfig::default(),
            profiles: Vec::new(),
            clients: Vec::new(),
            users: Vec::new(),
            feeds: Vec::new(),
            feeds_global: FeedsGlobalConfig::default(),
            scan: ScanConfig::default(),
            access_requests: None,
            state: None,
        }
    }
}

/// A value whose `Debug` output is always `<redacted>`: secrets (hashes, tokens) and untyped
/// sections that may contain them (D-18, PF-0-07).
#[derive(Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(transparent)]
pub struct Redacted<T>(pub T);

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// An untyped v1.1 section kept until its phase types it (A-04).
pub type RawSection = Redacted<toml::Value>;

/// Maximum accepted config file size (PF-0-06).
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// `[limits]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    /// Maximum concurrent client connections.
    pub max_connections: usize,
    /// Maximum concurrent connections per client IP.
    pub max_connections_per_ip: usize,
    /// Maximum request head size in bytes.
    pub max_head_bytes: usize,
    /// Maximum number of request headers.
    pub max_headers: usize,
    /// Maximum request-target length in bytes.
    pub max_uri_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_connections_per_ip: 128,
            max_head_bytes: 65536,
            max_headers: 100,
            max_uri_bytes: 8192,
        }
    }
}

/// `[timeouts]`, all in seconds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TimeoutsConfig {
    /// Time allowed to read a full request head.
    pub client_head_read: u64,
    /// Idle time between keep-alive requests.
    pub client_keepalive_idle: u64,
    /// Upstream TCP connect timeout.
    pub upstream_connect: u64,
    /// Time allowed for the upstream response head.
    pub upstream_response_header: u64,
    /// Upstream body idle timeout.
    pub upstream_body_idle: u64,
    /// Tunnel idle timeout.
    pub tunnel_idle: u64,
    /// TLS handshake timeout.
    pub tls_handshake: u64,
    /// Graceful-shutdown drain time (D-31).
    pub shutdown_drain: u64,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            client_head_read: 15,
            client_keepalive_idle: 60,
            upstream_connect: 10,
            upstream_response_header: 30,
            upstream_body_idle: 60,
            tunnel_idle: 300,
            tls_handshake: 10,
            shutdown_drain: 10,
        }
    }
}

/// Allowed destination ports: an explicit list or `"any"` (tests only, D-12).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "PortSpec")]
pub enum PortSet {
    /// Every port 1-65535.
    Any,
    /// Only the listed ports.
    List(Vec<u16>),
}

impl PortSet {
    /// Whether `port` is allowed.
    pub fn allows(&self, port: u16) -> bool {
        match self {
            PortSet::Any => port != 0,
            PortSet::List(ports) => ports.contains(&port),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PortSpec {
    List(Vec<i64>),
    Keyword(String),
}

impl TryFrom<PortSpec> for PortSet {
    type Error = String;

    fn try_from(spec: PortSpec) -> Result<Self, String> {
        match spec {
            PortSpec::Keyword(k) if k == "any" => Ok(PortSet::Any),
            PortSpec::Keyword(k) => Err(format!("expected a port array or \"any\", got {k:?}")),
            PortSpec::List(list) if list.is_empty() => Err("port list must not be empty".into()),
            PortSpec::List(list) => list
                .into_iter()
                .map(|p| match u16::try_from(p) {
                    Ok(port) if port != 0 => Ok(port),
                    _ => Err(format!("port {p} is out of range (1-65535)")),
                })
                .collect::<Result<Vec<u16>, String>>()
                .map(PortSet::List),
        }
    }
}

/// `[ports]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PortConfig {
    /// Ports allowed for plain HTTP.
    pub http_allowed: PortSet,
    /// Ports allowed for CONNECT.
    pub connect_allowed: PortSet,
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            http_allowed: PortSet::List(vec![80, 8000, 8080, 8888]),
            connect_allowed: PortSet::List(vec![443, 8443]),
        }
    }
}

/// `[destination]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DestinationConfig {
    /// Deny private/loopback/link-local destinations (code default false, D-36).
    pub deny_private_ranges: bool,
}

/// `[logging]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingConfig {
    /// Log directory.
    pub dir: PathBuf,
    /// Rotate a file when it reaches this size.
    pub max_bytes: u64,
    /// Rotated files to keep.
    pub backup_count: u32,
    /// Bounded logging channel capacity (D-17).
    pub queue_capacity: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("../logs"),
            max_bytes: 52_428_800,
            backup_count: 10,
            queue_capacity: 10_000,
        }
    }
}

/// `[blocklists]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BlocklistConfig {
    /// Domain blocklist file.
    pub domains: PathBuf,
    /// URL regex pattern file.
    pub url_patterns: PathBuf,
    /// IP/CIDR blocklist file.
    pub ip_blocklist: PathBuf,
    /// Reload poll interval in seconds.
    pub reload_interval_secs: u64,
    /// UTC offset for category schedules, e.g. `"+05:30"` (A-27).
    pub utc_offset: String,
    /// Named, switchable, optionally scheduled list categories (A-27).
    pub categories: Vec<CategoryConfig>,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            domains: PathBuf::from("blocklists/domains.txt"),
            url_patterns: PathBuf::from("blocklists/url_patterns.txt"),
            ip_blocklist: PathBuf::from("blocklists/ip_blocklist.txt"),
            reload_interval_secs: 5,
            utc_offset: "+00:00".to_owned(),
            categories: Vec::new(),
        }
    }
}

/// `[[blocklists.categories]]` (A-27): a named set of list files, switchable and scheduled.
/// Empty paths mean "no list of that kind"; `active` empty = always active.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryConfig {
    /// Name shown on the block page and in logs (`[a-z0-9_-]`, 1-32 chars).
    pub name: String,
    /// Switch the category on/off.
    #[serde(default = "enabled_default")]
    pub enabled: bool,
    /// Domain list (same grammar as domains.txt).
    #[serde(default)]
    pub domains: PathBuf,
    /// URL pattern list.
    #[serde(default)]
    pub url_patterns: PathBuf,
    /// IP/CIDR list.
    #[serde(default)]
    pub ip_blocklist: PathBuf,
    /// Time windows when the category blocks, e.g. `["Mon-Fri 09:00-17:00"]`.
    #[serde(default)]
    pub active: Vec<String>,
}

fn enabled_default() -> bool {
    true
}

impl BlocklistConfig {
    /// Every list file: the default lists, then each category's (empty paths included).
    pub fn files(&self) -> impl Iterator<Item = &PathBuf> {
        [&self.domains, &self.url_patterns, &self.ip_blocklist]
            .into_iter()
            .chain(self.categories.iter().flat_map(CategoryConfig::files))
    }
}

/// Paths among `files` that are world-writable (PT-5.4); anyone could change policy through them.
pub fn world_writable<'a>(files: impl IntoIterator<Item = &'a Path>) -> Vec<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        files
            .into_iter()
            .filter(|p| std::fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o002 != 0))
            .map(|p| p.display().to_string())
            .collect()
    }
    #[cfg(not(unix))]
    {
        let _ = files;
        Vec::new()
    }
}

impl CategoryConfig {
    /// The category's list files (empty paths for kinds it does not use).
    pub fn files(&self) -> [&PathBuf; 3] {
        [&self.domains, &self.url_patterns, &self.ip_blocklist]
    }
}

/// `[rules]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuleConfig {
    /// Domains that are always allowed.
    pub allow_domains: Vec<String>,
    /// Blocked path extensions (with leading dot).
    pub blocked_extensions: Vec<String>,
    /// Blocked response content types.
    pub blocked_content_types: Vec<String>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            allow_domains: Vec::new(),
            blocked_extensions: [".exe", ".scr", ".bat", ".ps1"].map(String::from).to_vec(),
            blocked_content_types: vec!["application/x-msdownload".to_owned()],
        }
    }
}

/// `[tls]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    /// Enable TLS interception (Phase 4).
    pub intercept: bool,
    /// Local CA directory; must not be group/world accessible (D-19).
    pub ca_dir: PathBuf,
    /// Domains that are never intercepted.
    pub passthrough_domains: Vec<String>,
    /// Optional extra upstream roots (PEM); empty = none. Verification is always on (D-20).
    pub upstream_ca_bundle: PathBuf,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            intercept: false,
            ca_dir: PathBuf::from("~/.webfilter"),
            passthrough_domains: vec![
                "*.bank.example".to_owned(),
                "update.microsoft.com".to_owned(),
            ],
            upstream_ca_bundle: PathBuf::new(),
        }
    }
}

/// `[proxy_auth]` (D-14).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyAuthConfig {
    /// Basic-auth user name.
    pub username: String,
    /// argon2id PHC hash from `webfilter-proxy hash-password`.
    pub password_hash: Redacted<String>,
}

/// `[[users]]` (D-50).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    /// `[A-Za-z0-9._-]{1,64}`.
    pub username: String,
    /// argon2id PHC hash.
    pub password_hash: Redacted<String>,
    /// Profile name.
    #[serde(default = "default_profile")]
    pub profile: String,
}

/// `[[clients]]`: source network -> profile (longest prefix wins).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// CIDR, e.g. `192.168.1.0/24`.
    pub cidr: String,
    /// Profile name.
    pub profile: String,
}

fn default_profile() -> String {
    "default".to_owned()
}

/// `[[profiles]]` (SPEC_EXT_POLICY P1). Never weakens safety policy (D-50).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProfileConfig {
    /// `[a-z0-9_-]{1,32}`.
    pub name: String,
    /// Content-rule mode for this profile.
    pub mode: Option<Mode>,
    /// Extra allowlist (bypasses list rules only).
    pub allow_domains: Vec<String>,
    /// Extra blocked domains (blocklist grammar).
    pub extra_blocked_domains: Vec<String>,
    /// Extra URL patterns (blocklist grammar).
    pub extra_url_patterns: Vec<String>,
    /// Replaces `rules.blocked_extensions`.
    pub blocked_extensions: Option<Vec<String>>,
    /// Replaces `rules.blocked_content_types`.
    pub blocked_content_types: Option<Vec<String>>,
    /// Threat feeds (Phase 10).
    pub feeds: Vec<String>,
    /// Download scanning (Phase 10).
    pub scan_downloads: Option<bool>,
    /// Access requests (Phase 11).
    pub access_requests: Option<bool>,
    /// Limits; absent = unlimited (A-39).
    pub rate: Option<RateConfig>,
}

/// `[profiles.rate]` (SPEC_EXT_POLICY P2); missing keys take these defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RateConfig {
    /// Sustained requests per second.
    pub requests_per_sec: u32,
    /// Bucket size.
    pub burst: u32,
    /// Concurrent client connections.
    pub max_concurrent_connections: u32,
    /// Requests in flight.
    pub max_inflight_requests: u32,
    /// Open CONNECT tunnels.
    pub max_tunnels: u32,
    /// Download cap (0 = unlimited, else >= 4096).
    pub down_bytes_per_sec: u64,
    /// Upload cap (0 = unlimited, else >= 4096).
    pub up_bytes_per_sec: u64,
    /// Bytes per UTC day (0 = off).
    pub daily_quota_bytes: u64,
}

impl Default for RateConfig {
    fn default() -> Self {
        Self {
            requests_per_sec: 50,
            burst: 100,
            max_concurrent_connections: 64,
            max_inflight_requests: 128,
            max_tunnels: 32,
            down_bytes_per_sec: 0,
            up_bytes_per_sec: 0,
            daily_quota_bytes: 0,
        }
    }
}

/// Feed file formats (P3).
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedFormat {
    DomainsText,
    Hostfile,
    UrlsText,
    CsvUrlhaus,
    IpsText,
}

/// `[[feeds]]` (D-52).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedConfig {
    /// `[a-z0-9_-]{1,32}`.
    pub name: String,
    /// Fetch and use this feed.
    #[serde(default)]
    pub enabled: bool,
    /// HTTPS URL.
    pub url: String,
    /// File format.
    pub format: FeedFormat,
    /// Refresh interval (>= 300).
    #[serde(default = "feed_refresh")]
    pub refresh_secs: u64,
    /// Download cap.
    #[serde(default = "feed_max_bytes")]
    pub max_bytes: u64,
    /// Entry cap (global cap 5,000,000).
    #[serde(default = "feed_max_entries")]
    pub max_entries: usize,
    /// File with the API key (header `Auth-Key`); empty = none. Never logged.
    #[serde(default)]
    pub auth_header_file: PathBuf,
    /// Deactivate after this long without a successful update.
    #[serde(default = "feed_expire")]
    pub expire_after_secs: u64,
}

fn feed_refresh() -> u64 {
    3600
}
fn feed_max_bytes() -> u64 {
    50 * 1024 * 1024
}
fn feed_max_entries() -> usize {
    2_000_000
}
fn feed_expire() -> u64 {
    604_800
}

/// `[feeds_global]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FeedsGlobalConfig {
    /// Feed store (`feeds/<name>/v<unix>.list`, `active`).
    pub dir: PathBuf,
    /// Never accepted from a feed (in addition to `localhost` and `webfilter.local`).
    pub protected_domains: Vec<String>,
}

impl Default for FeedsGlobalConfig {
    fn default() -> Self {
        Self { dir: PathBuf::from("feeds"), protected_domains: Vec::new() }
    }
}

/// Scan mode (D-53).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    /// Stream unchanged; log the verdict afterwards.
    #[default]
    Detect,
    /// Buffer, scan, then deliver or block.
    Block,
}

/// Unscannable / scanner-unavailable action.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanAction {
    Block,
    Allow,
}

/// `[scan]` (SPEC_EXT_POLICY P4).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScanConfig {
    /// Master switch; a profile must also set `scan_downloads = true`.
    pub enabled: bool,
    /// detect | block.
    pub mode: ScanMode,
    /// Largest scanned body.
    pub max_bytes: u64,
    /// Concurrent scans.
    pub max_concurrent: usize,
    /// Block mode: time allowed to receive the body.
    pub buffer_timeout_secs: u64,
    /// 0700 directory for 0600 temp files.
    pub temp_dir: PathBuf,
    /// Total temp bytes.
    pub temp_quota_bytes: u64,
    /// Default: block in block mode, else allow.
    pub unscannable_action: Option<ScanAction>,
    /// Default: block in block mode, else allow.
    pub scanner_unavailable_action: Option<ScanAction>,
    /// Eligible extensions.
    pub extensions: Vec<String>,
    /// Eligible media types.
    pub content_types: Vec<String>,
    /// Magic-byte eligibility.
    pub magic: bool,
    /// SHA-256 hex list; empty = none.
    pub hash_blocklist: PathBuf,
    /// ClamAV daemon.
    pub clamd: Option<ClamdConfig>,
    /// YARA (cargo feature `yara`).
    pub yara: Option<YaraConfig>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: ScanMode::Detect,
            max_bytes: 26_214_400,
            max_concurrent: 8,
            buffer_timeout_secs: 60,
            temp_dir: PathBuf::from("state/scan_tmp"),
            temp_quota_bytes: 1 << 30,
            unscannable_action: None,
            scanner_unavailable_action: None,
            extensions: [
                ".exe", ".dll", ".msi", ".zip", ".rar", ".7z", ".js", ".jar", ".ps1", ".bat",
                ".scr", ".apk", ".dmg", ".iso", ".docm", ".xlsm", ".pdf",
            ]
            .map(String::from)
            .to_vec(),
            content_types: [
                "application/octet-stream",
                "application/x-msdownload",
                "application/zip",
                "application/x-dosexec",
                "application/java-archive",
                "application/pdf",
            ]
            .map(String::from)
            .to_vec(),
            magic: true,
            hash_blocklist: PathBuf::new(),
            clamd: None,
            yara: None,
        }
    }
}

impl ScanConfig {
    /// Effective unscannable action.
    pub fn on_unscannable(&self) -> ScanAction {
        self.unscannable_action.unwrap_or(self.default_action())
    }
    /// Effective scanner-unavailable action.
    pub fn on_unavailable(&self) -> ScanAction {
        self.scanner_unavailable_action.unwrap_or(self.default_action())
    }
    fn default_action(&self) -> ScanAction {
        if self.mode == ScanMode::Block { ScanAction::Block } else { ScanAction::Allow }
    }
}

/// `[scan.clamd]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClamdConfig {
    /// `unix:/path` or `tcp:127.0.0.1:3310` (loopback only).
    pub address: String,
    /// Per-scan timeout.
    #[serde(default = "clamd_timeout")]
    pub timeout_secs: u64,
    /// INSTREAM chunk size.
    #[serde(default = "clamd_chunk")]
    pub chunk_bytes: usize,
}

fn clamd_timeout() -> u64 {
    30
}
fn clamd_chunk() -> usize {
    65_536
}

/// `[scan.yara]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YaraConfig {
    /// Directory of operator-trusted `.yar` rules.
    pub rules_dir: PathBuf,
    /// Per-scan timeout.
    #[serde(default = "yara_timeout")]
    pub timeout_secs: u64,
}

fn yara_timeout() -> u64 {
    10
}

/// `[block_page]` (A-26): an HTML template with `{url}`, `{host}`, `{reason}`, `{rule_id}`,
/// `{category}`, `{event_id}`, `{timestamp}` placeholders (always HTML-escaped).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BlockPageConfig {
    /// Template file; empty = built-in page.
    pub template: PathBuf,
}

/// `[http]` HTTP/1 parser options (A-25).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HttpConfig {
    /// Tolerate lowercase methods and chunk extensions. Never relaxes CL/TE, duplicate-header,
    /// bare CR/LF, NUL, obs-fold or spacing rules (anti-smuggling).
    pub compat: bool,
}

/// `[http2]` flood limits; tunable, never disabled (D-45).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Http2Config {
    /// SETTINGS_MAX_CONCURRENT_STREAMS.
    pub max_concurrent_streams: u32,
    /// SETTINGS_MAX_HEADER_LIST_SIZE.
    pub max_header_list_size: u32,
    /// SETTINGS_MAX_FRAME_SIZE (16384..=16777215).
    pub max_frame_size: u32,
    /// Initial stream flow-control window.
    pub initial_stream_window: u32,
    /// Initial connection flow-control window.
    pub initial_conn_window: u32,
    /// Maximum CONTINUATION frames per header block.
    pub max_continuation_frames: u32,
    /// RST_STREAM frames allowed per window.
    pub reset_limit: u32,
    /// Control frames allowed per window.
    pub control_frame_limit: u32,
    /// Window length in seconds.
    pub limit_window_secs: u64,
    /// Total streams per connection.
    pub max_streams_per_connection: u32,
    /// Stalled-stream timeout in seconds.
    pub stall_timeout_secs: u64,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 100,
            max_header_list_size: 65536,
            max_frame_size: 16384,
            initial_stream_window: 1_048_576,
            initial_conn_window: 4_194_304,
            max_continuation_frames: 16,
            reset_limit: 100,
            control_frame_limit: 200,
            limit_window_secs: 10,
            max_streams_per_connection: 10_000,
            stall_timeout_secs: 30,
        }
    }
}

/// Host/SNI verification against the original destination (D-42).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostVerify {
    /// Resolved Host/SNI set must contain the original IP.
    #[default]
    Strict,
    /// Skip that check.
    Relaxed,
}

/// Action for missing SNI or present ECH in transparent mode (D-42).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparentAction {
    /// Close the connection.
    #[default]
    Block,
    /// Filter by original IP only.
    IpOnly,
}

/// Original-destination lookup method (D-41).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrigDstMethod {
    /// `SO_ORIGINAL_DST` socket option.
    #[default]
    SoOriginalDst,
    /// Parse `/proc/net/nf_conntrack`.
    Conntrack,
}

/// `[transparent]` (Phase 7, Linux lab only).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TransparentConfig {
    /// Enable transparent listeners.
    pub enabled: bool,
    /// Must be true to start (D-41).
    pub acknowledge_lab_only: bool,
    /// Transparent HTTP listener.
    pub http_listen: SocketAddr,
    /// Transparent TLS listener.
    pub tls_listen: SocketAddr,
    /// Host verification mode.
    pub host_verify: HostVerify,
    /// Action when the ClientHello has no SNI.
    pub no_sni_action: TransparentAction,
    /// Action when the ClientHello carries ECH.
    pub ech_action: TransparentAction,
    /// Original-destination method.
    pub orig_dst: OrigDstMethod,
}

impl Default for TransparentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            acknowledge_lab_only: false,
            http_listen: SocketAddr::from(([127, 0, 0, 1], 18880)),
            tls_listen: SocketAddr::from(([127, 0, 0, 1], 18443)),
            host_verify: HostVerify::Strict,
            no_sni_action: TransparentAction::Block,
            ech_action: TransparentAction::Block,
            orig_dst: OrigDstMethod::SoOriginalDst,
        }
    }
}

/// `[admin]` (Phase 11, D-55). Loopback only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AdminConfig {
    /// Enable the admin listener.
    pub enabled: bool,
    /// Admin listen address; must be loopback.
    pub listen: SocketAddr,
    /// argon2id hash of the bearer token.
    pub token_hash: Redacted<String>,
    /// Serve the embedded web UI.
    pub ui_enabled: bool,
    /// Serve `/metrics` without a token.
    pub metrics_public: bool,
    /// Maximum request body size.
    pub max_body_bytes: usize,
    /// Per-request timeout in seconds.
    pub request_timeout_secs: u64,
    /// Maximum concurrent admin connections.
    pub max_connections: usize,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: SocketAddr::from(([127, 0, 0, 1], 9090)),
            token_hash: Redacted::default(),
            ui_enabled: true,
            metrics_public: false,
            max_body_bytes: 65536,
            request_timeout_secs: 10,
            max_connections: 64,
        }
    }
}

impl Config {
    /// Read, parse, resolve paths against the file's directory, and validate.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let read_err = |source| ConfigError::Read { path: path.to_path_buf(), source };
        let meta = std::fs::metadata(path).map_err(read_err)?;
        if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
            return Err(read_err(std::io::Error::other(format!(
                "must be a regular file of at most {MAX_CONFIG_BYTES} bytes"
            ))));
        }
        let text = std::fs::read_to_string(path).map_err(read_err)?;
        let abs = std::path::absolute(path).map_err(read_err)?;
        let base = abs.parent().unwrap_or(Path::new("/"));
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let mut cfg = Self::parse(&text, base, home.as_deref())?;
        cfg.source = Some(abs);
        Ok(cfg)
    }

    /// Files whose tampering changes policy: the config itself, every list and the block page.
    pub fn policy_files(&self) -> Vec<&Path> {
        self.source
            .iter()
            .chain(self.blocklists.files())
            .chain(std::iter::once(&self.block_page.template))
            .map(PathBuf::as_path)
            .filter(|p| !p.as_os_str().is_empty())
            .collect()
    }

    /// Parse TOML text, resolve relative paths against `base_dir` and `~` against `home`,
    /// then validate.
    pub fn parse(text: &str, base_dir: &Path, home: Option<&Path>) -> Result<Self, ConfigError> {
        let mut cfg: Config = toml::from_str(text).map_err(|e| parse_error(text, &e))?;
        cfg.resolve_paths(base_dir, home)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Effective worker thread count (0 = available parallelism, at least 1).
    pub fn effective_worker_threads(&self) -> usize {
        if self.worker_threads > 0 {
            return self.worker_threads;
        }
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    }

    fn resolve_paths(&mut self, base: &Path, home: Option<&Path>) -> Result<(), ConfigError> {
        let r = |key: &str, p: &Path| resolve_path(p, base, home).map_err(|e| invalid(key, e));
        self.logging.dir = r("logging.dir", &self.logging.dir)?;
        self.blocklists.domains = r("blocklists.domains", &self.blocklists.domains)?;
        self.blocklists.url_patterns = r("blocklists.url_patterns", &self.blocklists.url_patterns)?;
        self.blocklists.ip_blocklist = r("blocklists.ip_blocklist", &self.blocklists.ip_blocklist)?;
        for cat in &mut self.blocklists.categories {
            for path in [&mut cat.domains, &mut cat.url_patterns, &mut cat.ip_blocklist] {
                if !path.as_os_str().is_empty() {
                    *path = r("blocklists.categories", path)?;
                }
            }
        }
        // Resolved whenever possible (`ca generate/export`); an unresolvable `~` (no HOME) is an
        // error only when interception needs the CA (PF-0-04).
        match r("tls.ca_dir", &self.tls.ca_dir) {
            Ok(dir) => self.tls.ca_dir = dir,
            Err(e) if self.tls.intercept => return Err(e),
            Err(_) => {}
        }
        if !self.block_page.template.as_os_str().is_empty() {
            self.block_page.template = r("block_page.template", &self.block_page.template)?;
        }
        if !self.tls.upstream_ca_bundle.as_os_str().is_empty() {
            self.tls.upstream_ca_bundle =
                r("tls.upstream_ca_bundle", &self.tls.upstream_ca_bundle)?;
        }
        self.feeds_global.dir = r("feeds_global.dir", &self.feeds_global.dir)?;
        for f in &mut self.feeds {
            if !f.auth_header_file.as_os_str().is_empty() {
                f.auth_header_file = r("feeds.auth_header_file", &f.auth_header_file)?;
            }
        }
        self.scan.temp_dir = r("scan.temp_dir", &self.scan.temp_dir)?;
        if !self.scan.hash_blocklist.as_os_str().is_empty() {
            self.scan.hash_blocklist = r("scan.hash_blocklist", &self.scan.hash_blocklist)?;
        }
        if let Some(y) = &mut self.scan.yara {
            y.rules_dir = r("scan.yara.rules_dir", &y.rules_dir)?;
        }
        Ok(())
    }

    /// Semantic validation (SPEC 6). Paths must already be resolved.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.listen.ip().is_loopback() && self.proxy_auth.is_none() && self.users.is_empty() {
            return Err(invalid(
                "listen",
                format!(
                    "{} is not loopback; [proxy_auth] or [[users]] is required (D-13)",
                    self.listen
                ),
            ));
        }
        self.validate_policies()?;
        if let Some(auth) = &self.proxy_auth {
            if auth.username.is_empty() || auth.username.contains(':') {
                return Err(invalid("proxy_auth.username", "must be non-empty and contain no ':'"));
            }
            if !crate::auth::is_argon2id_phc(&auth.password_hash.0) {
                return Err(invalid(
                    "proxy_auth.password_hash",
                    "must be an argon2id PHC hash (webfilter-proxy hash-password)",
                ));
            }
        }
        if !self.admin.listen.ip().is_loopback() {
            return Err(invalid("admin.listen", "admin listener must be loopback (D-55)"));
        }
        if self.admin.enabled && !crate::auth::is_argon2id_phc(&self.admin.token_hash.0) {
            return Err(invalid(
                "admin.token_hash",
                "an argon2id hash is required when admin.enabled (D-55)",
            ));
        }
        if self.transparent.enabled {
            let t = &self.transparent;
            if !t.acknowledge_lab_only {
                return Err(invalid(
                    "transparent.acknowledge_lab_only",
                    "must be true when transparent.enabled (D-41)",
                ));
            }
            if !cfg!(target_os = "linux") {
                return Err(invalid(
                    "transparent.enabled",
                    "transparent mode is Linux only (D-41)",
                ));
            }
            let fixed = |a: &SocketAddr| a.port() != 0;
            if [t.http_listen, t.tls_listen].iter().any(|a| fixed(a) && *a == self.listen)
                || (fixed(&t.http_listen) && t.http_listen == t.tls_listen)
            {
                return Err(invalid(
                    "transparent.http_listen",
                    "transparent listeners must differ from each other and from listen",
                ));
            }
        }
        self.validate_ranges()?;
        for (key, path) in [
            ("blocklists.domains", &self.blocklists.domains),
            ("blocklists.url_patterns", &self.blocklists.url_patterns),
            ("blocklists.ip_blocklist", &self.blocklists.ip_blocklist),
        ] {
            check_readable_file(key, path)?;
        }
        self.validate_categories()?;
        if !self.block_page.template.as_os_str().is_empty() {
            check_readable_file("block_page.template", &self.block_page.template)?;
        }
        if !self.tls.upstream_ca_bundle.as_os_str().is_empty() {
            check_readable_file("tls.upstream_ca_bundle", &self.tls.upstream_ca_bundle)?;
        }
        if self.tls.intercept {
            check_private_dir("tls.ca_dir", &self.tls.ca_dir)?;
        }
        Ok(())
    }

    /// Category names unique and well-formed, files readable, schedules parse (A-27).
    /// Users, clients and profiles (D-50, D-51); the lists compile via `PolicySet::build`.
    fn validate_policies(&self) -> Result<(), ConfigError> {
        if self.profiles.len() > 100 || self.users.len() + self.clients.len() > 10_000 {
            return Err(invalid("profiles", "at most 100 profiles and 10,000 users+clients"));
        }
        for u in &self.users {
            let ok = (1..=64).contains(&u.username.len())
                && u.username.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
            if !ok {
                return Err(invalid(
                    "users.username",
                    format!("{:?}: use [A-Za-z0-9._-], 1-64 chars", u.username),
                ));
            }
            if !crate::auth::is_argon2id_phc(&u.password_hash.0) {
                return Err(invalid(
                    "users.password_hash",
                    format!("{}: argon2id PHC hash required", u.username),
                ));
            }
        }
        for p in &self.profiles {
            if let Some(r) = p.rate {
                let cap_ok = |v: u64| v == 0 || v >= 4096;
                if r.requests_per_sec == 0
                    || r.burst == 0
                    || r.max_concurrent_connections == 0
                    || r.max_inflight_requests == 0
                    || r.max_tunnels == 0
                    || !cap_ok(r.down_bytes_per_sec)
                    || !cap_ok(r.up_bytes_per_sec)
                {
                    return Err(invalid(
                        "profiles.rate",
                        format!("{}: limits must be >= 1; byte caps 0 or >= 4096", p.name),
                    ));
                }
            }
        }
        crate::profiles::PolicySet::build(self).map(|_| ()).map_err(|e| invalid("profiles", e))?;
        self.validate_feeds_and_scan()
    }

    /// `[[feeds]]` and `[scan]` (D-52..D-54).
    fn validate_feeds_and_scan(&self) -> Result<(), ConfigError> {
        let mut names = std::collections::HashSet::new();
        let mut total = 0usize;
        for f in &self.feeds {
            let name_ok = (1..=32).contains(&f.name.len())
                && f.name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b));
            if !name_ok || !names.insert(f.name.as_str()) {
                return Err(invalid(
                    "feeds.name",
                    format!("invalid or duplicate feed name {:?}", f.name),
                ));
            }
            if !f.url.starts_with("https://") || url::Url::parse(&f.url).is_err() {
                return Err(invalid("feeds.url", format!("{}: an https URL is required", f.name)));
            }
            if f.refresh_secs < 300
                || f.max_entries == 0
                || f.max_entries > 2_000_000
                || f.max_bytes == 0
            {
                return Err(invalid(
                    "feeds",
                    format!(
                        "{}: refresh_secs >= 300, 1..=2,000,000 entries, max_bytes > 0",
                        f.name
                    ),
                ));
            }
            total = total.saturating_add(f.max_entries);
        }
        if total > 5_000_000 {
            return Err(invalid(
                "feeds.max_entries",
                "all feeds together may hold at most 5,000,000 entries",
            ));
        }
        for p in &self.profiles {
            if let Some(unknown) = p.feeds.iter().find(|n| !names.contains(n.as_str())) {
                return Err(invalid(
                    "profiles.feeds",
                    format!("{}: unknown feed {unknown:?}", p.name),
                ));
            }
        }
        let s = &self.scan;
        if s.max_bytes == 0
            || s.max_concurrent == 0
            || s.buffer_timeout_secs == 0
            || s.temp_quota_bytes < s.max_bytes
        {
            return Err(invalid(
                "scan",
                "max_bytes, max_concurrent and buffer_timeout_secs > 0; temp_quota_bytes >= max_bytes",
            ));
        }
        if let Some(c) = &s.clamd {
            let ok = match c.address.split_once(':') {
                Some(("unix", path)) => path.starts_with('/'),
                Some(("tcp", addr)) => {
                    addr.parse::<SocketAddr>().is_ok_and(|a| a.ip().is_loopback())
                }
                _ => false,
            };
            if !ok || c.timeout_secs == 0 || !(1024..=1 << 20).contains(&c.chunk_bytes) {
                return Err(invalid(
                    "scan.clamd",
                    "address unix:/path or tcp:<loopback>:port; timeout > 0; chunk 1 KiB..1 MiB",
                ));
            }
        }
        if s.yara.is_some() && !cfg!(feature = "yara") {
            return Err(invalid("scan.yara", "this build lacks the `yara` feature (D-54)"));
        }
        if !s.hash_blocklist.as_os_str().is_empty() {
            check_readable_file("scan.hash_blocklist", &s.hash_blocklist)?;
        }
        Ok(())
    }

    fn validate_categories(&self) -> Result<(), ConfigError> {
        const KEY: &str = "blocklists.categories";
        let offset = crate::schedule::parse_offset(&self.blocklists.utc_offset)
            .map_err(|e| invalid("blocklists.utc_offset", e))?;
        let mut names = std::collections::HashSet::new();
        for cat in &self.blocklists.categories {
            let name_ok = (1..=32).contains(&cat.name.len())
                && cat.name.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
                });
            if !name_ok || !names.insert(cat.name.as_str()) {
                return Err(invalid(
                    KEY,
                    format!(
                        "invalid or duplicate category name {:?} (use [a-z0-9_-], 1-32 chars)",
                        cat.name
                    ),
                ));
            }
            if cat.files().iter().all(|p| p.as_os_str().is_empty()) {
                return Err(invalid(KEY, format!("category {:?} has no list files", cat.name)));
            }
            for path in cat.files().into_iter().filter(|p| !p.as_os_str().is_empty()) {
                check_readable_file(KEY, path)?;
            }
            crate::schedule::Schedule::parse(&cat.active, offset)
                .map_err(|e| invalid(KEY, format!("{}: {e}", cat.name)))?;
        }
        Ok(())
    }

    /// Every numeric limit must lie in `min..=max`: zero disables a limit and a huge value
    /// silently does the same (D-45, PF-0-03, A-10).
    fn validate_ranges(&self) -> Result<(), ConfigError> {
        const ANY: u64 = u64::MAX;
        const MIB: u64 = MAX_CONFIG_BYTES;
        const WINDOW_MAX: u64 = (1 << 31) - 1; // RFC 9113 6.9.1
        let (l, t, h2, a) = (&self.limits, &self.timeouts, &self.http2, &self.admin);
        let n = |v: usize| v as u64;
        let w = |v: u32| u64::from(v);
        let rows = [
            ("limits.max_connections", n(l.max_connections), 1, ANY),
            ("limits.max_connections_per_ip", n(l.max_connections_per_ip), 1, ANY),
            ("limits.max_head_bytes", n(l.max_head_bytes), 1, MIB),
            ("limits.max_headers", n(l.max_headers), 1, 1000),
            ("limits.max_uri_bytes", n(l.max_uri_bytes), 1, n(l.max_head_bytes)),
            ("timeouts.client_head_read", t.client_head_read, 1, ANY),
            ("timeouts.client_keepalive_idle", t.client_keepalive_idle, 1, ANY),
            ("timeouts.upstream_connect", t.upstream_connect, 1, ANY),
            ("timeouts.upstream_response_header", t.upstream_response_header, 1, ANY),
            ("timeouts.upstream_body_idle", t.upstream_body_idle, 1, ANY),
            ("timeouts.tunnel_idle", t.tunnel_idle, 1, ANY),
            ("timeouts.tls_handshake", t.tls_handshake, 1, ANY),
            ("timeouts.shutdown_drain", t.shutdown_drain, 1, ANY),
            ("logging.max_bytes", self.logging.max_bytes, 1, ANY),
            ("logging.queue_capacity", n(self.logging.queue_capacity), 1, 1_000_000),
            ("logging.backup_count", u64::from(self.logging.backup_count), 0, 100),
            ("blocklists.reload_interval_secs", self.blocklists.reload_interval_secs, 1, ANY),
            ("http2.max_concurrent_streams", w(h2.max_concurrent_streams), 1, 1000),
            ("http2.max_header_list_size", w(h2.max_header_list_size), 1, MIB),
            ("http2.max_frame_size", w(h2.max_frame_size), 16_384, 16_777_215),
            ("http2.initial_stream_window", w(h2.initial_stream_window), 1, WINDOW_MAX),
            ("http2.initial_conn_window", w(h2.initial_conn_window), 1, WINDOW_MAX),
            ("http2.max_continuation_frames", w(h2.max_continuation_frames), 1, 1000),
            ("http2.reset_limit", w(h2.reset_limit), 1, ANY),
            ("http2.control_frame_limit", w(h2.control_frame_limit), 1, ANY),
            ("http2.limit_window_secs", h2.limit_window_secs, 1, ANY),
            ("http2.max_streams_per_connection", w(h2.max_streams_per_connection), 1, ANY),
            ("http2.stall_timeout_secs", h2.stall_timeout_secs, 1, ANY),
            ("admin.max_body_bytes", n(a.max_body_bytes), 1, ANY),
            ("admin.request_timeout_secs", a.request_timeout_secs, 1, ANY),
            ("admin.max_connections", n(a.max_connections), 1, ANY),
        ];
        for (key, value, min, max) in rows {
            if value < min {
                return Err(invalid(key, format!("must be at least {min}")));
            }
            if value > max {
                return Err(invalid(key, format!("must be at most {max}")));
            }
        }
        Ok(())
    }
}

/// Resolve `~` (exactly `~` as first component) against `home`, then relative paths against
/// `base`. `~user` forms are rejected.
fn resolve_path(p: &Path, base: &Path, home: Option<&Path>) -> Result<PathBuf, String> {
    let mut comps = p.components();
    match comps.next() {
        Some(Component::Normal(first)) if first == "~" => match home {
            Some(h) if h.is_absolute() => Ok(h.join(comps.as_path())),
            Some(_) => Err("`~` used but HOME is empty or not absolute".to_owned()),
            None => Err("`~` used but HOME is not set".to_owned()),
        },
        Some(Component::Normal(first)) if first.to_string_lossy().starts_with('~') => {
            Err("`~user` paths are not supported; use an absolute path".to_owned())
        }
        _ if p.is_absolute() => Ok(p.to_path_buf()),
        _ => Ok(base.join(p)),
    }
}

/// Build a parse error from the message and line only. toml's `Display` echoes the offending
/// source line, which may contain a secret (D-18, PF-0-02).
fn parse_error(text: &str, e: &toml::de::Error) -> ConfigError {
    let line =
        e.span().and_then(|s| text.get(..s.start)).map(|before| before.matches('\n').count() + 1);
    let msg = e.message().trim();
    ConfigError::Parse(match line {
        Some(n) => format!("line {n}: {msg}"),
        None => msg.to_owned(),
    })
}

fn check_readable_file(key: &str, path: &Path) -> Result<(), ConfigError> {
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => std::fs::File::open(path)
            .map(drop)
            .map_err(|e| invalid(key, format!("{} is not readable: {e}", path.display()))),
        Ok(_) => Err(invalid(key, format!("{} is not a regular file", path.display()))),
        Err(e) => Err(invalid(key, format!("{}: {e}", path.display()))),
    }
}

/// The CA directory may be absent (created in Phase 4); if present it must be a directory with
/// no group/other permission bits (D-19). Owner check: DECISIONS_ADDENDUM A-06.
fn check_private_dir(key: &str, path: &Path) -> Result<(), ConfigError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(invalid(key, format!("{}: {e}", path.display()))),
    };
    if !meta.is_dir() {
        return Err(invalid(
            key,
            format!("{} is not a directory (symlinks refused)", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(invalid(
                key,
                format!(
                    "{} has mode {mode:o}; must not be group/world accessible (0700)",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}
