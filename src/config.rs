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
    /// HTTP/2 flood limits (D-45).
    pub http2: Http2Config,
    /// Transparent mode (D-41..D-43).
    pub transparent: TransparentConfig,
    /// Admin listener (D-55).
    pub admin: AdminConfig,
    /// v1.1 placeholder, typed in Phase 9 (DECISIONS_ADDENDUM A-04).
    pub profiles: Option<RawSection>,
    /// v1.1 placeholder, typed in Phase 9.
    pub clients: Option<RawSection>,
    /// v1.1 placeholder, typed in Phase 9.
    pub users: Option<RawSection>,
    /// v1.1 placeholder, typed in Phase 10.
    pub feeds: Option<RawSection>,
    /// v1.1 placeholder, typed in Phase 10.
    pub feeds_global: Option<RawSection>,
    /// v1.1 placeholder, typed in Phase 10.
    pub scan: Option<RawSection>,
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
            http2: Http2Config::default(),
            transparent: TransparentConfig::default(),
            admin: AdminConfig::default(),
            profiles: None,
            clients: None,
            users: None,
            feeds: None,
            feeds_global: None,
            scan: None,
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
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            domains: PathBuf::from("blocklists/domains.txt"),
            url_patterns: PathBuf::from("blocklists/url_patterns.txt"),
            ip_blocklist: PathBuf::from("blocklists/ip_blocklist.txt"),
            reload_interval_secs: 5,
        }
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
        Self::parse(&text, base, home.as_deref())
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
        if self.tls.intercept {
            self.tls.ca_dir = r("tls.ca_dir", &self.tls.ca_dir)?;
        }
        if !self.tls.upstream_ca_bundle.as_os_str().is_empty() {
            self.tls.upstream_ca_bundle =
                r("tls.upstream_ca_bundle", &self.tls.upstream_ca_bundle)?;
        }
        Ok(())
    }

    /// Semantic validation (SPEC 6). Paths must already be resolved.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.listen.ip().is_loopback() && self.proxy_auth.is_none() {
            return Err(invalid(
                "listen",
                format!("{} is not loopback; [proxy_auth] is required (D-13)", self.listen),
            ));
        }
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
        if self.transparent.enabled && !self.transparent.acknowledge_lab_only {
            return Err(invalid(
                "transparent.acknowledge_lab_only",
                "must be true when transparent.enabled (D-41)",
            ));
        }
        self.validate_ranges()?;
        for (key, path) in [
            ("blocklists.domains", &self.blocklists.domains),
            ("blocklists.url_patterns", &self.blocklists.url_patterns),
            ("blocklists.ip_blocklist", &self.blocklists.ip_blocklist),
        ] {
            check_readable_file(key, path)?;
        }
        if !self.tls.upstream_ca_bundle.as_os_str().is_empty() {
            check_readable_file("tls.upstream_ca_bundle", &self.tls.upstream_ca_bundle)?;
        }
        if self.tls.intercept {
            check_private_dir("tls.ca_dir", &self.tls.ca_dir)?;
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
