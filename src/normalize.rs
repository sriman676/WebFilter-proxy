//! Target canonicalization (SPEC 4.5, D-09). Pure and panic-free; fuzzed by F-01.
//!
//! The raw request-target is parsed by two independent parsers (`http::Uri` and `url::Url`);
//! any disagreement on scheme, host, port, path or query is rejected. The outgoing request is
//! built only from the returned [`NormalizedTarget`].
#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::reason::Reason;

/// URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `http`
    Http,
    /// `https`
    Https,
}

impl Scheme {
    /// Lowercase scheme name.
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    /// Default port (80 / 443).
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

/// A validated host.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// ASCII lowercase domain without trailing dot.
    Domain(String),
    /// Canonical dotted-quad IPv4.
    Ipv4(Ipv4Addr),
    /// IPv6 (IPv4-mapped addresses are kept here; [`Host::ip`] folds them).
    Ipv6(Ipv6Addr),
}

impl Host {
    /// The IP used for policy and IP rules: IPv4-mapped IPv6 is folded to IPv4. `None` for domains.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Host::Domain(_) => None,
            Host::Ipv4(v4) => Some(IpAddr::V4(*v4)),
            Host::Ipv6(v6) => Some(fold_ip(IpAddr::V6(*v6))),
        }
    }

    /// The domain name, if this host is one.
    pub fn domain(&self) -> Option<&str> {
        match self {
            Host::Domain(d) => Some(d),
            _ => None,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Domain(d) => f.write_str(d),
            Host::Ipv4(v4) => write!(f, "{v4}"),
            Host::Ipv6(v6) => write!(f, "[{v6}]"),
        }
    }
}

/// Fold IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4; other addresses unchanged.
pub fn fold_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// The canonical form of a request target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedTarget {
    /// Scheme.
    pub scheme: Scheme,
    /// Host.
    pub host: Host,
    /// Effective port (default port filled in).
    pub port: u16,
    /// Normalized path, always starting with `/`.
    pub path: String,
    /// Raw query (never logged by value, D-18).
    pub query: Option<String>,
    /// `scheme://host[:port]path[?query]` (default port omitted).
    pub url_norm: String,
    /// Regex views: normalized, decoded once, decoded twice (SPEC 4.5 step 7).
    pub views: [String; 3],
    /// Decoding twice changed the URL.
    pub suspicious_encoding: bool,
}

impl NormalizedTarget {
    /// `host[:port]` with the default port omitted.
    pub fn authority(&self) -> String {
        if self.port == self.scheme.default_port() {
            self.host.to_string()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Origin-form `path[?query]` for the forwarded request line (D-09).
    pub fn origin_form(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{q}", self.path),
            None => self.path.clone(),
        }
    }
}

/// Where the raw target came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetContext<'a> {
    /// Absolute-form on the plain listener (`http://host/path`).
    PlainAbsolute,
    /// CONNECT authority-form (`host:port`).
    ConnectAuthority,
    /// Origin-form inside an intercepted tunnel; host and port come from the CONNECT.
    InterceptedOrigin {
        /// Normalized CONNECT host.
        connect_host: &'a str,
        /// CONNECT port.
        port: u16,
    },
}

/// Why a target was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    /// Malformed or ambiguous target (400 `invalid_request`).
    #[error("invalid request target: {0}")]
    Invalid(&'static str),
    /// The two parsers disagree (400 `parser_differential`).
    #[error("request target parsers disagree")]
    ParserDifferential,
    /// Userinfo in the authority (403 `userinfo_in_url`).
    #[error("userinfo in URL")]
    UserInfo,
}

impl TargetError {
    /// The reason to log and return.
    pub fn reason(&self) -> Reason {
        match self {
            TargetError::Invalid(_) => Reason::InvalidRequest,
            TargetError::ParserDifferential => Reason::ParserDifferential,
            TargetError::UserInfo => Reason::UserinfoInUrl,
        }
    }
}

use TargetError::{Invalid, ParserDifferential, UserInfo};

/// Canonicalize a raw request-target (SPEC 4.5).
///
/// ```
/// use webfilter::normalize::{canonicalize, TargetContext};
/// let t = canonicalize("http://EVIL.com:80/a/../%61dmin/", TargetContext::PlainAbsolute).unwrap();
/// assert_eq!(t.url_norm, "http://evil.com/admin/");
/// ```
pub fn canonicalize(raw: &str, ctx: TargetContext<'_>) -> Result<NormalizedTarget, TargetError> {
    precheck(raw)?;
    match ctx {
        TargetContext::PlainAbsolute => {
            check_userinfo(raw)?;
            parse_absolute(raw, false)
        }
        TargetContext::ConnectAuthority => {
            if raw.contains('@') {
                return Err(UserInfo);
            }
            if raw.contains(['/', '?']) {
                return Err(Invalid("CONNECT target must be host:port"));
            }
            parse_absolute(&format!("https://{raw}/"), true)
        }
        TargetContext::InterceptedOrigin { connect_host, port } => {
            if !raw.starts_with('/') {
                check_userinfo(raw)?;
                return parse_absolute(raw, false);
            }
            let host = if connect_host.contains(':') {
                format!("[{connect_host}]")
            } else {
                connect_host.to_owned()
            };
            parse_absolute(&format!("https://{host}:{port}{raw}"), false)
        }
    }
}

/// Step 1: bytes that are never allowed anywhere in a target.
fn precheck(raw: &str) -> Result<(), TargetError> {
    if raw.is_empty() {
        return Err(Invalid("empty target"));
    }
    for b in raw.bytes() {
        match b {
            0..=0x20 | 0x7F.. => return Err(Invalid("control, space or non-ASCII byte")),
            b'\\' => return Err(Invalid("backslash")),
            b'#' => return Err(Invalid("fragment")),
            _ => {}
        }
    }
    if raw.to_ascii_lowercase().contains("%00") {
        return Err(Invalid("encoded NUL"));
    }
    Ok(())
}

/// `@` anywhere in the authority of an absolute-form target is userinfo.
fn check_userinfo(raw: &str) -> Result<(), TargetError> {
    let (_, rest) = raw.split_once("://").ok_or(Invalid("absolute-form target required"))?;
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.contains('@') { Err(UserInfo) } else { Ok(()) }
}

fn parse_absolute(s: &str, require_port: bool) -> Result<NormalizedTarget, TargetError> {
    let a: http::Uri = s.parse().map_err(|_| Invalid("unparseable target"))?;
    let b = url::Url::parse(s).map_err(|_| Invalid("unparseable target"))?;

    let scheme = match a.scheme_str().map(str::to_ascii_lowercase).as_deref() {
        Some("http") => Scheme::Http,
        Some("https") => Scheme::Https,
        _ => return Err(Invalid("scheme must be http or https")),
    };
    if b.scheme() != scheme.as_str() {
        return Err(ParserDifferential);
    }

    let host = normalize_host(a.host().ok_or(Invalid("missing host"))?, b.host())?;

    let port = match (a.port(), a.port_u16()) {
        (None, _) if require_port => return Err(Invalid("CONNECT target must be host:port")),
        (None, _) => scheme.default_port(),
        (Some(_), Some(p)) if p != 0 => p,
        _ => return Err(Invalid("port must be 1-65535")),
    };
    if b.port_or_known_default() != Some(port) {
        return Err(ParserDifferential);
    }

    let path = normalize_path(a.path())?;
    if decode_once(&path) != decode_once(&normalize_path(b.path())?) {
        return Err(ParserDifferential);
    }
    let query = a.query().map(str::to_owned);
    if query.as_deref().map(decode_once) != b.query().map(decode_once) {
        return Err(ParserDifferential);
    }

    let authority =
        if port == scheme.default_port() { host.to_string() } else { format!("{host}:{port}") };
    let prefix = format!("{}://{authority}", scheme.as_str());
    let pq = match &query {
        Some(q) => format!("{path}?{q}"),
        None => path.clone(),
    };
    let once = decode_once(&pq);
    let twice = decode_once(&once);
    Ok(NormalizedTarget {
        scheme,
        host,
        port,
        suspicious_encoding: twice != once,
        url_norm: format!("{prefix}{pq}"),
        views: [format!("{prefix}{pq}"), format!("{prefix}{once}"), format!("{prefix}{twice}")],
        path,
        query,
    })
}

/// Step 3: compare both parsers' hosts and produce the canonical host.
fn normalize_host(a_raw: &str, b: Option<url::Host<&str>>) -> Result<Host, TargetError> {
    match b.ok_or(Invalid("missing host"))? {
        url::Host::Ipv6(b6) => {
            let inner = a_raw.strip_prefix('[').and_then(|s| s.strip_suffix(']'));
            let inner = inner.ok_or(ParserDifferential)?;
            if inner.contains('%') {
                return Err(Invalid("IPv6 zone id"));
            }
            let a6: Ipv6Addr = inner.parse().map_err(|_| ParserDifferential)?;
            if a6 != b6 {
                return Err(ParserDifferential);
            }
            Ok(Host::Ipv6(a6))
        }
        url::Host::Ipv4(b4) => {
            // std rejects octal, hex, short and leading-zero forms; url accepts them.
            let a4: Ipv4Addr = a_raw.parse().map_err(|_| ParserDifferential)?;
            if a4 != b4 || a4.to_string() != a_raw {
                return Err(ParserDifferential);
            }
            Ok(Host::Ipv4(a4))
        }
        url::Host::Domain(d) => {
            let a_lower = a_raw.to_ascii_lowercase();
            let host = strip_one_dot(&a_lower)?;
            if host != strip_one_dot(d)? {
                return Err(ParserDifferential);
            }
            validate_domain(host)?;
            Ok(Host::Domain(host.to_owned()))
        }
    }
}

fn strip_one_dot(host: &str) -> Result<&str, TargetError> {
    if host.ends_with("..") {
        return Err(Invalid("multiple trailing dots"));
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() { Err(Invalid("empty host")) } else { Ok(host) }
}

/// UTS-46 strict (STD3, DNS lengths); `xn--` labels must round-trip to a non-ASCII label.
fn validate_domain(host: &str) -> Result<(), TargetError> {
    let bad = Invalid("invalid host name");
    if idna::domain_to_ascii_strict(host).map_err(|_| bad.clone())? != host {
        return Err(bad);
    }
    for label in host.split('.').filter(|l| l.starts_with("xn--")) {
        let (unicode, res) = idna::domain_to_unicode(label);
        if res.is_err() || unicode.is_ascii() {
            return Err(bad);
        }
    }
    Ok(())
}

/// Step 5: decode escapes of unreserved characters, uppercase the rest, remove dot segments.
pub fn normalize_path(raw: &str) -> Result<String, TargetError> {
    let raw = if raw.is_empty() { "/" } else { raw };
    let mut out = String::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(b) = bytes.next() {
        if b != b'%' {
            out.push(char::from(b));
            continue;
        }
        let hex = (bytes.next().and_then(hex_val), bytes.next().and_then(hex_val));
        let (Some(hi), Some(lo)) = hex else {
            return Err(Invalid("malformed percent-escape"));
        };
        let v = hi << 4 | lo;
        if v.is_ascii_alphanumeric() || matches!(v, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(v));
        } else {
            out.push_str(&format!("%{v:02X}"));
        }
    }
    if !out.starts_with('/') {
        return Err(Invalid("path must start with '/'"));
    }
    Ok(remove_dot_segments(&out))
}

/// RFC 3986 section 5.2.4; `//` is not collapsed.
fn remove_dot_segments(path: &str) -> String {
    let mut input = path.to_owned();
    let mut out = String::with_capacity(path.len());
    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix("../").or_else(|| input.strip_prefix("./")) {
            input = rest.to_owned();
        } else if let Some(rest) = input.strip_prefix("/./") {
            input = format!("/{rest}");
        } else if input == "/." {
            input = "/".to_owned();
        } else if let Some(rest) = input.strip_prefix("/../") {
            input = format!("/{rest}");
            out.truncate(out.rfind('/').unwrap_or(0));
        } else if input == "/.." {
            input = "/".to_owned();
            out.truncate(out.rfind('/').unwrap_or(0));
        } else if input == "." || input == ".." {
            input.clear();
        } else {
            let start = usize::from(input.starts_with('/'));
            let end =
                input.get(start..).and_then(|s| s.find('/')).map_or(input.len(), |i| i + start);
            let rest = input.split_off(end);
            out.push_str(&input);
            input = rest;
        }
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    char::from(b).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// Percent-decode once (malformed escapes kept literally); invalid UTF-8 is replaced lossily.
pub fn decode_once(s: &str) -> String {
    let src = s.as_bytes();
    let mut out = Vec::with_capacity(src.len());
    let mut i = 0;
    while let Some(&b) = src.get(i) {
        let hex =
            (src.get(i + 1).copied().and_then(hex_val), src.get(i + 2).copied().and_then(hex_val));
        match (b, hex) {
            (b'%', (Some(hi), Some(lo))) => {
                out.push(hi << 4 | lo);
                i += 3;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
