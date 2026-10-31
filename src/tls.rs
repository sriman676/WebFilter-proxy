//! TLS interception (SPEC 4.9, D-19..D-22): local CA, leaf minting with a bounded cache, the
//! always-verifying upstream config (D-20), a strict ClientHello peek (SNI, ALPN, ECH) and a stream
//! that replays the peeked bytes into rustls.
#![forbid(unsafe_code)]

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
    SerialNumber,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::normalize::Host;

/// CA validity (D-19).
pub const CA_VALIDITY_DAYS: i64 = 3 * 365;
/// Leaf validity (D-19).
pub const LEAF_VALIDITY: Duration = Duration::from_secs(24 * 3600);
/// Leaf cache capacity and TTL (D-19).
pub const LEAF_CACHE_MAX: u64 = 10_000;
/// Leaf cache time-to-live.
pub const LEAF_CACHE_TTL: Duration = Duration::from_secs(12 * 3600);
/// ClientHello size limit while peeking.
pub const MAX_CLIENT_HELLO: usize = 64 * 1024;
/// Common name of generated CAs.
pub const CA_COMMON_NAME: &str = "WebFilter Proxy Local CA";

/// TLS errors.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// CA files missing, unreadable, or with unsafe permissions/ownership.
    #[error("CA: {0}")]
    Ca(String),
    /// Certificate generation failed.
    #[error("certificate: {0}")]
    Cert(String),
    /// rustls configuration failed.
    #[error("tls config: {0}")]
    Config(String),
}

fn ca_err(e: impl std::fmt::Display) -> TlsError {
    TlsError::Ca(e.to_string())
}

/// The running user's uid (Linux `/proc/self/status`); `None` elsewhere.
#[cfg(unix)]
fn current_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|l| l.strip_prefix("Uid:"))?.split_whitespace().nth(1)?.parse().ok()
}

/// Read a secret file safely: regular file (not a symlink), mode without group/other bits, owned
/// by the current user; checks run on the opened handle so a swap after `lstat` is detected.
pub fn read_private_file(path: &Path) -> Result<Zeroizing<String>, TlsError> {
    let link =
        std::fs::symlink_metadata(path).map_err(|e| ca_err(format!("{}: {e}", path.display())))?;
    if !link.file_type().is_file() {
        return Err(ca_err(format!(
            "{} must be a regular file (symlinks are refused)",
            path.display()
        )));
    }
    let mut file =
        std::fs::File::open(path).map_err(|e| ca_err(format!("{}: {e}", path.display())))?;
    let meta = file.metadata().map_err(ca_err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if (meta.dev(), meta.ino()) != (link.dev(), link.ino()) {
            return Err(ca_err(format!("{} changed while opening", path.display())));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ca_err(format!(
                "{} has mode {mode:o}; must be 0600 (D-19)",
                path.display()
            )));
        }
        if current_uid().is_some_and(|uid| uid != meta.uid()) {
            return Err(ca_err(format!("{} is owned by another user", path.display())));
        }
    }
    let mut text = Zeroizing::new(String::new());
    io::Read::read_to_string(&mut file, &mut text).map_err(ca_err)?;
    Ok(text)
}

/// The local CA (`ca.pem` public, `ca.key` 0600).
pub struct CaStore {
    issuer: Issuer<'static, KeyPair>,
    /// Public certificate PEM (`webfilter-proxy ca export`).
    pub cert_pem: String,
}

impl std::fmt::Debug for CaStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CaStore(<key redacted>)")
    }
}

impl CaStore {
    /// `ca.pem` and `ca.key` inside `dir`.
    pub fn paths(dir: &Path) -> (PathBuf, PathBuf) {
        (dir.join("ca.pem"), dir.join("ca.key"))
    }

    /// Generate a new CA into `dir` (created 0700); refuses to overwrite an existing key.
    pub fn generate(dir: &Path) -> Result<Self, TlsError> {
        let (cert_path, key_path) = Self::paths(dir);
        if key_path.exists() || cert_path.exists() {
            return Err(ca_err(format!(
                "{} already holds a CA; refusing to overwrite",
                dir.display()
            )));
        }
        std::fs::create_dir_all(dir).map_err(ca_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(ca_err)?;
        }
        let key = KeyPair::generate().map_err(|e| TlsError::Cert(e.to_string()))?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| TlsError::Cert(e.to_string()))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.distinguished_name.push(DnType::CommonName, CA_COMMON_NAME);
        params.distinguished_name.push(DnType::OrganizationName, "WebFilter (local lab)");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(CA_VALIDITY_DAYS);
        params.serial_number = Some(random_serial()?);
        let cert = params.self_signed(&key).map_err(|e| TlsError::Cert(e.to_string()))?;
        let key_pem = Zeroizing::new(key.serialize_pem());
        write_new(&key_path, key_pem.as_bytes(), 0o600)?;
        write_new(&cert_path, cert.pem().as_bytes(), 0o644)?;
        Self::load(dir)
    }

    /// Load an existing CA; the key file must pass [`read_private_file`].
    pub fn load(dir: &Path) -> Result<Self, TlsError> {
        let (cert_path, key_path) = Self::paths(dir);
        let key_pem = read_private_file(&key_path)?;
        let cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| ca_err(format!("{}: {e}", cert_path.display())))?;
        let key = KeyPair::from_pem(&key_pem).map_err(|e| ca_err(format!("ca.key: {e}")))?;
        let issuer =
            Issuer::from_ca_cert_pem(&cert_pem, key).map_err(|e| ca_err(format!("ca.pem: {e}")))?;
        Ok(Self { issuer, cert_pem })
    }

    /// Mint a leaf for exactly `host` (D-19): fresh P-256 key, 24 h validity, unique serial.
    pub fn mint(
        &self,
        host: &Host,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
        let cert_err = |e: rcgen::Error| TlsError::Cert(e.to_string());
        let key = KeyPair::generate().map_err(cert_err)?;
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(cert_err)?;
        params.subject_alt_names = vec![match host {
            Host::Domain(d) => SanType::DnsName(d.clone().try_into().map_err(cert_err)?),
            Host::Ipv4(v4) => SanType::IpAddress((*v4).into()),
            Host::Ipv6(v6) => SanType::IpAddress((*v6).into()),
        }];
        params.distinguished_name.push(DnType::CommonName, host.to_string());
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + LEAF_VALIDITY;
        params.serial_number = Some(random_serial()?);
        let cert = params.signed_by(&key, &self.issuer).map_err(cert_err)?;
        Ok((vec![cert.der().clone()], PrivateKeyDer::Pkcs8(key.serialize_der().into())))
    }
}

fn random_serial() -> Result<SerialNumber, TlsError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| TlsError::Cert(e.to_string()))?;
    bytes[0] &= 0x7f; // positive
    Ok(SerialNumber::from_slice(&bytes))
}

fn write_new(path: &Path, data: &[u8], mode: u32) -> Result<(), TlsError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, mode);
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(path).map_err(|e| ca_err(format!("{}: {e}", path.display())))?;
    io::Write::write_all(&mut f, data).map_err(ca_err)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Server configs per host, minted on demand and cached (bounded, 12 h TTL).
pub struct LeafCache {
    ca: CaStore,
    cache: moka::sync::Cache<String, Arc<rustls::ServerConfig>>,
}

impl LeafCache {
    /// A cache minting from `ca`.
    pub fn new(ca: CaStore) -> Self {
        let cache = moka::sync::Cache::builder()
            .max_capacity(LEAF_CACHE_MAX)
            .time_to_live(LEAF_CACHE_TTL)
            .build();
        Self { ca, cache }
    }

    /// The CA's public certificate.
    pub fn ca_pem(&self) -> &str {
        &self.ca.cert_pem
    }

    /// TLS 1.2/1.3 server config presenting a leaf for `host` and offering exactly `alpn`
    /// (the protocol the origin selected, D-40; empty = no ALPN).
    pub fn server_config_for(
        &self,
        host: &Host,
        alpn: Vec<Vec<u8>>,
    ) -> Result<Arc<rustls::ServerConfig>, TlsError> {
        let base = self.leaf_config(host)?;
        if base.alpn_protocols == alpn {
            return Ok(base);
        }
        let mut config = (*base).clone();
        config.alpn_protocols = alpn;
        Ok(Arc::new(config))
    }

    /// The cached leaf config (ALPN `http/1.1`).
    fn leaf_config(&self, host: &Host) -> Result<Arc<rustls::ServerConfig>, TlsError> {
        let key = host.to_string();
        if let Some(c) = self.cache.get(&key) {
            return Ok(c);
        }
        let (certs, private) = self.ca.mint(host)?;
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::Config(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certs, private)
            .map_err(|e| TlsError::Config(e.to_string()))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        self.cache.insert(key, Arc::clone(&config));
        Ok(config)
    }

    /// Number of cached leaves (tests).
    pub fn cached(&self) -> u64 {
        self.cache.run_pending_tasks();
        self.cache.entry_count()
    }
}

/// Upstream client config: certificate verification ALWAYS on (D-20); webpki roots plus
/// optional extra roots. There is no switch to disable verification.
pub fn upstream_client_config(
    extra_roots: &[PathBuf],
) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    for path in extra_roots {
        let pem = std::fs::read(path)
            .map_err(|e| TlsError::Config(format!("{}: {e}", path.display())))?;
        for cert in CertificateDer::pem_slice_iter(&pem) {
            let cert = cert.map_err(|e| TlsError::Config(format!("{}: {e}", path.display())))?;
            roots.add(cert).map_err(|e| TlsError::Config(format!("{}: {e}", path.display())))?;
        }
    }
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// `host` matches a passthrough pattern: exact host or `*.suffix` (subdomains only).
pub fn is_passthrough(host: &str, patterns: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    patterns.iter().any(|p| {
        let p = p.trim().trim_end_matches('.').to_ascii_lowercase();
        match p.strip_prefix("*.") {
            Some(suffix) => host.strip_suffix(suffix).is_some_and(|rest| rest.ends_with('.')),
            None => host == p,
        }
    })
}

// ---------------------------------------------------------------------------------------------
// ClientHello peek

/// What the proxy needs from a ClientHello.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// SNI host name (lowercase), if any.
    pub sni: Option<String>,
    /// Offered ALPN protocols.
    pub alpn: Vec<Vec<u8>>,
    /// An ECH extension (0xfe0d) is present (D-21).
    pub ech_present: bool,
}

/// Result of inspecting the first bytes of a tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peek {
    /// Need more bytes.
    Incomplete,
    /// Not a TLS handshake (plain HTTP, SSH banner, ...).
    NotTls,
    /// A complete, well-formed ClientHello.
    Hello(ClientHelloInfo),
    /// Looks like TLS but is malformed or too large.
    Malformed(&'static str),
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = (self.data.get(..n)?, self.data.get(n..)?);
        self.data = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<usize> {
        self.take(1).and_then(|b| b.first()).map(|b| usize::from(*b))
    }
    fn u16(&mut self) -> Option<usize> {
        self.take(2).map(|b| b.iter().fold(0usize, |a, x| a << 8 | usize::from(*x)))
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3).map(|b| b.iter().fold(0usize, |a, x| a << 8 | usize::from(*x)))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
}

/// Inspect buffered tunnel bytes: reassemble handshake records and parse the ClientHello.
pub fn peek_client_hello(buf: &[u8]) -> Peek {
    match buf.first() {
        None => return Peek::Incomplete,
        Some(0x16) => {}
        Some(_) => return Peek::NotTls,
    }
    if buf.len() > MAX_CLIENT_HELLO {
        return Peek::Malformed("ClientHello too large");
    }
    // Concatenate handshake-record payloads until the handshake message is complete.
    let mut payload = Vec::new();
    let mut rest = buf;
    loop {
        let Some(header) = rest.get(..5) else { return Peek::Incomplete };
        if header.first() != Some(&0x16) || header.get(1) != Some(&0x03) {
            return Peek::Malformed("not a TLS handshake record");
        }
        let len = usize::from(header.get(3).copied().unwrap_or(0)) << 8
            | usize::from(header.get(4).copied().unwrap_or(0));
        if len == 0 || len > 16_384 {
            return Peek::Malformed("bad record length");
        }
        let Some(body) = rest.get(5..5 + len) else { return Peek::Incomplete };
        payload.extend_from_slice(body);
        rest = rest.get(5 + len..).unwrap_or(&[]);
        if payload.len() >= 4 {
            let need = 4
                + (usize::from(payload.get(1).copied().unwrap_or(0)) << 16
                    | usize::from(payload.get(2).copied().unwrap_or(0)) << 8
                    | usize::from(payload.get(3).copied().unwrap_or(0)));
            if payload.len() >= need {
                break;
            }
        }
    }
    match parse_hello(&payload) {
        Some(info) => Peek::Hello(info),
        None => Peek::Malformed("malformed ClientHello"),
    }
}

fn parse_hello(msg: &[u8]) -> Option<ClientHelloInfo> {
    let mut r = Reader { data: msg };
    if r.u8()? != 1 {
        return None; // not ClientHello
    }
    let len = r.u24()?;
    let mut r = Reader { data: r.take(len)? };
    r.take(2)?; // legacy_version
    r.take(32)?; // random
    r.vec8()?; // session id
    r.vec16()?; // cipher suites
    r.vec8()?; // compression methods
    let mut info = ClientHelloInfo::default();
    let Some(ext) = r.vec16() else { return Some(info) }; // no extensions
    let mut ext = Reader { data: ext };
    while !ext.data.is_empty() {
        let kind = ext.u16()?;
        let mut body = Reader { data: ext.vec16()? };
        match kind {
            0x0000 => {
                let mut list = Reader { data: body.vec16()? };
                while !list.data.is_empty() {
                    let name_type = list.u8()?;
                    let name = list.vec16()?;
                    if name_type == 0 {
                        let name = std::str::from_utf8(name).ok()?;
                        if name.is_empty()
                            || !name.bytes().all(|b| b.is_ascii_graphic())
                            || info.sni.is_some()
                        {
                            return None;
                        }
                        info.sni = Some(name.to_ascii_lowercase());
                    }
                }
            }
            0x0010 => {
                let mut list = Reader { data: body.vec16()? };
                while !list.data.is_empty() {
                    info.alpn.push(list.vec8()?.to_vec());
                }
            }
            0xfe0d => info.ech_present = true,
            _ => {}
        }
    }
    Some(info)
}

/// A stream that first yields `prefix` (bytes already read while peeking), then the inner stream.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    /// Wrap `inner`, replaying `prefix` first.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(rest) = self.prefix.get(self.pos..).filter(|r| !r.is_empty()) {
            let n = rest.len().min(buf.remaining());
            buf.put_slice(rest.get(..n).unwrap_or(&[]));
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
