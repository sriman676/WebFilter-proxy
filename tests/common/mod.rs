//! Shared integration-test harness (TEST_PLAN 2): temp labs, recording origin servers, an
//! injectable resolver, an in-process proxy and a raw TCP client for byte-exact payloads.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A temporary lab directory holding a config file and empty blocklists.
pub struct Lab {
    pub dir: tempfile::TempDir,
}

impl Lab {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let lists = dir.path().join("blocklists");
        std::fs::create_dir(&lists).unwrap();
        for f in ["domains.txt", "url_patterns.txt", "ip_blocklist.txt"] {
            std::fs::write(lists.join(f), "").unwrap();
        }
        Self { dir }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Write `config.toml` into the lab and return its path.
    pub fn write_config(&self, body: &str) -> PathBuf {
        let p = self.path().join("config.toml");
        std::fs::write(&p, body).unwrap();
        p
    }

    pub fn write_list(&self, name: &str, body: &str) {
        std::fs::write(self.path().join("blocklists").join(name), body).unwrap();
    }
}

/// Repository root (for shipped config files).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

// ---------------------------------------------------------------------------------------------
// Resolver

/// `TestResolver`: static name -> IPs map (or a scripted sequence), counts lookups.
#[derive(Default)]
pub struct TestResolver {
    pub map: Mutex<HashMap<String, Vec<Vec<IpAddr>>>>,
    pub lookups: AtomicUsize,
}

impl TestResolver {
    pub fn with(entries: &[(&str, &str)]) -> Arc<Self> {
        let r = Self::default();
        for (name, ip) in entries {
            r.map.lock().unwrap().insert((*name).to_owned(), vec![vec![ip.parse().unwrap()]]);
        }
        Arc::new(r)
    }

    /// Successive lookups of `name` return successive answers (DNS rebinding simulation).
    pub fn script(&self, name: &str, answers: Vec<Vec<IpAddr>>) {
        self.map.lock().unwrap().insert(name.to_owned(), answers);
    }

    pub fn count(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl webfilter::policy::Resolver for TestResolver {
    fn resolve<'a>(&'a self, host: &'a str, _port: u16) -> webfilter::policy::ResolveFuture<'a> {
        let n = self.lookups.fetch_add(1, Ordering::SeqCst);
        let answer = self
            .map
            .lock()
            .unwrap()
            .get(host)
            .and_then(|seq| seq.get(n.min(seq.len().saturating_sub(1))).cloned());
        Box::pin(async move { answer.ok_or_else(|| std::io::Error::other("NXDOMAIN")) })
    }
}

// ---------------------------------------------------------------------------------------------
// Origin

/// What an origin does with one request.
#[derive(Clone, Default)]
pub struct Reply {
    pub bytes: Vec<u8>,
    /// Sent right after the request head, before the body is read (e.g. `100 Continue`).
    pub interim: Option<Vec<u8>>,
    pub delay: Duration,
    /// After the reply, echo bytes back until EOF (tunnels/websockets).
    pub echo: bool,
}

impl Reply {
    pub fn ok(body: &str) -> Self {
        Self::raw(format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        ))
    }

    pub fn raw(s: impl Into<Vec<u8>>) -> Self {
        Self { bytes: s.into(), ..Self::default() }
    }
}

type Handler = Arc<dyn Fn(&[u8]) -> Reply + Send + Sync>;

/// A recording HTTP origin on 127.0.0.1:0. Every received request (head + body) is recorded.
pub struct Origin {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Read one request: head, then a Content-Length or chunked body (naive, independent parser).
async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    interim: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        if let Some(i) = find(buf, b"\r\n\r\n") {
            break i + 4;
        }
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    if let Some(i) = interim(&buf[..head_end]) {
        s.write_all(&i).await.ok()?;
    }
    // Only scan bytes not yet searched (keeps large chunked bodies linear).
    let mut scanned = head_end;
    let mut need_end = |b: &[u8]| -> Option<usize> {
        if let Some(cl) = head.lines().find_map(|l| l.strip_prefix("content-length:")) {
            let n: usize = cl.trim().parse().ok()?;
            (b.len() >= head_end + n).then_some(head_end + n)
        } else if head.contains("transfer-encoding: chunked") {
            let from = scanned.saturating_sub(4).max(head_end);
            scanned = b.len();
            find(&b[from..], b"0\r\n\r\n").map(|i| from + i + 5)
        } else {
            Some(head_end)
        }
    };
    loop {
        if let Some(end) = need_end(buf) {
            let req: Vec<u8> = buf.drain(..end).collect();
            return Some(req);
        }
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Serve requests on one connection until EOF (a proxy must never reuse it, D-07).
async fn serve_conn<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    rec: Arc<Mutex<Vec<Vec<u8>>>>,
    handler: Handler,
) {
    let mut buf = Vec::new();
    while let Some(req) = read_request(&mut s, &mut buf, |h| handler(h).interim).await {
        rec.lock().unwrap().push(req.clone());
        let reply = handler(&req);
        tokio::time::sleep(reply.delay).await;
        if s.write_all(&reply.bytes).await.is_err() {
            return;
        }
        if reply.echo {
            let (mut r, mut w) = tokio::io::split(s);
            let _ = tokio::io::copy(&mut r, &mut w).await;
            return;
        }
    }
    let _ = s.shutdown().await;
}

impl Origin {
    pub async fn start(handler: impl Fn(&[u8]) -> Reply + Send + Sync + 'static) -> Self {
        Self::start_inner(None, handler).await
    }

    /// An HTTPS origin presenting `certs` (TLS 1.2/1.3, ring provider).
    pub async fn start_tls(
        certs: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
        handler: impl Fn(&[u8]) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs.0, certs.1)
            .unwrap();
        Self::start_inner(Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))), handler).await
    }

    async fn start_inner(
        tls: Option<tokio_rustls::TlsAcceptor>,
        handler: impl Fn(&[u8]) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handler: Handler = Arc::new(handler);
        let rec = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else { return };
                let (rec, handler, tls) = (Arc::clone(&rec), Arc::clone(&handler), tls.clone());
                tokio::spawn(async move {
                    match tls {
                        Some(acceptor) => {
                            if let Ok(t) = acceptor.accept(s).await {
                                serve_conn(t, rec, handler).await;
                            }
                        }
                        None => serve_conn(s, rec, handler).await,
                    }
                });
            }
        });
        Self { addr, seen }
    }

    pub fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().iter().map(|r| String::from_utf8_lossy(r).into_owned()).collect()
    }
}

// ---------------------------------------------------------------------------------------------
// Test PKI

/// `TestPki`: a throwaway CA and leaves (valid, wrong-name, expired, untrusted). Never leaves tmp.
pub struct TestPki {
    pub ca_pem: String,
    ca_params: rcgen::CertificateParams,
    ca_key: rcgen::KeyPair,
}

impl TestPki {
    pub fn new() -> Self {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "webfilter test CA");
        let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
        Self { ca_pem, ca_params, ca_key }
    }

    /// A leaf for `names`; `expired` sets a validity window in the past.
    pub fn leaf(
        &self,
        names: &[&str],
        expired: bool,
    ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(
            names.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        )
        .unwrap();
        if expired {
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        }
        let issuer = rcgen::Issuer::from_params(&self.ca_params, &self.ca_key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        (vec![cert.der().clone()], PrivateKeyDer::Pkcs8(key.serialize_der().into()))
    }

    /// Write the CA certificate to `dir/ca.pem` (public cert only).
    pub fn write_ca(&self, dir: &Path) -> PathBuf {
        let p = dir.join("test-ca.pem");
        std::fs::write(&p, &self.ca_pem).unwrap();
        p
    }
}

// ---------------------------------------------------------------------------------------------
// Proxy harness

pub struct ProxyHarness {
    pub lab: Lab,
    pub handle: Option<webfilter::proxy::ProxyHandle>,
    pub addr: SocketAddr,
    pub resolver: Arc<TestResolver>,
}

/// Base config for tests: loopback, any port, private ranges allowed (local origins), short timeouts.
pub fn base_config(extra: &str) -> String {
    format!(
        "listen = \"127.0.0.1:0\"\n{extra}\n[ports]\nhttp_allowed = \"any\"\nconnect_allowed = \"any\"\n\
[destination]\ndeny_private_ranges = false\n[logging]\ndir = \"logs\"\n"
    )
}

impl ProxyHarness {
    /// Start a proxy with `config` (TOML), lists, and a resolver mapping names to 127.0.0.1.
    pub async fn start(config: &str, lists: &[(&str, &str)], resolver: Arc<TestResolver>) -> Self {
        let lab = Lab::new();
        for (name, body) in lists {
            lab.write_list(name, body);
        }
        let path = lab.write_config(config);
        let cfg = webfilter::config::Config::load(&path).unwrap();
        let handle = webfilter::proxy::start(
            cfg,
            Some(resolver.clone() as Arc<dyn webfilter::policy::Resolver>),
        )
        .await
        .unwrap();
        let addr = handle.local_addr;
        Self { lab, handle: Some(handle), addr, resolver }
    }

    pub async fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.shutdown().await;
        }
    }

    /// Parsed request log lines (call after `stop`).
    pub fn log_lines(&self) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(self.lab.path().join("logs/webfilter.jsonl"))
            .unwrap_or_default();
        text.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    pub fn system_lines(&self) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(self.lab.path().join("logs/webfilter_system.jsonl"))
            .unwrap_or_default();
        text.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    /// Send raw bytes, read the full answer until the proxy closes (or `wait` passes).
    pub async fn raw(&self, bytes: &[u8], wait: Duration) -> String {
        raw_exchange(self.addr, bytes, wait).await
    }
}

/// `RawClient`: write bytes, then read until EOF or timeout.
pub async fn raw_exchange(addr: SocketAddr, bytes: &[u8], wait: Duration) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(bytes).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(wait, s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// Status code of the first response in `resp`.
pub fn status(resp: &str) -> u16 {
    resp.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}
