//! The fetch client (SPEC 5, D-25, D-26): explicit proxy only, manual CONNECT so blocks are
//! visible, TLS always verified, redirects re-validated per hop, size/time caps, atomic
//! no-clobber saves named by SPEC 5.3.
#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use url::Url;

use crate::naming::{output_filename, write_unique};
use crate::proxy::http1::{Limits, parse_response_head, single};
use crate::proxy::io::{IoError, read_head};

/// Client settings (SPEC 5.1).
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Proxy (`http://host:port`); env proxies are never used (D-25).
    pub proxy: Url,
    /// Proxy credentials (user, password).
    pub proxy_auth: Option<(String, String)>,
    /// Output directory.
    pub out_dir: PathBuf,
    /// Explicit output name (single URL only).
    pub name: Option<String>,
    /// Extra trusted roots (PEM files).
    pub ca_certs: Vec<PathBuf>,
    /// Concurrent fetches.
    pub jobs: usize,
    /// Whole-fetch timeout.
    pub timeout: Duration,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Redirect limit.
    pub max_redirects: usize,
    /// Body size limit.
    pub max_bytes: u64,
    /// Save block pages as `<name>.blocked.html`.
    pub save_blocked: bool,
    /// `User-Agent`.
    pub user_agent: String,
}

/// Why a fetch was blocked (from the proxy's block response).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BlockInfo {
    /// `X-WebFilter-Event-Id`.
    pub event_id: Option<String>,
    /// `X-WebFilter-Reason`.
    pub reason: Option<String>,
}

/// Fetch failure classes; all exit 1 except `Usage` (2 when before any fetch, else 1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// Invalid URL or scheme.
    #[error("usage: {0}")]
    Usage(String),
    /// Connection, DNS or proxy error.
    #[error("network: {0}")]
    Network(String),
    /// TLS handshake or verification failure.
    #[error("tls: {0}")]
    Tls(String),
    /// Unexpected HTTP from proxy or origin.
    #[error("protocol: {0}")]
    Protocol(String),
    /// Redirect loop, limit or bad target.
    #[error("redirect: {0}")]
    Redirect(String),
    /// Body larger than `--max-bytes`.
    #[error("response exceeds max bytes")]
    TooLarge,
    /// Overall timeout.
    #[error("timeout")]
    Timeout,
    /// Writing the file failed.
    #[error("io: {0}")]
    Io(String),
}

/// Result for one URL (SPEC 5.4 `--json` fields).
#[derive(Debug, Clone, Default, Serialize)]
pub struct FetchResult {
    /// URL as given (userinfo removed).
    pub url: String,
    /// Last URL fetched (after redirects).
    pub final_url: String,
    /// Final status.
    pub status: Option<u16>,
    /// Body bytes received.
    pub bytes: u64,
    /// Response media type.
    pub content_type: Option<String>,
    /// Saved file.
    pub saved_path: Option<PathBuf>,
    /// Blocked by the proxy.
    pub blocked: bool,
    /// Block event id.
    pub event_id: Option<String>,
    /// Block reason.
    pub reason: Option<String>,
    /// Error message.
    pub error: Option<String>,
    /// Duration.
    pub duration_ms: u64,
    /// Non-fatal warnings (encoding, content type, stripped userinfo).
    #[serde(skip)]
    pub warnings: Vec<String>,
    /// Usage error for this URL.
    #[serde(skip)]
    pub usage_error: bool,
}

impl FetchResult {
    /// `OK|BLOCKED|ERROR <status> <bytes> <url> -> <path|reason>` (SPEC 5.4).
    pub fn human_line(&self) -> String {
        let status = self.status.map_or_else(|| "-".to_owned(), |s| s.to_string());
        if self.blocked {
            let detail = format!(
                "{} (event {})",
                self.reason.as_deref().unwrap_or("blocked"),
                self.event_id.as_deref().unwrap_or("-")
            );
            format!("BLOCKED {status} {} {} -> {detail}", self.bytes, self.url)
        } else if let Some(e) = &self.error {
            format!("ERROR {status} {} {} -> {e}", self.bytes, self.url)
        } else {
            let path =
                self.saved_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
            format!("OK {status} {} {} -> {path}", self.bytes, self.url)
        }
    }
}

/// Exit code (SPEC 5.4): 1 any error > 3 any blocked > 0. Usage errors before any fetch are
/// handled by the binary (exit 2).
pub fn exit_code(results: &[FetchResult]) -> i32 {
    if results.iter().any(|r| r.error.is_some()) {
        1
    } else if results.iter().any(|r| r.blocked) {
        3
    } else {
        0
    }
}

/// One HTTP response, body fully read (bounded).
struct Response {
    status: u16,
    headers: hyper::HeaderMap,
    body: Vec<u8>,
}

enum Hop {
    Response(Response),
    Blocked(BlockInfo, Vec<u8>),
}

/// Normalize a user-supplied URL (SPEC 5.2): trim, default `https://`, http/https only, strip
/// userinfo (warning).
pub fn parse_input(raw: &str) -> Result<(Url, Option<String>), ClientError> {
    let raw = raw.trim();
    let with_scheme = if raw.contains("://") { raw.to_owned() } else { format!("https://{raw}") };
    let mut url = Url::parse(&with_scheme)
        .map_err(|e| ClientError::Usage(format!("invalid URL {raw:?}: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ClientError::Usage(format!(
            "unsupported scheme {:?} (http/https only)",
            url.scheme()
        )));
    }
    let mut warning = None;
    if !url.username().is_empty() || url.password().is_some() {
        let _ = url.set_username("");
        let _ = url.set_password(None);
        warning = Some("userinfo removed from URL".to_owned());
    }
    Ok((url, warning))
}

/// Resolve a redirect `Location` against the current URL; only http/https targets (SPEC 5.2).
pub fn next_hop(current: &Url, location: &str) -> Result<Url, ClientError> {
    let next = current.join(location).map_err(|e| ClientError::Redirect(e.to_string()))?;
    if matches!(next.scheme(), "http" | "https") && next.host_str().is_some() {
        Ok(next)
    } else {
        Err(ClientError::Redirect(format!("refusing redirect to {} URL", next.scheme())))
    }
}

fn tls_config(extra: &[PathBuf]) -> Result<Arc<rustls::ClientConfig>, ClientError> {
    let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    for path in extra {
        let pem = std::fs::read(path)
            .map_err(|e| ClientError::Usage(format!("{}: {e}", path.display())))?;
        for cert in CertificateDer::pem_slice_iter(&pem) {
            let cert = cert.map_err(|e| ClientError::Usage(format!("{}: {e}", path.display())))?;
            roots.add(cert).map_err(|e| ClientError::Usage(format!("{}: {e}", path.display())))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The fetcher: shared options and TLS config.
pub struct Client {
    opts: ClientOptions,
    tls: Arc<rustls::ClientConfig>,
}

impl Client {
    /// Build a client; fails on unreadable `--ca-cert` files.
    pub fn new(opts: ClientOptions) -> Result<Self, ClientError> {
        let tls = tls_config(&opts.ca_certs)?;
        Ok(Self { opts, tls })
    }

    fn proxy_authorization(&self) -> Option<String> {
        self.opts.proxy_auth.as_ref().map(|(u, p)| {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
            )
        })
    }

    /// Fetch all URLs with at most `jobs` in flight; results keep the input order.
    pub async fn fetch_all(self: Arc<Self>, urls: Vec<String>) -> Vec<FetchResult> {
        let permits = Arc::new(Semaphore::new(self.opts.jobs.max(1)));
        let tasks: Vec<_> = urls
            .into_iter()
            .map(|u| {
                let (me, permits) = (Arc::clone(&self), Arc::clone(&permits));
                tokio::spawn(async move {
                    let _permit = permits.acquire().await;
                    me.fetch(&u).await
                })
            })
            .collect();
        let mut out = Vec::with_capacity(tasks.len());
        for t in tasks {
            out.push(t.await.unwrap_or_else(|_| FetchResult {
                error: Some("internal error".into()),
                ..FetchResult::default()
            }));
        }
        out
    }

    /// Fetch one URL (with redirects) and save it.
    pub async fn fetch(&self, raw: &str) -> FetchResult {
        let started = Instant::now();
        let mut result = FetchResult { url: raw.trim().to_owned(), ..FetchResult::default() };
        let outcome = match parse_input(raw) {
            Ok((url, warning)) => {
                result.url = url.to_string();
                result.warnings.extend(warning);
                match tokio::time::timeout(self.opts.timeout, self.fetch_url(url, &mut result))
                    .await
                {
                    Ok(r) => r,
                    Err(_) => Err(ClientError::Timeout),
                }
            }
            Err(e) => {
                result.usage_error = true;
                Err(e)
            }
        };
        if let Err(e) = outcome {
            result.error = Some(e.to_string());
        }
        result.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        result
    }

    async fn fetch_url(&self, original: Url, result: &mut FetchResult) -> Result<(), ClientError> {
        let name = self.opts.name.clone().unwrap_or_else(|| output_filename(original.as_str()));
        let mut url = original;
        let mut visited = HashSet::new();
        loop {
            result.final_url = url.to_string();
            if !visited.insert(url.to_string()) {
                return Err(ClientError::Redirect("redirect loop".into()));
            }
            match self.hop(&url).await? {
                Hop::Blocked(info, page) => {
                    result.blocked = true;
                    result.status = Some(403);
                    result.event_id = info.event_id;
                    result.reason = info.reason;
                    if self.opts.save_blocked {
                        let stem = name.strip_suffix(".html").unwrap_or(&name);
                        result.saved_path =
                            Some(self.save(&format!("{stem}.blocked.html"), page).await?);
                    }
                    return Ok(());
                }
                Hop::Response(resp) => {
                    result.status = Some(resp.status);
                    let location =
                        resp.headers.get(hyper::header::LOCATION).and_then(|v| v.to_str().ok());
                    if matches!(resp.status, 301 | 302 | 303 | 307 | 308) && location.is_some() {
                        if visited.len() > self.opts.max_redirects {
                            return Err(ClientError::Redirect(format!(
                                "more than {} redirects",
                                self.opts.max_redirects
                            )));
                        }
                        url = next_hop(&url, location.unwrap_or(""))?;
                        continue;
                    }
                    result.bytes = resp.body.len() as u64;
                    let header =
                        |n| resp.headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_owned);
                    result.content_type = header(hyper::header::CONTENT_TYPE)
                        .map(|c| c.split(';').next().unwrap_or("").trim().to_owned());
                    if !(200..300).contains(&resp.status) {
                        return Err(ClientError::Protocol(format!("HTTP {}", resp.status)));
                    }
                    if result.content_type.as_deref().is_some_and(|c| c != "text/html") {
                        result.warnings.push(format!(
                            "content type is {}, saved as .html anyway",
                            result.content_type.as_deref().unwrap_or("")
                        ));
                    }
                    if header(hyper::header::CONTENT_ENCODING)
                        .is_some_and(|e| !e.eq_ignore_ascii_case("identity"))
                    {
                        result
                            .warnings
                            .push("server sent an encoded body; saved as received".into());
                    }
                    result.saved_path = Some(self.save(&name, resp.body).await?);
                    return Ok(());
                }
            }
        }
    }

    async fn save(&self, name: &str, body: Vec<u8>) -> Result<PathBuf, ClientError> {
        let (dir, name, max) = (self.opts.out_dir.clone(), name.to_owned(), self.opts.max_bytes);
        tokio::task::spawn_blocking(move || write_unique(&dir, &name, &body[..], max))
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?
            .map_err(|e| ClientError::Io(e.to_string()))
    }

    async fn connect_proxy(&self) -> Result<TcpStream, ClientError> {
        let host = self
            .opts
            .proxy
            .host_str()
            .ok_or_else(|| ClientError::Usage("proxy URL has no host".into()))?;
        let port = self.opts.proxy.port_or_known_default().unwrap_or(8080);
        let host = host.trim_start_matches('[').trim_end_matches(']');
        tokio::time::timeout(self.opts.connect_timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| ClientError::Network("proxy connect timeout".into()))?
            .map_err(|e| ClientError::Network(format!("proxy unreachable: {e}")))
    }

    /// One request through the proxy.
    async fn hop(&self, url: &Url) -> Result<Hop, ClientError> {
        let host =
            url.host_str().ok_or_else(|| ClientError::Usage("URL has no host".into()))?.to_owned();
        let port = url.port_or_known_default().unwrap_or(443);
        let authority = match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        let mut stream = self.connect_proxy().await?;
        if url.scheme() == "http" {
            return self.request(stream, url.as_str(), &authority, true).await;
        }
        // https: manual CONNECT so the proxy's answer (e.g. a block) is visible (D-25).
        let auth = self
            .proxy_authorization()
            .map(|a| format!("Proxy-Authorization: {a}\r\n"))
            .unwrap_or_default();
        let connect = format!(
            "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}User-Agent: {}\r\n\r\n",
            self.opts.user_agent
        );
        stream
            .write_all(connect.as_bytes())
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        let limits =
            Limits { max_head_bytes: 65536, max_headers: 100, max_uri_bytes: 8192, compat: false };
        let mut buf = Vec::new();
        let deadline = tokio::time::Instant::now() + self.opts.timeout;
        let head =
            match read_head(&mut stream, &mut buf, deadline, |b| parse_response_head(b, &limits))
                .await
            {
                Ok(Some(h)) => h,
                Ok(None) | Err(IoError::Closed) => {
                    return Err(ClientError::Network("proxy closed the CONNECT".into()));
                }
                Err(e) => return Err(ClientError::Protocol(format!("bad CONNECT reply: {e}"))),
            };
        if head.status != 200 {
            let blocked = single(&head.headers, "x-webfilter-action")
                .is_some_and(|v| v.eq_ignore_ascii_case(b"blocked"));
            if blocked {
                let text =
                    |n| single(&head.headers, n).map(|v| String::from_utf8_lossy(v).into_owned());
                let info = BlockInfo {
                    event_id: text("x-webfilter-event-id"),
                    reason: text("x-webfilter-reason"),
                };
                return Ok(Hop::Blocked(info, buf));
            }
            return Err(ClientError::Network(format!(
                "proxy refused CONNECT: HTTP {}",
                head.status
            )));
        }
        let server =
            ServerName::try_from(host.clone()).map_err(|e| ClientError::Tls(e.to_string()))?;
        let tls = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls))
            .connect(server, stream)
            .await
            .map_err(|e| ClientError::Tls(e.to_string()))?;
        let target = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_owned(),
        };
        self.request(tls, &target, &authority, false).await
    }

    /// Send a GET on `io` (absolute-form to the proxy, or origin-form inside a tunnel).
    async fn request<T>(
        &self,
        io: T,
        target: &str,
        authority: &str,
        via_proxy: bool,
    ) -> Result<Hop, ClientError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        tokio::spawn(conn);
        let mut req = Request::get(target)
            .header("host", authority)
            .header("user-agent", &self.opts.user_agent)
            .header("accept", "text/html,*/*;q=0.8")
            .header("accept-encoding", "identity")
            .header("connection", "close");
        if via_proxy && let Some(a) = self.proxy_authorization() {
            req = req.header("proxy-authorization", a);
        }
        let req = req.body(Empty::<Bytes>::new()).map_err(|e| ClientError::Usage(e.to_string()))?;
        let resp =
            sender.send_request(req).await.map_err(|e| ClientError::Network(e.to_string()))?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let blocked = via_proxy
            && status == 403
            && headers
                .get("x-webfilter-action")
                .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"blocked"));
        let mut body = resp.into_body();
        let mut data = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| ClientError::Network(e.to_string()))?;
            if let Some(chunk) = frame.data_ref() {
                if (data.len() + chunk.len()) as u64 > self.opts.max_bytes {
                    return Err(ClientError::TooLarge);
                }
                data.extend_from_slice(chunk);
            }
        }
        if blocked {
            let text = |n| headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_owned);
            let info = BlockInfo {
                event_id: text("x-webfilter-event-id"),
                reason: text("x-webfilter-reason"),
            };
            return Ok(Hop::Blocked(info, data));
        }
        Ok(Hop::Response(Response { status, headers, body: data }))
    }
}
