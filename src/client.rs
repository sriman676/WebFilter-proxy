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
use crate::util::LockExt;

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
    /// Retries of transient failures (C2, max 10).
    pub retries: u32,
    /// Cap for backoff and `Retry-After`.
    pub retry_max_delay: Duration,
    /// Continue `.part` files with `Range` + `If-Range`.
    pub resume_partial: bool,
    /// Save pages with their same-site assets for offline viewing (C3).
    pub snapshot: Option<SnapshotOptions>,
}

/// `--snapshot` settings.
#[derive(Debug, Clone, Default)]
pub struct SnapshotOptions {
    /// Keep scripts (not recommended).
    pub allow_scripts: bool,
    /// Extra asset hosts (CDNs) allowed besides the page's own site.
    pub extra_hosts: Vec<String>,
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
    /// Requests made (retries included).
    pub attempts: u32,
    /// Snapshot report (`--snapshot`).
    pub snapshot_report: Option<PathBuf>,
    /// Link depth of a crawled page (`--crawl-depth`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crawl_depth: Option<u8>,
    /// SHA-256 of the saved file (manifest).
    #[serde(skip)]
    pub sha256: Option<String>,
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

/// A finished GET after redirects (and retries).
#[derive(Debug)]
pub enum Outcome {
    /// An origin response (any status).
    Ok {
        /// URL that answered.
        final_url: Url,
        /// Status.
        status: u16,
        /// Headers.
        headers: hyper::HeaderMap,
        /// Body (bounded by `max_bytes`).
        body: Vec<u8>,
    },
    /// The proxy blocked it.
    Blocked {
        /// Block details.
        info: BlockInfo,
        /// The block page.
        page: Vec<u8>,
    },
}

/// Bytes received before a failure, kept for `--resume-partial` (C2).
#[derive(Debug, Default, Clone)]
struct Partial {
    data: Vec<u8>,
    etag: Option<String>,
    last_modified: Option<String>,
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

/// Replace `path` with `data` without following a symlink: refuses when `path` is a symlink,
/// writes a fresh `create_new` temp file in the same directory and renames it over `path`
/// (review L6). A planted link is never written through and never left half-written.
pub fn replace_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::other(format!(
            "{} is a symlink; refusing to write through it",
            path.display()
        )));
    }
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut r = [0u8; 8];
    let _ = getrandom::fill(&mut r);
    let temp = dir.join(format!(
        ".{name}.{}-{}-{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
        hex::encode(r)
    ));
    let written = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        std::io::Write::write_all(&mut f, data)?;
        f.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
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
    partials: std::sync::Mutex<std::collections::HashMap<String, Partial>>,
}

impl Client {
    /// Build a client; fails on unreadable `--ca-cert` files.
    pub fn new(opts: ClientOptions) -> Result<Self, ClientError> {
        let tls = tls_config(&opts.ca_certs)?;
        Ok(Self { opts, tls, partials: std::sync::Mutex::default() })
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
                self.fetch_url(url, &mut result).await
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

    /// The client options.
    pub fn options(&self) -> &ClientOptions {
        &self.opts
    }

    /// GET with redirects and retries of transient failures (C2). Returns the outcome and the
    /// number of requests made. Each attempt has the whole-fetch timeout.
    pub async fn get(
        &self,
        url: &Url,
        extra: &[(&'static str, String)],
    ) -> (Result<Outcome, ClientError>, u32) {
        self.get_within(url, extra, &|_| true).await
    }

    /// [`Client::get`] that refuses redirects to URLs outside `scope` (crawl, C4).
    pub async fn get_within(
        &self,
        url: &Url,
        extra: &[(&'static str, String)],
        scope: &(dyn Fn(&Url) -> bool + Sync),
    ) -> (Result<Outcome, ClientError>, u32) {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let r = tokio::time::timeout(self.opts.timeout, self.get_once(url, extra, scope))
                .await
                .unwrap_or(Err(ClientError::Timeout));
            let retry = match &r {
                Ok(Outcome::Ok { status, headers, .. })
                    if crate::batch::retryable_status(*status) =>
                {
                    let server = headers
                        .get(hyper::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| crate::batch::retry_after(v, std::time::SystemTime::now()));
                    Some(server)
                }
                Err(ClientError::Network(_) | ClientError::Timeout) => Some(None),
                _ => None, // BLOCKED, TLS, usage, size and other 4xx are never retried
            };
            match retry {
                Some(server) if attempt <= self.opts.retries.min(crate::batch::MAX_RETRIES) => {
                    let mut r = [0u8; 2];
                    let _ = getrandom::fill(&mut r);
                    let jitter = f64::from(u16::from_be_bytes(r)) / f64::from(u16::MAX);
                    let delay =
                        crate::batch::backoff(attempt, server, self.opts.retry_max_delay, jitter);
                    tokio::time::sleep(delay).await;
                }
                _ => return (r, attempt),
            }
        }
    }

    async fn get_once(
        &self,
        original: &Url,
        extra: &[(&'static str, String)],
        scope: &(dyn Fn(&Url) -> bool + Sync),
    ) -> Result<Outcome, ClientError> {
        let mut url = original.clone();
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(url.to_string()) {
                return Err(ClientError::Redirect("redirect loop".into()));
            }
            match self.hop(&url, extra).await? {
                Hop::Blocked(info, page) => return Ok(Outcome::Blocked { info, page }),
                Hop::Response(resp) => {
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
                        if !scope(&url) {
                            return Err(ClientError::Redirect(format!(
                                "redirect out of scope not followed: {}",
                                url.origin().ascii_serialization()
                            )));
                        }
                        continue;
                    }
                    return Ok(Outcome::Ok {
                        final_url: url,
                        status: resp.status,
                        headers: resp.headers,
                        body: resp.body,
                    });
                }
            }
        }
    }

    fn part_paths(&self, name: &str) -> (PathBuf, PathBuf) {
        let dir = &self.opts.out_dir;
        (dir.join(format!(".{name}.part")), dir.join(format!(".{name}.part.json")))
    }

    /// `Range` + `If-Range` for an existing partial download of `url` (C2).
    fn resume_headers(
        &self,
        url: &Url,
        name: &str,
    ) -> (Vec<(&'static str, String)>, Option<Vec<u8>>) {
        if !self.opts.resume_partial {
            return (Vec::new(), None);
        }
        let (part, meta) = self.part_paths(name);
        let meta: Option<serde_json::Value> =
            std::fs::read(&meta).ok().and_then(|b| serde_json::from_slice(&b).ok());
        let Some(meta) =
            meta.filter(|m| m.get("url").and_then(serde_json::Value::as_str) == Some(url.as_str()))
        else {
            return (Vec::new(), None);
        };
        let field = |k: &str| meta.get(k).and_then(serde_json::Value::as_str).map(str::to_owned);
        let validator = field("etag").or_else(|| field("last_modified"));
        match (std::fs::read(&part), validator) {
            (Ok(data), Some(v)) if !data.is_empty() => {
                (vec![("range", format!("bytes={}-", data.len())), ("if-range", v)], Some(data))
            }
            _ => (Vec::new(), None),
        }
    }

    fn keep_partial(&self, url: &Url, name: &str) {
        let p = self.partials.lock_or_recover().remove(url.as_str());
        if let Some(p) =
            p.filter(|p| !p.data.is_empty() && (p.etag.is_some() || p.last_modified.is_some()))
        {
            let (part, meta) = self.part_paths(name);
            let m = serde_json::json!({ "url": url.as_str(), "etag": p.etag, "last_modified": p.last_modified });
            let _ = replace_file(&part, &p.data)
                .and_then(|()| replace_file(&meta, m.to_string().as_bytes()));
        }
    }

    async fn fetch_url(&self, original: Url, result: &mut FetchResult) -> Result<(), ClientError> {
        let name = self.opts.name.clone().unwrap_or_else(|| output_filename(original.as_str()));
        let (extra, partial) = self.resume_headers(&original, &name);
        let (outcome, attempts) = self.get(&original, &extra).await;
        result.attempts = attempts;
        result.final_url = original.to_string();
        let outcome = match outcome {
            Ok(o) => o,
            Err(e) => {
                if self.opts.resume_partial {
                    self.keep_partial(&original, &name);
                }
                return Err(e);
            }
        };
        self.partials.lock_or_recover().remove(original.as_str());
        match outcome {
            Outcome::Blocked { info, page } => {
                result.blocked = true;
                result.status = Some(403);
                result.event_id = info.event_id;
                result.reason = info.reason;
                if self.opts.save_blocked {
                    let stem = name.strip_suffix(".html").unwrap_or(&name);
                    result.saved_path =
                        Some(self.save(&format!("{stem}.blocked.html"), page).await?);
                }
                Ok(())
            }
            Outcome::Ok { final_url, status, headers, mut body } => {
                result.final_url = final_url.to_string();
                result.status = Some(status);
                let header = |n| {
                    headers
                        .get(n)
                        .and_then(|v: &hyper::header::HeaderValue| v.to_str().ok())
                        .map(str::to_owned)
                };
                if status == 206 {
                    // Resume: the range must start exactly where the partial file ends (C2).
                    let start = header(hyper::header::CONTENT_RANGE).and_then(|r| {
                        r.strip_prefix("bytes ")?.split('-').next()?.parse::<usize>().ok()
                    });
                    match partial {
                        Some(mut p) if start == Some(p.len()) => {
                            p.extend_from_slice(&body);
                            body = p;
                            result.status = Some(200);
                        }
                        _ => {
                            let (part, meta) = self.part_paths(&name);
                            let _ = std::fs::remove_file(part);
                            let _ = std::fs::remove_file(meta);
                            return Err(ClientError::Protocol(
                                "partial response does not continue the .part file; restart".into(),
                            ));
                        }
                    }
                }
                if self.opts.resume_partial {
                    let (part, meta) = self.part_paths(&name);
                    let _ = std::fs::remove_file(part);
                    let _ = std::fs::remove_file(meta);
                }
                result.bytes = body.len() as u64;
                result.content_type = header(hyper::header::CONTENT_TYPE)
                    .map(|c| crate::util::media_type(&c).to_owned());
                if !(200..300).contains(&status) {
                    return Err(ClientError::Protocol(format!("HTTP {status}")));
                }
                let html = result.content_type.as_deref().is_none_or(|c| c == "text/html");
                if !html {
                    result.warnings.push(format!(
                        "content type is {}, saved as .html anyway",
                        result.content_type.as_deref().unwrap_or("")
                    ));
                }
                if header(hyper::header::CONTENT_ENCODING)
                    .is_some_and(|e| !e.eq_ignore_ascii_case("identity"))
                {
                    result.warnings.push("server sent an encoded body; saved as received".into());
                }
                result.sha256 = Some(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&body)));
                let saved = self.save(&name, body.clone()).await?;
                if let (Some(opts), true) = (&self.opts.snapshot, html) {
                    let page = String::from_utf8_lossy(&body).into_owned();
                    match self.snapshot(&final_url, &page, &saved, opts).await {
                        Ok(report) => result.snapshot_report = Some(report),
                        Err(e) => result.warnings.push(format!("snapshot: {e}")),
                    }
                    result.sha256 = crate::batch::file_sha256(&saved);
                }
                result.saved_path = Some(saved);
                Ok(())
            }
        }
    }

    /// Fetch the page's same-site assets and rewrite the saved page to use them (C3). Returns
    /// the report path.
    pub async fn snapshot(
        &self,
        page: &Url,
        html: &str,
        saved: &std::path::Path,
        opts: &SnapshotOptions,
    ) -> Result<PathBuf, ClientError> {
        use crate::snapshot as snap;
        let io = |e: std::io::Error| ClientError::Io(e.to_string());
        let dir = saved.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
        let file = saved.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let stem = file.strip_suffix(".html").unwrap_or(&file).to_owned();
        let mut queue: std::collections::VecDeque<(Url, u8)> =
            snap::plan(html, page, opts.allow_scripts).into_iter().map(|u| (u, 0)).collect();
        let mut map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut css: Vec<(Url, String, String)> = Vec::new(); // (url, local, text) rewritten at the end
        let mut omitted: Vec<snap::Omitted> = Vec::new();
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        let (mut count, mut total) = (0usize, 0u64);
        let mut seen = HashSet::new();
        let omit = |omitted: &mut Vec<snap::Omitted>,
                    url: &Url,
                    reason: &str,
                    event_id: Option<String>| {
            omitted.push(snap::Omitted {
                url: url.to_string(),
                reason: reason.to_owned(),
                event_id,
            });
        };
        while let Some((url, depth)) = queue.pop_front() {
            if !seen.insert(url.to_string()) {
                continue;
            }
            if count >= snap::MAX_ASSETS {
                omit(&mut omitted, &url, "asset limit (200)", None);
                continue;
            }
            if !snap::same_site(page, &url, &opts.extra_hosts) {
                omit(&mut omitted, &url, "cross-site", None);
                continue;
            }
            // Redirects must stay in the snapshot scope too (review L6).
            let scope = |u: &Url| snap::same_site(page, u, &opts.extra_hosts);
            let (r, _) = self.get_within(&url, &[], &scope).await;
            let (status, headers, body) = match r {
                Ok(Outcome::Ok { status, headers, body, .. }) => (status, headers, body),
                Ok(Outcome::Blocked { info, .. }) => {
                    omit(
                        &mut omitted,
                        &url,
                        &format!("blocked: {}", info.reason.unwrap_or_default()),
                        info.event_id,
                    );
                    continue;
                }
                Err(e) => {
                    omit(&mut omitted, &url, &e.to_string(), None);
                    continue;
                }
            };
            let media = headers
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|c| crate::util::media_type(c).to_ascii_lowercase())
                .unwrap_or_default();
            if !(200..300).contains(&status) {
                omit(&mut omitted, &url, &format!("HTTP {status}"), None);
                continue;
            }
            if !snap::allowed_media(&media) {
                omit(&mut omitted, &url, &format!("media type {media} not allowed"), None);
                continue;
            }
            let len = body.len() as u64;
            if len > snap::MAX_ASSET_BYTES || total + len > snap::MAX_PAGE_BYTES {
                omit(&mut omitted, &url, "size limit", None);
                continue;
            }
            count += 1;
            total += len;
            let local = snap::local_name(&stem, &url, &media);
            map.insert(url.to_string(), local.clone());
            if media == "text/css" {
                let text = String::from_utf8_lossy(&body).into_owned();
                for (_, r) in snap::css_refs(&text) {
                    if let Ok(u) = url.join(&r) {
                        if depth < snap::MAX_CSS_DEPTH && matches!(u.scheme(), "http" | "https") {
                            queue.push_back((u, depth + 1));
                        } else if matches!(u.scheme(), "http" | "https")
                            && !seen.contains(u.as_str())
                        {
                            omit(&mut omitted, &u, "css import depth", None);
                        }
                    }
                }
                css.push((url, local, text));
            } else {
                files.push((local, body));
            }
        }
        // CSS files reference siblings in the same `_files` directory.
        for (url, local, text) in css {
            let rewritten = snap::rewrite_css(&text, &|r: &str| {
                let u = url.join(r).ok()?;
                map.get(u.as_str()).map(|l| l.rsplit('/').next().unwrap_or(l).to_owned())
            });
            files.push((local, rewritten.into_bytes()));
        }
        if !files.is_empty() {
            std::fs::create_dir(dir.join(format!("{stem}_files"))).map_err(io)?;
        }
        for (local, data) in files {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(&local))
                .map_err(io)?;
            std::io::Write::write_all(&mut f, &data).map_err(io)?;
        }
        let page_html = snap::rewrite(html, page, &map, opts.allow_scripts);
        replace_file(saved, page_html.as_bytes()).map_err(io)?;
        let report = dir.join(format!("{stem}_snapshot_report.json"));
        let json =
            serde_json::json!({ "page": page.as_str(), "assets": map.len(), "omitted": omitted });
        replace_file(&report, &serde_json::to_vec_pretty(&json).unwrap_or_default()).map_err(io)?;
        Ok(report)
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
    async fn hop(&self, url: &Url, extra: &[(&'static str, String)]) -> Result<Hop, ClientError> {
        let host =
            url.host_str().ok_or_else(|| ClientError::Usage("URL has no host".into()))?.to_owned();
        let port = url.port_or_known_default().unwrap_or(443);
        let authority = match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        let mut stream = self.connect_proxy().await?;
        if url.scheme() == "http" {
            return self.request(stream, url.as_str(), &authority, true, url.as_str(), extra).await;
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
            let refused = format!("proxy refused CONNECT: HTTP {}", head.status);
            // Only transient refusals (limits, overload) are retried (C2).
            return Err(if crate::batch::retryable_status(head.status) {
                ClientError::Network(refused)
            } else {
                ClientError::Protocol(refused)
            });
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
        self.request(tls, &target, &authority, false, url.as_str(), extra).await
    }

    /// Send a GET on `io` (absolute-form to the proxy, or origin-form inside a tunnel).
    async fn request<T>(
        &self,
        io: T,
        target: &str,
        authority: &str,
        via_proxy: bool,
        key: &str,
        extra: &[(&'static str, String)],
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
        for (name, value) in extra {
            req = req.header(*name, value.as_str());
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
        // `--resume-partial`: remember validators and the bytes so far, in case this fails.
        let header = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let track = self.opts.resume_partial
            && !blocked
            && status == 200
            && (header("etag").is_some() || header("last-modified").is_some());
        if track {
            let p = Partial {
                data: Vec::new(),
                etag: header("etag"),
                last_modified: header("last-modified"),
            };
            self.partials.lock_or_recover().insert(key.to_owned(), p);
        }
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| ClientError::Network(e.to_string()))?;
            if let Some(chunk) = frame.data_ref() {
                if (data.len() + chunk.len()) as u64 > self.opts.max_bytes {
                    return Err(ClientError::TooLarge);
                }
                data.extend_from_slice(chunk);
                if track && let Some(p) = self.partials.lock_or_recover().get_mut(key) {
                    p.data.extend_from_slice(chunk);
                }
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
