//! Admin listener (SPEC_EXT_OPS O1-O4, D-55..D-57, A-30): loopback only, off by default, built
//! on hyper (off the proxy data path). Every route checks `Host` against the allowlist first
//! (DNS rebinding, R-14); no CORS, no cookies; Bearer token (argon2id, constant-time cache,
//! per-IP lockout); `Origin` checked on state-changing calls; security headers everywhere;
//! every authenticated change and every auth failure goes to `webfilter_admin.jsonl`.
#![forbid(unsafe_code)]

pub mod edit;

use std::convert::Infallible;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::auth::{Lockout, verify_password};
use crate::proxy::ProxyDeps;
use crate::telemetry::{header as metric_header, label, render_counters};

/// Embedded dashboard (D-57): no CDN, no inline script or style.
const INDEX_HTML: &str = include_str!("../../assets/admin/index.html");
const APP_JS: &str = include_str!("../../assets/admin/app.js");
const STYLE_CSS: &str = include_str!("../../assets/admin/style.css");
const UI_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

type Resp = Response<Full<Bytes>>;

struct Admin {
    deps: Arc<ProxyDeps>,
    hosts: Vec<String>,
    origins: Vec<String>,
    lockout: Lockout<IpAddr>,
    verified: Mutex<Option<[u8; 32]>>,
    argon: Semaphore,
}

/// Bind the admin listener and serve; returns the bound address.
pub async fn spawn(
    deps: Arc<ProxyDeps>,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let cfg = &deps.cfg.admin;
    let listener = TcpListener::bind(cfg.listen).await?;
    let addr = listener.local_addr()?;
    let mut hosts = cfg.hosts();
    if cfg.allowed_hosts.is_empty() && cfg.listen.port() == 0 {
        let p = addr.port(); // tests bind port 0
        hosts = vec![format!("127.0.0.1:{p}"), format!("localhost:{p}"), format!("[::1]:{p}")];
    }
    let origins = hosts.iter().map(|h| format!("http://{h}")).collect();
    let admin = Arc::new(Admin {
        deps,
        hosts,
        origins,
        lockout: Lockout::default(),
        verified: Mutex::new(None),
        argon: Semaphore::new(2),
    });
    let slots = Arc::new(Semaphore::new(admin.deps.cfg.admin.max_connections));
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else { continue };
            let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else { continue }; // full: drop
            let admin = Arc::clone(&admin);
            tokio::spawn(async move {
                let timeout = Duration::from_secs(admin.deps.cfg.admin.request_timeout_secs);
                let svc = hyper::service::service_fn(move |req| {
                    let admin = Arc::clone(&admin);
                    async move {
                        let r = tokio::time::timeout(timeout, admin.handle(req, peer)).await;
                        Ok::<_, Infallible>(
                            r.unwrap_or_else(|_| plain(StatusCode::REQUEST_TIMEOUT, "timeout")),
                        )
                    }
                });
                let conn = hyper::server::conn::http1::Builder::new()
                    .max_buf_size(64 * 1024)
                    .serve_connection(TokioIo::new(stream), svc);
                let _ = tokio::time::timeout(timeout * 6, conn).await;
                drop(permit);
            });
        }
    });
    Ok((addr, task))
}

fn with_headers(mut r: Resp) -> Resp {
    let h = r.headers_mut();
    for (k, v) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-resource-policy", "same-origin"),
    ] {
        h.insert(k, http::HeaderValue::from_static(v));
    }
    r
}

fn plain(status: StatusCode, text: &'static str) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from_static(text.as_bytes())));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(header::CONTENT_TYPE, http::HeaderValue::from_static("text/plain; charset=utf-8"));
    with_headers(r)
}

fn json_resp(status: StatusCode, v: &Value) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from(v.to_string())));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(header::CONTENT_TYPE, http::HeaderValue::from_static("application/json"));
    with_headers(r)
}

fn err(status: StatusCode, msg: &str) -> Resp {
    json_resp(status, &json!({ "error": msg }))
}

fn asset(body: &'static str, ctype: &'static str) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    r.headers_mut().insert(header::CONTENT_TYPE, http::HeaderValue::from_static(ctype));
    r.headers_mut().insert("content-security-policy", http::HeaderValue::from_static(UI_CSP));
    with_headers(r)
}

fn query(req: &Request<Incoming>) -> Vec<(String, String)> {
    req.uri()
        .query()
        .map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned().collect())
        .unwrap_or_default()
}

fn q<'a>(qs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    qs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

impl Admin {
    async fn handle(self: Arc<Self>, req: Request<Incoming>, peer: SocketAddr) -> Resp {
        // 1. Host allowlist on every route, before anything else (R-14).
        let mut hosts = req.headers().get_all(header::HOST).iter();
        let host = match (hosts.next(), hosts.next()) {
            (Some(h), None) => h.to_str().unwrap_or("").to_ascii_lowercase(),
            _ => return plain(StatusCode::BAD_REQUEST, "exactly one Host header is required"),
        };
        if !self.hosts.contains(&host) {
            return plain(StatusCode::MISDIRECTED_REQUEST, "unknown host");
        }
        // 2. Cross-origin state changes are refused (no CORS, ever).
        let changing = req.method() != Method::GET && req.method() != Method::HEAD;
        if changing
            && let Some(o) = req.headers().get(header::ORIGIN)
            && !self.origins.iter().any(|a| a.as_bytes().eq_ignore_ascii_case(o.as_bytes()))
        {
            return plain(StatusCode::FORBIDDEN, "cross-origin request refused");
        }
        let path = req.uri().path().to_owned();
        let ui = self.deps.cfg.admin.ui_enabled;
        match (req.method().clone(), path.as_str()) {
            (Method::GET, "/healthz") => {
                return json_resp(StatusCode::OK, &json!({ "status": "ok" }));
            }
            (Method::GET, "/readyz") => return self.readyz(),
            (Method::GET, "/") if ui => {
                let mut r = plain(StatusCode::FOUND, "");
                r.headers_mut().insert(header::LOCATION, http::HeaderValue::from_static("/ui/"));
                return r;
            }
            (Method::GET, "/ui/" | "/ui/index.html") if ui => {
                return asset(INDEX_HTML, "text/html; charset=utf-8");
            }
            (Method::GET, "/ui/app.js") if ui => {
                return asset(APP_JS, "text/javascript; charset=utf-8");
            }
            (Method::GET, "/ui/style.css") if ui => {
                return asset(STYLE_CSS, "text/css; charset=utf-8");
            }
            (Method::GET, "/metrics") if self.deps.cfg.admin.metrics_public => {
                return self.metrics();
            }
            _ => {}
        }
        // 3. Everything else needs the Bearer token.
        if let Err(r) = self.authenticate(&req, peer).await {
            return *r;
        }
        if path == "/metrics" && req.method() == Method::GET {
            return self.metrics();
        }
        let Some(api) = path.strip_prefix("/api/v1/") else {
            return plain(StatusCode::NOT_FOUND, "not found");
        };
        let api = api.to_owned();
        if !changing {
            return self.get(&api, &query(&req));
        }
        let is_json = req.headers().get(header::CONTENT_TYPE).is_some_and(|v| {
            v.to_str().is_ok_and(|s| {
                s.split(';')
                    .next()
                    .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
            })
        });
        if !is_json {
            return err(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type: application/json is required",
            );
        }
        let method = req.method().clone();
        let max = self.deps.cfg.admin.max_body_bytes;
        let body = match Limited::new(req.into_body(), max).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return err(StatusCode::PAYLOAD_TOO_LARGE, "body too large"),
        };
        let body: Value = if body.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => return err(StatusCode::BAD_REQUEST, "invalid JSON"),
            }
        };
        let (resp, target, ok) = self.change(&method, &api, &body).await;
        self.deps.logger.admin(
            "token",
            &peer.ip().to_string(),
            &format!("{method} {}", api_route(&api)),
            &target,
            if ok { "ok" } else { "error" },
        );
        resp
    }

    async fn authenticate(
        &self,
        req: &Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<(), Box<Resp>> {
        let ip = peer.ip();
        let now = std::time::Instant::now();
        if self.lockout.is_locked(ip, now) {
            return Err(Box::new(err(
                StatusCode::TOO_MANY_REQUESTS,
                "too many authentication failures",
            )));
        }
        let token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .unwrap_or("");
        let fail = |admin: &Admin| {
            admin.lockout.record_failure(ip, now);
            admin.deps.logger.admin("unknown", &ip.to_string(), "auth", "", "auth_failed");
            Err(Box::new(err(StatusCode::UNAUTHORIZED, "a valid Bearer token is required")))
        };
        if token.is_empty() {
            return fail(self);
        }
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let cached = self
            .verified
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|d| bool::from(d.ct_eq(&digest)));
        if cached {
            return Ok(());
        }
        let Ok(_permit) = self.argon.acquire().await else { return fail(self) };
        let (phc, t) = (self.deps.cfg.admin.token_hash.0.clone(), token.to_owned());
        let ok = tokio::task::spawn_blocking(move || verify_password(&phc, t.as_bytes()))
            .await
            .unwrap_or(false);
        if !ok {
            return fail(self);
        }
        *self.verified.lock().unwrap_or_else(|e| e.into_inner()) = Some(digest);
        self.lockout.record_success(ip);
        Ok(())
    }

    fn readyz(&self) -> Resp {
        let d = &self.deps;
        let mut failed = Vec::new();
        if d.lists.snapshot().domains.len() == usize::MAX {
            failed.push("blocklists");
        }
        if std::fs::metadata(&d.cfg.logging.dir).is_err() {
            failed.push("logger");
        }
        if d.cfg.tls.intercept && d.leaves.is_none() {
            failed.push("ca");
        }
        if failed.is_empty() {
            json_resp(StatusCode::OK, &json!({ "status": "ready" }))
        } else {
            json_resp(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({ "status": "not_ready", "failed": failed }),
            )
        }
    }

    fn metrics(&self) -> Resp {
        let d = &self.deps;
        let mut out = String::new();
        render_counters(&d.telemetry.counters.lock().unwrap_or_else(|e| e.into_inner()), &mut out);
        metric_header(
            &mut out,
            "webfilter_active_connections",
            "gauge",
            "Open client connections.",
        );
        let _ = writeln!(
            out,
            "webfilter_active_connections {}",
            d.stats.active_connections.load(std::sync::atomic::Ordering::Relaxed)
        );
        let lists = d.lists.snapshot();
        metric_header(&mut out, "webfilter_blocklist_entries", "gauge", "Entries per list kind.");
        for (k, n) in [
            ("domains", lists.domains.len()),
            ("url_patterns", lists.patterns.len()),
            ("ip_blocklist", lists.ips.len()),
        ] {
            let _ = writeln!(out, "webfilter_blocklist_entries{{list=\"{k}\"}} {n}");
        }
        let feeds = d.feeds.status();
        metric_header(&mut out, "webfilter_feed_entries", "gauge", "Active entries per feed.");
        for f in &feeds {
            let _ = writeln!(
                out,
                "webfilter_feed_entries{{feed=\"{}\"}} {}",
                label(&f.name),
                f.entries
            );
        }
        metric_header(
            &mut out,
            "webfilter_feed_last_success_timestamp_seconds",
            "gauge",
            "Last successful feed update.",
        );
        for f in &feeds {
            let _ = writeln!(
                out,
                "webfilter_feed_last_success_timestamp_seconds{{feed=\"{}\"}} {}",
                label(&f.name),
                f.last_success.unwrap_or(0)
            );
        }
        metric_header(
            &mut out,
            "webfilter_feed_updates_total",
            "counter",
            "Feed update attempts by result.",
        );
        for ((feed, result), n) in d.feeds.update_counts() {
            let _ = writeln!(
                out,
                "webfilter_feed_updates_total{{feed=\"{}\",result=\"{}\"}} {n}",
                label(&feed),
                label(result)
            );
        }
        metric_header(&mut out, "webfilter_access_requests", "gauge", "Access requests by state.");
        for (state, n) in d.access.counts() {
            let _ = writeln!(out, "webfilter_access_requests{{state=\"{state}\"}} {n}");
        }
        metric_header(
            &mut out,
            "webfilter_log_dropped_total",
            "counter",
            "Log events dropped under pressure.",
        );
        let _ = writeln!(out, "webfilter_log_dropped_total {}", d.logger.dropped());
        metric_header(&mut out, "webfilter_up", "gauge", "1 while the proxy runs.");
        let _ = writeln!(out, "webfilter_up 1");
        metric_header(&mut out, "webfilter_build_info", "gauge", "Build information.");
        let _ =
            writeln!(out, "webfilter_build_info{{version=\"{}\"}} 1", env!("CARGO_PKG_VERSION"));
        let mut r = Response::new(Full::new(Bytes::from(out)));
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        );
        with_headers(r)
    }

    fn get(&self, api: &str, qs: &[(String, String)]) -> Resp {
        let d = &self.deps;
        let num = |k: &str, def: usize| q(qs, k).and_then(|v| v.parse().ok()).unwrap_or(def);
        let v = match api {
            "stats" => {
                let c = d.telemetry.counters.lock().unwrap_or_else(|e| e.into_inner());
                let total: u64 = c.requests.values().sum();
                let blocked: u64 = c.requests.iter().filter(|((a, _, _), _)| a == "blocked").map(|(_, n)| n).sum();
                let lists = d.lists.snapshot();
                json!({
                    "requests": total, "blocked": blocked,
                    "bytes_in": c.bytes.get("in").copied().unwrap_or(0), "bytes_out": c.bytes.get("out").copied().unwrap_or(0),
                    "active_connections": d.stats.active_connections.load(std::sync::atomic::Ordering::Relaxed),
                    "mode": if d.mode() == crate::config::Mode::Monitor { "monitor" } else { "enforce" },
                    "lists": { "domains": lists.domains.len(), "url_patterns": lists.patterns.len(), "ip_blocklist": lists.ips.len() },
                    "intercept": d.cfg.tls.intercept, "scan": d.scanner.is_some(),
                    "access_requests": d.cfg.access_requests.enabled, "log_dropped": d.logger.dropped(),
                })
            }
            "events/recent" => json!(d.telemetry.recent(num("limit", 100), q(qs, "action"), q(qs, "reason"))),
            "top/blocked" => json!(d.telemetry.top_blocked(num("n", 20)).into_iter().map(|(h, c)| json!({"host": h, "count": c})).collect::<Vec<_>>()),
            "clients" => json!(d.telemetry.clients().into_iter().map(|(id, r, b, t)| json!({"client_id": id, "requests": r, "blocked": b, "last_seen": t})).collect::<Vec<_>>()),
            "profiles" => {
                let ps = d.policies.load();
                json!(ps.profile_names().filter_map(|n| ps.profile(n)).map(|p| json!({
                    "name": p.name, "mode": if p.mode == crate::config::Mode::Monitor { "monitor" } else { "enforce" },
                    "feeds": p.feeds, "scan_downloads": p.scan_downloads, "access_requests": p.access_requests,
                    "rate": p.rate.map(|r| json!({"requests_per_sec": r.requests_per_sec, "burst": r.burst,
                        "down_bytes_per_sec": r.down_bytes_per_sec, "daily_quota_bytes": r.daily_quota_bytes})),
                })).collect::<Vec<_>>())
            }
            "lists" => {
                let cfg = d.lists.config();
                let now = time::OffsetDateTime::now_utc();
                let snap = d.lists.snapshot();
                json!({
                    "lists": edit::targets(&cfg).iter().map(|t| json!({"name": t.name, "kind": t.kind,
                        "versions": edit::versions(&d.cfg.state.dir, &t.name).len()})).collect::<Vec<_>>(),
                    "categories": cfg.categories.iter().map(|c| json!({"name": c.name, "enabled": c.enabled, "active": c.active,
                        "active_now": snap.categories.iter().any(|s| s.name == c.name && s.enabled && s.schedule.is_active(now))})).collect::<Vec<_>>(),
                })
            }
            "settings" => json!({ "settings": *d.settings.load_full(), "versions": edit::versions(&d.cfg.state.dir, "settings").len(),
                "config_mode": if d.cfg.mode == crate::config::Mode::Monitor { "monitor" } else { "enforce" },
                "config_allow_domains": d.cfg.rules.allow_domains }),
            "feeds" => json!(d.feeds.status()),
            "temp-allows" => json!(d.access.allows()),
            "access-requests" => json!(d.access.requests(q(qs, "status"))),
            "audit" => {
                let text = std::fs::read_to_string(d.cfg.logging.dir.join(crate::logger::ADMIN_FILE)).unwrap_or_default();
                let lines: Vec<Value> = text.lines().rev().take(num("limit", 100).min(500)).filter_map(|l| serde_json::from_str(l).ok()).collect();
                json!(lines)
            }
            other => match other.strip_prefix("lists/") {
                Some(name) => match edit::targets(&d.lists.config()).into_iter().find(|t| t.name == name) {
                    Some(t) => json!({ "name": t.name, "kind": t.kind, "content": std::fs::read_to_string(&t.path).unwrap_or_default(),
                        "versions": edit::versions(&d.cfg.state.dir, &t.name) }),
                    None => return err(StatusCode::NOT_FOUND, "unknown list"),
                },
                None => return err(StatusCode::NOT_FOUND, "unknown endpoint"),
            },
        };
        json_resp(StatusCode::OK, &v)
    }

    /// State-changing calls: (response, audit target, success).
    async fn change(&self, method: &Method, api: &str, body: &Value) -> (Resp, String, bool) {
        let d = &self.deps;
        let bad = |m: &str| (err(StatusCode::BAD_REQUEST, m), String::new(), false);
        let s = |k: &str| body.get(k).and_then(Value::as_str);
        let state = d.cfg.state.dir.clone();
        let known = |keys: &[&str]| {
            body.as_object().is_none_or(|o| o.keys().all(|k| keys.contains(&k.as_str())))
        };
        match (method.as_str(), api) {
            ("POST", "reload") => {
                let lists =
                    matches!(d.lists.reload(), crate::blocklist::ReloadOutcome::Reloaded(_));
                let policies = d.reload_policies().is_ok();
                (
                    json_resp(StatusCode::OK, &json!({ "lists": lists, "policies": policies })),
                    "reload".into(),
                    lists && policies,
                )
            }
            ("POST", "feeds/update") => {
                if !known(&["name", "force"]) {
                    return bad("unknown field");
                }
                let Some(name) = s("name") else { return bad("name is required") };
                let force = body.get("force").and_then(Value::as_bool).unwrap_or(false);
                match d.feeds.update(name, force).await {
                    Ok(u) => (
                        json_resp(StatusCode::OK, &json!({ "result": format!("{u:?}") })),
                        name.into(),
                        true,
                    ),
                    Err(e) => (err(StatusCode::BAD_GATEWAY, &e.to_string()), name.into(), false),
                }
            }
            ("POST", "temp-allows") => {
                if !known(&["host", "scope", "target", "ttl_secs", "include_subdomains"]) {
                    return bad("unknown field");
                }
                let (Some(host), Some(target)) = (s("host"), s("target")) else {
                    return bad("host and target are required");
                };
                let scope = match s("scope").unwrap_or("client") {
                    "client" => crate::access::Scope::Client(target.into()),
                    "profile" => crate::access::Scope::Profile(target.into()),
                    _ => return bad("scope is client or profile"),
                };
                let ttl = body
                    .get("ttl_secs")
                    .and_then(Value::as_u64)
                    .unwrap_or(d.cfg.access_requests.default_ttl_secs);
                if ttl == 0 || ttl > d.cfg.access_requests.max_ttl_secs {
                    return bad("ttl_secs must be 1..=max_ttl_secs (<= 24 h)");
                }
                let subs = body.get("include_subdomains").and_then(Value::as_bool).unwrap_or(false);
                match d.access.add_allow(host, subs, scope, ttl, "admin") {
                    Ok(a) => {
                        d.logger.system().event(
                            crate::logger::SysEvent::TempAllowAdded,
                            json!({ "id": a.id, "host": a.host }),
                        );
                        (json_resp(StatusCode::CREATED, &json!(a)), host.into(), true)
                    }
                    Err(e) => bad(e),
                }
            }
            ("DELETE", a) if a.starts_with("temp-allows/") => {
                let id = a.trim_start_matches("temp-allows/");
                if d.access.remove_allow(id) {
                    (json_resp(StatusCode::OK, &json!({ "removed": id })), id.into(), true)
                } else {
                    (err(StatusCode::NOT_FOUND, "unknown temp allow"), id.into(), false)
                }
            }
            ("POST", a) if a.starts_with("access-requests/") && a.ends_with("/decide") => {
                if !known(&["decision", "ttl_secs", "scope"]) {
                    return bad("unknown field");
                }
                let id = a.trim_start_matches("access-requests/").trim_end_matches("/decide");
                let approve = match s("decision") {
                    Some("approve") => true,
                    Some("deny") => false,
                    _ => return bad("decision is approve or deny"),
                };
                let ttl = body
                    .get("ttl_secs")
                    .and_then(Value::as_u64)
                    .unwrap_or(d.cfg.access_requests.default_ttl_secs);
                if ttl == 0 || ttl > d.cfg.access_requests.max_ttl_secs {
                    return bad("ttl_secs must be 1..=max_ttl_secs (<= 24 h)");
                }
                match d.access.decide(id, approve, "admin", ttl, s("scope") == Some("profile")) {
                    Ok((r, allow)) => {
                        let sys = d.logger.system();
                        sys.event(
                            crate::logger::SysEvent::AccessRequestDecided,
                            json!({ "id": r.id, "status": r.status }),
                        );
                        d.logger.access(json!({ "request_id": r.id, "event_id": r.event_id, "client_id": r.client_id, "host": r.host,
                            "reason": r.reason, "status": r.status, "decided_by": "admin", "ttl_secs": allow.as_ref().map(|_| ttl),
                            "justification_len": r.justification.chars().count() }));
                        if let Some(a) = &allow {
                            sys.event(
                                crate::logger::SysEvent::TempAllowAdded,
                                json!({ "id": a.id, "host": a.host }),
                            );
                        }
                        (
                            json_resp(
                                StatusCode::OK,
                                &json!({ "request": r, "temp_allow": allow }),
                            ),
                            id.into(),
                            true,
                        )
                    }
                    Err(e) => (err(StatusCode::CONFLICT, e), id.into(), false),
                }
            }
            ("PUT", a) if a.starts_with("lists/") => {
                if !known(&["content"]) {
                    return bad("unknown field");
                }
                let name = a.trim_start_matches("lists/");
                let Some(t) = edit::targets(&d.lists.config()).into_iter().find(|t| t.name == name)
                else {
                    return (err(StatusCode::NOT_FOUND, "unknown list"), name.into(), false);
                };
                let Some(content) = s("content") else { return bad("content is required") };
                match edit::save_list(&state, &d.lists, &t, content) {
                    Ok(n) => {
                        (json_resp(StatusCode::OK, &json!({ "entries": n })), name.into(), true)
                    }
                    Err(e) => (err(StatusCode::BAD_REQUEST, &e), name.into(), false),
                }
            }
            ("POST", a) if a.starts_with("lists/") && a.ends_with("/rollback") => {
                let name = a.trim_start_matches("lists/").trim_end_matches("/rollback");
                let Some(t) = edit::targets(&d.lists.config()).into_iter().find(|t| t.name == name)
                else {
                    return (err(StatusCode::NOT_FOUND, "unknown list"), name.into(), false);
                };
                match edit::rollback_list(&state, &d.lists, &t) {
                    Ok(v) => {
                        (json_resp(StatusCode::OK, &json!({ "restored": v })), name.into(), true)
                    }
                    Err(e) => (err(StatusCode::CONFLICT, &e), name.into(), false),
                }
            }
            ("POST", "settings") => {
                match serde_json::from_value::<crate::profiles::Settings>(body.clone()) {
                    Err(e) => bad(&format!("invalid settings: {e}")),
                    Ok(new) => match self.apply_settings(&new, true) {
                        Ok(()) => (
                            json_resp(StatusCode::OK, &json!({ "settings": new })),
                            "settings".into(),
                            true,
                        ),
                        Err(e) => (err(StatusCode::BAD_REQUEST, &e), "settings".into(), false),
                    },
                }
            }
            ("POST", "settings/rollback") => match edit::previous_settings(&state)
                .and_then(|prev| self.apply_settings(&prev, false).map(|()| prev))
            {
                Ok(prev) => (
                    json_resp(StatusCode::OK, &json!({ "settings": prev })),
                    "settings".into(),
                    true,
                ),
                Err(e) => (err(StatusCode::CONFLICT, &e), "settings".into(), false),
            },
            _ => (err(StatusCode::NOT_FOUND, "unknown endpoint"), api.into(), false),
        }
    }

    /// Validate, persist (optional), then apply settings; any failure leaves the old ones active.
    fn apply_settings(&self, new: &crate::profiles::Settings, persist: bool) -> Result<(), String> {
        let d = &self.deps;
        edit::validate_settings(new, &d.lists.config())?;
        let policies = crate::profiles::PolicySet::build(&new.apply(&d.cfg))?;
        if let crate::blocklist::ReloadOutcome::Failed(e) =
            d.lists.set_category_overrides(new.categories.clone())
        {
            return Err(e);
        }
        if persist {
            edit::save_settings(&d.cfg.state.dir, new)?;
        }
        d.settings.store(Arc::new(new.clone()));
        d.policies.store(Arc::new(policies));
        Ok(())
    }
}

/// The audit `action` without ids (bounded values).
fn api_route(api: &str) -> String {
    let parts: Vec<&str> = api.split('/').collect();
    match parts.as_slice() {
        ["access-requests", _, "decide"] => "access-requests/{id}/decide".into(),
        ["temp-allows", _] => "temp-allows/{id}".into(),
        ["lists", .., "rollback"] => "lists/{name}/rollback".into(),
        ["lists", ..] => "lists/{name}".into(),
        _ => api.chars().take(64).collect(),
    }
}
