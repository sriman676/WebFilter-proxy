//! The proxy: first-party HTTP/1 core (D-05), per-request pipeline, CONNECT passthrough,
//! listener with connection limits, auth, panic isolation, stats and graceful shutdown.
#![forbid(unsafe_code)]

pub mod connect;
pub mod http1;
pub mod io;
pub mod pipeline;
pub mod response;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use futures_util::FutureExt;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::time::Instant;

use crate::auth::{Lockout, verify_credentials};
use crate::blocklist::BlocklistHandle;
use crate::config::{Config, Mode};
use crate::filter::{Action, Decision, Phase, evaluate};
use crate::logger::{EventLogger, ListCounts, RequestEvent, Stats, SysEvent, SystemLog};
use crate::normalize::{NormalizedTarget, fold_ip};
use crate::policy::{DestPolicy, Resolver, SystemResolver};
use crate::reason::Reason;
use http1::{Limits, RequestHead, single};
use pipeline::{Fail, fail};
use response::{BlockPage, error_page};

/// Stats window (SPEC 4.14).
pub const STATS_WINDOW: Duration = Duration::from_secs(60);
/// Verified-credential cache lifetime (avoids one argon2 run per request).
pub const AUTH_CACHE_TTL: Duration = Duration::from_secs(300);
/// Verified-credential cache size.
pub const AUTH_CACHE_MAX: usize = 1024;
/// Concurrent argon2 verifications (each costs ~19 MiB and tens of ms).
pub const AUTH_PARALLELISM: usize = 4;

/// Proxy authentication state (D-14, SPEC 4.10).
struct ProxyAuth {
    user: String,
    phc: String,
    lockout: Lockout,
    cache: Mutex<HashMap<[u8; 32], Instant>>,
    permits: Semaphore,
}

impl ProxyAuth {
    fn new(user: &str, phc: &str) -> Self {
        Self {
            user: user.to_owned(),
            phc: phc.to_owned(),
            lockout: Lockout::default(),
            cache: Mutex::new(HashMap::new()),
            permits: Semaphore::new(AUTH_PARALLELISM),
        }
    }

    /// Check `Proxy-Authorization: Basic ...`; returns the user name.
    async fn check(&self, head: &RequestHead, ip: IpAddr, sys: &SystemLog) -> Result<String, Fail> {
        if self.lockout.is_locked(ip, std::time::Instant::now()) {
            return Err(fail(429, Reason::RateLimited, "too many authentication failures"));
        }
        let Some(value) = single(&head.headers, "proxy-authorization") else {
            return Err(fail(407, Reason::AuthRequired, "proxy authentication required"));
        };
        let creds = value
            .strip_prefix(b"Basic ")
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .and_then(|raw| String::from_utf8(raw).ok());
        let Some((user, password)) = creds.as_deref().and_then(|c| c.split_once(':')) else {
            self.failure(ip, "", sys);
            return Err(fail(407, Reason::AuthFailed, "malformed proxy credentials"));
        };
        let key: [u8; 32] = Sha256::digest(format!("{user}:{password}").as_bytes()).into();
        let cached = {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.iter().any(|(k, at)| bool::from(k.ct_eq(&key)) && at.elapsed() < AUTH_CACHE_TTL)
        };
        let ok = cached || {
            let _permit = self
                .permits
                .acquire()
                .await
                .map_err(|_| fail(500, Reason::InternalError, "auth unavailable"))?;
            let (expected, phc, u, p) =
                (self.user.clone(), self.phc.clone(), user.to_owned(), password.to_owned());
            tokio::task::spawn_blocking(move || {
                verify_credentials(&expected, &phc, &u, p.as_bytes())
            })
            .await
            .unwrap_or(false)
        };
        if !ok {
            self.failure(ip, user, sys);
            return Err(fail(407, Reason::AuthFailed, "invalid proxy credentials"));
        }
        if !cached {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if cache.len() >= AUTH_CACHE_MAX {
                cache.clear();
            }
            cache.insert(key, Instant::now());
        }
        self.lockout.record_success(ip);
        Ok(user.to_owned())
    }

    fn failure(&self, ip: IpAddr, user: &str, sys: &SystemLog) {
        if self.lockout.record_failure(ip, std::time::Instant::now()) {
            sys.event(
                SysEvent::AuthLockout,
                serde_json::json!({ "ip": ip.to_string(), "user": user }),
            );
        }
    }
}

/// Releases a connection slot on drop.
struct ConnGuard {
    deps: Arc<ProxyDeps>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.deps.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
        let mut map = self.deps.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = map.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Everything a connection needs; shared by all connection tasks.
pub struct ProxyDeps {
    /// Configuration.
    pub cfg: Arc<Config>,
    /// Blocklists (hot-reloaded).
    pub lists: Arc<BlocklistHandle>,
    /// Logger.
    pub logger: Arc<EventLogger>,
    /// Name resolution (injectable for tests).
    pub resolver: Arc<dyn Resolver>,
    /// Counters.
    pub stats: Arc<Stats>,
    /// Destination policy.
    pub policy: DestPolicy,
    /// Head limits.
    pub limits: Limits,
    /// Block page.
    pub block_page: BlockPage,
    /// Leaf certificates when interception is on (SPEC 4.9).
    pub leaves: Option<Arc<crate::tls::LeafCache>>,
    /// Upstream TLS: verification always on (D-20).
    pub upstream_tls: Arc<rustls::ClientConfig>,
    auth: Option<ProxyAuth>,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    shutdown: watch::Receiver<bool>,
}

impl ProxyDeps {
    fn shutting_down(&self) -> bool {
        *self.shutdown.borrow()
    }

    fn new_event(&self, peer: SocketAddr) -> RequestEvent {
        RequestEvent {
            src_ip: fold_ip(peer.ip()).to_string(),
            src_port: peer.port(),
            proxy_mode: if self.cfg.mode == Mode::Monitor { "monitor" } else { "enforce" },
            ..RequestEvent::default()
        }
    }

    fn finish(&self, ev: RequestEvent) {
        let action =
            if ev.action == Action::Block.as_str() { Action::Block } else { Action::Allow };
        self.stats.record(action, &ev.dest_host, ev.bytes_in, ev.bytes_out);
        if ev.error.is_some() && action == Action::Allow {
            self.stats.record_error();
        }
        self.logger.log(ev);
    }

    fn evaluate(&self, t: &NormalizedTarget, phase: Phase<'_>) -> Decision {
        evaluate(t, phase, &self.lists.snapshot(), &self.cfg.rules, self.cfg.mode)
    }

    async fn authorize(
        &self,
        head: &RequestHead,
        ev: &mut RequestEvent,
        peer: IpAddr,
    ) -> Result<(), Fail> {
        let Some(auth) = &self.auth else { return Ok(()) };
        ev.proxy_user = Some(auth.check(head, peer, &self.logger.system()).await?);
        Ok(())
    }

    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        let ip = fold_ip(ip);
        let mut map = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        let total = self.stats.active_connections.load(Ordering::Relaxed);
        let per_ip = map.get(&ip).copied().unwrap_or(0);
        if total >= self.cfg.limits.max_connections as u64
            || per_ip >= self.cfg.limits.max_connections_per_ip
        {
            return None;
        }
        *map.entry(ip).or_default() += 1;
        self.stats.active_connections.fetch_add(1, Ordering::Relaxed);
        Some(ConnGuard { deps: Arc::clone(self), ip })
    }
}

/// A running proxy.
pub struct ProxyHandle {
    /// Bound address (useful with port 0 in tests).
    pub local_addr: SocketAddr,
    /// Shared state (tests inspect logs/stats and trigger reloads through it).
    pub deps: Arc<ProxyDeps>,
    shutdown: watch::Sender<bool>,
    accept: tokio::task::JoinHandle<()>,
    background: Vec<tokio::task::JoinHandle<()>>,
}

impl ProxyHandle {
    /// Stop accepting, drain in-flight connections up to `shutdown_drain`, flush logs (D-31).
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        self.accept.abort();
        let deadline = Instant::now() + Duration::from_secs(self.deps.cfg.timeouts.shutdown_drain);
        while self.deps.stats.active_connections.load(Ordering::Relaxed) > 0
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        for t in &self.background {
            t.abort();
        }
        self.deps.logger.system().event(SysEvent::ProxyStop, serde_json::json!({}));
        let logger = Arc::clone(&self.deps.logger);
        let _ = tokio::task::spawn_blocking(move || logger.shutdown(Duration::from_secs(5))).await;
    }
}

/// Bind, load lists, start the logger and serve. `resolver` is injected by tests.
pub async fn start(
    cfg: Config,
    resolver: Option<Arc<dyn Resolver>>,
) -> std::io::Result<ProxyHandle> {
    let invalid = |e: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, e);
    let template = &cfg.block_page.template;
    let block_page =
        BlockPage::load((!template.as_os_str().is_empty()).then_some(template.as_path()))
            .map_err(invalid)?;
    let (lists, report) =
        BlocklistHandle::load(&cfg.blocklists).map_err(|e| invalid(e.to_string()))?;
    let lists = Arc::new(lists);
    let logger = Arc::new(EventLogger::start(&cfg.logging)?);
    let sys = logger.system();
    let upstream_tls = crate::tls::upstream_client_config(&extra_roots(&cfg))
        .map_err(|e| invalid(e.to_string()))?;
    let leaves = if cfg.tls.intercept { Some(Arc::new(load_ca(&cfg, &sys)?)) } else { None };
    let listener = TcpListener::bind(cfg.listen).await?;
    let local_addr = listener.local_addr()?;
    let (tx, rx) = watch::channel(false);
    let auth = cfg.proxy_auth.as_ref().map(|a| ProxyAuth::new(&a.username, &a.password_hash.0));
    let mode = if cfg.mode == Mode::Monitor { "monitor" } else { "enforce" };
    let deps = Arc::new(ProxyDeps {
        policy: DestPolicy::new(cfg.destination.deny_private_ranges, vec![local_addr]),
        limits: Limits::new(&cfg.limits, cfg.http.compat),
        resolver: resolver.unwrap_or_else(|| Arc::new(SystemResolver)),
        stats: Arc::new(Stats::default()),
        lists: Arc::clone(&lists),
        cfg: Arc::new(cfg),
        logger,
        block_page,
        leaves,
        upstream_tls,
        auth,
        per_ip: Mutex::new(HashMap::new()),
        shutdown: rx,
    });
    sys.event(
        SysEvent::ProxyStart,
        serde_json::json!({ "listen": local_addr.to_string(), "mode": mode }),
    );
    let source = deps.cfg.source.as_ref().map(|p| p.display().to_string());
    sys.event(SysEvent::ConfigLoaded, serde_json::json!({ "source": source, "mode": mode }));
    sys.event(
        SysEvent::BlocklistLoaded,
        serde_json::json!({ "domains": report.domains, "regexes": report.regexes, "ips": report.ips, "warnings": report.warnings }),
    );
    sys.insecure_files(deps.cfg.policy_files());

    let watcher =
        lists.spawn_watcher(Duration::from_secs(deps.cfg.blocklists.reload_interval_secs), sys);
    let stats_task = tokio::spawn(stats_loop(Arc::clone(&deps)));
    let accept = tokio::spawn(accept_loop(listener, Arc::clone(&deps)));
    Ok(ProxyHandle {
        local_addr,
        deps,
        shutdown: tx,
        accept,
        background: vec![watcher, stats_task],
    })
}

fn extra_roots(cfg: &Config) -> Vec<std::path::PathBuf> {
    let bundle = &cfg.tls.upstream_ca_bundle;
    if bundle.as_os_str().is_empty() { Vec::new() } else { vec![bundle.clone()] }
}

/// Load the CA from `tls.ca_dir`, generating it on first run (SPEC 4.9); unsafe key files refuse
/// start (D-19).
fn load_ca(cfg: &Config, sys: &SystemLog) -> std::io::Result<crate::tls::LeafCache> {
    let dir = &cfg.tls.ca_dir;
    let (_, key_path) = crate::tls::CaStore::paths(dir);
    let (store, kind) = if key_path.exists() {
        (crate::tls::CaStore::load(dir), SysEvent::CaLoaded)
    } else {
        (crate::tls::CaStore::generate(dir), SysEvent::CaGenerated)
    };
    match store {
        Ok(ca) => {
            sys.event(kind, serde_json::json!({ "dir": dir.display().to_string() }));
            Ok(crate::tls::LeafCache::new(ca))
        }
        Err(e) => {
            sys.event(SysEvent::CaPermissionError, serde_json::json!({ "error": e.to_string() }));
            Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()))
        }
    }
}

/// One stats line per window (SPEC 4.14).
async fn stats_loop(deps: Arc<ProxyDeps>) {
    let mut tick = tokio::time::interval(STATS_WINDOW);
    tick.tick().await;
    loop {
        tick.tick().await;
        let l = deps.lists.snapshot();
        let counts =
            ListCounts { domains: l.domains.len(), regexes: l.patterns.len(), ips: l.ips.len() };
        deps.logger.log_stats(&deps.stats.take_window(
            STATS_WINDOW.as_secs(),
            deps.logger.dropped(),
            counts,
        ));
    }
}

async fn accept_loop(listener: TcpListener, deps: Arc<ProxyDeps>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                deps.logger
                    .system()
                    .event(SysEvent::ListenerError, serde_json::json!({ "error": e.to_string() }));
                tokio::time::sleep(Duration::from_millis(50)).await; // e.g. EMFILE: back off
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let deps = Arc::clone(&deps);
        tokio::spawn(async move {
            let Some(guard) = deps.try_acquire(peer.ip()) else {
                reject_over_limit(stream, peer, &deps).await;
                return;
            };
            // Panic isolation: a panic in one connection never affects others (SPEC 9).
            let served =
                AssertUnwindSafe(pipeline::serve_connection(stream, peer, Arc::clone(&deps), None))
                    .catch_unwind()
                    .await;
            if served.is_err() {
                deps.logger.system().event(
                    SysEvent::PanicIsolated,
                    serde_json::json!({ "peer": peer.ip().to_string() }),
                );
            }
            drop(guard);
        });
    }
}

async fn reject_over_limit(mut stream: TcpStream, peer: SocketAddr, deps: &ProxyDeps) {
    let mut ev = deps.new_event(peer);
    let bytes =
        error_page(503, Reason::TooManyConnections, &ev.event_id, &[("retry-after", "5".into())]);
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.write_all(&bytes)).await;
    ev.status = 503;
    ev.reason = Reason::TooManyConnections.as_str();
    ev.error = Some("connection limit".into());
    deps.logger.log(ev);
}
