//! The proxy: first-party HTTP/1 core (D-05), per-request pipeline, CONNECT passthrough,
//! listener with connection limits, auth, panic isolation, stats and graceful shutdown.
#![forbid(unsafe_code)]

pub mod connect;
pub mod h2;
pub mod h2guard;
pub mod http1;
pub mod io;
pub mod pipeline;
pub mod response;
pub mod scanning;
pub mod transparent;
pub mod vhost;

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

use crate::auth::{Lockout, verify_password};
use crate::blocklist::BlocklistHandle;
use crate::config::{Config, Mode};
use crate::filter::{Action, Decision, Phase, evaluate_profile};
use crate::limiter::{LimitReject, Limiter, Permit, SystemClock};
use crate::logger::{EventLogger, ListCounts, RequestEvent, Stats, SysEvent, SystemLog};
use crate::normalize::{NormalizedTarget, fold_ip};
use crate::policy::{DestPolicy, Resolver, SystemResolver};
use crate::profiles::{PolicySet, Profile};
use crate::reason::Reason;
use crate::util::LockExt;
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

/// Hash of a random, discarded password with the same parameters as `hash-password`: unknown
/// user names are verified against it so they cost the same as a wrong password (PT-9.7).
const DUMMY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$/LgZaRwAUqKQTcyrNq4vMQ$9fQXbi3WR1jHWdNQmy96Td4xVgBOz8gFK4i0RSuG/z0";

/// Proxy authentication (D-14, D-50, SPEC 4.10): users come from the current [`PolicySet`].
struct ProxyAuth {
    ip_lockout: Lockout<IpAddr>,
    user_lockout: Lockout<String>,
    cache: Mutex<HashMap<[u8; 32], Instant>>,
    permits: Semaphore,
    /// Verified for unknown users so they cost the same as a wrong password (PT-9.7).
    dummy_phc: String,
}

impl ProxyAuth {
    fn new() -> Self {
        Self {
            ip_lockout: Lockout::default(),
            user_lockout: Lockout::default(),
            cache: Mutex::new(HashMap::new()),
            permits: Semaphore::new(AUTH_PARALLELISM),
            dummy_phc: DUMMY_PHC.to_owned(),
        }
    }

    /// Check `Proxy-Authorization: Basic ...` against `users`; returns the user name.
    async fn check(
        &self,
        head: &RequestHead,
        ip: IpAddr,
        users: &PolicySet,
        sys: &SystemLog,
    ) -> Result<String, Fail> {
        let locked = || fail(429, Reason::RateLimited, "too many authentication failures");
        if self.ip_lockout.is_locked(ip, std::time::Instant::now()) {
            return Err(locked());
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
        if self.user_lockout.is_locked(user.to_owned(), std::time::Instant::now()) {
            return Err(locked());
        }
        let known = users.user(user);
        let phc = known.map_or(self.dummy_phc.as_str(), |u| u.phc.as_str());
        let key: [u8; 32] = Sha256::digest(format!("{user}\0{password}\0{phc}").as_bytes()).into();
        let cached = known.is_some() && {
            let cache = self.cache.lock_or_recover();
            cache.iter().any(|(k, at)| bool::from(k.ct_eq(&key)) && at.elapsed() < AUTH_CACHE_TTL)
        };
        let ok = cached || {
            let _permit = self
                .permits
                .acquire()
                .await
                .map_err(|_| fail(500, Reason::InternalError, "auth unavailable"))?;
            let (phc, p) = (phc.to_owned(), password.to_owned());
            let valid = tokio::task::spawn_blocking(move || verify_password(&phc, p.as_bytes()))
                .await
                .unwrap_or(false);
            valid && known.is_some()
        };
        if !ok {
            self.failure(ip, user, sys);
            return Err(fail(407, Reason::AuthFailed, "invalid proxy credentials"));
        }
        if !cached {
            let mut cache = self.cache.lock_or_recover();
            if cache.len() >= AUTH_CACHE_MAX {
                cache.clear();
            }
            cache.insert(key, Instant::now());
        }
        self.ip_lockout.record_success(ip);
        self.user_lockout.record_success(user.to_owned());
        Ok(user.to_owned())
    }

    fn failure(&self, ip: IpAddr, user: &str, sys: &SystemLog) {
        let now = std::time::Instant::now();
        let by_ip = self.ip_lockout.record_failure(ip, now);
        let by_user = !user.is_empty() && self.user_lockout.record_failure(user.to_owned(), now);
        if by_ip || by_user {
            sys.event(
                SysEvent::AuthLockout,
                serde_json::json!({ "ip": ip.to_string(), "user": user, "by": if by_ip { "ip" } else { "user" } }),
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
        let mut map = self.deps.per_ip.lock_or_recover();
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
    /// Original destination of transparent connections (D-41).
    pub orig_dst: Arc<dyn transparent::OriginalDst>,
    /// Users, clients and profiles (hot-reloaded, D-50).
    pub policies: arc_swap::ArcSwap<PolicySet>,
    /// Per-client limits (D-51).
    pub limiter: Arc<Limiter>,
    /// Threat feeds (D-52).
    pub feeds: Arc<crate::feeds::FeedManager>,
    /// Download scanning when `[scan] enabled` (D-53).
    pub scanner: Option<Arc<crate::scan::Scanner>>,
    /// Admin views and metrics (O2/O3).
    pub telemetry: Arc<crate::telemetry::Telemetry>,
    /// Access requests and temp allows (O6).
    pub access: Arc<crate::access::AccessState>,
    /// Dashboard settings (A-30).
    pub settings: arc_swap::ArcSwap<crate::profiles::Settings>,
    /// WASM rule plugins (O10); reloaded with policies.
    pub plugins: arc_swap::ArcSwap<crate::plugins::Plugins>,
    auth: ProxyAuth,
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
            proxy_mode: if self.mode() == Mode::Monitor { "monitor" } else { "enforce" },
            ..RequestEvent::default()
        }
    }

    /// The effective global mode (config, or the dashboard setting).
    pub fn mode(&self) -> Mode {
        self.settings.load().mode.unwrap_or(self.cfg.mode)
    }

    fn finish(&self, ev: RequestEvent) {
        self.telemetry.record(&ev);
        if ev.action == Action::Block.as_str()
            && let (Some(id), Some(profile)) = (&ev.client_id, &ev.profile)
            && let Some(reason) = Reason::ALL.iter().find(|r| r.as_str() == ev.reason)
        {
            self.access.recent.add(id, &ev.event_id, *reason, &ev.dest_host, profile);
        }
        if let (Some(id), Some(name)) = (&ev.client_id, &ev.profile)
            && let Some(rate) = self.policies.load().profile(name).and_then(|p| p.rate)
        {
            self.limiter.add_bytes(id, &rate, ev.bytes_in.saturating_add(ev.bytes_out));
        }
        let action =
            if ev.action == Action::Block.as_str() { Action::Block } else { Action::Allow };
        self.stats.record(action, &ev.dest_host, ev.bytes_in, ev.bytes_out);
        if ev.error.is_some() && action == Action::Allow {
            self.stats.record_error();
        }
        self.logger.log(ev);
    }

    /// Rule order (O6): allowlist, feeds (never overridable), the client's temp allows, then the
    /// remaining local rules. Safety policy is checked elsewhere and never here.
    fn evaluate(
        &self,
        t: &NormalizedTarget,
        phase: Phase<'_>,
        profile: &Profile,
        client: &str,
    ) -> Decision {
        let now = time::OffsetDateTime::now_utc();
        let d = evaluate_profile(t, phase, &self.lists.snapshot(), profile, now);
        if d.reason == Reason::Allowlist {
            return d;
        }
        if let Some(f) = self.feeds.check(t, phase, &profile.feeds, profile.mode) {
            return f;
        }
        if crate::access::eligible(d.reason)
            && let Some(id) = self.access.matches(client, &profile.name, t)
        {
            return Decision {
                reason: Reason::Allowlist,
                rule_id: Some(format!("temp_allow:{id}")),
                rule_list: Some("temp_allows".into()),
                ..Decision::allow()
            };
        }
        // Plugins only ever add blocks, and only to requests nothing else has decided (O10).
        let connect = matches!(phase, Phase::ConnectPreDns);
        if d.action == Action::Allow
            && d.reason != Reason::Allowlist
            && !d.would_block
            && (connect || matches!(phase, Phase::PreDns))
        {
            let plugins = self.plugins.load();
            if !plugins.is_empty() {
                let view = crate::plugins::view(t, connect, &profile.name);
                match plugins.check(&view) {
                    Some(crate::plugins::Outcome::Block { plugin }) => {
                        return Decision::block(
                            profile.mode,
                            Reason::PluginRule,
                            format!("plugin:{plugin}"),
                            "plugins",
                        );
                    }
                    Some(crate::plugins::Outcome::Error { plugin, block, detail, log }) => {
                        if log {
                            self.logger.system().event(
                                SysEvent::PluginError,
                                serde_json::json!({ "plugin": plugin, "detail": detail, "blocked": block }),
                            );
                        }
                        if block {
                            return Decision::block(
                                profile.mode,
                                Reason::PluginError,
                                format!("plugin:{plugin}"),
                                "plugins",
                            );
                        }
                    }
                    None => {}
                }
            }
        }
        d
    }

    /// Authenticate when users exist (per request, D-50); returns the user name.
    async fn authorize(
        &self,
        head: &RequestHead,
        ev: &mut RequestEvent,
        peer: IpAddr,
    ) -> Result<Option<String>, Fail> {
        let users = self.policies.load();
        if !users.has_users() {
            return Ok(None);
        }
        let user = self.auth.check(head, peer, &users, &self.logger.system()).await?;
        ev.proxy_user = Some(user.clone());
        Ok(Some(user))
    }

    /// Identity and profile for this request; logged on `ev` (D-50).
    fn identify(
        &self,
        peer: IpAddr,
        user: Option<&str>,
        ev: &mut RequestEvent,
    ) -> (String, Arc<Profile>) {
        let (id, profile) = self.policies.load().resolve(peer, user);
        ev.client_id = Some(id.clone());
        ev.profile = Some(profile.name.clone());
        (id, profile)
    }

    /// The request-rate/in-flight/quota check (step 3b); limits apply in every mode (D-51).
    fn admit(&self, id: &str, profile: &Profile) -> Result<Option<Permit>, LimitReject> {
        let Some(rate) = &profile.rate else { return Ok(None) };
        self.limiter.check_request(id, rate).map(Some).inspect_err(|r| {
            self.stats.record_limit(&profile.name, r.reason);
        })
    }

    /// Re-read users, clients and profiles from the config file; the old set stays on error.
    pub fn reload_policies(&self) -> Result<(), String> {
        let path = self.cfg.source.as_ref().ok_or("no config file")?;
        let settings = self.settings.load_full();
        let result = Config::load(path).map_err(|e| e.to_string()).and_then(|c| {
            let policies = PolicySet::build(&settings.apply(&c))?;
            // A plugin set that fails to load keeps the previous one (O10).
            let plugins = crate::plugins::Plugins::load(&c.plugins)?;
            self.policies.store(Arc::new(policies));
            if !plugins.is_empty() {
                self.logger.system().event(
                    SysEvent::PluginsLoaded,
                    serde_json::json!({ "plugins": plugins.names() }),
                );
            }
            self.plugins.store(Arc::new(plugins));
            Ok(())
        });
        let detail = match &result {
            Ok(()) => serde_json::json!({ "ok": true }),
            Err(e) => serde_json::json!({ "ok": false, "error": e }),
        };
        self.logger.system().event(SysEvent::PolicyReloaded, detail);
        result
    }

    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        let ip = fold_ip(ip);
        let mut map = self.per_ip.lock_or_recover();
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
    /// Transparent HTTP and TLS listener addresses when enabled (SPEC 4.17).
    pub transparent_addrs: Option<(SocketAddr, SocketAddr)>,
    /// Admin listener address when enabled (O1).
    pub admin_addr: Option<SocketAddr>,
    shutdown: watch::Sender<bool>,
    accept: Vec<tokio::task::JoinHandle<()>>,
    background: Vec<tokio::task::JoinHandle<()>>,
}

impl ProxyHandle {
    /// Stop accepting, drain in-flight connections up to `shutdown_drain`, flush logs (D-31).
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for a in &self.accept {
            a.abort();
        }
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
    start_with(cfg, resolver, None).await
}

/// [`start`] with an injected original-destination source for transparent tests (D-43).
pub async fn start_with(
    cfg: Config,
    resolver: Option<Arc<dyn Resolver>>,
    orig_dst: Option<Arc<dyn transparent::OriginalDst>>,
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
    let transparent = if cfg.transparent.enabled {
        let http = TcpListener::bind(cfg.transparent.http_listen).await?;
        let tls = TcpListener::bind(cfg.transparent.tls_listen).await?;
        Some((http, tls))
    } else {
        None
    };
    let transparent_addrs = match &transparent {
        Some((h, t)) => Some((h.local_addr()?, t.local_addr()?)),
        None => None,
    };
    let mut own = vec![local_addr];
    own.extend(transparent_addrs.iter().flat_map(|(h, t)| [*h, *t]));
    // The admin listener is the proxy too (review 2 L4); it binds later, so its configured
    // address is used (an ephemeral port 0 is unknown here and never a valid destination).
    if cfg.admin.enabled && cfg.admin.listen.port() != 0 {
        own.push(cfg.admin.listen);
    }
    let resolver = resolver.or_else(crate::policy::test_hosts_resolver);
    let (tx, rx) = watch::channel(false);
    let (access, access_warning) =
        crate::access::AccessState::load(&cfg.state.dir, cfg.access_requests.max_ttl_secs);
    let (settings, settings_warning) = crate::admin::edit::load_settings(&cfg.state.dir);
    let policies = PolicySet::build(&settings.apply(&cfg)).map_err(invalid)?;
    if !settings.categories.is_empty() {
        let _ = lists.set_category_overrides(settings.categories.clone());
    }
    let plugins = crate::plugins::Plugins::load(&cfg.plugins).map_err(invalid)?;
    if !plugins.is_empty() {
        sys.event(SysEvent::PluginsLoaded, serde_json::json!({ "plugins": plugins.names() }));
    }
    let scanner = if cfg.scan.enabled {
        Some(Arc::new(crate::scan::Scanner::new(cfg.scan.clone()).map_err(invalid)?))
    } else {
        None
    };
    let feeds = Arc::new(crate::feeds::FeedManager::new(
        cfg.feeds.clone(),
        cfg.feeds_global.dir.clone(),
        cfg.feeds_global.protected_domains.clone(),
        Some(crate::feeds::Fetcher {
            tls: Arc::clone(&upstream_tls),
            resolver: resolver.clone().unwrap_or_else(|| Arc::new(SystemResolver)),
            policy: DestPolicy::new(!feed_loopback_allowed(), Vec::new()),
        }),
        Some(sys.clone()),
    ));
    let mode =
        if settings.mode.unwrap_or(cfg.mode) == Mode::Monitor { "monitor" } else { "enforce" };
    let deps = Arc::new(ProxyDeps {
        policy: DestPolicy::new(cfg.destination.deny_private_ranges, own),
        orig_dst: orig_dst
            .unwrap_or_else(|| transparent::original_dst_source(cfg.transparent.orig_dst)),
        limits: Limits::new(&cfg.limits, cfg.http.compat),
        resolver: resolver.unwrap_or_else(|| Arc::new(SystemResolver)),
        stats: Arc::new(Stats::default()),
        lists: Arc::clone(&lists),
        cfg: Arc::new(cfg),
        logger,
        block_page,
        leaves,
        upstream_tls,
        policies: arc_swap::ArcSwap::from_pointee(policies),
        limiter: Limiter::new(Arc::new(SystemClock), crate::limiter::MAX_KEYS),
        feeds: Arc::clone(&feeds),
        scanner,
        telemetry: Arc::new(crate::telemetry::Telemetry::default()),
        access: Arc::new(access),
        settings: arc_swap::ArcSwap::from_pointee(settings),
        plugins: arc_swap::ArcSwap::from_pointee(plugins),
        auth: ProxyAuth::new(),
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
    for w in [access_warning, settings_warning].into_iter().flatten() {
        sys.event(SysEvent::ConfigLoaded, serde_json::json!({ "state_warning": w }));
    }

    let watcher =
        lists.spawn_watcher(Duration::from_secs(deps.cfg.blocklists.reload_interval_secs), sys);
    let stats_task = tokio::spawn(stats_loop(Arc::clone(&deps)));
    let policy_task = tokio::spawn(policy_watch(Arc::clone(&deps)));
    let feed_tasks = feeds.spawn();
    let sweeper = tokio::spawn(temp_allow_sweeper(Arc::clone(&deps)));
    let admin = if deps.cfg.admin.enabled {
        Some(crate::admin::spawn(Arc::clone(&deps)).await?)
    } else {
        None
    };
    let mut accept =
        vec![tokio::spawn(accept_loop(listener, Arc::clone(&deps), Listener::Explicit))];
    if let Some((http, tls)) = transparent {
        accept.push(tokio::spawn(accept_loop(http, Arc::clone(&deps), Listener::TransparentHttp)));
        accept.push(tokio::spawn(accept_loop(tls, Arc::clone(&deps), Listener::TransparentTls)));
    }
    Ok(ProxyHandle {
        local_addr,
        deps,
        transparent_addrs,
        shutdown: tx,
        accept,
        admin_addr: admin.as_ref().map(|(a, _)| *a),
        background: [watcher, stats_task, policy_task, sweeper]
            .into_iter()
            .chain(feed_tasks)
            .chain(admin.map(|(_, t)| t))
            .collect(),
    })
}

/// Feed hosts must be public (P3); only `insecure-test` builds may allow a loopback test feed.
fn feed_loopback_allowed() -> bool {
    cfg!(feature = "insecure-test")
        && std::env::var("WEBFILTER_TEST_FEED_ALLOW_LOOPBACK").is_ok_and(|v| v == "1")
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

/// Expire temp allows (O6): `temp_allow_expired` events.
async fn temp_allow_sweeper(deps: Arc<ProxyDeps>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tick.tick().await;
        for a in deps.access.sweep() {
            deps.logger.system().event(
                SysEvent::TempAllowExpired,
                serde_json::json!({ "id": a.id, "host": a.host }),
            );
        }
    }
}

/// Reload users/clients/profiles when the config file changes (SPEC_EXT_POLICY P1).
async fn policy_watch(deps: Arc<ProxyDeps>) {
    let Some(path) = deps.cfg.source.clone() else { return };
    let stamp = || std::fs::metadata(&path).ok().and_then(|m| Some((m.len(), m.modified().ok()?)));
    let mut last = stamp();
    let mut tick =
        tokio::time::interval(Duration::from_secs(deps.cfg.blocklists.reload_interval_secs));
    loop {
        tick.tick().await;
        let now = stamp();
        if now != last {
            last = now;
            let _ = deps.reload_policies();
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

/// Which listener a connection arrived on.
#[derive(Debug, Clone, Copy)]
enum Listener {
    Explicit,
    TransparentHttp,
    TransparentTls,
}

async fn accept_loop(listener: TcpListener, deps: Arc<ProxyDeps>, kind: Listener) {
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
                reject_over_limit(stream, peer, &deps, 5).await;
                return;
            };
            // Per-client connection cap by source identity (D-51; users are known per request).
            let profile = Arc::clone(deps.policies.load().profile_for_ip(peer.ip()));
            let id = crate::profiles::client_id(peer.ip(), None);
            let _slot = match profile.rate.as_ref().map(|r| deps.limiter.acquire_connection(&id, r))
            {
                Some(Err(r)) => {
                    deps.stats.record_limit(&profile.name, r.reason);
                    reject_over_limit(stream, peer, &deps, r.retry_after).await;
                    return;
                }
                slot => slot,
            };
            // Panic isolation: a panic in one connection never affects others (SPEC 9).
            let served = match kind {
                Listener::Explicit => {
                    let via = pipeline::Via::Explicit;
                    AssertUnwindSafe(pipeline::serve_connection(
                        stream,
                        peer,
                        Arc::clone(&deps),
                        via,
                    ))
                    .catch_unwind()
                    .await
                }
                Listener::TransparentHttp | Listener::TransparentTls => {
                    let tls = matches!(kind, Listener::TransparentTls);
                    AssertUnwindSafe(transparent::serve(stream, peer, Arc::clone(&deps), tls))
                        .catch_unwind()
                        .await
                }
            };
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

async fn reject_over_limit(mut stream: TcpStream, peer: SocketAddr, deps: &ProxyDeps, retry: u64) {
    let mut ev = deps.new_event(peer);
    let bytes = error_page(
        503,
        Reason::TooManyConnections,
        &ev.event_id,
        &[("retry-after", retry.to_string())],
    );
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.write_all(&bytes)).await;
    ev.status = 503;
    ev.reason = Reason::TooManyConnections.as_str();
    ev.error = Some("connection limit".into());
    deps.logger.log(ev);
}
