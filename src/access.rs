//! Access-request workflow (SPEC_EXT_OPS O6, D-59): HMAC CSRF tokens for the block-page form, a
//! bounded store of recent eligible blocks per client, request records (0600 JSONL), and
//! time-boxed temp allows persisted atomically and schema-checked on load. A temp allow only
//! ever suppresses local `domain_blocklist`, `url_pattern`, `extension` and `content_type` rules.
#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::normalize::NormalizedTarget;
use crate::reason::Reason;

/// CSRF token lifetime.
pub const CSRF_TTL: Duration = Duration::from_secs(15 * 60);
/// Recent eligible blocks kept per client.
pub const RECENT_PER_CLIENT: usize = 50;
/// Clients tracked by `RecentBlocks`.
pub const RECENT_CLIENTS: usize = 100_000;
/// Longest justification / contact.
pub const MAX_JUSTIFICATION: usize = 500;
/// Longest contact field.
pub const MAX_CONTACT: usize = 100;

/// Reasons a user may ask to review (everything else shows "cannot be reviewed").
pub fn eligible(reason: Reason) -> bool {
    matches!(
        reason,
        Reason::DomainBlocklist | Reason::UrlPattern | Reason::Extension | Reason::ContentType
    )
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// HMAC-SHA256 CSRF tokens bound to (event_id, client_id, expiry); 128-bit truncated.
pub struct Csrf {
    key: [u8; 32],
}

impl Csrf {
    /// A fresh in-memory secret (tokens do not survive a restart).
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        let _ = getrandom::fill(&mut key);
        Self { key }
    }

    fn mac(&self, event_id: &str, client_id: &str, expiry: u64) -> String {
        let Ok(mut m) = Hmac::<Sha256>::new_from_slice(&self.key) else { return String::new() };
        m.update(format!("{event_id}\n{client_id}\n{expiry}").as_bytes());
        hex::encode(m.finalize().into_bytes().get(..16).unwrap_or(&[]))
    }

    /// `<expiry>.<mac>` for the block-page form.
    pub fn token(&self, event_id: &str, client_id: &str) -> String {
        let expiry = unix_now() + CSRF_TTL.as_secs();
        format!("{expiry}.{}", self.mac(event_id, client_id, expiry))
    }

    /// Constant-time check of an unexpired token.
    pub fn verify(&self, token: &str, event_id: &str, client_id: &str) -> bool {
        let Some((exp, mac)) = token.split_once('.') else { return false };
        let Ok(expiry) = exp.parse::<u64>() else { return false };
        let expected = self.mac(event_id, client_id, expiry);
        let same: bool = subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), mac.as_bytes()).into();
        same && !expected.is_empty() && unix_now() <= expiry
    }
}

impl Default for Csrf {
    fn default() -> Self {
        Self::new()
    }
}

/// A recent, really blocked (never monitor-mode) request with an eligible reason.
#[derive(Debug, Clone)]
pub struct RecentBlock {
    /// Event id.
    pub event_id: String,
    /// Reason.
    pub reason: Reason,
    /// Blocked host.
    pub host: String,
    /// The client's profile.
    pub profile: String,
    at: Instant,
}

/// Last 50 eligible blocks per client, 15-minute TTL, 100,000 clients (O6).
#[derive(Debug, Default)]
pub struct RecentBlocks {
    map: Mutex<HashMap<String, VecDeque<RecentBlock>>>,
}

impl RecentBlocks {
    /// Remember an eligible block.
    pub fn add(&self, client: &str, event_id: &str, reason: Reason, host: &str, profile: &str) {
        if !eligible(reason) {
            return;
        }
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= RECENT_CLIENTS && !map.contains_key(client) {
            map.retain(|_, q| q.back().is_some_and(|b| b.at.elapsed() < CSRF_TTL));
            if map.len() >= RECENT_CLIENTS {
                return;
            }
        }
        let q = map.entry(client.to_owned()).or_default();
        if q.len() >= RECENT_PER_CLIENT {
            q.pop_front();
        }
        q.push_back(RecentBlock {
            event_id: event_id.to_owned(),
            reason,
            host: host.to_owned(),
            profile: profile.to_owned(),
            at: Instant::now(),
        });
    }

    /// The client's own recent block for `event_id`.
    pub fn find(&self, client: &str, event_id: &str) -> Option<RecentBlock> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.get(client)?
            .iter()
            .find(|b| b.event_id == event_id && b.at.elapsed() < CSRF_TTL)
            .cloned()
    }
}

/// One access request (stored in `state/access_requests.jsonl`, 0600).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessRequest {
    /// Request id.
    pub id: String,
    /// The blocked event.
    pub event_id: String,
    /// Requesting client.
    pub client_id: String,
    /// Client profile.
    pub profile: String,
    /// Blocked host.
    pub host: String,
    /// Block reason.
    pub reason: String,
    /// User text (rendered as text only, never as HTML).
    pub justification: String,
    /// Optional contact.
    pub contact: String,
    /// pending | approved | denied.
    pub status: String,
    /// Unix seconds.
    pub created: u64,
    /// Who decided.
    pub decided_by: Option<String>,
}

/// Scope of a temp allow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum Scope {
    /// One client id.
    Client(String),
    /// Every client of a profile.
    Profile(String),
}

/// A time-boxed exception to local list rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TempAllow {
    /// Id.
    pub id: String,
    /// Exact host.
    pub host: String,
    /// Also subdomains of `host`.
    pub include_subdomains: bool,
    /// Who it applies to.
    pub scope: Scope,
    /// Unix seconds.
    pub expires: u64,
    /// Admin actor.
    pub created_by: String,
}

/// Request and temp-allow state (INTERFACES `AccessRequests`, `TempAllows`).
pub struct AccessState {
    dir: PathBuf,
    /// CSRF tokens.
    pub csrf: Csrf,
    /// Recent eligible blocks.
    pub recent: RecentBlocks,
    requests: Mutex<Vec<AccessRequest>>,
    allows: Mutex<Vec<TempAllow>>,
    hourly: Mutex<HashMap<String, VecDeque<Instant>>>,
}

/// Why a request was refused (status code for the virtual host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// HTTP status.
    pub status: u16,
    /// Short message shown to the user.
    pub message: &'static str,
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

fn random_id() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    hex::encode(b)
}

impl AccessState {
    /// Load state from `dir` (0700). A tampered or invalid `temp_allows.json` is ignored and
    /// reported by the returned warning (AR-25).
    pub fn load(dir: &Path, max_ttl: u64) -> (Self, Option<String>) {
        let _ = std::fs::create_dir_all(dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let mut warning = None;
        let now = unix_now();
        let allows = match std::fs::read(dir.join("temp_allows.json")) {
            Err(_) => Vec::new(),
            Ok(bytes) => match serde_json::from_slice::<Vec<TempAllow>>(&bytes) {
                Ok(v)
                    if v.len() <= 10_000
                        && v.iter().all(|a| a.expires <= now + max_ttl && !a.host.is_empty()) =>
                {
                    v.into_iter().filter(|a| a.expires > now).collect()
                }
                _ => {
                    warning = Some(
                        "temp_allows.json rejected (schema or TTL); no temp allows loaded".into(),
                    );
                    Vec::new()
                }
            },
        };
        let requests = std::fs::read_to_string(dir.join("access_requests.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<AccessRequest>(l).ok())
            .collect();
        let me = Self {
            dir: dir.to_path_buf(),
            csrf: Csrf::new(),
            recent: RecentBlocks::default(),
            requests: Mutex::new(requests),
            allows: Mutex::new(allows),
            hourly: Mutex::new(HashMap::new()),
        };
        (me, warning)
    }

    fn persist_requests(&self, all: &[AccessRequest]) -> std::io::Result<()> {
        let text: String =
            all.iter().filter_map(|r| serde_json::to_string(r).ok()).map(|l| l + "\n").collect();
        write_private(&self.dir.join("access_requests.jsonl"), text.as_bytes())
    }

    fn persist_allows(&self, all: &[TempAllow]) -> std::io::Result<()> {
        let text = serde_json::to_vec_pretty(all).unwrap_or_default();
        write_private(&self.dir.join("temp_allows.json"), &text)
    }

    /// Validate and store a request (AR-01..AR-14).
    #[allow(clippy::too_many_arguments)]
    pub fn submit(
        &self,
        client: &str,
        event_id: &str,
        csrf: &str,
        justification: &str,
        contact: &str,
        per_hour: u32,
        max_pending: u32,
    ) -> Result<AccessRequest, Refused> {
        let forbidden = |m| Refused { status: 403, message: m };
        if !self.csrf.verify(csrf, event_id, client) {
            return Err(forbidden("invalid or expired form; reload the blocked page"));
        }
        let block =
            self.recent.find(client, event_id).ok_or(forbidden("this block cannot be reviewed"))?;
        if justification.chars().count() > MAX_JUSTIFICATION
            || contact.chars().count() > MAX_CONTACT
        {
            return Err(Refused { status: 400, message: "text too long" });
        }
        {
            let mut hourly = self.hourly.lock().unwrap_or_else(|e| e.into_inner());
            let q = hourly.entry(client.to_owned()).or_default();
            q.retain(|t| t.elapsed() < Duration::from_secs(3600));
            if q.len() >= per_hour as usize {
                return Err(Refused { status: 429, message: "too many requests this hour" });
            }
            let pending = self
                .requests
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|r| r.client_id == client && r.status == "pending")
                .count();
            if pending >= max_pending as usize {
                return Err(Refused { status: 429, message: "too many pending requests" });
            }
            q.push_back(Instant::now());
        }
        let req = AccessRequest {
            id: random_id(),
            event_id: event_id.to_owned(),
            client_id: client.to_owned(),
            profile: block.profile,
            host: block.host,
            reason: block.reason.as_str().to_owned(),
            justification: justification.to_owned(),
            contact: contact.to_owned(),
            status: "pending".into(),
            created: unix_now(),
            decided_by: None,
        };
        let mut all = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        all.push(req.clone());
        let _ = self.persist_requests(&all);
        Ok(req)
    }

    /// Requests, optionally by status.
    pub fn requests(&self, status: Option<&str>) -> Vec<AccessRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|r| status.is_none_or(|s| r.status == s))
            .cloned()
            .collect()
    }

    /// One request.
    pub fn request(&self, id: &str) -> Option<AccessRequest> {
        self.requests.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|r| r.id == id).cloned()
    }

    /// Approve (creating a temp allow) or deny a pending request.
    pub fn decide(
        &self,
        id: &str,
        approve: bool,
        actor: &str,
        ttl: u64,
        profile_scope: bool,
    ) -> Result<(AccessRequest, Option<TempAllow>), &'static str> {
        let mut all = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let r = all.iter_mut().find(|r| r.id == id).ok_or("unknown request")?;
        if r.status != "pending" {
            return Err("request already decided");
        }
        r.status = if approve { "approved" } else { "denied" }.into();
        r.decided_by = Some(actor.to_owned());
        let decided = r.clone();
        let _ = self.persist_requests(&all);
        drop(all);
        let allow = if approve {
            let scope = if profile_scope {
                Scope::Profile(decided.profile.clone())
            } else {
                Scope::Client(decided.client_id.clone())
            };
            Some(self.add_allow(&decided.host, false, scope, ttl, actor)?)
        } else {
            None
        };
        Ok((decided, allow))
    }

    /// Add a temp allow (ttl already clamped by the caller to <= max).
    pub fn add_allow(
        &self,
        host: &str,
        include_subdomains: bool,
        scope: Scope,
        ttl: u64,
        actor: &str,
    ) -> Result<TempAllow, &'static str> {
        let host = crate::blocklist::parse_domain_entry(host).map_err(|_| "invalid host")?.1;
        let allow = TempAllow {
            id: random_id(),
            host,
            include_subdomains,
            scope,
            expires: unix_now() + ttl,
            created_by: actor.to_owned(),
        };
        let mut all = self.allows.lock().unwrap_or_else(|e| e.into_inner());
        if all.len() >= 10_000 {
            return Err("too many temp allows");
        }
        all.push(allow.clone());
        self.persist_allows(&all).map_err(|_| "cannot persist temp allows")?;
        Ok(allow)
    }

    /// Remove a temp allow.
    pub fn remove_allow(&self, id: &str) -> bool {
        let mut all = self.allows.lock().unwrap_or_else(|e| e.into_inner());
        let before = all.len();
        all.retain(|a| a.id != id);
        let removed = all.len() != before;
        if removed {
            let _ = self.persist_allows(&all);
        }
        removed
    }

    /// Current (unexpired) temp allows.
    pub fn allows(&self) -> Vec<TempAllow> {
        let now = unix_now();
        self.allows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|a| a.expires > now)
            .cloned()
            .collect()
    }

    /// Drop expired allows; returns them (for `temp_allow_expired` events).
    pub fn sweep(&self) -> Vec<TempAllow> {
        let now = unix_now();
        let mut all = self.allows.lock().unwrap_or_else(|e| e.into_inner());
        let (gone, keep): (Vec<_>, Vec<_>) = all.drain(..).partition(|a| a.expires <= now);
        *all = keep;
        if !gone.is_empty() {
            let _ = self.persist_allows(&all);
        }
        gone
    }

    /// The temp allow covering this client/profile and host, if any (checked at match time).
    pub fn matches(&self, client: &str, profile: &str, t: &NormalizedTarget) -> Option<String> {
        let host = t.host.domain()?.trim_end_matches('.');
        let now = unix_now();
        self.allows.lock().unwrap_or_else(|e| e.into_inner()).iter().find_map(|a| {
            let scope_ok = match &a.scope {
                Scope::Client(c) => c == client,
                Scope::Profile(p) => p == profile,
            };
            let host_ok =
                host == a.host || (a.include_subdomains && host.ends_with(&format!(".{}", a.host)));
            (scope_ok && host_ok && a.expires > now).then(|| a.id.clone())
        })
    }

    /// Pending/approved/denied counts (metrics).
    pub fn counts(&self) -> [(&'static str, usize); 3] {
        let all = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let n = |s: &str| all.iter().filter(|r| r.status == s).count();
        [("pending", n("pending")), ("approved", n("approved")), ("denied", n("denied"))]
    }
}
