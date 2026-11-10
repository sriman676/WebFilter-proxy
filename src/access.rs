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
/// Stored access requests (all statuses); the oldest decided ones go first.
pub const MAX_REQUESTS: usize = 10_000;
/// Decided requests are kept this long (seconds).
pub const DECIDED_RETENTION: u64 = 7 * 86_400;
/// Temp allows kept at most.
pub const MAX_ALLOWS: usize = 10_000;
/// Per-client hourly windows tracked before expired ones are swept on submit.
const HOURLY_CLIENTS: usize = 10_000;
const HOUR: Duration = Duration::from_secs(3600);

/// Apply retention to `all`: drop decided requests older than [`DECIDED_RETENTION`], then the
/// oldest decided ones while more than `cap` remain. Pending requests are never dropped (the
/// per-client pending cap bounds them; a full store refuses new submissions). True if changed.
pub fn retain_requests(all: &mut Vec<AccessRequest>, now: u64, cap: usize) -> bool {
    let before = all.len();
    all.retain(|r| r.status == "pending" || r.created.saturating_add(DECIDED_RETENTION) > now);
    let mut excess = all.len().saturating_sub(cap);
    if excess > 0 {
        let mut decided: Vec<(u64, usize)> = all
            .iter()
            .enumerate()
            .filter(|(_, r)| r.status != "pending")
            .map(|(i, r)| (r.created, i))
            .collect();
        decided.sort_unstable();
        let mut doomed = vec![false; all.len()];
        for (_, i) in decided {
            if excess == 0 {
                break;
            }
            if let Some(d) = doomed.get_mut(i) {
                *d = true;
                excess -= 1;
            }
        }
        // `retain` visits elements in order.
        let mut flags = doomed.into_iter();
        all.retain(|_| !flags.next().unwrap_or(false));
    }
    all.len() != before
}

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

/// Forget clients whose hourly window holds no submission from the last hour.
fn prune_hourly(hourly: &mut HashMap<String, VecDeque<Instant>>) {
    hourly.retain(|_, q| {
        q.retain(|t| t.elapsed() < HOUR);
        !q.is_empty()
    });
}

/// Append one line to a 0600 file (created if missing).
fn append_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_data()
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
        let mut requests: Vec<AccessRequest> =
            std::fs::read_to_string(dir.join("access_requests.jsonl"))
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str::<AccessRequest>(l).ok())
                .collect();
        let pruned = retain_requests(&mut requests, now, MAX_REQUESTS);
        let me = Self {
            dir: dir.to_path_buf(),
            csrf: Csrf::new(),
            recent: RecentBlocks::default(),
            requests: Mutex::new(requests),
            allows: Mutex::new(allows),
            hourly: Mutex::new(HashMap::new()),
        };
        if pruned {
            let all = me.requests.lock().unwrap_or_else(|e| e.into_inner());
            let _ = me.persist_requests(&all);
        }
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
        let busy = |m| Refused { status: 429, message: m };
        // Lock order everywhere: hourly, then requests, then allows.
        let mut hourly = self.hourly.lock().unwrap_or_else(|e| e.into_inner());
        if hourly.len() >= HOURLY_CLIENTS && !hourly.contains_key(client) {
            prune_hourly(&mut hourly);
            if hourly.len() >= HOURLY_CLIENTS {
                return Err(busy("too many requests this hour"));
            }
        }
        let q = hourly.entry(client.to_owned()).or_default();
        q.retain(|t| t.elapsed() < HOUR);
        if q.len() >= per_hour as usize {
            return Err(busy("too many requests this hour"));
        }
        let mut all = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let pending = all.iter().filter(|r| r.client_id == client && r.status == "pending").count();
        if pending >= max_pending as usize {
            return Err(busy("too many pending requests"));
        }
        // Make room for one more (oldest decided first); a store full of pending refuses.
        let pruned = retain_requests(&mut all, unix_now(), MAX_REQUESTS.saturating_sub(1));
        if all.len() >= MAX_REQUESTS {
            if pruned {
                let _ = self.persist_requests(&all);
            }
            return Err(busy("too many pending requests"));
        }
        q.push_back(Instant::now());
        drop(hourly);
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
        all.push(req.clone());
        // Append the new record unless retention changed the file's contents.
        let path = self.dir.join("access_requests.jsonl");
        let appended = !pruned
            && serde_json::to_string(&req)
                .ok()
                .is_some_and(|l| append_private(&path, format!("{l}\n").as_bytes()).is_ok());
        if !appended {
            let _ = self.persist_requests(&all);
        }
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
        // Both records change under the requests lock: an approval whose temp allow cannot be
        // created (invalid host, cap, I/O) leaves the request pending (review L3).
        let mut all = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let r = all.iter_mut().find(|r| r.id == id).ok_or("unknown request")?;
        if r.status != "pending" {
            return Err("request already decided");
        }
        let allow = if approve {
            let scope = if profile_scope {
                Scope::Profile(r.profile.clone())
            } else {
                Scope::Client(r.client_id.clone())
            };
            Some(self.add_allow(&r.host, false, scope, ttl, actor)?)
        } else {
            None
        };
        r.status = if approve { "approved" } else { "denied" }.into();
        r.decided_by = Some(actor.to_owned());
        let decided = r.clone();
        if self.persist_requests(&all).is_err() {
            // Roll back so memory and disk agree: still pending, no allow.
            if let Some(r) = all.iter_mut().find(|r| r.id == id) {
                r.status = "pending".into();
                r.decided_by = None;
            }
            if let Some(a) = &allow {
                self.remove_allow(&a.id);
            }
            return Err("cannot persist access requests");
        }
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
        if all.len() >= MAX_ALLOWS {
            return Err("too many temp allows");
        }
        all.push(allow.clone());
        if self.persist_allows(&all).is_err() {
            all.pop(); // memory matches disk
            return Err("cannot persist temp allows");
        }
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

    /// Drop expired allows; returns them (for `temp_allow_expired` events). Also applies request
    /// retention and forgets expired per-client hourly windows.
    pub fn sweep(&self) -> Vec<TempAllow> {
        let now = unix_now();
        prune_hourly(&mut self.hourly.lock().unwrap_or_else(|e| e.into_inner()));
        {
            let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
            if retain_requests(&mut requests, now, MAX_REQUESTS) {
                let _ = self.persist_requests(&requests);
            }
        }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn submit(s: &AccessState, client: &str, event: &str, host: &str) -> AccessRequest {
        s.recent.add(client, event, Reason::DomainBlocklist, host, "default");
        let token = s.csrf.token(event, client);
        s.submit(client, event, &token, "need it", "", 100, 100).unwrap()
    }

    fn record(id: &str, status: &str, created: u64) -> AccessRequest {
        AccessRequest {
            id: id.into(),
            event_id: format!("ev-{id}"),
            client_id: "ip:10.0.0.1".into(),
            profile: "default".into(),
            host: "x.test".into(),
            reason: "domain_blocklist".into(),
            justification: String::new(),
            contact: String::new(),
            status: status.into(),
            created,
            decided_by: None,
        }
    }

    #[test]
    fn l3_approval_without_a_valid_allow_stays_pending() {
        let dir = tempfile::tempdir().unwrap();
        let (s, _) = AccessState::load(dir.path(), 86_400);
        let r = submit(&s, "ip:10.0.0.1", "ev1", "::1"); // IPv6 literal: no domain allow
        assert!(s.decide(&r.id, true, "admin", 3600, false).is_err());
        assert_eq!(s.request(&r.id).unwrap().status, "pending", "nothing committed");
        assert!(s.allows().is_empty());
        let on_disk = std::fs::read_to_string(dir.path().join("access_requests.jsonl")).unwrap();
        assert!(on_disk.contains("\"pending\"") && !on_disk.contains("\"approved\""));
        // A valid approval commits both records.
        let ok = submit(&s, "ip:10.0.0.1", "ev2", "ok.test");
        let (d, allow) = s.decide(&ok.id, true, "admin", 3600, false).unwrap();
        assert_eq!(d.status, "approved");
        assert_eq!(allow.unwrap().host, "ok.test");
        // The failed one can still be denied.
        assert_eq!(s.decide(&r.id, false, "admin", 3600, false).unwrap().0.status, "denied");
    }

    #[test]
    fn l4_retention_drops_old_decided_and_caps_oldest_decided_first() {
        let now = 100 * 86_400;
        let old = now - DECIDED_RETENTION - 1;
        let mut all = vec![
            record("a", "approved", old),
            record("b", "pending", old),
            record("c", "denied", now - 10),
            record("d", "denied", now - 20),
            record("e", "pending", now),
        ];
        assert!(retain_requests(&mut all, now, 10));
        let ids: Vec<&str> = all.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["b", "c", "d", "e"], "old decided gone, old pending kept");
        assert!(retain_requests(&mut all, now, 3));
        let ids: Vec<&str> = all.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["b", "c", "e"], "the oldest decided goes first, order kept");
        assert!(retain_requests(&mut all, now, 1));
        assert!(all.iter().all(|r| r.status == "pending"), "pending never dropped");
        assert!(!retain_requests(&mut all, now, 1));
    }

    #[test]
    fn l4_load_prunes_and_submit_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access_requests.jsonl");
        let now = unix_now();
        let lines: String = [
            record("old", "approved", now - DECIDED_RETENTION - 5),
            record("new", "denied", now - 5),
        ]
        .iter()
        .map(|r| serde_json::to_string(r).unwrap() + "\n")
        .collect();
        std::fs::write(&path, lines).unwrap();
        let (s, _) = AccessState::load(dir.path(), 86_400);
        assert!(s.request("old").is_none() && s.request("new").is_some());
        let before = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before.lines().count(), 1, "pruned on load and persisted");
        let r = submit(&s, "ip:10.0.0.2", "ev3", "a.test");
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.starts_with(&before), "appended, earlier lines untouched");
        assert_eq!(after.lines().count(), 2);
        assert!(after.contains(&r.id));
        // Sweep keeps live hourly windows: the per-hour cap still applies afterwards.
        s.sweep();
        s.recent.add("ip:10.0.0.2", "ev4", Reason::DomainBlocklist, "b.test", "default");
        let token = s.csrf.token("ev4", "ip:10.0.0.2");
        let e = s.submit("ip:10.0.0.2", "ev4", &token, "", "", 1, 100).unwrap_err();
        assert_eq!(e.status, 429);
    }

    #[test]
    fn l4_global_store_cap_refuses_when_full_of_pending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access_requests.jsonl");
        let now = unix_now();
        let lines: String = (0..MAX_REQUESTS)
            .map(|i| {
                let mut r = record(&format!("p{i}"), "pending", now);
                r.client_id = format!("ip:10.{}.{}.1", i / 256, i % 256);
                serde_json::to_string(&r).unwrap() + "\n"
            })
            .collect();
        std::fs::write(&path, lines).unwrap();
        let (s, _) = AccessState::load(dir.path(), 86_400);
        s.recent.add("ip:10.200.0.9", "evx", Reason::DomainBlocklist, "c.test", "default");
        let token = s.csrf.token("evx", "ip:10.200.0.9");
        let e = s.submit("ip:10.200.0.9", "evx", &token, "", "", 5, 5).unwrap_err();
        assert_eq!(e.status, 429, "store full of pending requests");
        // Once some are decided, the oldest decided one makes room.
        let first = s.requests(Some("pending")).first().unwrap().id.clone();
        s.decide(&first, false, "admin", 60, false).unwrap();
        s.submit("ip:10.200.0.9", "evx", &token, "", "", 5, 5).unwrap();
        assert_eq!(s.requests(None).len(), MAX_REQUESTS);
        assert!(s.request(&first).is_none(), "oldest decided dropped");
    }
}
