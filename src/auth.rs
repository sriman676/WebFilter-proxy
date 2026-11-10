//! Proxy authentication primitives (D-14): argon2id PHC hashes, constant-time credential check,
//! per-client lockout (5 failures within 60 s -> 60 s).
#![forbid(unsafe_code)]

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::util::LockExt;
use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use subtle::ConstantTimeEq;

/// Failures before lockout.
pub const MAX_FAILURES: u32 = 5;
/// Lockout duration.
pub const LOCKOUT: Duration = Duration::from_secs(60);
/// Failures count only within this window; older ones decay (RV3-L1).
pub const FAILURE_WINDOW: Duration = Duration::from_secs(60);
/// Longest user name that is looked up or counted (configured names are 1-64 bytes, RV3-M3).
pub const MAX_USER_LEN: usize = 64;
/// The one per-user lockout name every unknown user name is counted under (RV3-M3).
pub const UNKNOWN_USER: &str = "<unknown>";
/// Tracked client IPs (bounded memory).
pub const MAX_TRACKED: usize = 100_000;

/// Hash a password into an argon2id PHC string (`webfilter-proxy hash-password`).
pub fn hash_password(password: &[u8]) -> Result<String, String> {
    Argon2::default().hash_password(password).map(|h| h.to_string()).map_err(|e| e.to_string())
}

/// Whether `phc` parses as an argon2id PHC string.
pub fn is_argon2id_phc(phc: &str) -> bool {
    phc.starts_with("$argon2id$") && PasswordHash::new(phc).is_ok()
}

/// Verify `password` against an argon2id PHC string; any parse error is a failure.
pub fn verify_password(phc: &str, password: &[u8]) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| Argon2::default().verify_password(password, &h).is_ok())
}

/// Check user and password; the expensive hash is always computed so a wrong user name takes
/// the same time as a wrong password.
pub fn verify_credentials(expected_user: &str, phc: &str, user: &str, password: &[u8]) -> bool {
    let user_ok: bool = expected_user.as_bytes().ct_eq(user.as_bytes()).into();
    let password_ok = verify_password(phc, password);
    user_ok & password_ok
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

impl Entry {
    fn new(now: Instant) -> Self {
        Self { failures: 0, window_start: now, locked_until: None }
    }
}

/// What a lockout counter is keyed by.
pub trait LockKey: Eq + Hash + Clone {
    /// The canonical key.
    fn lock_key(self) -> Self;
}

/// IPv4 (mapped IPv6 folded) or the IPv6 /64, so rotating addresses inside one /64 does not reset
/// the counter (PF-1-05, as D-50).
impl LockKey for IpAddr {
    fn lock_key(self) -> Self {
        crate::profiles::client_net(self)
    }
}

/// Per-user counters per client network (PT-9.7, RV3-M3): failures from one network never lock
/// the user out from another. Build keys with [`user_key`].
impl LockKey for (String, IpAddr) {
    fn lock_key(self) -> Self {
        (self.0, crate::profiles::client_net(self.1))
    }
}

/// The per-user lockout key: a known user per (name, client /64); every unknown name shares
/// [`UNKNOWN_USER`], so attacker-chosen names never grow the table (RV3-M3).
pub fn user_key(user: &str, known: bool, ip: IpAddr) -> (String, IpAddr) {
    let name = if known { user } else { UNKNOWN_USER };
    (name.to_owned(), ip)
}

#[derive(Debug)]
struct Table<K> {
    map: HashMap<K, Entry>,
    /// Expiry of every lockout started (min-heap), so the active count is O(log n) (RV3-M4).
    /// A lockout cleared early by a success stays here until it expires: the count may only
    /// overestimate, briefly, which errs towards failing closed.
    locks: BinaryHeap<Reverse<Instant>>,
}

impl<K> Table<K> {
    /// Drop expired lockouts from the heap and return how many are still active.
    fn active_locks(&mut self, now: Instant) -> usize {
        while self.locks.peek().is_some_and(|Reverse(until)| *until <= now) {
            self.locks.pop();
        }
        self.locks.len()
    }
}

/// Per-key failure counter with lockout. Time is passed in so tests are deterministic.
#[derive(Debug)]
pub struct Lockout<K = IpAddr> {
    table: Mutex<Table<K>>,
}

impl<K> Default for Lockout<K> {
    fn default() -> Self {
        Self { table: Mutex::new(Table { map: HashMap::new(), locks: BinaryHeap::new() }) }
    }
}

impl<K: LockKey> Lockout<K> {
    /// Whether `k` is locked out. When the table is full of active lockouts, unknown clients
    /// are treated as locked (fail closed). O(1) for known keys, O(log n) amortized otherwise.
    pub fn is_locked(&self, k: K, now: Instant) -> bool {
        let key = k.lock_key();
        let mut guard = self.table.lock_or_recover();
        let t = &mut *guard;
        if let Some(e) = t.map.get(&key) {
            return e.locked_until.is_some_and(|until| now < until);
        }
        t.map.len() >= MAX_TRACKED && t.active_locks(now) >= MAX_TRACKED
    }

    /// Record a failed attempt; returns true when this failure starts a lockout. Failures older
    /// than [`FAILURE_WINDOW`] no longer count (RV3-L1).
    pub fn record_failure(&self, k: K, now: Instant) -> bool {
        let key = k.lock_key();
        let mut guard = self.table.lock_or_recover();
        let t = &mut *guard;
        if t.map.len() >= MAX_TRACKED && !t.map.contains_key(&key) {
            // Drop expired and partial counters.
            t.map.retain(|_, e| e.locked_until.is_some_and(|u| now < u));
            if t.map.len() >= MAX_TRACKED {
                return false; // full of active lockouts: is_locked already fails closed
            }
        }
        let e = t.map.entry(key).or_insert_with(|| Entry::new(now));
        let lock_over = e.locked_until.is_some_and(|u| now >= u);
        let window_over = e.locked_until.is_none()
            && now.saturating_duration_since(e.window_start) >= FAILURE_WINDOW;
        if lock_over || window_over {
            *e = Entry::new(now); // lockout or window over: start over
        }
        e.failures = e.failures.saturating_add(1);
        if e.failures >= MAX_FAILURES && e.locked_until.is_none() {
            let until = now + LOCKOUT;
            e.locked_until = Some(until);
            t.active_locks(now);
            t.locks.push(Reverse(until));
            return true;
        }
        false
    }

    /// Clear the counter after a successful login.
    pub fn record_success(&self, k: K) {
        self.table.lock_or_recover().map.remove(&k.lock_key());
    }

    /// Number of tracked keys (bounded by [`MAX_TRACKED`]).
    pub fn tracked(&self) -> usize {
        self.table.lock_or_recover().map.len()
    }
}
