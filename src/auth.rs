//! Proxy authentication primitives (D-14): argon2id PHC hashes, constant-time credential check,
//! per-client-IP lockout (5 failures -> 60 s).
#![forbid(unsafe_code)]

use std::collections::HashMap;
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
    locked_until: Option<Instant>,
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
        match crate::normalize::fold_ip(self) {
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
            v4 => v4,
        }
    }
}

/// Per-user counters (PT-9.7); unknown names are counted too, so lockout reveals nothing.
impl LockKey for String {
    fn lock_key(self) -> Self {
        self
    }
}

/// Per-key failure counter with lockout. Time is passed in so tests are deterministic.
#[derive(Debug)]
pub struct Lockout<K = IpAddr> {
    map: Mutex<HashMap<K, Entry>>,
}

impl<K> Default for Lockout<K> {
    fn default() -> Self {
        Self { map: Mutex::new(HashMap::new()) }
    }
}

impl<K: LockKey> Lockout<K> {
    fn active(map: &HashMap<K, Entry>, now: Instant) -> usize {
        map.values().filter(|e| e.locked_until.is_some_and(|u| now < u)).count()
    }

    /// Whether `ip` is locked out. When the table is full of active lockouts, unknown clients
    /// are treated as locked (fail closed).
    pub fn is_locked(&self, k: K, now: Instant) -> bool {
        let map = self.map.lock_or_recover();
        match map.get(&k.lock_key()) {
            Some(e) => e.locked_until.is_some_and(|until| now < until),
            None => map.len() >= MAX_TRACKED && Self::active(&map, now) >= MAX_TRACKED,
        }
    }

    /// Record a failed attempt; returns true when this failure starts a lockout.
    pub fn record_failure(&self, k: K, now: Instant) -> bool {
        let ip = k.lock_key();
        let mut map = self.map.lock_or_recover();
        if map.len() >= MAX_TRACKED && !map.contains_key(&ip) {
            map.retain(|_, e| e.locked_until.is_some_and(|u| now < u)); // drop expired/partial counters
            if map.len() >= MAX_TRACKED {
                return false; // full of active lockouts: is_locked already fails closed
            }
        }
        let e = map.entry(ip).or_insert(Entry { failures: 0, locked_until: None });
        if e.locked_until.is_some_and(|u| now >= u) {
            *e = Entry { failures: 0, locked_until: None }; // lockout expired: start over
        }
        e.failures += 1;
        if e.failures >= MAX_FAILURES && e.locked_until.is_none() {
            e.locked_until = Some(now + LOCKOUT);
            return true;
        }
        false
    }

    /// Clear the counter after a successful login.
    pub fn record_success(&self, k: K) {
        self.map.lock_or_recover().remove(&k.lock_key());
    }
}
