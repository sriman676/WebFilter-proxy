//! Rate limits, quotas and bandwidth caps (SPEC_EXT_POLICY P2, D-51): token buckets on a
//! monotonic clock in a bounded LRU keyed by `client_id`, saturating integer math, enforced in
//! every mode. Bandwidth caps delay bytes (never drop or alter them) in 10 ms quanta.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::RateConfig;
use crate::reason::Reason;
use crate::util::LockExt;

/// Maximum tracked clients (D-51); an evicted idle key restarts with a full bucket.
pub const MAX_KEYS: usize = 100_000;
/// Bandwidth quantum.
pub const QUANTUM: Duration = Duration::from_millis(10);
/// Token unit: one request = 1,000 milli-tokens.
const MILLI: u64 = 1000;

/// Time source (injectable for tests, E-56).
pub trait Clock: Send + Sync {
    /// Monotonic now.
    fn now(&self) -> Instant;
    /// Wall clock (UTC day boundaries for quotas).
    fn wall(&self) -> SystemTime;
}

/// The real clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Why a request/connection/tunnel was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitReject {
    /// HTTP status (429 or 503).
    pub status: u16,
    /// `rate_limited`, `quota_exceeded` or `too_many_connections`.
    pub reason: Reason,
    /// `Retry-After` seconds.
    pub retry_after: u64,
}

/// A shared byte-rate bucket (one per client and direction).
#[derive(Debug)]
pub struct Bucket {
    rate: u64,
    state: Mutex<(u64, Instant)>,
}

impl Bucket {
    /// A bucket of `rate` bytes/s, full.
    pub fn new(rate: u64, now: Instant) -> Self {
        Self { rate, state: Mutex::new((Self::cap(rate), now)) }
    }

    fn cap(rate: u64) -> u64 {
        (rate / 100).max(1) // one 10 ms quantum: connections take turns
    }

    /// Take up to `want` bytes; `Err(wait)` when the bucket is empty.
    pub fn take(&self, want: usize, now: Instant) -> Result<usize, Duration> {
        let mut s = self.state.lock_or_recover();
        let elapsed = now.saturating_duration_since(s.1);
        let refill =
            u64::try_from(elapsed.as_micros().saturating_mul(u128::from(self.rate)) / 1_000_000)
                .unwrap_or(u64::MAX);
        if refill > 0 {
            s.0 = s.0.saturating_add(refill).min(Self::cap(self.rate));
            s.1 = now;
        }
        if s.0 == 0 {
            return Err(QUANTUM);
        }
        let n = u64::try_from(want).unwrap_or(u64::MAX).min(s.0);
        s.0 -= n;
        Ok(usize::try_from(n).unwrap_or(want))
    }
}

#[derive(Debug)]
struct Entry {
    tokens: u64,
    refilled: Instant,
    seen: Instant,
    connections: u32,
    inflight: u32,
    tunnels: u32,
    quota_day: u64,
    quota_used: u64,
    down: Option<Arc<Bucket>>,
    up: Option<Arc<Bucket>>,
}

/// Per-client limiter (INTERFACES `Limiter`).
pub struct Limiter {
    clock: Arc<dyn Clock>,
    map: Mutex<HashMap<String, Entry>>,
    max_keys: usize,
}

/// Counter kinds released on drop.
#[derive(Debug, Clone, Copy)]
enum Slot {
    Connection,
    Inflight,
    Tunnel,
}

/// Holds a connection, in-flight or tunnel slot until dropped.
pub struct Permit {
    limiter: Arc<Limiter>,
    key: String,
    slot: Slot,
}

impl std::fmt::Debug for Permit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Permit").field("key", &self.key).field("slot", &self.slot).finish()
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut map = self.limiter.map.lock_or_recover();
        if let Some(e) = map.get_mut(&self.key) {
            let c = match self.slot {
                Slot::Connection => &mut e.connections,
                Slot::Inflight => &mut e.inflight,
                Slot::Tunnel => &mut e.tunnels,
            };
            *c = c.saturating_sub(1);
        }
    }
}

fn utc_day(t: SystemTime) -> (u64, u64) {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    (secs / 86_400, 86_400 - secs % 86_400)
}

impl Limiter {
    /// A limiter with `clock` and at most `max_keys` tracked clients.
    pub fn new(clock: Arc<dyn Clock>, max_keys: usize) -> Arc<Self> {
        Arc::new(Self { clock, map: Mutex::new(HashMap::new()), max_keys: max_keys.max(1) })
    }

    /// Tracked clients (tests, E-57).
    pub fn len(&self) -> usize {
        self.map.lock_or_recover().len()
    }

    /// Whether no client is tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn with<T>(&self, key: &str, rate: &RateConfig, f: impl FnOnce(&mut Entry, Instant) -> T) -> T {
        let now = self.clock.now();
        let mut map = self.map.lock_or_recover();
        if !map.contains_key(key) && map.len() >= self.max_keys {
            // Evict the least recently seen idle 1 % (amortized); busy entries are kept.
            let mut idle: Vec<(Instant, String)> = map
                .iter()
                .filter(|(_, e)| e.connections == 0 && e.inflight == 0 && e.tunnels == 0)
                .map(|(k, e)| (e.seen, k.clone()))
                .collect();
            idle.sort_unstable();
            for (_, k) in idle.into_iter().take((self.max_keys / 100).max(1)) {
                map.remove(&k);
            }
        }
        let entry = map.entry(key.to_owned()).or_insert_with(|| Entry {
            tokens: u64::from(rate.burst).saturating_mul(MILLI),
            refilled: now,
            seen: now,
            connections: 0,
            inflight: 0,
            tunnels: 0,
            quota_day: 0,
            quota_used: 0,
            down: (rate.down_bytes_per_sec > 0)
                .then(|| Arc::new(Bucket::new(rate.down_bytes_per_sec, now))),
            up: (rate.up_bytes_per_sec > 0)
                .then(|| Arc::new(Bucket::new(rate.up_bytes_per_sec, now))),
        });
        entry.seen = now;
        f(entry, now)
    }

    fn permit(self: &Arc<Self>, key: &str, slot: Slot) -> Permit {
        Permit { limiter: Arc::clone(self), key: key.to_owned(), slot }
    }

    /// Request rate, in-flight cap and daily quota (429). The permit holds the in-flight slot.
    pub fn check_request(
        self: &Arc<Self>,
        key: &str,
        rate: &RateConfig,
    ) -> Result<Permit, LimitReject> {
        let (day, to_midnight) = utc_day(self.clock.wall());
        self.with(key, rate, |e, now| {
            let elapsed = now.saturating_duration_since(e.refilled);
            let refill = u64::try_from(
                elapsed.as_millis().saturating_mul(u128::from(rate.requests_per_sec)),
            )
            .unwrap_or(u64::MAX);
            e.tokens =
                e.tokens.saturating_add(refill).min(u64::from(rate.burst).saturating_mul(MILLI));
            e.refilled = now;
            if e.quota_day != day {
                (e.quota_day, e.quota_used) = (day, 0);
            }
            if rate.daily_quota_bytes > 0 && e.quota_used >= rate.daily_quota_bytes {
                return Err(LimitReject {
                    status: 429,
                    reason: Reason::QuotaExceeded,
                    retry_after: to_midnight,
                });
            }
            if e.tokens < MILLI || e.inflight >= rate.max_inflight_requests {
                return Err(LimitReject {
                    status: 429,
                    reason: Reason::RateLimited,
                    retry_after: 1,
                });
            }
            e.tokens -= MILLI;
            e.inflight += 1;
            Ok(())
        })?;
        Ok(self.permit(key, Slot::Inflight))
    }

    /// One client connection (503 when over the cap).
    pub fn acquire_connection(
        self: &Arc<Self>,
        key: &str,
        rate: &RateConfig,
    ) -> Result<Permit, LimitReject> {
        self.with(key, rate, |e, _| {
            if e.connections >= rate.max_concurrent_connections {
                return Err(LimitReject {
                    status: 503,
                    reason: Reason::TooManyConnections,
                    retry_after: 5,
                });
            }
            e.connections += 1;
            Ok(())
        })?;
        Ok(self.permit(key, Slot::Connection))
    }

    /// One CONNECT tunnel (429 when over the cap).
    pub fn acquire_tunnel(
        self: &Arc<Self>,
        key: &str,
        rate: &RateConfig,
    ) -> Result<Permit, LimitReject> {
        self.with(key, rate, |e, _| {
            if e.tunnels >= rate.max_tunnels {
                return Err(LimitReject {
                    status: 429,
                    reason: Reason::RateLimited,
                    retry_after: 1,
                });
            }
            e.tunnels += 1;
            Ok(())
        })?;
        Ok(self.permit(key, Slot::Tunnel))
    }

    /// Count transferred bytes against the daily quota.
    pub fn add_bytes(&self, key: &str, rate: &RateConfig, bytes: u64) {
        if rate.daily_quota_bytes == 0 {
            return;
        }
        let (day, _) = utc_day(self.clock.wall());
        self.with(key, rate, |e, _| {
            if e.quota_day != day {
                (e.quota_day, e.quota_used) = (day, 0);
            }
            e.quota_used = e.quota_used.saturating_add(bytes);
        });
    }

    /// The client's shared (down, up) buckets, when capped.
    pub fn buckets(&self, key: &str, rate: &RateConfig) -> Shaping {
        self.with(key, rate, |e, _| Shaping { down: e.down.clone(), up: e.up.clone() })
    }
}

/// Bandwidth buckets for one client (down = to the client, up = from it).
#[derive(Debug, Clone, Default)]
pub struct Shaping {
    /// Bytes written to the client.
    pub down: Option<Arc<Bucket>>,
    /// Bytes read from the client.
    pub up: Option<Arc<Bucket>>,
}

/// A client stream whose reads/writes are paced by the current [`Shaping`] (D-51).
pub struct Shaped<S> {
    inner: S,
    shaping: Shaping,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    throttled: AtomicBool,
}

impl<S> Shaped<S> {
    /// Unshaped until [`Shaped::set`] is called.
    pub fn new(inner: S) -> Self {
        Self { inner, shaping: Shaping::default(), sleep: None, throttled: AtomicBool::new(false) }
    }

    /// Use these buckets from now on (identity is per request).
    pub fn set(&mut self, shaping: Shaping) {
        self.shaping = shaping;
    }

    /// Whether any byte was delayed since the last call (`throttled` log field).
    pub fn take_throttled(&self) -> bool {
        self.throttled.swap(false, Ordering::Relaxed)
    }

    /// Ask `bucket` for up to `want` bytes, sleeping one quantum when empty.
    fn grant(
        &mut self,
        cx: &mut Context<'_>,
        bucket: Option<Arc<Bucket>>,
        want: usize,
    ) -> Poll<usize> {
        let Some(bucket) = bucket else { return Poll::Ready(want) };
        loop {
            if let Some(s) = self.sleep.as_mut() {
                if s.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.sleep = None;
            }
            match bucket.take(want, Instant::now()) {
                Ok(n) => return Poll::Ready(n),
                Err(wait) => {
                    self.throttled.store(true, Ordering::Relaxed);
                    self.sleep = Some(Box::pin(tokio::time::sleep(wait)));
                }
            }
        }
    }
}

use std::future::Future;

impl<S: AsyncRead + Unpin> AsyncRead for Shaped<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let up = self.shaping.up.clone();
        let n = match self.grant(cx, up, buf.remaining()) {
            Poll::Ready(n) => n,
            Poll::Pending => return Poll::Pending,
        };
        if n >= buf.remaining() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        let mut limited = ReadBuf::new(buf.initialize_unfilled_to(n));
        let res = Pin::new(&mut self.inner).poll_read(cx, &mut limited);
        let filled = limited.filled().len();
        buf.advance(filled);
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Shaped<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let down = self.shaping.down.clone();
        let n = match self.grant(cx, down, data.len()) {
            Poll::Ready(n) => n,
            Poll::Pending => return Poll::Pending,
        };
        Pin::new(&mut self.inner).poll_write(cx, data.get(..n).unwrap_or(data))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
