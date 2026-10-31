//! PT-9.9: arbitrary operation sequences against the limiter with a fake clock: no panic, no
//! overflow, bounded key count.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libfuzzer_sys::fuzz_target;
use webfilter::config::RateConfig;
use webfilter::limiter::{Clock, Limiter};

struct Fake(Mutex<(Instant, SystemTime)>);
impl Clock for Fake {
    fn now(&self) -> Instant {
        self.0.lock().unwrap().0
    }
    fn wall(&self) -> SystemTime {
        self.0.lock().unwrap().1
    }
}

fuzz_target!(|data: &[u8]| {
    let clock = Arc::new(Fake(Mutex::new((Instant::now(), UNIX_EPOCH + Duration::from_secs(1 << 31)))));
    let l = Limiter::new(clock.clone(), 64);
    let rate = RateConfig {
        requests_per_sec: u32::from(data.first().copied().unwrap_or(1)).max(1),
        burst: u32::from(data.get(1).copied().unwrap_or(1)).max(1),
        max_concurrent_connections: 3,
        max_inflight_requests: 3,
        max_tunnels: 3,
        daily_quota_bytes: u64::from(data.get(2).copied().unwrap_or(0)) << 20,
        ..RateConfig::default()
    };
    let mut held = Vec::new();
    for chunk in data.chunks(3).skip(1) {
        let key = format!("k{}", chunk[0] % 100);
        let arg = u64::from(*chunk.get(1).unwrap_or(&0)) * u64::from(*chunk.get(2).unwrap_or(&0));
        match chunk[0] % 6 {
            0 => held.extend(l.check_request(&key, &rate).ok()),
            1 => held.extend(l.acquire_connection(&key, &rate).ok()),
            2 => held.extend(l.acquire_tunnel(&key, &rate).ok()),
            3 => l.add_bytes(&key, &rate, arg.saturating_mul(1 << 40)),
            4 => {
                let mut t = clock.0.lock().unwrap();
                t.0 += Duration::from_millis(arg);
                t.1 += Duration::from_millis(arg);
            }
            _ => drop(held.pop()),
        }
        assert!(l.len() <= 64 + held.len());
    }
});
