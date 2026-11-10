//! Phase 9 (identity, profiles, limits): E-53..E-58, P-07, P-08 and PT-9 regressions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::{Origin, ProxyHarness, Reply, TestResolver, base_config, status};
use proptest::prelude::*;
use webfilter::config::{Config, RateConfig};
use webfilter::limiter::{Bucket, Clock, Limiter};
use webfilter::profiles::{PolicySet, client_id};
use webfilter::reason::Reason;

const W: Duration = Duration::from_secs(5);

fn cfg(extra: &str) -> Config {
    let dir = tempfile::tempdir().unwrap().keep();
    for f in ["domains.txt", "url_patterns.txt", "ip_blocklist.txt"] {
        std::fs::create_dir_all(dir.join("blocklists")).unwrap();
        std::fs::write(dir.join("blocklists").join(f), "").unwrap();
    }
    Config::parse(&format!("listen = \"127.0.0.1:0\"\n{extra}"), &dir, None).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

// ------------------------------------------------------------------------------------ identity

#[test]
fn p08_client_ids_fold_mapped_and_ipv6_64() {
    assert_eq!(client_id(ip("10.0.0.7"), None), "ip:10.0.0.7");
    assert_eq!(client_id(ip("::ffff:10.0.0.7"), None), "ip:10.0.0.7");
    assert_eq!(client_id(ip("2001:db8:1:2:aaaa::1"), None), "ip:2001:db8:1:2::/64");
    assert_eq!(client_id(ip("2001:db8:1:2:ffff::9"), None), client_id(ip("2001:db8:1:2::1"), None));
    assert_eq!(client_id(ip("10.0.0.7"), Some("alice")), "user:alice");
}

const PROFILES: &str = r#"
[[profiles]]
name = "kids"
extra_blocked_domains = ["games.test"]
[profiles.rate]
requests_per_sec = 2
burst = 2

[[profiles]]
name = "lab"
allow_domains = ["games.test"]

[[clients]]
cidr = "0.0.0.0/0"
profile = "lab"

[[clients]]
cidr = "127.0.0.0/8"
profile = "kids"

[[clients]]
cidr = "127.0.0.9/32"
profile = "default"
"#;

#[test]
fn e53_resolution_user_then_longest_prefix_then_default() {
    let hash = webfilter::auth::hash_password(b"pw").unwrap();
    let c = cfg(&format!(
        "{PROFILES}\n[[users]]\nusername = \"alice\"\npassword_hash = \"{hash}\"\nprofile = \"lab\"\n"
    ));
    let ps = PolicySet::build(&c).unwrap();
    assert_eq!(ps.resolve(ip("127.0.0.1"), None).1.name, "kids", "/8 beats /0");
    assert_eq!(ps.resolve(ip("127.0.0.9"), None).1.name, "default", "/32 beats /8");
    assert_eq!(ps.resolve(ip("8.8.8.8"), None).1.name, "lab", "/0 catches the rest");
    assert_eq!(ps.resolve(ip("::1"), None).1.name, "default", "no v6 client entry");
    assert_eq!(ps.resolve(ip("127.0.0.1"), Some("alice")).1.name, "lab", "user beats CIDR");
    assert!(ps.has_users() && ps.user("alice").is_some() && ps.user("bob").is_none());
}

#[test]
fn pt_9_2_bad_policy_configs_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("blocklists")).unwrap();
    for f in ["domains.txt", "url_patterns.txt", "ip_blocklist.txt"] {
        std::fs::write(dir.path().join("blocklists").join(f), "").unwrap();
    }
    let parse = |extra: &str| {
        Config::parse(&format!("listen = \"127.0.0.1:0\"\n{extra}"), dir.path(), None)
    };
    for (bad, why) in [
        ("[[clients]]\ncidr = \"10.0.0.0/8\"\nprofile = \"nope\"\n", "unknown profile"),
        ("[[clients]]\ncidr = \"10.0.0.0/33\"\nprofile = \"default\"\n", "invalid cidr"),
        ("[[profiles]]\nname = \"Kids!\"\n", "profile name"),
        ("[[profiles]]\nname = \"a\"\n[[profiles]]\nname = \"a\"\n", "duplicate profile"),
        ("[[profiles]]\nname = \"a\"\nextra_url_patterns = [\"(\"]\n", "profile a"),
        ("[[profiles]]\nname = \"a\"\n[profiles.rate]\ndown_bytes_per_sec = 10\n", "byte caps"),
        ("[[users]]\nusername = \"bad user\"\npassword_hash = \"x\"\n", "users.username"),
        ("[[users]]\nusername = \"u\"\npassword_hash = \"plain\"\n", "argon2id"),
        ("[[profiles]]\nname = \"a\"\nports = \"any\"\n", "unknown field"),
    ] {
        let err = parse(bad).unwrap_err().to_string();
        assert!(err.contains(why), "{bad:?} -> {err}");
    }
    // A non-loopback listener is fine with [[users]] instead of [proxy_auth] (D-13).
    let hash = webfilter::auth::hash_password(b"pw").unwrap();
    let ok = format!("[[users]]\nusername = \"u\"\npassword_hash = \"{hash}\"\n");
    assert!(Config::parse(&format!("listen = \"0.0.0.0:0\"\n{ok}"), dir.path(), None).is_ok());
}

// ------------------------------------------------------------------------------------ limiter

/// A manual clock (E-56).
struct TestClock(Mutex<(Instant, SystemTime)>);
impl TestClock {
    fn at(wall_secs: u64) -> Arc<Self> {
        Arc::new(Self(Mutex::new((Instant::now(), UNIX_EPOCH + Duration::from_secs(wall_secs)))))
    }
    fn advance(&self, d: Duration) {
        let mut t = self.0.lock().unwrap();
        t.0 += d;
        t.1 += d;
    }
}
impl Clock for TestClock {
    fn now(&self) -> Instant {
        self.0.lock().unwrap().0
    }
    fn wall(&self) -> SystemTime {
        self.0.lock().unwrap().1
    }
}

fn rate(f: impl FnOnce(&mut RateConfig)) -> RateConfig {
    let mut r = RateConfig::default();
    f(&mut r);
    r
}

#[test]
fn e54_request_rate_burst_refill_and_inflight() {
    let clock = TestClock::at(1_000_000);
    let l = Limiter::new(clock.clone(), 1000);
    let r = rate(|r| {
        r.requests_per_sec = 2;
        r.burst = 3;
        r.max_inflight_requests = 2;
    });
    let a = l.check_request("ip:1", &r).unwrap();
    let b = l.check_request("ip:1", &r).unwrap();
    let busy = l.check_request("ip:1", &r).unwrap_err();
    assert_eq!((busy.status, busy.reason), (429, Reason::RateLimited), "in-flight cap");
    drop((a, b));
    let _c = l.check_request("ip:1", &r).unwrap();
    assert_eq!(l.check_request("ip:1", &r).unwrap_err().retry_after, 1, "burst used up");
    assert!(l.check_request("ip:2", &r).is_ok(), "other clients unaffected");
    clock.advance(Duration::from_millis(500)); // 2/s -> one token
    assert!(l.check_request("ip:1", &r).is_ok());
}

#[test]
fn e54_connections_and_tunnels_caps() {
    let l = Limiter::new(TestClock::at(0), 1000);
    let r = rate(|r| {
        r.max_concurrent_connections = 1;
        r.max_tunnels = 1;
    });
    let c = l.acquire_connection("ip:1", &r).unwrap();
    assert_eq!(l.acquire_connection("ip:1", &r).unwrap_err().status, 503);
    drop(c);
    assert!(l.acquire_connection("ip:1", &r).is_ok());
    let _t = l.acquire_tunnel("ip:1", &r).unwrap();
    assert_eq!(l.acquire_tunnel("ip:1", &r).unwrap_err().status, 429);
}

#[test]
fn e56_daily_quota_until_utc_midnight() {
    let clock = TestClock::at(86_400 * 20_000 + 86_400 - 100); // 100 s before UTC midnight
    let l = Limiter::new(clock.clone(), 1000);
    let r = rate(|r| r.daily_quota_bytes = 1000);
    drop(l.check_request("u", &r).unwrap());
    l.add_bytes("u", &r, 1500);
    let rej = l.check_request("u", &r).unwrap_err();
    assert_eq!((rej.reason, rej.retry_after), (Reason::QuotaExceeded, 100));
    clock.advance(Duration::from_secs(100));
    assert!(l.check_request("u", &r).is_ok(), "new UTC day");
}

#[test]
fn e57_limiter_memory_bounded_and_64_counted_once() {
    let l = Limiter::new(TestClock::at(0), 100_000);
    let r = RateConfig::default();
    for i in 0..200_000u32 {
        drop(l.check_request(&format!("ip:10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255), &r));
    }
    assert!(l.len() <= 100_000, "{}", l.len());
    let l = Limiter::new(TestClock::at(0), 1000);
    for i in 0..1000u16 {
        let addr: IpAddr = format!("2001:db8:1:2::{i:x}").parse().unwrap();
        drop(l.check_request(&client_id(addr, None), &r));
    }
    assert_eq!(l.len(), 1, "one /64 = one key");
}

proptest! {
    #[test]
    fn p07_token_bucket_never_over_capacity(steps in proptest::collection::vec((0u64..5_000, 1usize..100_000), 1..200)) {
        let start = Instant::now();
        let b = Bucket::new(10_000, start);
        let mut now = start;
        for (ms, want) in steps {
            now += Duration::from_millis(ms);
            if let Ok(n) = b.take(want, now) {
                prop_assert!(n <= want && n <= 100, "a grant never exceeds one quantum");
            }
        }
    }
}

// ------------------------------------------------------------------------------------ end to end

async fn origin_big() -> Origin {
    let body: String = (0..262_144).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
    Origin::start(move |_| Reply::ok(&body)).await
}

#[tokio::test]
async fn e53_profiles_apply_lists_and_log_identity() {
    let origin = Origin::start(|_| Reply::ok("hello")).await;
    let config =
        base_config(&format!("{PROFILES}\n[[clients]]\ncidr = \"::1/128\"\nprofile = \"lab\"\n"));
    let resolver = TestResolver::with(&[("games.test", "127.0.0.1"), ("ok.test", "127.0.0.1")]);
    let mut h = ProxyHarness::start(&config, &[], resolver).await;
    let port = origin.addr.port();
    let get = |host: &str| {
        format!(
            "GET http://{host}:{port}/ HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
        )
    };
    let resp = h.raw(get("games.test").as_bytes(), W).await;
    assert_eq!(status(&resp), 403, "kids profile blocks games.test: {resp}");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(status(&h.raw(get("ok.test").as_bytes(), W).await), 200);
    h.stop().await;
    let lines = h.log_lines();
    assert!(lines.iter().all(|v| v["client_id"] == "ip:127.0.0.1" && v["profile"] == "kids"));
    assert_eq!(lines[0]["rule_list"], "profile:kids");
}

#[tokio::test]
async fn e54_e58_rate_limit_429_with_retry_after_even_in_monitor_mode() {
    let origin = Origin::start(|_| Reply::ok("hello")).await;
    let config = base_config(&format!("mode = \"monitor\"\n{PROFILES}"));
    let mut h =
        ProxyHarness::start(&config, &[], TestResolver::with(&[("games.test", "127.0.0.1")])).await;
    let port = origin.addr.port();
    let req = format!(
        "GET http://games.test:{port}/ HTTP/1.1\r\nHost: games.test:{port}\r\nConnection: close\r\n\r\n"
    );
    assert_eq!(status(&h.raw(req.as_bytes(), W).await), 200, "monitor: content rule only logged");
    assert_eq!(status(&h.raw(req.as_bytes(), W).await), 200);
    let third = h.raw(req.as_bytes(), W).await;
    assert_eq!(status(&third), 429, "limits are enforced in monitor mode (D-51)");
    assert!(third.to_ascii_lowercase().contains("retry-after: 1"));
    h.stop().await;
    let lines = h.log_lines();
    assert_eq!(lines[0]["would_block"], true);
    assert_eq!(lines[2]["reason"], "rate_limited");
}

#[tokio::test]
async fn e55_bandwidth_cap_paces_bytes_and_keeps_them_intact() {
    let origin = origin_big().await;
    let config = base_config(
        "[[profiles]]\nname = \"slow\"\n[profiles.rate]\ndown_bytes_per_sec = 131072\n[[clients]]\ncidr = \"127.0.0.1/32\"\nprofile = \"slow\"\n",
    );
    let mut h =
        ProxyHarness::start(&config, &[], TestResolver::with(&[("big.test", "127.0.0.1")])).await;
    let port = origin.addr.port();
    let req = format!(
        "GET http://big.test:{port}/ HTTP/1.1\r\nHost: big.test:{port}\r\nConnection: close\r\n\r\n"
    );
    let started = Instant::now();
    let resp = common::raw_exchange(h.addr, req.as_bytes(), Duration::from_secs(10)).await;
    let secs = started.elapsed().as_secs_f64();
    h.stop().await;
    let body = resp.split_once("\r\n\r\n").unwrap().1;
    let expect: String = (0..262_144).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
    assert!(body == expect, "byte-identical");
    // The lower bound proves the cap; the upper bound only catches gross over-throttling (a busy
    // test host adds latency, never bandwidth).
    assert!((1.7..=3.0).contains(&secs), "256 KiB at 128 KiB/s took {secs:.2}s");
    assert_eq!(h.log_lines()[0]["throttled"], true);
}

#[tokio::test]
async fn pt_9_7_unknown_user_and_wrong_password_look_the_same() {
    let hash = webfilter::auth::hash_password(b"right").unwrap();
    let config =
        base_config(&format!("[[users]]\nusername = \"alice\"\npassword_hash = \"{hash}\"\n"));
    let mut h = ProxyHarness::start(&config, &[], TestResolver::with(&[])).await;
    let auth = |u: &str, p: &str| {
        use base64::Engine;
        let b = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
        format!(
            "GET http://x.test/ HTTP/1.1\r\nHost: x.test\r\nProxy-Authorization: Basic {b}\r\nConnection: close\r\n\r\n"
        )
    };
    let strip = |r: String| {
        r.lines()
            .filter(|l| !l.to_ascii_lowercase().contains("event"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let wrong_pw = strip(h.raw(auth("alice", "nope").as_bytes(), W).await);
    let no_user = strip(h.raw(auth("mallory", "nope").as_bytes(), W).await);
    assert_eq!(status(&wrong_pw), 407);
    assert_eq!(wrong_pw, no_user, "responses are indistinguishable");
    h.stop().await;
    let lines = h.log_lines();
    assert!(lines.iter().all(|v| v["reason"] == "auth_failed" && v["client_id"].is_null()));
}

#[tokio::test]
async fn policy_hot_reload_swaps_and_bad_config_keeps_old() {
    let origin = Origin::start(|_| Reply::ok("hello")).await;
    let mut h = ProxyHarness::start(
        &base_config(""),
        &[],
        TestResolver::with(&[("new.test", "127.0.0.1")]),
    )
    .await;
    let port = origin.addr.port();
    let req = format!(
        "GET http://new.test:{port}/ HTTP/1.1\r\nHost: new.test:{port}\r\nConnection: close\r\n\r\n"
    );
    assert_eq!(status(&h.raw(req.as_bytes(), W).await), 200);
    let path = h.lab.path().join("config.toml");
    let base = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!(
            "{base}\n[[profiles]]\nname = \"default\"\nextra_blocked_domains = [\"new.test\"]\n"
        ),
    )
    .unwrap();
    let deps = Arc::clone(&h.handle.as_ref().unwrap().deps);
    deps.reload_policies().unwrap();
    assert_eq!(status(&h.raw(req.as_bytes(), W).await), 403, "reloaded profile applies");
    std::fs::write(&path, format!("{base}\n[[clients]]\ncidr = \"bad\"\nprofile = \"default\"\n"))
        .unwrap();
    assert!(deps.reload_policies().is_err());
    assert_eq!(status(&h.raw(req.as_bytes(), W).await), 403, "old policies kept");
    h.stop().await;
    let reloads: Vec<_> =
        h.system_lines().into_iter().filter(|v| v["kind"] == "policy_reloaded").collect();
    assert_eq!(reloads.len(), 2);
    assert_eq!(reloads[1]["detail"]["ok"], false);
}
