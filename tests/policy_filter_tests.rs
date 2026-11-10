//! U-policy, filter rule order, P-01, P-05, P-06, U-auth.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use proptest::prelude::*;
use webfilter::auth::{
    LOCKOUT, Lockout, MAX_FAILURES, hash_password, is_argon2id_phc, verify_credentials,
    verify_password,
};
use webfilter::blocklist::{Blocklists, parse_domains, parse_ips, parse_patterns};
use webfilter::config::{Mode, PortConfig, PortSet, RuleConfig};
use webfilter::filter::{Action, Phase, evaluate};
use webfilter::normalize::{NormalizedTarget, TargetContext, canonicalize};
use webfilter::policy::{
    DestPolicy, PolicyVerdict, PortKind, ResolveFuture, Resolver, check_destination, check_port,
};
use webfilter::reason::Reason;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn target(raw: &str) -> NormalizedTarget {
    canonicalize(raw, TargetContext::PlainAbsolute).unwrap()
}

fn lists() -> Blocklists {
    Blocklists {
        domains: parse_domains("evil.com\n").unwrap().list,
        patterns: parse_patterns("[id=adm] /admin/\n").unwrap().list,
        ips: parse_ips("10.0.0.0/8\n").unwrap().list,
        categories: vec![],
    }
}

// ---- policy ----

#[test]
fn always_denied_even_without_private_flag() {
    let p = DestPolicy::new(false, vec![]);
    for a in ["169.254.169.254", "0.1.2.3", "fd00:ec2::254", "::ffff:169.254.169.254"] {
        assert_eq!(p.check_ip(ip(a), 80), Err(Reason::PrivateRange), "{a}");
    }
    assert!(p.check_ip(ip("127.0.0.1"), 80).is_ok(), "loopback allowed when deny_private=false");
}

#[test]
fn private_ranges_denied_when_enabled() {
    let p = DestPolicy::new(true, vec![]);
    for a in [
        "127.0.0.1",
        "10.1.1.1",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "fd12::1",
        "ff02::1",
        "::ffff:10.0.0.1",
    ] {
        assert_eq!(p.check_ip(ip(a), 80), Err(Reason::PrivateRange), "{a}");
    }
    for a in ["93.184.216.34", "100.128.0.1", "2001:4860::8888", "172.32.0.1"] {
        assert!(p.check_ip(ip(a), 80).is_ok(), "{a}");
    }
}

#[test]
fn loop_detection_on_own_address() {
    let own: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let p = DestPolicy::new(false, vec![own]);
    assert_eq!(p.check_ip(ip("127.0.0.1"), 8080), Err(Reason::LoopDetected));
    assert!(p.check_ip(ip("127.0.0.1"), 8081).is_ok());
    let any = DestPolicy::new(false, vec!["0.0.0.0:3128".parse().unwrap()]);
    assert_eq!(any.check_ip(ip("127.0.0.1"), 3128), Err(Reason::LoopDetected));
}

#[test]
fn port_policy() {
    let cfg = PortConfig::default();
    assert!(check_port(PortKind::Http, 80, &cfg).is_ok());
    assert_eq!(check_port(PortKind::Http, 25, &cfg), Err(Reason::PortNotAllowed));
    assert_eq!(check_port(PortKind::Connect, 80, &cfg), Err(Reason::PortNotAllowed));
    assert!(check_port(PortKind::Connect, 8443, &cfg).is_ok());
    let any = PortConfig { http_allowed: PortSet::Any, ..PortConfig::default() };
    assert!(check_port(PortKind::Http, 6379, &any).is_ok());
}

/// TEST_PLAN `TestResolver`: static map + scripted answers, counts lookups.
struct TestResolver {
    map: HashMap<String, Vec<IpAddr>>,
}

impl Resolver for TestResolver {
    fn resolve<'a>(&'a self, host: &'a str, _port: u16) -> ResolveFuture<'a> {
        let answer = self.map.get(host).cloned().ok_or_else(|| std::io::Error::other("NXDOMAIN"));
        Box::pin(async move { answer })
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
}

#[test]
fn destination_validates_every_resolved_address() {
    let r = TestResolver {
        map: HashMap::from([
            (
                "good.test".to_owned(),
                vec![ip("93.184.216.34"), ip("93.184.216.34"), ip("2001:db8::1")],
            ),
            ("mixed.test".to_owned(), vec![ip("93.184.216.34"), ip("10.0.0.1")]),
            ("meta.test".to_owned(), vec![ip("169.254.169.254")]),
            ("empty.test".to_owned(), vec![]),
        ]),
    };
    let p = DestPolicy::new(true, vec![]);
    assert_eq!(
        block_on(check_destination(&target("http://good.test/"), &r, &p)),
        PolicyVerdict::Allow(vec![ip("93.184.216.34"), ip("2001:db8::1")]),
        "deduplicated, order kept"
    );
    assert_eq!(
        block_on(check_destination(&target("http://mixed.test/"), &r, &p)),
        PolicyVerdict::Deny(Reason::PrivateRange),
        "one bad IP denies"
    );
    assert_eq!(
        block_on(check_destination(&target("http://meta.test/"), &r, &p)),
        PolicyVerdict::Deny(Reason::PrivateRange)
    );
    assert_eq!(
        block_on(check_destination(&target("http://empty.test/"), &r, &p)),
        PolicyVerdict::Deny(Reason::UpstreamError)
    );
    assert_eq!(
        block_on(check_destination(&target("http://nx.test/"), &r, &p)),
        PolicyVerdict::Deny(Reason::UpstreamError)
    );
    assert_eq!(
        block_on(check_destination(&target("http://10.0.0.5/"), &r, &p)),
        PolicyVerdict::Deny(Reason::PrivateRange)
    );
}

// ---- filter ----

#[test]
fn rule_order_and_ids() {
    let (l, r) = (lists(), RuleConfig::default());
    let pre = |raw| evaluate(&target(raw), Phase::PreDns, &l, &r, Mode::Enforce);
    let d = pre("http://evil.com/admin/x.exe");
    assert_eq!(
        (d.reason, d.rule_id.as_deref(), d.rule_list.as_deref()),
        (Reason::DomainBlocklist, Some("domain:evil.com"), Some("domains.txt"))
    );
    let d = pre("http://good.test/admin/x.exe");
    assert_eq!((d.reason, d.rule_id.as_deref()), (Reason::UrlPattern, Some("url:adm")));
    let d = pre("http://good.test/x.EXE");
    assert_eq!((d.reason, d.rule_id.as_deref()), (Reason::Extension, Some("ext:.exe")));
    assert!(!pre("http://good.test/.exe").is_block(), "a bare `.exe` name has no extension");
    assert_eq!(pre("http://good.test/fine").action, Action::Allow);

    let t = target("http://good.test/");
    let d = evaluate(&t, Phase::Resolved { ip: ip("10.2.3.4") }, &l, &r, Mode::Enforce);
    assert_eq!((d.reason, d.rule_id.as_deref()), (Reason::IpBlocklist, Some("ip:10.0.0.0/8")));
    let d = evaluate(
        &t,
        Phase::ResponseHeaders { content_type: Some("Application/X-MSDownload; charset=x") },
        &l,
        &r,
        Mode::Enforce,
    );
    assert_eq!(
        (d.reason, d.rule_id.as_deref()),
        (Reason::ContentType, Some("ctype:application/x-msdownload"))
    );
    assert!(
        !evaluate(
            &t,
            Phase::ResponseHeaders { content_type: Some("text/html") },
            &l,
            &r,
            Mode::Enforce
        )
        .is_block()
    );
}

#[test]
fn allowlist_bypasses_rules_2_to_6_only() {
    let l = lists();
    let r = RuleConfig { allow_domains: vec!["evil.com".into()], ..RuleConfig::default() };
    let t = target("http://sub.evil.com/admin/x.exe");
    for phase in [
        Phase::PreDns,
        Phase::Resolved { ip: ip("10.0.0.1") },
        Phase::ResponseHeaders { content_type: Some("application/x-msdownload") },
    ] {
        let d = evaluate(&t, phase, &l, &r, Mode::Enforce);
        assert_eq!(
            (d.action, d.reason, d.rule_id.as_deref()),
            (Action::Allow, Reason::Allowlist, Some("allowlist"))
        );
    }
    let not_sub =
        evaluate(&target("http://notevil.com/admin/"), Phase::PreDns, &l, &r, Mode::Enforce);
    assert!(not_sub.is_block(), "allowlist does not match notevil.com");
}

#[test]
fn monitor_mode_never_blocks_but_records() {
    let d = evaluate(
        &target("http://evil.com/"),
        Phase::PreDns,
        &lists(),
        &RuleConfig::default(),
        Mode::Monitor,
    );
    assert_eq!((d.action, d.would_block, d.reason), (Action::Allow, true, Reason::DomainBlocklist));
}

#[test]
fn reason_names_match_serde() {
    for r in Reason::ALL {
        assert_eq!(serde_json::to_value(r).unwrap(), serde_json::json!(r.as_str()));
    }
    assert_eq!(Reason::ALL.len(), 40);
}

// ---- auth ----

#[test]
fn argon2id_hash_verify_and_reject() {
    let hash = hash_password(b"correct horse").unwrap();
    assert!(is_argon2id_phc(&hash));
    assert!(verify_password(&hash, b"correct horse"));
    assert!(!verify_password(&hash, b"wrong"));
    assert!(!verify_password("not a hash", b"correct horse"));
    assert!(verify_credentials("analyst", &hash, "analyst", b"correct horse"));
    assert!(!verify_credentials("analyst", &hash, "Analyst", b"correct horse"));
    assert!(!verify_credentials("analyst", &hash, "analyst", b"wrong"));
    assert!(!is_argon2id_phc("$argon2i$v=19$m=16,t=2,p=1$c2FsdHNhbHQ$aGFzaA"));
}

#[test]
fn wrong_user_still_pays_hash_cost() {
    // Constant-time path: a wrong user name must not short-circuit the argon2 computation.
    let hash = hash_password(b"pw").unwrap();
    let time = |user: &str| {
        let start = Instant::now();
        for _ in 0..3 {
            let _ = verify_credentials("analyst", &hash, user, b"pw-wrong");
        }
        start.elapsed()
    };
    let (wrong_user, wrong_pw) = (time("mallory"), time("analyst"));
    assert!(wrong_user * 3 > wrong_pw, "wrong user {wrong_user:?} vs wrong password {wrong_pw:?}");
}

#[test]
fn lockout_after_five_failures_for_sixty_seconds() {
    let l = Lockout::default();
    let (a, b, t0) = (ip("192.0.2.1"), ip("192.0.2.2"), Instant::now());
    for i in 1..MAX_FAILURES {
        assert!(!l.record_failure(a, t0), "failure {i} does not lock");
    }
    assert!(l.record_failure(a, t0), "5th failure locks");
    assert!(l.is_locked(a, t0 + Duration::from_secs(59)));
    assert!(!l.is_locked(b, t0), "other IPs unaffected");
    assert!(!l.is_locked(a, t0 + LOCKOUT), "expires after 60 s");
    assert!(!l.record_failure(a, t0 + LOCKOUT), "counter restarts after expiry");
    l.record_success(a);
    assert!(!l.is_locked(a, t0));
}

// ---- properties ----

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// P-01: canonicalize never panics and is idempotent on its own output.
    #[test]
    fn p01_canonicalize_total_and_idempotent(raw in "\\PC{0,80}", path in "(/[a-zA-Z0-9%._~!$&'()*+,;=:@-]{0,12}){0,6}") {
        let _ = canonicalize(&raw, TargetContext::PlainAbsolute);
        let _ = canonicalize(&raw, TargetContext::ConnectAuthority);
        if let Ok(t) = canonicalize(&format!("http://good.test{path}"), TargetContext::PlainAbsolute) {
            let again = canonicalize(&t.url_norm, TargetContext::PlainAbsolute).unwrap();
            prop_assert_eq!(again, t);
        }
    }

    /// P-05: decisions are invariant under host case, default port and one trailing dot.
    #[test]
    fn p05_decision_invariant(host in "[a-z]{1,8}\\.(evil\\.com|good\\.test)", upper in any::<bool>(), port in any::<bool>(), dot in any::<bool>()) {
        let (l, r) = (lists(), RuleConfig::default());
        let base = evaluate(&target(&format!("http://{host}/")), Phase::PreDns, &l, &r, Mode::Enforce);
        let h = if upper { host.to_ascii_uppercase() } else { host.clone() };
        let variant = format!("http://{h}{}{}/", if dot { "." } else { "" }, if port { ":80" } else { "" });
        prop_assert_eq!(evaluate(&target(&variant), Phase::PreDns, &l, &r, Mode::Enforce), base);
    }

    /// P-06: the forwarded request line comes only from normalized fields: it never contains
    /// raw dot segments, lowercase escapes or escaped unreserved characters, and re-canonicalizes
    /// to itself.
    #[test]
    fn p06_forwarded_target_is_normalized(path in "(/(\\.|\\.\\.|%2e|%41|%2f|[a-z]{1,4})){1,6}") {
        let t = canonicalize(&format!("http://good.test{path}"), TargetContext::PlainAbsolute);
        prop_assert!(t.is_ok(), "valid path rejected: {path}"); // never vacuous (PF-1-12)
        let line = t.unwrap().origin_form();
        prop_assert!(!line.split('/').any(|s| s == "." || s == ".."));
        prop_assert!(!line.contains("%2e") && !line.contains("%41") && !line.contains("%2f"));
        let again = canonicalize(&format!("http://good.test{line}"), TargetContext::PlainAbsolute).unwrap();
        prop_assert_eq!(again.origin_form(), line);
    }
}

#[tokio::test]
async fn static_resolver_parses_spec_and_is_off_without_env() {
    use webfilter::policy::{Resolver, StaticResolver, test_hosts_resolver};
    let r = StaticResolver::parse(
        "Site.Test=192.0.2.10, site.test=192.0.2.11,bad,x=notanip,v6.test=2001:db8::1",
    );
    assert_eq!(
        r.resolve("SITE.test", 80).await.unwrap(),
        vec!["192.0.2.10".parse::<std::net::IpAddr>().unwrap(), "192.0.2.11".parse().unwrap()]
    );
    assert_eq!(r.resolve("v6.test", 443).await.unwrap().len(), 1);
    assert!(r.resolve("x", 80).await.is_err(), "malformed entries are skipped");
    assert!(r.resolve("missing.test", 80).await.is_err());
    if std::env::var_os("WEBFILTER_TEST_HOSTS").is_none() {
        assert!(test_hosts_resolver().is_none());
    }
}

/// Review 2 L4: the deprecated site-local range is private. Documentation ranges (TEST-NETs,
/// 2001:db8::/32) are not internal networks and the netns lab uses them as origins (A-49).
#[test]
fn rv2_l4_site_local_is_private() {
    use webfilter::policy::is_private;
    let p = DestPolicy::new(true, vec![]);
    for a in ["fec0::1", "feff:ffff::1", "::ffff:10.0.0.1"] {
        assert!(is_private(ip(a)), "{a}");
        assert_eq!(p.check_ip(ip(a), 80), Err(Reason::PrivateRange), "{a}");
    }
    for a in ["2001:db8::1", "192.0.2.1", "2001:4860::8888", "ff00::1"] {
        let public = a != "ff00::1";
        assert_eq!(!is_private(ip(a)), public, "{a}");
    }
}

/// RV3-M3: attacker-chosen unknown names share one counter; a known user is locked per client
/// network only, so failures from network A never lock the user out from network B.
#[test]
fn rv3_m3_user_lockout_bounded_and_per_client_network() {
    use webfilter::auth::{UNKNOWN_USER, user_key};
    let l: Lockout<(String, IpAddr)> = Lockout::default();
    let (a, b, t0) = (ip("192.0.2.1"), ip("198.51.100.7"), Instant::now());
    let long = "n".repeat(40 * 1024);
    for i in 0..1_000 {
        l.record_failure(user_key(&format!("{long}{i}"), false, a), t0);
    }
    assert_eq!(l.tracked(), 1, "every unknown name shares one key");
    assert!(l.is_locked(user_key("whatever", false, a), t0));
    assert_eq!(user_key("x", false, a).0, UNKNOWN_USER);

    let users: Lockout<(String, IpAddr)> = Lockout::default();
    for _ in 0..MAX_FAILURES {
        users.record_failure(user_key("alice", true, a), t0);
    }
    assert!(users.is_locked(user_key("alice", true, a), t0), "alice locked from A");
    assert!(!users.is_locked(user_key("alice", true, b), t0), "alice still usable from B");
    let v6 = Lockout::<(String, IpAddr)>::default();
    for i in 0..MAX_FAILURES {
        v6.record_failure(user_key("alice", true, ip(&format!("2001:db8:1:2::{i:x}"))), t0);
    }
    assert!(v6.is_locked(user_key("alice", true, ip("2001:db8:1:2::ffff")), t0), "same /64");
    assert!(!v6.is_locked(user_key("alice", true, ip("2001:db8:1:3::1")), t0), "other /64");
}

/// RV3-M4: the active-lockout check for a new client is O(log n), and partial counters from many
/// networks never make a newcomer fail closed.
#[test]
fn rv3_m4_many_partial_counters_never_lock_a_new_client() {
    let l = Lockout::default();
    let t0 = Instant::now();
    for i in 0..webfilter::auth::MAX_TRACKED as u32 {
        l.record_failure(IpAddr::from((0x0a00_0000u32 + i).to_be_bytes()), t0);
    }
    let newcomer = ip("192.0.2.200");
    let start = Instant::now();
    for _ in 0..10_000 {
        assert!(!l.is_locked(newcomer, t0), "partial counters never fail closed");
    }
    assert!(start.elapsed() < Duration::from_secs(2), "no full-table scan per check");
    assert!(!l.record_failure(newcomer, t0), "a newcomer can still be counted");
    assert!(l.tracked() <= webfilter::auth::MAX_TRACKED);
}

/// RV3-L1: failures decay; one every 15 s (at most 4 per 60 s window) never locks, while 5
/// within 60 s still do.
#[test]
fn rv3_l1_failures_outside_the_window_decay() {
    let l = Lockout::default();
    let (a, t0) = (ip("192.0.2.9"), Instant::now());
    for i in 0..20u64 {
        let at = t0 + Duration::from_secs(15 * i);
        assert!(!l.record_failure(a, at), "failure {i} spread out must not lock");
        assert!(!l.is_locked(a, at));
    }
    let b = ip("192.0.2.10");
    for i in 0..MAX_FAILURES - 1 {
        assert!(!l.record_failure(b, t0 + Duration::from_secs(u64::from(i))));
    }
    assert!(l.record_failure(b, t0 + Duration::from_secs(59)), "5 within 60 s still lock");
    assert!(l.is_locked(b, t0 + Duration::from_secs(60)));
}
