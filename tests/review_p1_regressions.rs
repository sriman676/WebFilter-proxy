//! Regression tests for the Phase 1 security review (docs/pentest/phase-1/FINDINGS.md PF-1-02..).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::net::IpAddr;
use std::time::{Duration, Instant};

use webfilter::auth::{Lockout, MAX_TRACKED};
use webfilter::blocklist::{Blocklists, parse_domains, parse_ips, parse_patterns};
use webfilter::config::{Mode, RuleConfig};
use webfilter::filter::{Action, Phase, evaluate};
use webfilter::logger::{RequestEvent, clean};
use webfilter::normalize::{TargetContext, TargetError, canonicalize};
use webfilter::policy::DestPolicy;
use webfilter::reason::Reason;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn lists(patterns: &str) -> Blocklists {
    Blocklists {
        domains: parse_domains("evil.com\n").unwrap().list,
        patterns: parse_patterns(patterns).unwrap().list,
        ips: parse_ips("10.0.0.0/8\n").unwrap().list,
    }
}

/// PF-1-02: dot segments created by decoding must be resolved in the decoded views.
#[test]
fn pf_1_02_decoded_views_resolve_dot_segments() {
    let t =
        canonicalize("http://good.test/pub%2F..%2Fadmin/x", TargetContext::PlainAbsolute).unwrap();
    assert!(t.views[1].ends_with("good.test/admin/x"), "{:?}", t.views);
    let l = lists("^https?://good\\.test/admin\n");
    assert!(evaluate(&t, Phase::PreDns, &l, &RuleConfig::default(), Mode::Enforce).is_block());
    let t =
        canonicalize("http://good.test/a/%252e%252e/admin/", TargetContext::PlainAbsolute).unwrap();
    assert!(t.views[2].ends_with("good.test/admin/"), "{:?}", t.views);
}

/// PF-1-03: inside a tunnel, an absolute-form target must name the CONNECT authority over https.
#[test]
fn pf_1_03_intercepted_absolute_form_must_match_connect() {
    let ctx = TargetContext::InterceptedOrigin { connect_host: "good.test", port: 443 };
    for raw in [
        "http://allowlisted.com/x.exe",
        "https://allowlisted.com/x",
        "http://good.test/x",
        "https://good.test:8443/x",
    ] {
        assert_eq!(canonicalize(raw, ctx), Err(TargetError::HostMismatch), "{raw}");
    }
    assert_eq!(TargetError::HostMismatch.reason(), Reason::HostMismatch);
    let ok = canonicalize("https://GOOD.test:443/x", ctx).unwrap();
    assert_eq!(ok.url_norm, "https://good.test/x");
    assert_eq!(canonicalize("/x", ctx).unwrap(), ok);
}

/// PF-1-04: IPv4 embedded in IPv6 (NAT64, 6to4, IPv4-compatible, Teredo) and extra reserved
/// IPv4 ranges are checked like the IPv4 they reach.
#[test]
fn pf_1_04_embedded_ipv4_and_reserved_ranges() {
    let strict = DestPolicy::new(true, vec![]);
    for a in [
        "64:ff9b::a00:1",
        "64:ff9b::7f00:1",
        "64:ff9b:1::1",
        "2002:a00:1::1",
        "2002:7f00:1::1",
        "::a00:1",
        "::7f00:1",
        "2001:0:0:0:0:0:f5ff:fffe",
        "192.0.0.1",
        "240.0.0.1",
        "198.18.0.1",
        "198.19.255.255",
    ] {
        assert_eq!(strict.check_ip(ip(a), 80), Err(Reason::PrivateRange), "{a}");
    }
    let lab = DestPolicy::new(false, vec![]);
    for a in
        ["64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "::a9fe:a9fe", "192.0.0.192", "100.100.100.200"]
    {
        assert_eq!(
            lab.check_ip(ip(a), 80),
            Err(Reason::PrivateRange),
            "{a}: metadata reached via embedding is always denied"
        );
    }
    for a in ["64:ff9b::5db8:d822", "2002:5db8:d822::1", "2001:db8::1", "93.184.216.34"] {
        assert!(strict.check_ip(ip(a), 80).is_ok(), "{a} (public)");
    }
}

/// PF-1-05: lockout keys IPv6 by /64 and fails closed when the table is full.
#[test]
fn pf_1_05_lockout_ipv6_slash64_and_fail_closed() {
    let l = Lockout::default();
    let t0 = Instant::now();
    for i in 0..5 {
        l.record_failure(ip(&format!("2001:db8:1:2::{i:x}")), t0);
    }
    assert!(l.is_locked(ip("2001:db8:1:2::ffff"), t0), "whole /64 locked");
    assert!(!l.is_locked(ip("2001:db8:1:3::1"), t0), "other /64 not locked");

    let full = Lockout::default();
    for i in 0..MAX_TRACKED as u32 {
        for _ in 0..5 {
            full.record_failure(IpAddr::from((0x0a00_0000u32 + i).to_be_bytes()), t0);
        }
    }
    let newcomer = ip("192.0.2.77");
    assert!(full.is_locked(newcomer, t0), "table full of active lockouts: fail closed");
    assert!(
        !full.is_locked(newcomer, t0 + Duration::from_secs(61)),
        "recovers once lockouts expire"
    );
}

/// PF-1-07: the `url` log field never carries the query (D-18).
#[test]
fn pf_1_07_logged_url_has_no_query() {
    let mut e = RequestEvent {
        url: "http://good.test/a?token=SECRET&x=1".into(),
        ..RequestEvent::default()
    };
    e.sanitize();
    assert_eq!(e.url, "http://good.test/a");
}

/// PF-1-08 (Low): mapped IPv6 CIDRs in ip_blocklist.txt are folded to IPv4.
#[test]
fn pf_1_08_mapped_cidr_folded() {
    let set = parse_ips("::ffff:10.0.0.0/104\n").unwrap().list;
    assert_eq!(set.matches(ip("10.9.9.9")).unwrap().to_string(), "10.0.0.0/8");
}

/// PF-1-09 (Low): allowlist `*.x.com` does not allow the apex; IP entries match exactly.
#[test]
fn pf_1_09_allowlist_forms() {
    let l = lists("zz-never-matches\n");
    let r = RuleConfig {
        allow_domains: vec!["*.evil.com".into(), "0.0.1".into()],
        ..RuleConfig::default()
    };
    let eval = |raw: &str| {
        evaluate(
            &canonicalize(raw, TargetContext::PlainAbsolute).unwrap(),
            Phase::PreDns,
            &l,
            &r,
            Mode::Enforce,
        )
    };
    assert_eq!(eval("http://a.evil.com/").reason, Reason::Allowlist);
    assert_eq!(
        eval("http://evil.com/").reason,
        Reason::DomainBlocklist,
        "*. entry must not allow the apex"
    );
    let t = canonicalize("http://10.0.0.1/", TargetContext::PlainAbsolute).unwrap();
    let d = evaluate(&t, Phase::Resolved { ip: ip("10.0.0.1") }, &l, &r, Mode::Enforce);
    assert_eq!(
        d.reason,
        Reason::IpBlocklist,
        "IP literal must not suffix-match an allowlist entry"
    );
}

/// PF-1-10 (Low): empty extension entries never block everything; trailing dots are ignored.
#[test]
fn pf_1_10_extension_edge_cases() {
    let l = lists("zz-never-matches\n");
    let r = RuleConfig {
        blocked_extensions: vec![String::new(), ".exe".into()],
        ..RuleConfig::default()
    };
    let eval = |raw: &str| {
        evaluate(
            &canonicalize(raw, TargetContext::PlainAbsolute).unwrap(),
            Phase::PreDns,
            &l,
            &r,
            Mode::Enforce,
        )
    };
    assert_eq!(eval("http://good.test/index.html").action, Action::Allow);
    assert_eq!(
        eval("http://good.test/x.exe.").reason,
        Reason::Extension,
        "Windows strips trailing dots"
    );
}

/// PF-1-11 (Low): bidi overrides and line/paragraph separators are stripped from log text.
#[test]
fn pf_1_11_clean_strips_bidi_and_separators() {
    let s = clean("a\u{202e}b\u{2066}c\u{2028}d\u{2029}e\u{200f}f", 100);
    assert_eq!(s, "abcdef");
}

/// PF-1-12 (Low): P-06 must not pass vacuously; normal paths always canonicalize.
#[test]
fn pf_1_12_normal_paths_always_canonicalize() {
    for p in ["/", "/.", "/..", "/a/./b", "/%2e", "/%41/b", "/a%2fb", "/x/../.."] {
        assert!(
            canonicalize(&format!("http://good.test{p}"), TargetContext::PlainAbsolute).is_ok(),
            "{p}"
        );
    }
}
