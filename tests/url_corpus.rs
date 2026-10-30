//! U-001..U-055 / PT-1.1: `tests/corpus/url_bypass_cases.tsv` through canonicalize + policy + evaluate.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use webfilter::blocklist::{Blocklists, parse_domains, parse_ips, parse_patterns};
use webfilter::config::{Mode, RuleConfig};
use webfilter::filter::{Phase, evaluate};
use webfilter::normalize::{TargetContext, TargetError, canonicalize};
use webfilter::policy::DestPolicy;

/// Corpus setup: domains "evil.com", pattern "/admin/", IPs 127.0.0.1 and ::1, default rules.
pub fn corpus_lists() -> Blocklists {
    Blocklists {
        domains: parse_domains("evil.com\n").unwrap().list,
        patterns: parse_patterns("/admin/\n").unwrap().list,
        ips: parse_ips("127.0.0.1\n::1\n").unwrap().list,
    }
}

fn outcome(raw: &str, lists: &Blocklists, rules: &RuleConfig) -> &'static str {
    let t = match canonicalize(raw, TargetContext::PlainAbsolute) {
        Err(TargetError::UserInfo) => return "BLOCK_USERINFO",
        Err(_) => return "REJECT400",
        Ok(t) => t,
    };
    if evaluate(&t, Phase::PreDns, lists, rules, Mode::Enforce).is_block() {
        return "BLOCK";
    }
    if let Some(ip) = t.host.ip() {
        let policy = DestPolicy::new(false, vec![]);
        if policy.check_ip(ip, t.port).is_err()
            || evaluate(&t, Phase::Resolved { ip }, lists, rules, Mode::Enforce).is_block()
        {
            return "BLOCK";
        }
    }
    "ALLOW"
}

fn cases() -> Vec<(String, String, String)> {
    let text =
        std::fs::read_to_string(common::repo_root().join("tests/corpus/url_bypass_cases.tsv"))
            .unwrap();
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let cols: Vec<&str> = l.split('\t').collect();
            let raw = cols[1].replace("\\x0d", "\r").replace("\\x0a", "\n");
            (cols[0].to_owned(), raw, cols[3].to_owned())
        })
        .collect()
}

#[test]
fn url_bypass_corpus_all_cases_match() {
    let (lists, rules) = (corpus_lists(), RuleConfig::default());
    let cases = cases();
    assert_eq!(cases.len(), 55, "corpus must contain U-001..U-055");
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|(id, raw, want)| {
            let got = outcome(raw, &lists, &rules);
            (got != want).then(|| format!("{id} {raw:?}: expected {want}, got {got}"))
        })
        .collect();
    assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn u039_double_encoding_is_flagged() {
    let t =
        canonicalize("http://good.test/%252e%252e/admin/", TargetContext::PlainAbsolute).unwrap();
    assert!(t.suspicious_encoding);
    assert_eq!(t.path, "/%252e%252e/admin/");
}

#[test]
fn u050_encoded_crlf_stays_encoded_in_forwarded_target() {
    let t =
        canonicalize("http://good.test/%0d%0aX-Injected:1", TargetContext::PlainAbsolute).unwrap();
    assert_eq!(t.origin_form(), "/%0D%0AX-Injected:1");
    assert!(!t.origin_form().contains(['\r', '\n']));
}

#[test]
fn u030_mapped_ipv6_folds_to_ipv4_for_policy() {
    let t = canonicalize("http://[::ffff:127.0.0.1]/", TargetContext::PlainAbsolute).unwrap();
    assert_eq!(t.host.ip(), Some("127.0.0.1".parse().unwrap()));
}
