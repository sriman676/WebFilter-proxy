//! A-27: named categories (switchable, scheduled) and the schedule engine; A-26 block page shows
//! the category.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use common::{Lab, Origin, ProxyHarness, Reply, TestResolver, base_config, status};
use time::macros::datetime;
use webfilter::blocklist::Blocklists;
use webfilter::config::{Config, ConfigError, Mode, RuleConfig};
use webfilter::filter::{Phase, evaluate_at};
use webfilter::normalize::{TargetContext, canonicalize};
use webfilter::schedule::{Schedule, parse_offset};

fn sched(specs: &[&str], offset: &str) -> Schedule {
    Schedule::parse(
        &specs.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        parse_offset(offset).unwrap(),
    )
    .unwrap()
}

#[test]
fn schedule_windows_days_and_offsets() {
    let s = sched(&["Mon-Fri 09:00-17:00"], "+00:00");
    assert!(s.is_active(datetime!(2026-11-02 09:00 UTC)), "Monday 09:00");
    assert!(!s.is_active(datetime!(2026-11-02 17:00 UTC)), "end is exclusive");
    assert!(!s.is_active(datetime!(2026-11-07 12:00 UTC)), "Saturday");
    let ist = sched(&["Mon-Fri 09:00-17:00"], "+05:30");
    assert!(ist.is_active(datetime!(2026-11-02 04:00 UTC)), "09:30 in +05:30");
    assert!(!ist.is_active(datetime!(2026-11-02 12:00 UTC)), "17:30 in +05:30");
    assert!(Schedule::default().is_active(datetime!(2026-11-07 03:00 UTC)), "no windows = always");
}

#[test]
fn schedule_overnight_and_wrapping_ranges() {
    let s = sched(&["Fri 22:00-02:00"], "+00:00");
    assert!(s.is_active(datetime!(2026-11-06 23:00 UTC)), "Friday night");
    assert!(s.is_active(datetime!(2026-11-07 01:59 UTC)), "after midnight, Saturday morning");
    assert!(!s.is_active(datetime!(2026-11-07 02:00 UTC)));
    assert!(!s.is_active(datetime!(2026-11-05 23:00 UTC)), "Thursday night");
    let wrap = sched(&["Sat-Mon 00:00-24:00"], "+00:00");
    for d in [
        datetime!(2026-11-07 12:00 UTC),
        datetime!(2026-11-08 12:00 UTC),
        datetime!(2026-11-09 23:59 UTC),
    ] {
        assert!(wrap.is_active(d), "{d}");
    }
    assert!(!wrap.is_active(datetime!(2026-11-10 00:00 UTC)), "Tuesday");
    let list = sched(&["Mon,Wed 08:00-09:00", "Sun 10:00-11:00"], "+00:00");
    assert!(
        list.is_active(datetime!(2026-11-04 08:30 UTC))
            && list.is_active(datetime!(2026-11-08 10:30 UTC))
    );
}

#[test]
fn schedule_rejects_bad_specs() {
    for bad in [
        "Mon-Fri",
        "Mon 9:00-17:00",
        "Mon 09:00-25:00",
        "Funday 09:00-10:00",
        "Mon 09:60-10:00",
        "Mon 10:00-10:00",
        "Mon 24:00-01:00",
    ] {
        assert!(
            Schedule::parse(&[bad.to_owned()], parse_offset("+00:00").unwrap()).is_err(),
            "{bad}"
        );
    }
    for bad in ["05:30", "+5:30", "+25:00", "UTC"] {
        assert!(parse_offset(bad).is_err(), "{bad}");
    }
}

fn lab_with_category(cat: &str) -> (Lab, Result<Config, ConfigError>) {
    let lab = Lab::new();
    lab.write_list("social.txt", "social.test\n");
    let path = lab.write_config(&format!("[blocklists]\nutc_offset = \"+00:00\"\n{cat}"));
    let cfg = Config::load(&path);
    (lab, cfg)
}

#[test]
fn category_config_validation() {
    let ok = "[[blocklists.categories]]\nname = \"social\"\ndomains = \"blocklists/social.txt\"\nactive = [\"Mon-Fri 09:00-17:00\"]\n";
    assert!(lab_with_category(ok).1.is_ok());
    for bad in [
        "[[blocklists.categories]]\nname = \"Social Media\"\ndomains = \"blocklists/social.txt\"\n",
        "[[blocklists.categories]]\nname = \"a\"\ndomains = \"blocklists/social.txt\"\n[[blocklists.categories]]\nname = \"a\"\ndomains = \"blocklists/social.txt\"\n",
        "[[blocklists.categories]]\nname = \"empty\"\n",
        "[[blocklists.categories]]\nname = \"x\"\ndomains = \"blocklists/missing.txt\"\n",
        "[[blocklists.categories]]\nname = \"x\"\ndomains = \"blocklists/social.txt\"\nactive = [\"sometimes\"]\n",
        "[[blocklists.categories]]\nname = \"x\"\ndomains = \"blocklists/social.txt\"\ncolour = \"red\"\n",
    ] {
        assert!(lab_with_category(bad).1.is_err(), "{bad}");
    }
}

#[test]
fn category_matching_respects_enabled_and_schedule() {
    let cat = |enabled: bool| {
        format!(
            "[[blocklists.categories]]\nname = \"social\"\nenabled = {enabled}\ndomains = \"blocklists/social.txt\"\nactive = [\"Mon-Fri 09:00-17:00\"]\n"
        )
    };
    let (_lab, cfg) = lab_with_category(&cat(true));
    let cfg = cfg.unwrap();
    let (lists, report) = Blocklists::load(&cfg.blocklists).unwrap();
    assert_eq!(report.domains, 1, "category entries counted");
    let t = canonicalize("http://www.social.test/", TargetContext::PlainAbsolute).unwrap();
    let rules = RuleConfig::default();
    let at_work = evaluate_at(
        &t,
        Phase::PreDns,
        &lists,
        &rules,
        Mode::Enforce,
        datetime!(2026-11-02 10:00 UTC),
    );
    assert!(at_work.is_block());
    assert_eq!(
        (at_work.category.as_deref(), at_work.rule_id.as_deref(), at_work.rule_list.as_deref()),
        (Some("social"), Some("domain:social.test"), Some("social.txt"))
    );
    assert!(
        !evaluate_at(
            &t,
            Phase::PreDns,
            &lists,
            &rules,
            Mode::Enforce,
            datetime!(2026-11-02 20:00 UTC)
        )
        .is_block(),
        "outside the window"
    );
    assert!(
        !evaluate_at(
            &t,
            Phase::ConnectPreDns,
            &lists,
            &rules,
            Mode::Enforce,
            datetime!(2026-11-08 10:00 UTC)
        )
        .is_block(),
        "weekend"
    );

    let (_lab2, off) = lab_with_category(&cat(false));
    let (lists, _) = Blocklists::load(&off.unwrap().blocklists).unwrap();
    assert!(
        !evaluate_at(
            &t,
            Phase::PreDns,
            &lists,
            &rules,
            Mode::Enforce,
            datetime!(2026-11-02 10:00 UTC)
        )
        .is_block(),
        "disabled"
    );
}

#[tokio::test]
async fn always_on_category_blocks_through_proxy_with_category_on_page() {
    let origin = Origin::start(|_| Reply::ok("ok")).await;
    let resolver = TestResolver::with(&[("social.test", "127.0.0.1")]);
    let extra = "[blocklists]\n[[blocklists.categories]]\nname = \"social\"\ndomains = \"blocklists/social.txt\"\n";
    let mut p =
        ProxyHarness::start(&base_config(extra), &[("social.txt", "social.test\n")], resolver)
            .await;
    let resp = p
        .raw(
            format!("GET http://social.test:{}/ HTTP/1.1\r\n\r\n", origin.addr.port()).as_bytes(),
            std::time::Duration::from_secs(3),
        )
        .await;
    assert_eq!(status(&resp), 403, "{resp}");
    assert!(resp.contains("Category: <code>social</code>"), "{resp}");
    p.stop().await;
    assert_eq!(p.log_lines()[0]["rule_list"], "social.txt");
}
