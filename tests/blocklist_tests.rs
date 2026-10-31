//! U-blocklist, U-regex, P-03, P-04, PT-1.3, PT-1.6.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::time::{Duration, Instant};

use proptest::prelude::*;
use webfilter::blocklist::{
    BlocklistHandle, ListError, MAX_FILE_BYTES, ReloadOutcome, parse_domain_entry, parse_domains,
    parse_ips, parse_patterns,
};
use webfilter::config::BlocklistConfig;

#[test]
fn domain_grammar_apex_subdomain_exact() {
    let set = parse_domains("evil.com\n*.wild.test\n=exact.test\n").unwrap().list;
    assert_eq!(set.matches("evil.com").as_deref(), Some("evil.com"));
    assert_eq!(set.matches("a.b.evil.com").as_deref(), Some("evil.com"));
    assert_eq!(set.matches("notevil.com"), None);
    assert_eq!(set.matches("evil.com.attacker.test"), None);
    assert_eq!(set.matches("wild.test"), None, "*. form does not match the apex");
    assert_eq!(set.matches("x.wild.test").as_deref(), Some("*.wild.test"));
    assert_eq!(set.matches("exact.test").as_deref(), Some("=exact.test"));
    assert_eq!(set.matches("sub.exact.test"), None);
}

#[test]
fn domain_entries_idna_case_comments_bom_crlf() {
    let text =
        "\u{feff}# header\r\nBÜCHER.example\r\nfoo.test # trailing comment\r\nbar#baz.test\r\n\r\n";
    let p = parse_domains(text).unwrap();
    assert!(p.list.matches("xn--bcher-kva.example").is_some());
    assert!(p.list.matches("foo.test").is_some());
    assert_eq!(
        p.invalid, 1,
        "`bar#baz.test`: # not preceded by whitespace is part of the entry -> invalid"
    );
}

#[test]
fn domain_entry_validation() {
    for bad in [
        "com",
        "-bad.test",
        "bad-.test",
        "a..b",
        "under_score.test",
        &format!("{}.test", "a".repeat(64)),
        "evil.com/x",
        "1.2.3.4/8",
    ] {
        assert!(parse_domain_entry(bad).is_err(), "{bad} should be rejected");
    }
    assert!(parse_domain_entry("localhost").is_ok());
    assert!(parse_domain_entry("evil.com.").is_ok(), "one trailing dot allowed");
}

#[test]
fn duplicates_counted_and_warnings_capped() {
    let mut text = String::from("a.test\na.test\nA.TEST\n");
    for i in 0..30 {
        text.push_str(&format!("ok{i}.test\nbad_{i}\n"));
    }
    let p = parse_domains(&text).unwrap();
    assert_eq!(p.duplicates, 2);
    assert_eq!(p.invalid, 30);
    assert_eq!(p.warnings.len(), 20, "only the first 20 invalid lines are listed");
    assert!(p.warnings[0].starts_with("line 5:"), "{:?}", p.warnings[0]);
}

#[test]
fn more_than_half_invalid_rejects_file() {
    let err = parse_domains("ok.test\nbad1\nbad2\n").unwrap_err();
    assert!(matches!(err, ListError::TooManyInvalid { invalid: 2, total: 3 }));
    assert!(parse_domains("ok.test\nbad1\n").is_ok(), "exactly 50% is still accepted");
}

#[test]
fn ip_list_cidr_mapped_and_host_bits() {
    let set =
        parse_ips("10.0.0.0/8\n192.168.1.5\n::ffff:127.0.0.1\n2001:db8::/32\n172.16.5.5/12\n")
            .unwrap()
            .list;
    assert_eq!(set.matches("10.1.2.3".parse().unwrap()).unwrap().to_string(), "10.0.0.0/8");
    assert_eq!(set.matches("192.168.1.5".parse().unwrap()).unwrap().to_string(), "192.168.1.5/32");
    assert!(set.matches("192.168.1.6".parse().unwrap()).is_none());
    assert!(set.matches("127.0.0.1".parse().unwrap()).is_some(), "mapped entry folded to IPv4");
    assert!(
        set.matches("::ffff:10.9.9.9".parse().unwrap()).is_some(),
        "mapped lookup folded to IPv4"
    );
    assert!(set.matches("2001:db8:1::1".parse().unwrap()).is_some());
    assert_eq!(set.matches("172.31.0.1".parse().unwrap()).unwrap().to_string(), "172.16.0.0/12");
}

#[test]
fn ip_list_prefers_most_specific() {
    let set = parse_ips("10.0.0.0/8\n10.1.0.0/16\n").unwrap().list;
    assert_eq!(set.matches("10.1.2.3".parse().unwrap()).unwrap().to_string(), "10.1.0.0/16");
}

#[test]
fn patterns_ids_comments_invalid_and_case() {
    let text = "# comment\n[id=rx-007] /admin/\nevil#frag\n(unclosed\n[id=bad id] x\n";
    let p = parse_patterns(text).unwrap();
    assert_eq!(p.entries, 2);
    assert_eq!(p.invalid, 2);
    let views = |s: &str| [s.to_owned(), s.to_owned(), s.to_owned()];
    assert_eq!(p.list.matches(&views("http://x.test/ADMIN/")), Some("rx-007"));
    assert_eq!(
        p.list.matches(&views("http://x.test/evil#frag")),
        Some("line-3"),
        "# inside a regex is not a comment"
    );
    assert_eq!(p.list.matches(&views("http://x.test/")), None);
}

#[test]
fn pattern_too_long_is_invalid() {
    let text = format!("ok\n{}\n", "a".repeat(1025));
    assert_eq!(parse_patterns(&text).unwrap().invalid, 1);
}

#[test]
fn pattern_first_matching_view_and_leftmost_match() {
    let p = parse_patterns("[id=first] zzz\n[id=second] /admin/\n").unwrap().list;
    let views = ["http://x/a".to_owned(), "http://x/admin/".to_owned(), "http://x/zzz".to_owned()];
    assert_eq!(p.matches(&views), Some("second"), "the first matching view decides");
    let same = ["http://x/zzz/admin/".to_owned()];
    assert_eq!(p.matches(&same), Some("first"), "leftmost match within a view");
}

#[test]
fn redos_patterns_are_linear_time() {
    // PT-1.3 (unit-level): catastrophic-backtracking shapes stay fast with the linear-time engine.
    let p = parse_patterns("(a+)+$\n(a|aa)+$\n(.*a){12}\n").unwrap();
    assert_eq!(p.invalid, 0, "no pattern rejected silently");
    let attack = format!("{}!", "a".repeat(64 * 1024));
    let views = [attack.clone(), attack.clone(), attack];
    let start = Instant::now();
    let _ = p.list.matches(&views);
    assert!(start.elapsed() < Duration::from_millis(500), "took {:?}", start.elapsed());
}

fn write_lists(dir: &std::path::Path, domains: &str) -> BlocklistConfig {
    std::fs::write(dir.join("domains.txt"), domains).unwrap();
    std::fs::write(dir.join("url_patterns.txt"), "/admin/\n").unwrap();
    std::fs::write(dir.join("ip_blocklist.txt"), "10.0.0.0/8\n").unwrap();
    BlocklistConfig {
        domains: dir.join("domains.txt"),
        url_patterns: dir.join("url_patterns.txt"),
        ip_blocklist: dir.join("ip_blocklist.txt"),
        reload_interval_secs: 1,
        ..BlocklistConfig::default()
    }
}

#[test]
fn hot_reload_swaps_and_keeps_old_list_on_failure() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_lists(dir.path(), "evil.com\n");
    let (handle, report) = BlocklistHandle::load(&cfg).unwrap();
    assert_eq!((report.domains, report.regexes, report.ips), (1, 1, 1));
    let before = handle.snapshot();
    assert!(handle.reload_if_changed().is_none(), "unchanged files are not reloaded");

    std::fs::write(&cfg.domains, "evil.com\nnew.test\n").unwrap();
    assert!(matches!(handle.reload_if_changed(), Some(ReloadOutcome::Reloaded(_))));
    assert!(handle.snapshot().domains.matches("new.test").is_some());
    assert!(before.domains.matches("new.test").is_none(), "old snapshot is immutable");

    std::fs::write(&cfg.domains, "bad1\nbad2\nbad3\n").unwrap();
    assert!(matches!(handle.reload(), ReloadOutcome::Failed(_)));
    assert!(handle.snapshot().domains.matches("new.test").is_some(), "previous list kept");
}

#[test]
fn oversized_binary_and_missing_files_fail_load() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_lists(dir.path(), "evil.com\n");
    let (handle, _) = BlocklistHandle::load(&cfg).unwrap();

    std::fs::write(&cfg.domains, vec![b'a'; usize::try_from(MAX_FILE_BYTES).unwrap() + 1]).unwrap();
    assert!(matches!(handle.reload(), ReloadOutcome::Failed(e) if e.contains("larger than")));

    std::fs::write(&cfg.domains, [0xff, 0xfe, 0x00, 0x41, 0x0a]).unwrap();
    assert!(matches!(handle.reload(), ReloadOutcome::Failed(e) if e.contains("UTF-8")));

    std::fs::remove_file(&cfg.domains).unwrap();
    assert!(matches!(handle.reload(), ReloadOutcome::Failed(_)));
    assert!(
        handle.snapshot().domains.matches("evil.com").is_some(),
        "previous list kept throughout"
    );
}

#[test]
fn nul_and_junk_lines_are_invalid_not_fatal() {
    let p = parse_domains("evil.com\nok.test\nfine.test\nx\u{0}y.test\n").unwrap();
    assert_eq!(p.invalid, 1);
    assert_eq!(p.entries, 3);
}

/// Reference suffix algorithm for P-03.
fn reference_match(entries: &[String], host: &str) -> bool {
    entries.iter().any(|e| host == e || host.ends_with(&format!(".{e}")))
}

fn label() -> impl Strategy<Value = String> {
    "[a-z0-9]{1,6}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// P-03: matching equals the reference suffix algorithm for apex entries.
    #[test]
    fn p03_matching_equals_reference(entries in prop::collection::vec(prop::collection::vec(label(), 2..4), 1..6),
                                      host in prop::collection::vec(label(), 1..5)) {
        let entries: Vec<String> = entries.iter().map(|l| l.join(".")).collect();
        let host = host.join(".");
        let set = parse_domains(&entries.join("\n")).unwrap().list;
        prop_assert_eq!(set.matches(&host).is_some(), reference_match(&entries, &host));
    }

    /// P-04: parse(serialize(x)) == x for domain lists.
    #[test]
    fn p04_domain_roundtrip(entries in prop::collection::btree_set(prop::collection::vec(label(), 2..4), 1..20)) {
        let lines: Vec<String> = entries.iter().map(|l| l.join(".")).collect();
        let first = parse_domains(&lines.join("\n")).unwrap();
        let again = parse_domains(&lines.join("\r\n")).unwrap();
        prop_assert_eq!(first.entries, lines.len());
        prop_assert_eq!(again.entries, lines.len());
        for l in &lines {
            prop_assert_eq!(first.list.matches(l), again.list.matches(l));
        }
    }

    /// The parsers never panic on arbitrary text (F-02 smoke).
    #[test]
    fn parsers_never_panic(text in ".{0,400}") {
        let _ = parse_domains(&text);
        let _ = parse_patterns(&text);
        let _ = parse_ips(&text);
    }
}

#[test]
fn watcher_reloads_and_logs_system_events() {
    use webfilter::config::LoggingConfig;
    use webfilter::logger::{EventLogger, SYSTEM_FILE};
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_lists(dir.path(), "evil.com\n");
    let (handle, _) = BlocklistHandle::load(&cfg).unwrap();
    let handle = std::sync::Arc::new(handle);
    let logdir = dir.path().join("logs");
    let log = EventLogger::start(&LoggingConfig {
        dir: logdir.clone(),
        max_bytes: 1 << 20,
        backup_count: 1,
        queue_capacity: 100,
    })
    .unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    rt.block_on(async {
        let task = handle.spawn_watcher(Duration::from_millis(20), log.system());
        std::fs::write(&cfg.domains, "evil.com\nnew.test\n").unwrap();
        for _ in 0..200 {
            if handle.snapshot().domains.matches("new.test").is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        std::fs::write(&cfg.domains, "bad1\nbad2\nbad3\n").unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        task.abort();
    });
    assert!(
        handle.snapshot().domains.matches("new.test").is_some(),
        "reloaded, then kept on failure"
    );
    assert_eq!(
        (
            handle.snapshot().domains.len(),
            handle.snapshot().patterns.len(),
            handle.snapshot().ips.len()
        ),
        (2, 1, 1)
    );
    assert!(
        !handle.snapshot().domains.is_empty()
            && !handle.snapshot().patterns.is_empty()
            && !handle.snapshot().ips.is_empty()
    );
    log.shutdown(Duration::from_secs(5));
    let sys = std::fs::read_to_string(logdir.join(SYSTEM_FILE)).unwrap();
    assert!(
        sys.contains("\"blocklist_loaded\"") && sys.contains("\"blocklist_reload_failed\""),
        "{sys}"
    );
}

#[test]
fn entry_limit_is_enforced() {
    use webfilter::blocklist::MAX_ENTRIES;
    let text: String = (0..=MAX_ENTRIES)
        .map(|i| format!("10.{}.{}.{}\n", i >> 16 & 255, i >> 8 & 255, i & 255))
        .collect::<String>()
        + &(0..=MAX_ENTRIES / 65536).map(|i| format!("11.{i}.0.0/16\n")).collect::<String>();
    assert!(matches!(parse_ips(&text), Err(ListError::TooManyEntries)));
}
