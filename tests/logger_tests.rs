//! U-logger, PT-1.7: all keys present, caps, control-character stripping, one JSON object per
//! line, rotation without splitting lines, drop counter, disk errors never panic.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::path::Path;
use std::time::Duration;

use serde_json::Value;
use webfilter::config::LoggingConfig;
use webfilter::filter::Action;
use webfilter::logger::{
    EventLogger, ListCounts, REQUEST_FILE, RequestEvent, STATS_FILE, SYSTEM_FILE, Stats, SysEvent,
    clean,
};

const SCHEMA_KEYS: &[&str] = &[
    "timestamp",
    "event_id",
    "event_type",
    "src_ip",
    "src_port",
    "http_method",
    "url",
    "url_scheme",
    "dest_host",
    "dest_ip",
    "dest_port",
    "uri_path",
    "uri_query_keys",
    "status",
    "action",
    "would_block",
    "reason",
    "rule_id",
    "rule_list",
    "user_agent",
    "http_content_type",
    "http_version",
    "bytes_in",
    "bytes_out",
    "duration_ms",
    "tls_intercepted",
    "tls_sni",
    "ech_present",
    "alpn",
    "h2_stream_id",
    "transparent",
    "orig_dst_ip",
    "orig_dst_port",
    "host_verified",
    "upgrade",
    "suspicious_encoding",
    "client_id",
    "profile",
    "throttled",
    "scan_status",
    "scan_engine",
    "scan_signature",
    "body_sha256",
    "body_bytes",
    "download_name",
    "proxy_user",
    "error",
    "proxy_mode",
];

fn cfg(dir: &Path, max_bytes: u64, queue: usize) -> LoggingConfig {
    LoggingConfig { dir: dir.to_path_buf(), max_bytes, backup_count: 3, queue_capacity: queue }
}

fn lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("not one JSON object: {l:?}: {e}"))
        })
        .collect()
}

#[test]
fn every_schema_key_present_and_nothing_else() {
    let v = serde_json::to_value(RequestEvent::default()).unwrap();
    let obj = v.as_object().unwrap();
    for k in SCHEMA_KEYS {
        assert!(obj.contains_key(*k), "missing {k}");
    }
    assert_eq!(obj.len(), SCHEMA_KEYS.len(), "unexpected extra keys");
    assert_eq!(obj["event_type"], "request");
    assert!(obj["timestamp"].as_str().unwrap().ends_with('Z'));
    assert_eq!(obj["timestamp"].as_str().unwrap().len(), "2026-10-28T14:03:22.114Z".len());
    assert_eq!(
        uuid::Uuid::parse_str(obj["event_id"].as_str().unwrap()).unwrap().get_version_num(),
        7
    );
}

#[test]
fn caps_and_control_character_stripping() {
    let mut e = RequestEvent {
        url: "a".repeat(5000),
        user_agent: Some(format!("evil\u{1b}[31m\r\n{{\"fake\":1}}{}", "x".repeat(1000))),
        error: Some("e".repeat(300)),
        proxy_user: Some("u".repeat(100)),
        uri_query_keys: (0..80).map(|i| format!("k{i}{}", "q".repeat(100))).collect(),
        ..RequestEvent::default()
    };
    e.sanitize();
    assert_eq!(e.url.chars().count(), 2048);
    assert!(e.url.ends_with('…'));
    let ua = e.user_agent.unwrap();
    assert!(!ua.chars().any(char::is_control), "no CR/LF/ESC survive");
    assert_eq!(ua.chars().count(), 512);
    assert_eq!(e.error.unwrap().chars().count(), 256);
    assert_eq!(e.proxy_user.unwrap().chars().count(), 64);
    assert_eq!(e.uri_query_keys.len(), 50);
    assert!(e.uri_query_keys.iter().all(|k| k.chars().count() <= 64));
    assert_eq!(clean("short", 10), "short");
}

#[test]
fn forged_lines_stay_one_json_object_per_line() {
    let dir = tempfile::tempdir().unwrap();
    let log = EventLogger::start(&cfg(dir.path(), 1 << 20, 100)).unwrap();
    let nasty = "\"\n{\"fake\":1}\r\n\u{1b}[2J\u{0}\u{7f}\u{85}";
    let lossy = String::from_utf8_lossy(&[0xff, 0xfe, b'x']).into_owned();
    for s in [nasty.to_owned(), lossy, "m".repeat(1 << 20)] {
        log.log(RequestEvent {
            http_method: s.clone(),
            url: s.clone(),
            user_agent: Some(s.clone()),
            error: Some(s),
            ..RequestEvent::default()
        });
    }
    log.system().event(SysEvent::ConfigLoaded, serde_json::json!({ "path": nasty }));
    log.shutdown(Duration::from_secs(5));
    let req = lines(&dir.path().join(REQUEST_FILE));
    assert_eq!(req.len(), 3);
    assert!(req.iter().all(|v| v.get("fake").is_none()));
    let sys = lines(&dir.path().join(SYSTEM_FILE));
    assert_eq!(sys[0]["kind"], "config_loaded");
    assert!(!sys[0]["detail"]["path"].as_str().unwrap().chars().any(char::is_control));
}

#[test]
fn rotation_never_splits_lines() {
    let dir = tempfile::tempdir().unwrap();
    let log = EventLogger::start(&cfg(dir.path(), 4096, 1000)).unwrap();
    for i in 0..60 {
        log.log(RequestEvent { uri_path: format!("/{i}"), ..RequestEvent::default() });
    }
    log.shutdown(Duration::from_secs(5));
    let mut total = 0;
    for name in [
        REQUEST_FILE.to_owned(),
        format!("{REQUEST_FILE}.1"),
        format!("{REQUEST_FILE}.2"),
        format!("{REQUEST_FILE}.3"),
    ] {
        let path = dir.path().join(&name);
        if path.exists() {
            assert!(std::fs::metadata(&path).unwrap().len() <= 4096, "{name} too large");
            total += lines(&path).len();
        }
    }
    assert!(!dir.path().join(format!("{REQUEST_FILE}.4")).exists(), "backup_count respected");
    assert!(total > 0 && total <= 60);
    assert!(lines(&dir.path().join(SYSTEM_FILE)).iter().any(|v| v["kind"] == "log_rotated"));
}

#[cfg(unix)]
#[test]
fn files_are_0640() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let log = EventLogger::start(&cfg(dir.path(), 1 << 20, 10)).unwrap();
    log.log(RequestEvent::default());
    log.shutdown(Duration::from_secs(5));
    let mode =
        std::fs::metadata(dir.path().join(REQUEST_FILE)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode & !0o640, 0, "mode {mode:o} is looser than 0640");
}

#[test]
fn full_queue_drops_and_counts_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let log = EventLogger::start(&cfg(dir.path(), 1 << 30, 1)).unwrap();
    let start = std::time::Instant::now();
    for _ in 0..20_000 {
        log.log(RequestEvent::default());
    }
    assert!(start.elapsed() < Duration::from_secs(5), "logging must not block the caller");
    assert!(log.dropped() > 0, "a 1-slot queue must drop under burst");
    log.shutdown(Duration::from_secs(5));
    assert!(lines(&dir.path().join(SYSTEM_FILE)).iter().any(|v| v["kind"] == "log_dropped"));
}

#[test]
fn disk_errors_never_panic() {
    let dir = tempfile::tempdir().unwrap();
    let log = EventLogger::start(&cfg(dir.path(), 1 << 20, 10)).unwrap();
    std::fs::create_dir(dir.path().join(REQUEST_FILE)).unwrap(); // a directory where the file should be
    for _ in 0..5 {
        log.log(RequestEvent::default());
    }
    log.shutdown(Duration::from_secs(5)); // writer survived and acknowledged
}

#[test]
fn stats_window_counts_and_top_blocked() {
    let s = Stats::default();
    for _ in 0..3 {
        s.record(Action::Block, "evil.com", 10, 1);
    }
    s.record(Action::Block, "other.test", 0, 0);
    s.record(Action::Allow, "good.test", 100, 5);
    s.record_error();
    let lists = ListCounts { domains: 1, regexes: 2, ips: 3 };
    let w = s.take_window(60, 7, lists);
    assert_eq!(
        (w.requests, w.allowed, w.blocked, w.errors, w.bytes_in, w.bytes_out),
        (5, 1, 4, 1, 130, 8)
    );
    assert_eq!((w.top_blocked[0].host.as_str(), w.top_blocked[0].count), ("evil.com", 3));
    assert_eq!(w.dropped_log_events, 7);
    let v = serde_json::to_value(&w).unwrap();
    for k in [
        "timestamp",
        "event_type",
        "window_secs",
        "requests",
        "allowed",
        "blocked",
        "errors",
        "bytes_in",
        "bytes_out",
        "active_connections",
        "dropped_log_events",
        "top_blocked",
        "lists",
    ] {
        assert!(v.get(k).is_some(), "stats missing {k}");
    }
    assert_eq!(s.take_window(60, 0, lists).requests, 0, "window resets");

    let dir = tempfile::tempdir().unwrap();
    let log = EventLogger::start(&cfg(dir.path(), 1 << 20, 10)).unwrap();
    log.log_stats(&w);
    log.shutdown(Duration::from_secs(5));
    assert_eq!(lines(&dir.path().join(STATS_FILE))[0]["event_type"], "stats");
}
