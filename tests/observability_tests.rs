//! Phase 5: E-25 (rotation under concurrent writers), system events, PT-5.1 (log injection end to
//! end) and PT-5.4 (world-writable policy files) as regression tests.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use common::{ProxyHarness, TestResolver, base_config};
use serde_json::Value;
use webfilter::config::LoggingConfig;
use webfilter::logger::{EventLogger, REQUEST_FILE, RequestEvent};

#[test]
fn e25_rotation_with_16_concurrent_writers_loses_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let max_bytes = 8192;
    let cfg = LoggingConfig {
        dir: dir.path().to_path_buf(),
        max_bytes,
        backup_count: 1000,
        queue_capacity: 100_000,
    };
    let log = Arc::new(EventLogger::start(&cfg).unwrap());
    let threads: Vec<_> = (0..16)
        .map(|t| {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                for i in 0..200 {
                    log.log(RequestEvent {
                        uri_path: format!("/{t}/{i}"),
                        ..RequestEvent::default()
                    });
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(log.dropped(), 0);
    log.shutdown(Duration::from_secs(10));

    let mut seen = HashSet::new();
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.starts_with(REQUEST_FILE) {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.len() as u64 <= max_bytes, "{name} exceeds max_bytes");
        assert!(text.is_empty() || text.ends_with('\n'), "{name} ends with a partial line");
        for line in text.lines() {
            let v: Value = serde_json::from_str(line).expect("every line is complete JSON");
            assert!(seen.insert(v["uri_path"].as_str().unwrap().to_owned()), "duplicate line");
        }
    }
    assert_eq!(seen.len(), 16 * 200, "lost lines");
}

#[tokio::test]
async fn start_logs_config_loaded_with_source() {
    let mut h = ProxyHarness::start(&base_config(""), &[], TestResolver::with(&[])).await;
    h.stop().await;
    let sys = h.system_lines();
    let loaded = sys.iter().find(|v| v["kind"] == "config_loaded").expect("config_loaded");
    assert!(loaded["detail"]["source"].as_str().unwrap().ends_with("config.toml"));
    assert!(sys.iter().all(|v| v["kind"] != "insecure_permissions"));
}

#[cfg(unix)]
#[tokio::test]
async fn pt_5_4_world_writable_policy_file_is_reported() {
    use std::os::unix::fs::PermissionsExt;
    let lab = common::Lab::new();
    let list = lab.path().join("blocklists/domains.txt");
    std::fs::set_permissions(&list, std::fs::Permissions::from_mode(0o666)).unwrap();
    let path = lab.write_config(&base_config(""));
    let cfg = webfilter::config::Config::load(&path).unwrap();
    let handle = webfilter::proxy::start(cfg, None).await.unwrap();
    handle.shutdown().await;
    let text = std::fs::read_to_string(lab.path().join("logs/webfilter_system.jsonl")).unwrap();
    let ev: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let warn = ev.iter().find(|v| v["kind"] == "insecure_permissions").expect("warning event");
    let files = warn["detail"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert!(files[0].as_str().unwrap().ends_with("domains.txt"));
}

#[tokio::test]
async fn pt_5_1_injection_fragments_stay_one_event_each() {
    let mut h = ProxyHarness::start(
        &base_config(""),
        &[("domains.txt", "blocked.test\n")],
        TestResolver::with(&[]),
    )
    .await;
    let requests = [
        "GET http://blocked.test/a%0d%0a%7B%22event_type%22:%22system%22%7D HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n",
        "GET http://blocked.test/%1b[31mred%1b[0m HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n",
        "GET http://blocked.test/q?%22%7D%7B=1&%7Cdelete=2&index%3D*=3 HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n",
        "GET http://blocked.test/ua HTTP/1.1\r\nHost: blocked.test\r\nUser-Agent: x\" | delete index=* | outputlookup evil \u{202e}\r\nConnection: close\r\n\r\n",
    ];
    for r in requests {
        let resp = h.raw(r.as_bytes(), Duration::from_secs(5)).await;
        assert_eq!(common::status(&resp), 403, "{r}");
    }
    h.stop().await;
    let lines = h.log_lines();
    assert_eq!(lines.len(), requests.len(), "exactly one event per request");
    for v in &lines {
        assert_eq!(v["event_type"], "request");
        assert_eq!(v["action"], "blocked");
        for (k, field) in v.as_object().unwrap() {
            if let Some(s) = field.as_str() {
                assert!(
                    !s.chars().any(|c| c.is_control() || c == '\u{202e}'),
                    "{k} keeps a control/bidi char: {s:?}"
                );
            }
        }
    }
    assert!(
        lines[3]["user_agent"].as_str().unwrap().contains("| delete index=*"),
        "data kept as text"
    );
}
