//! Phase 13: feature interactions (E-83, PT-13.2) and the v1.0 -> v1.1 upgrade path (PT-13.3).
//! Temp allows (access requests) never override feeds, scanning or the destination policy;
//! profiles, limits, feeds and scanning compose; h2 streams are limited like HTTP/1 requests
//! (see `h2_tests::e83_h2_streams_share_profile_limits`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{
    ADMIN_TOKEN, Origin, ProxyHarness, Reply, TestResolver, admin_token_hash, eicar, fake_clamd,
    raw_exchange, reason, status,
};
use serde_json::Value;
use webfilter::config::FeedFormat;
use webfilter::feeds::{Store, parse_feed};

const W: Duration = Duration::from_secs(10);

/// Admin + access requests + feed `bad` (feed.test) + scan (block) + local list (blocked.test),
/// all on for the default profile. `deny_private` turns on the destination policy.
async fn everything(deny_private: bool, profile_extra: &str) -> (ProxyHarness, SocketAddr) {
    let feeds = tempfile::tempdir().unwrap().keep();
    let (entries, _) = parse_feed(
        FeedFormat::DomainsText,
        "feed.test\nfiller1.example\nfiller2.example\n",
        &[],
        100,
    )
    .unwrap();
    Store::new(&feeds, "bad").promote(&entries).unwrap();
    let clamd = fake_clamd().await;
    let config = format!(
        r#"listen = "127.0.0.1:0"
[ports]
http_allowed = "any"
connect_allowed = "any"
[destination]
deny_private_ranges = {deny_private}
[logging]
dir = "logs"
[rules]
blocked_extensions = []
[admin]
enabled = true
listen = "127.0.0.1:0"
token_hash = "{hash}"
[access_requests]
enabled = true
[state]
dir = "state"
[[feeds]]
name = "bad"
enabled = true
url = "https://feeds.invalid/list"
format = "domains_text"
[feeds_global]
dir = "{feeds}"
[scan]
enabled = true
mode = "block"
temp_dir = "scan_tmp"
[scan.clamd]
address = "tcp:127.0.0.1:{clamd}"
[[profiles]]
name = "default"
feeds = ["bad"]
scan_downloads = true
access_requests = true
{profile_extra}
"#,
        hash = admin_token_hash(),
        feeds = feeds.display(),
    );
    let resolver = TestResolver::with(&[
        ("feed.test", "127.0.0.1"),
        ("blocked.test", "127.0.0.1"),
        ("ok.test", "127.0.0.1"),
    ]);
    let h = ProxyHarness::start(&config, &[("domains.txt", "blocked.test\nfeed.test\n")], resolver)
        .await;
    let admin = h.handle.as_ref().unwrap().admin_addr.unwrap();
    (h, admin)
}

async fn allow(admin: SocketAddr, host: &str) {
    let body =
        format!(r#"{{"host":"{host}","scope":"profile","target":"default","ttl_secs":600}}"#);
    let req = format!(
        "POST /api/v1/temp-allows HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {ADMIN_TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        admin.port(),
        body.len()
    );
    let r = raw_exchange(admin, req.as_bytes(), W).await;
    assert_eq!(status(&r), 201, "{r}");
}

fn origin_files() -> impl Fn(&[u8]) -> Reply + Send + Sync + 'static {
    |req| {
        let path = String::from_utf8_lossy(req).split(' ').nth(1).unwrap_or("").to_owned();
        let body =
            if path.ends_with("eicar.exe") { eicar() } else { b"<html>fine</html>".to_vec() };
        let mut out = format!("HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\n\r\n", body.len()).into_bytes();
        out.extend_from_slice(&body);
        Reply::raw(out)
    }
}

#[tokio::test]
async fn ix_temp_allow_overrides_local_lists_but_never_feeds_or_scans() {
    let origin = Origin::start(origin_files()).await;
    let port = origin.addr.port();
    let (mut h, admin) = everything(false, "").await;
    // Before: local list and feed both block.
    assert_eq!(reason(&h.get("blocked.test", port, "/").await), "domain_blocklist");
    assert_eq!(reason(&h.get("feed.test", port, "/").await), "feed_domain");
    allow(admin, "blocked.test").await;
    allow(admin, "feed.test").await;
    // IX-01: the temp allow lifts the local list block...
    assert_eq!(status(&h.get("blocked.test", port, "/page").await), 200);
    // IX-02: ...but a feed hit on the same host (also on the local list) still blocks.
    let r = h.get("feed.test", port, "/").await;
    assert_eq!((status(&r), reason(&r)), (403, "feed_domain".to_owned()), "{r}");
    // IX-03: a download through a temp-allowed host is still scanned and blocked.
    let r = h.get("blocked.test", port, "/eicar.exe").await;
    assert_eq!(status(&r), 403, "{r}");
    assert_eq!(reason(&r), "malware_detected");
    // A clean file through the same allow is delivered.
    assert_eq!(status(&h.get("blocked.test", port, "/clean.exe").await), 200);
    h.stop().await;
    let lines = h.log_lines();
    let feed_hit = lines.iter().rfind(|l| l["dest_host"] == "feed.test").unwrap();
    assert_eq!(feed_hit["rule_list"], "bad", "logged as the feed, not the temp allow");
    let allowed =
        lines.iter().find(|l| l["url"].as_str().is_some_and(|u| u.ends_with("/page"))).unwrap();
    assert!(allowed["rule_id"].as_str().unwrap().starts_with("temp_allow:"), "{allowed}");
}

#[tokio::test]
async fn ix_temp_allow_never_overrides_the_destination_policy() {
    let origin = Origin::start(origin_files()).await;
    let (mut h, admin) = everything(true, "").await;
    allow(admin, "blocked.test").await;
    let r = h.get("blocked.test", origin.addr.port(), "/").await;
    assert_eq!(status(&r), 403, "{r}");
    assert_ne!(reason(&r), "allowlist");
    assert!(origin.requests().is_empty(), "loopback origin never contacted");
    h.stop().await;
}

#[tokio::test]
async fn ix_rate_limits_apply_to_block_pages_vhost_and_allowed_traffic_alike() {
    let origin = Origin::start(origin_files()).await;
    let port = origin.addr.port();
    let (mut h, _) = everything(false, "[profiles.rate]\nrequests_per_sec = 1\nburst = 3\n").await;
    let vhost = b"GET http://webfilter.local/ HTTP/1.1\r\nHost: webfilter.local\r\nConnection: close\r\n\r\n";
    let statuses = [
        status(&h.get("ok.test", port, "/").await),
        status(&h.get("blocked.test", port, "/").await),
        status(&h.raw(vhost, W).await),
        status(&h.get("ok.test", port, "/").await),
    ];
    assert_eq!(
        &statuses[..3],
        &[200, 403, 200],
        "burst of 3 covers allowed, blocked and vhost requests"
    );
    assert_eq!(statuses[3], 429, "the next request of any kind is limited");
    h.stop().await;
}

/// PT-13.3: a v1.0 configuration (no v1.1 sections) loads unchanged and every v1.1 feature is off.
#[tokio::test]
async fn upgrade_v1_0_config_loads_with_v1_1_features_off() {
    let v10 = std::fs::read_to_string("config/config.example.toml").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, &v10).unwrap();
    std::fs::create_dir(dir.path().join("blocklists")).unwrap();
    for f in ["domains.txt", "url_patterns.txt", "ip_blocklist.txt"] {
        std::fs::write(dir.path().join("blocklists").join(f), "").unwrap();
    }
    let cfg = webfilter::config::Config::load(&path).unwrap();
    assert!(
        !cfg.admin.enabled && !cfg.access_requests.enabled && !cfg.scan.enabled,
        "v1.1 features off by default"
    );
    assert!(cfg.feeds.iter().all(|f| !f.enabled));
    assert!(cfg.users.is_empty() && cfg.clients.is_empty());
    // The v1.0 demo config (local origins) runs as before.
    let origin = Origin::start(|_| Reply::ok("v1.0")).await;
    let demo = std::fs::read_to_string("config/demo.toml").unwrap();
    let demo = regex_lite_listen(&demo);
    let lists = [("domains.txt", ""), ("url_patterns.txt", ""), ("ip_blocklist.txt", "")];
    let mut h =
        ProxyHarness::start(&demo, &lists, TestResolver::with(&[("ok.test", "127.0.0.1")])).await;
    let r = h.get("ok.test", origin.addr.port(), "/").await;
    assert_eq!(status(&r), 200, "{r}");
    assert!(h.handle.as_ref().unwrap().admin_addr.is_none(), "no admin listener");
    h.stop().await;
    let v: &Value = &h.log_lines()[0];
    assert_eq!(v["action"], "allowed");
}

/// Point the demo config at an ephemeral port and the lab's log dir.
fn regex_lite_listen(cfg: &str) -> String {
    cfg.lines()
        .map(|l| {
            if l.starts_with("listen") {
                "listen = \"127.0.0.1:0\"".to_owned()
            } else if l.trim_start().starts_with("dir") && l.contains("log") {
                "dir = \"logs\"".to_owned()
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
