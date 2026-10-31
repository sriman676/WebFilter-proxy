//! Phase 2 pentest cases as regression tests: PT-2.2, 2.6, 2.8, 2.11, 2.13, 2.15, 2.18 and the
//! binary-level E-23, E-24, E-36.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::time::Duration;

use common::{Origin, ProxyHarness, Reply, TestResolver, base_config, raw_exchange, status};
use tokio::io::AsyncWriteExt;

const W: Duration = Duration::from_secs(3);

fn strict() -> String {
    base_config("").replace("deny_private_ranges = false", "deny_private_ranges = true")
}

#[tokio::test]
async fn pt_2_6_ssrf_targets_denied() {
    let r = TestResolver::with(&[
        ("localhost", "127.0.0.1"),
        ("internal.test", "10.1.2.3"),
        ("v6.test", "::1"),
    ]);
    let mut p = ProxyHarness::start(&strict(), &[], r).await;
    for (target, want) in [
        ("http://127.0.0.1/", 403),
        ("http://[::1]/", 403),
        ("http://0.0.0.0/", 403),
        ("http://169.254.169.254/latest/meta-data/", 403),
        ("http://10.0.0.1/", 403),
        ("http://192.168.1.1/", 403),
        ("http://172.16.0.1/", 403),
        ("http://[::ffff:127.0.0.1]/", 403),
        ("http://[64:ff9b::a00:1]/", 403),
        ("http://localhost/", 403),
        ("http://internal.test/", 403),
        ("http://v6.test/", 403),
        ("http://2130706433/", 400),
        ("http://0x7f.0.0.1/", 400),
        ("http://0177.0.0.1/", 400),
        ("http://127.1/", 400),
    ] {
        let resp = p.raw(format!("GET {target} HTTP/1.1\r\n\r\n").as_bytes(), W).await;
        assert_eq!(status(&resp), want, "{target}: {resp}");
    }
    p.stop().await;
}

#[tokio::test]
async fn pt_2_6_redirects_to_internal_are_not_followed() {
    let origin = Origin::start(|_| {
        Reply::raw(
            "HTTP/1.1 302 Found\r\nlocation: http://169.254.169.254/\r\ncontent-length: 0\r\n\r\n",
        )
    })
    .await;
    let mut p = ProxyHarness::start(
        &base_config(""),
        &[],
        TestResolver::with(&[("good.test", "127.0.0.1")]),
    )
    .await;
    let resp = p
        .raw(format!("GET http://good.test:{}/ HTTP/1.1\r\n\r\n", origin.addr.port()).as_bytes(), W)
        .await;
    assert_eq!(status(&resp), 302, "the redirect is passed to the client, never followed");
    p.stop().await;
    assert_eq!(p.log_lines().len(), 1);
}

#[tokio::test]
async fn pt_2_8_e20_connect_and_port_abuse() {
    let r = TestResolver::with(&[("good.test", "127.0.0.1")]);
    let cfg = base_config("").replace("http_allowed = \"any\"\nconnect_allowed = \"any\"\n", "");
    let mut p = ProxyHarness::start(&cfg, &[], r).await;
    for port in [22, 25, 3306, 6379] {
        let resp = p.raw(format!("CONNECT good.test:{port} HTTP/1.1\r\n\r\n").as_bytes(), W).await;
        assert_eq!(status(&resp), 403, "CONNECT :{port}");
        assert!(resp.contains("port_not_allowed"));
        let resp = p
            .raw(format!("GET http://good.test:{port}/ HTTP/1.1\r\n\r\nSET x y\r\n").as_bytes(), W)
            .await;
        assert_eq!(status(&resp), 403, "GET :{port}");
    }
    for bad in ["good.test:0", "good.test:65536"] {
        assert_eq!(
            status(&p.raw(format!("CONNECT {bad} HTTP/1.1\r\n\r\n").as_bytes(), W).await),
            400,
            "{bad}"
        );
    }
    assert_eq!(p.resolver.count(), 0, "no lookups for disallowed ports");
    p.stop().await;
}

#[tokio::test]
async fn pt_2_2_no_shared_upstream_between_clients() {
    let origin = Origin::start(|req| {
        let who =
            if String::from_utf8_lossy(req).contains("/victim") { "victim" } else { "attacker" };
        Reply::ok(who)
    })
    .await;
    let mut p = ProxyHarness::start(
        &base_config(""),
        &[],
        TestResolver::with(&[("good.test", "127.0.0.1")]),
    )
    .await;
    let port = origin.addr.port();
    let attack = format!(
        "POST http://good.test:{port}/a HTTP/1.1\r\nContent-Length: 44\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /victim HTTP/1.1\r\nHost: good.test\r\n\r\n"
    );
    let victim =
        format!("GET http://good.test:{port}/victim HTTP/1.1\r\nConnection: close\r\n\r\n");
    let (a, v) = tokio::join!(p.raw(attack.as_bytes(), W), p.raw(victim.as_bytes(), W));
    assert_eq!(status(&a), 400, "ambiguous request rejected");
    assert!(v.ends_with("victim"), "victim gets its own response: {v}");
    assert_eq!(origin.requests().len(), 1, "only the victim's request reached the origin");
    p.stop().await;
}

#[tokio::test]
async fn pt_2_11_slowloris_closed_others_served() {
    let origin = Origin::start(|_| Reply::ok("ok")).await;
    let cfg = base_config("[timeouts]\nclient_head_read = 1\n");
    let mut p =
        ProxyHarness::start(&cfg, &[], TestResolver::with(&[("good.test", "127.0.0.1")])).await;
    let addr = p.addr;
    let slow = tokio::spawn(async move {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let start = std::time::Instant::now();
        for b in b"GET http://good.test/ HTTP/1.1\r\nX-Slow: ".iter() {
            if s.write_all(&[*b]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        start.elapsed()
    });
    let resp = raw_exchange(
        addr,
        format!(
            "GET http://good.test:{}/ HTTP/1.1\r\nConnection: close\r\n\r\n",
            origin.addr.port()
        )
        .as_bytes(),
        W,
    )
    .await;
    assert_eq!(status(&resp), 200, "other clients served during the attack");
    let elapsed = slow.await.unwrap();
    assert!(
        elapsed < Duration::from_secs(4),
        "slow client cut off by the head timeout ({elapsed:?})"
    );
    p.stop().await;
}

#[tokio::test]
async fn pt_2_13_block_page_xss_truncation_and_headers() {
    let mut p = ProxyHarness::start(
        &base_config(""),
        &[("url_patterns.txt", "blockme\n")],
        TestResolver::with(&[]),
    )
    .await;
    // Just under the 8 KiB URI limit (larger targets get 414 before any page is rendered).
    let nasty = format!("/blockme/%22onload=alert(1)%3E%3Cscript%3E{}", "x".repeat(7_000));
    let resp = p.raw(format!("GET http://good.test{nasty} HTTP/1.1\r\n\r\n").as_bytes(), W).await;
    assert_eq!(status(&resp), 403);
    let lower = resp.to_ascii_lowercase();
    assert!(!lower.contains("<script") && !lower.contains("\"onload"), "escaped");
    assert!(
        lower.contains("content-security-policy")
            && lower.contains("x-content-type-options: nosniff")
    );
    assert!(resp.len() < 6_000, "reflected values truncated ({} bytes)", resp.len());
    p.stop().await;
}

#[tokio::test]
async fn pt_2_15_e23_requests_to_the_proxy_itself_are_loops() {
    let r = TestResolver::with(&[]);
    let mut p = ProxyHarness::start(&base_config(""), &[], r).await;
    let port = p.addr.port();
    p.resolver.script("self.test", vec![vec!["127.0.0.1".parse().unwrap()]]);
    for target in [format!("http://127.0.0.1:{port}/"), format!("http://self.test:{port}/")] {
        let resp = p.raw(format!("GET {target} HTTP/1.1\r\n\r\n").as_bytes(), W).await;
        assert_eq!(status(&resp), 508, "{target}: {resp}");
    }
    let resp = p.raw(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n").as_bytes(), W).await;
    assert_eq!(status(&resp), 508);
    p.stop().await;
    assert_eq!(p.log_lines().len(), 3, "no recursion: exactly one log line per request");
}

#[tokio::test]
async fn pt_2_18_error_pages_leak_nothing() {
    let mut p = ProxyHarness::start(&base_config(""), &[], TestResolver::with(&[])).await;
    for req in [
        "GARBAGE\r\n\r\n",
        "GET http://nx.test/ HTTP/1.1\r\n\r\n",
        "GET http://good.test/ HTTP/1.2\r\n\r\n",
    ] {
        let resp = p.raw(req.as_bytes(), W).await.to_ascii_lowercase();
        for leak in [
            "webfilter-proxy",
            env!("CARGO_PKG_VERSION"),
            "/mnt/",
            "/home/",
            "panicked",
            "rust",
            "tokio",
            "127.0.0.1",
        ] {
            assert!(!resp.contains(&leak.to_ascii_lowercase()), "{leak} leaked in {resp}");
        }
        assert!(resp.contains("x-webfilter-event-id"));
    }
    p.stop().await;
}

/// E-36 / PT-2.9: the binary refuses a non-loopback bind without auth (exit 2).
#[test]
fn e36_non_loopback_without_auth_refuses_to_start() {
    let lab = common::Lab::new();
    let cfg = lab.write_config("listen = \"0.0.0.0:0\"\n");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_webfilter-proxy"))
        .arg("--config")
        .arg(&cfg)
        .arg("run")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("proxy_auth"));
}

/// E-24: SIGTERM mid-transfer: the in-flight request completes, logs are flushed, exit 0.
#[cfg(unix)]
#[tokio::test]
async fn e24_sigterm_drains_in_flight_and_exits_zero() {
    let origin =
        Origin::start(|_| Reply { delay: Duration::from_millis(800), ..Reply::ok("drained") })
            .await;
    let lab = common::Lab::new();
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let cfg = lab.write_config(&base_config("").replace("127.0.0.1:0", &free.to_string()));
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_webfilter-proxy"))
        .arg("--config")
        .arg(&cfg)
        .arg("run")
        .spawn()
        .unwrap();
    let mut up = false;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(free).await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(up, "proxy started");
    let req = format!(
        "GET http://127.0.0.1:{}/ HTTP/1.1\r\nConnection: close\r\n\r\n",
        origin.addr.port()
    );
    let inflight =
        tokio::spawn(
            async move { raw_exchange(free, req.as_bytes(), Duration::from_secs(5)).await },
        );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let pid = child.id().unwrap().to_string();
    assert!(std::process::Command::new("kill").args(["-TERM", &pid]).status().unwrap().success());
    let resp = inflight.await.unwrap();
    assert!(resp.ends_with("drained"), "{resp}");
    let code = tokio::time::timeout(Duration::from_secs(12), child.wait()).await.unwrap().unwrap();
    assert!(code.success(), "exit 0");
    let log = std::fs::read_to_string(lab.path().join("logs/webfilter.jsonl")).unwrap();
    assert!(log.contains("\"status\":200"), "request logged and flushed");
}
