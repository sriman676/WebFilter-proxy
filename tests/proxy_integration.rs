//! Phase 2 integration tests through the real listener: I-01..I-19, smuggling corpus over raw TCP
//! (I-20..I-28 / SM-xx), and E-tests for 2b (E-04,05,07..11,15,16,21,22,31..33,52).
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

const W: Duration = Duration::from_secs(3);

fn resolver() -> std::sync::Arc<TestResolver> {
    TestResolver::with(&[
        ("good.test", "127.0.0.1"),
        ("evil.com", "127.0.0.1"),
        ("sub.evil.com", "127.0.0.1"),
        ("notevil.com", "127.0.0.1"),
    ])
}

async fn proxy(extra: &str, lists: &[(&str, &str)]) -> ProxyHarness {
    ProxyHarness::start(&base_config(extra), lists, resolver()).await
}

fn get(host: &str, port: u16, path: &str) -> Vec<u8> {
    format!("GET http://{host}:{port}{path} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: it\r\nConnection: close\r\n\r\n").into_bytes()
}

#[tokio::test]
async fn i01_allowed_get_is_rebuilt_from_normalized_target() {
    let origin = Origin::start(|_| Reply::ok("hello")).await;
    let mut p = proxy("", &[]).await;
    let port = origin.addr.port();
    let req = format!(
        "GET http://GOOD.test:{port}/a/../b/%7e?q=1 HTTP/1.1\r\nHost: good.test:{port}\r\nX-Custom: yes\r\n\r\n"
    );
    let resp = p.raw(req.as_bytes(), W).await;
    assert_eq!(status(&resp), 200, "{resp}");
    assert!(resp.ends_with("hello"));
    let seen = origin.requests();
    assert_eq!(seen.len(), 1);
    assert!(
        seen[0].starts_with("GET /b/~?q=1 HTTP/1.1\r\nhost: good.test:"),
        "origin-form rebuilt: {:?}",
        seen[0]
    );
    assert!(seen[0].contains("connection: close") && seen[0].contains("x-custom: yes"));
    p.stop().await;
    let log = &p.log_lines()[0];
    assert_eq!((log["action"].as_str(), log["status"].as_u64()), (Some("allowed"), Some(200)));
    assert_eq!(log["uri_query_keys"][0], "q");
    assert!(!log["url"].as_str().unwrap().contains("q=1"), "query values never logged");
}

#[tokio::test]
async fn i02_e04_e52_blocked_domain_never_resolved_or_contacted() {
    let origin = Origin::start(|_| Reply::ok("secret")).await;
    let mut p = proxy("", &[("domains.txt", "evil.com\n")]).await;
    let resp = p.raw(&get("evil.com", origin.addr.port(), "/"), W).await;
    assert_eq!(status(&resp), 403);
    let head = resp.to_ascii_lowercase();
    for h in [
        "x-webfilter-action: blocked",
        "x-webfilter-reason: domain_blocklist",
        "x-webfilter-event-id: ",
        "cache-control: no-store",
        "x-content-type-options: nosniff",
        "content-security-policy: default-src 'none'",
        "connection: close",
    ] {
        assert!(head.contains(h), "missing {h}: {resp}");
    }
    assert!(origin.requests().is_empty(), "origin saw nothing");
    assert_eq!(p.resolver.count(), 0, "no DNS query for a blocked name (E-52)");
    p.stop().await;
    let log = &p.log_lines()[0];
    assert_eq!(
        (log["action"].as_str(), log["reason"].as_str(), log["rule_id"].as_str()),
        (Some("blocked"), Some("domain_blocklist"), Some("domain:evil.com"))
    );
    let event_id = log["event_id"].as_str().unwrap();
    assert!(resp.contains(event_id), "same event id on the page/header and in the log");
}

#[tokio::test]
async fn e05_subdomain_blocked_notevil_allowed() {
    let origin = Origin::start(|_| Reply::ok("ok")).await;
    let mut p = proxy("", &[("domains.txt", "evil.com\n")]).await;
    let port = origin.addr.port();
    assert_eq!(status(&p.raw(&get("sub.evil.com", port, "/"), W).await), 403);
    assert_eq!(status(&p.raw(&get("notevil.com", port, "/"), W).await), 200);
    p.stop().await;
}

#[tokio::test]
async fn i03_e31_bodies_preserved_chunked_and_content_length() {
    let origin = Origin::start(|_| Reply::ok("done")).await;
    let mut p = proxy("", &[]).await;
    let port = origin.addr.port();
    let cl = format!(
        "POST http://good.test:{port}/up HTTP/1.1\r\nHost: good.test:{port}\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world"
    );
    assert_eq!(status(&p.raw(cl.as_bytes(), W).await), 200);
    // 5 MB chunked body in odd chunk sizes; the proxy re-encodes chunks (R15).
    let body: Vec<u8> = (0..5_000_000u32).map(|i| (i % 251) as u8).collect();
    let mut req = format!("POST http://good.test:{port}/big HTTP/1.1\r\nHost: good.test:{port}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").into_bytes();
    for part in body.chunks(70_001) {
        req.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
        req.extend_from_slice(part);
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"0\r\n\r\n");
    assert_eq!(status(&raw_exchange(p.addr, &req, Duration::from_secs(20)).await), 200);
    let seen = origin.seen.lock().unwrap().clone();
    assert!(String::from_utf8_lossy(&seen[0]).ends_with("hello world"));
    let big = &seen[1];
    let head_end = big.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let mut decoder = webfilter::proxy::http1::ChunkedDecoder::default();
    let mut decoded = Vec::new();
    decoder.feed(&big[head_end..], &mut decoded).unwrap();
    assert!(decoder.is_done());
    assert_eq!(decoded, body, "origin receives identical bytes");
    p.stop().await;
}

#[tokio::test]
async fn i04_e32_head_204_304_no_body_no_hang() {
    let origin = Origin::start(|req| {
        let r = String::from_utf8_lossy(req);
        if r.starts_with("HEAD") {
            Reply::raw("HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n")
        } else if r.contains("/204") {
            Reply::raw("HTTP/1.1 204 No Content\r\ncontent-length: 5\r\n\r\n")
        } else {
            Reply::raw("HTTP/1.1 304 Not Modified\r\netag: x\r\n\r\n")
        }
    })
    .await;
    let mut p = proxy("", &[]).await;
    let port = origin.addr.port();
    let head = format!(
        "HEAD http://good.test:{port}/ HTTP/1.1\r\nHost: good.test:{port}\r\nConnection: close\r\n\r\n"
    );
    let start = std::time::Instant::now();
    for req in [head.into_bytes(), get("good.test", port, "/204"), get("good.test", port, "/304")] {
        let resp = p.raw(&req, W).await;
        assert!(matches!(status(&resp), 200 | 204 | 304), "{resp}");
        assert!(resp.ends_with("\r\n\r\n"), "no body forwarded: {resp:?}");
    }
    assert!(start.elapsed() < Duration::from_secs(2), "no hang waiting for a body");
    p.stop().await;
}

#[tokio::test]
async fn i05_e32_expect_100_continue_relayed_not_synthesized() {
    let origin = Origin::start(|req| Reply {
        interim: Some(b"HTTP/1.1 100 Continue\r\n\r\n".to_vec()),
        ..Reply::ok(&format!("got {}", req.len()))
    })
    .await;
    let mut p = proxy("", &[]).await;
    let port = origin.addr.port();
    let req = format!(
        "PUT http://good.test:{port}/x HTTP/1.1\r\nHost: good.test:{port}\r\nExpect: 100-continue\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody"
    );
    let resp = p.raw(req.as_bytes(), W).await;
    assert!(resp.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200"), "{resp}");
    assert_eq!(origin.requests().len(), 1, "exactly one request at the origin (SM-19)");
    p.stop().await;
}

#[tokio::test]
async fn i06_i07_hop_by_hop_and_proxy_headers_stripped_both_ways() {
    let origin = Origin::start(|_| {
        Reply::raw("HTTP/1.1 200 OK\r\nconnection: x-secret\r\nx-secret: 1\r\nkeep-alive: 5\r\nproxy-authenticate: Basic\r\nx-ok: 1\r\ncontent-length: 0\r\n\r\n")
    })
    .await;
    let mut p = proxy("", &[]).await;
    let port = origin.addr.port();
    let req = format!(
        "GET http://good.test:{port}/ HTTP/1.1\r\nHost: good.test:{port}\r\nConnection: close, X-Hop\r\nX-Hop: 1\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\nProxy-Connection: keep-alive\r\nX-Forwarded-For: 6.6.6.6\r\n\r\n"
    );
    let resp = p.raw(req.as_bytes(), W).await.to_ascii_lowercase();
    let seen = origin.requests()[0].to_ascii_lowercase();
    for gone in ["x-hop", "proxy-authorization", "proxy-connection", "via:"] {
        assert!(!seen.contains(gone), "{gone} forwarded upstream: {seen}");
    }
    assert!(
        seen.contains("x-forwarded-for: 6.6.6.6"),
        "client XFF passes through untouched; we never add our own (D-32)"
    );
    for gone in ["x-secret", "keep-alive", "proxy-authenticate"] {
        assert!(!resp.contains(gone), "{gone} forwarded to client: {resp}");
    }
    assert!(resp.contains("x-ok: 1"));
    p.stop().await;
}

#[tokio::test]
async fn i08_e16_origin_down_502() {
    let mut p = proxy("", &[]).await;
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port(); // closed after drop
    let resp = p.raw(&get("good.test", dead, "/"), W).await;
    assert_eq!(status(&resp), 502, "{resp}");
    assert!(resp.contains("x-webfilter-reason: upstream_error"));
    p.stop().await;
}

#[tokio::test]
async fn i09_e15_slow_origin_504() {
    let origin =
        Origin::start(|_| Reply { delay: Duration::from_secs(3), ..Reply::ok("late") }).await;
    let mut p = proxy("[timeouts]\nupstream_response_header = 1\n", &[]).await;
    let resp = p.raw(&get("good.test", origin.addr.port(), "/"), Duration::from_secs(5)).await;
    assert_eq!(status(&resp), 504, "{resp}");
    assert!(resp.contains("x-webfilter-reason: timeout"));
    p.stop().await;
}

#[tokio::test]
async fn i10_over_connection_limit_503() {
    let mut p = proxy("[limits]\nmax_connections_per_ip = 1\n", &[]).await;
    let _held = tokio::net::TcpStream::connect(p.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let resp = p.raw(b"GET http://good.test/ HTTP/1.1\r\n\r\n", W).await;
    assert_eq!(status(&resp), 503, "{resp}");
    assert!(resp.to_ascii_lowercase().contains("retry-after: 5"));
    drop(_held);
    p.stop().await;
}

#[tokio::test]
async fn i11_block_page_escapes_reflected_values_and_custom_template() {
    let template_dir = tempfile::tempdir().unwrap();
    let template = template_dir.path().join("page.html");
    std::fs::write(&template, "<h1>ACME blocked {host}</h1><p>{url} {reason} {rule_id} {event_id} {category} {unknown} {</p>").unwrap();
    let mut p = proxy(
        &format!("[block_page]\ntemplate = \"{}\"\n", template.display()),
        &[("url_patterns.txt", "evil\n")],
    )
    .await;
    let resp = p.raw(b"GET http://good.test/%3Cscript%3Ealert(1)%3C/script%3Eevil HTTP/1.1\r\nHost: good.test\r\n\r\n", W).await;
    assert_eq!(status(&resp), 403, "{resp}");
    assert!(resp.contains("<h1>ACME blocked good.test</h1>"));
    assert!(!resp.contains("<script>"), "reflected value escaped: {resp}");
    assert!(
        resp.contains("{unknown}") && resp.contains("{</p>"),
        "unknown placeholders left as text"
    );
    p.stop().await;
}

#[tokio::test]
async fn i12_e09_monitor_mode_forwards_and_logs_would_block() {
    let origin = Origin::start(|_| Reply::ok("page")).await;
    let mut p = proxy("mode = \"monitor\"\n", &[("domains.txt", "evil.com\n")]).await;
    let resp = p.raw(&get("evil.com", origin.addr.port(), "/"), W).await;
    assert_eq!(status(&resp), 200);
    p.stop().await;
    let log = &p.log_lines()[0];
    assert_eq!(
        (log["action"].as_str(), log["would_block"].as_bool(), log["proxy_mode"].as_str()),
        (Some("allowed"), Some(true), Some("monitor"))
    );
}

#[tokio::test]
async fn i13_e10_allowlist_beats_blocklist() {
    let origin = Origin::start(|_| Reply::ok("ok")).await;
    let mut p =
        proxy("[rules]\nallow_domains = [\"evil.com\"]\n", &[("domains.txt", "evil.com\n")]).await;
    assert_eq!(status(&p.raw(&get("sub.evil.com", origin.addr.port(), "/"), W).await), 200);
    p.stop().await;
    assert_eq!(p.log_lines()[0]["reason"], "allowlist");
}

#[tokio::test]
async fn i14_e11_hot_reload_add_and_invalid_keeps_old() {
    let origin = Origin::start(|_| Reply::ok("ok")).await;
    let mut p = proxy("[blocklists]\nreload_interval_secs = 1\n", &[]).await;
    let port = origin.addr.port();
    assert_eq!(status(&p.raw(&get("good.test", port, "/"), W).await), 200);
    p.lab.write_list("domains.txt", "good.test\n");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        status(&p.raw(&get("good.test", port, "/"), W).await),
        403,
        "enforced within the interval"
    );
    p.lab.write_list("domains.txt", "bad1\nbad2\nbad3 x\n");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        status(&p.raw(&get("good.test", port, "/"), W).await),
        403,
        "invalid file keeps the old list"
    );
    p.stop().await;
    assert!(p.system_lines().iter().any(|v| v["kind"] == "blocklist_reload_failed"));
}

#[tokio::test]
async fn e07_extension_rule() {
    let origin = Origin::start(|_| Reply::ok("ok")).await;
    let mut p = proxy("", &[]).await;
    let port = origin.addr.port();
    assert_eq!(status(&p.raw(&get("good.test", port, "/setup.EXE"), W).await), 403);
    assert_eq!(status(&p.raw(&get("good.test", port, "/index.html"), W).await), 200);
    p.stop().await;
}

#[tokio::test]
async fn e08_content_type_rule_never_forwards_body() {
    let origin = Origin::start(|_| Reply::raw("HTTP/1.1 200 OK\r\ncontent-type: application/x-msdownload\r\ncontent-length: 7\r\n\r\nMZ-EVIL")).await;
    let mut p = proxy("", &[]).await;
    let resp = p.raw(&get("good.test", origin.addr.port(), "/download"), W).await;
    assert_eq!(status(&resp), 403);
    assert!(!resp.contains("MZ-EVIL"), "body never reaches the client");
    p.stop().await;
    assert_eq!(p.log_lines()[0]["rule_id"], "ctype:application/x-msdownload");
}

#[tokio::test]
async fn e21_private_and_metadata_destinations() {
    let mut p = ProxyHarness::start(
        &base_config("").replace("deny_private_ranges = false", "deny_private_ranges = true"),
        &[],
        resolver(),
    )
    .await;
    let resp = p.raw(&get("good.test", 80, "/"), W).await;
    assert_eq!(status(&resp), 403);
    assert!(resp.contains("private_range"));
    p.stop().await;
    let mut lab_mode = proxy("", &[]).await;
    let meta =
        lab_mode.raw(b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\n\r\n", W).await;
    assert_eq!(status(&meta), 403, "metadata always denied even with deny_private_ranges=false");
    lab_mode.stop().await;
}

#[tokio::test]
async fn e22_dns_rebinding_resolved_once() {
    let origin = Origin::start(|_| Reply::ok("ok")).await;
    let r = resolver();
    r.script(
        "rebind.test",
        vec![vec!["127.0.0.1".parse().unwrap()], vec!["169.254.169.254".parse().unwrap()]],
    );
    let mut p = ProxyHarness::start(&base_config(""), &[], r).await;
    assert_eq!(status(&p.raw(&get("rebind.test", origin.addr.port(), "/"), W).await), 200);
    assert_eq!(p.resolver.count(), 1, "one lookup per request; connection used the validated IP");
    p.stop().await;
}

#[tokio::test]
async fn e33_sm14_sm15_keepalive_and_pipelining_filtered_per_request() {
    let origin = Origin::start(|_| Reply::ok("ok")).await;
    let mut p = proxy("", &[("domains.txt", "evil.com\n")]).await;
    let port = origin.addr.port();
    let pipelined = format!(
        "GET http://good.test:{port}/1 HTTP/1.1\r\nHost: good.test:{port}\r\n\r\nGET http://evil.com:{port}/2 HTTP/1.1\r\nHost: evil.com:{port}\r\n\r\n"
    );
    let resp = p.raw(pipelined.as_bytes(), W).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains("HTTP/1.1 403"), "second request filtered on its own (D-10): {resp}");
    assert_eq!(origin.requests().len(), 1, "blocked request never reached the origin");
    p.stop().await;
    let logs = p.log_lines();
    assert_eq!(logs.len(), 2, "both requests logged");
}

#[tokio::test]
async fn sm16_each_request_routed_by_its_own_target() {
    let a = Origin::start(|_| Reply::ok("A")).await;
    let b = Origin::start(|_| Reply::ok("B")).await;
    let mut p = proxy("", &[]).await;
    let req = format!(
        "GET http://good.test:{}/ HTTP/1.1\r\nHost: good.test:{}\r\n\r\nGET http://good.test:{}/ HTTP/1.1\r\nHost: good.test:{}\r\nConnection: close\r\n\r\n",
        a.addr.port(),
        a.addr.port(),
        b.addr.port(),
        b.addr.port()
    );
    let resp = p.raw(req.as_bytes(), W).await;
    assert!(resp.contains("\r\n\r\nA") && resp.ends_with("\r\n\r\nB"), "{resp}");
    assert_eq!((a.requests().len(), b.requests().len()), (1, 1));
    p.stop().await;
}

/// SM-xx payloads that must be rejected before anything reaches the origin.
#[tokio::test]
async fn i20_i28_smuggling_corpus_never_reaches_origin() {
    let origin = Origin::start(|_| Reply::ok("ok")).await;
    let mut p = proxy("", &[]).await;
    let port = origin.addr.port();
    let h = format!("good.test:{port}");
    let base = format!("http://{h}/");
    let cases: Vec<(&str, String, u16)> = vec![
        (
            "SM-01",
            format!(
                "POST {base} HTTP/1.1\r\nHost: {h}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"
            ),
            400,
        ),
        (
            "SM-02",
            format!(
                "POST {base} HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGET /smuggled-marker HTTP/1.1\r\n\r\n0\r\n\r\n"
            ),
            400,
        ),
        (
            "SM-03",
            format!("POST {base} HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: xchunked\r\n\r\n"),
            400,
        ),
        (
            "SM-03b",
            format!("POST {base} HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding : chunked\r\n\r\n"),
            400,
        ),
        (
            "SM-03c",
            format!(
                "POST {base} HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked, identity\r\n\r\n"
            ),
            400,
        ),
        (
            "SM-04",
            format!(
                "POST {base} HTTP/1.1\r\nHost: {h}\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"
            ),
            400,
        ),
        (
            "SM-05",
            format!(
                "POST {base} HTTP/1.1\r\nHost: {h}\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"
            ),
            400,
        ),
        (
            "SM-06",
            format!("POST {base} HTTP/1.1\r\nHost: {h}\r\nContent-Length: +5\r\n\r\nhello"),
            400,
        ),
        ("SM-07", format!("GET {base} HTTP/1.1\r\nHost: {h}\r\nX-A: 1\r\n continued\r\n\r\n"), 400),
        ("SM-08", format!("GET {base} HTTP/1.1\nHost: {h}\n\n"), 400),
        ("SM-09", format!("GET {base} HTTP/1.1\r\nHost: {h}\r\nX-A: a\0b\r\n\r\n"), 400),
        (
            "SM-10",
            format!(
                "GET {base} HTTP/1.1\r\nHost: {h}\r\nConnection: close, Content-Length\r\n\r\n"
            ),
            400,
        ),
        ("SM-11", format!("GET {base} HTTP/1.1\r\nHost: {h}\r\nHost: other.test\r\n\r\n"), 400),
        ("SM-12", format!("GET {base} HTTP/1.1\r\nHost: b.test\r\n\r\n"), 400),
        (
            "SM-13",
            format!(
                "GET {base} HTTP/1.1\r\nHost: {h}\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAAA\r\n\r\n"
            ),
            400,
        ),
        (
            "SM-17",
            format!(
                "POST {base} HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFF\r\nx\r\n"
            ),
            400,
        ),
        ("SM-18a", format!("GET  {base} HTTP/1.1\r\nHost: {h}\r\n\r\n"), 400),
        ("SM-18b", format!("GET {base} HTTP/1.2\r\nHost: {h}\r\n\r\n"), 505),
        ("SM-18c", format!("get {base} HTTP/1.1\r\nHost: {h}\r\n\r\n"), 400),
        (
            "SM-24a",
            format!("GET http://{h}/{} HTTP/1.1\r\nHost: {h}\r\n\r\n", "a".repeat(9 * 1024)),
            414,
        ),
        (
            "SM-24b",
            format!(
                "GET {base} HTTP/1.1\r\nHost: {h}\r\n{}\r\n",
                (0..101).map(|i| format!("X-{i}: v\r\n")).collect::<String>()
            ),
            431,
        ),
        ("SM-25a", "CONNECT good.test HTTP/1.1\r\nHost: good.test\r\n\r\n".to_owned(), 400),
        ("SM-25b", format!("CONNECT user@{h} HTTP/1.1\r\nHost: {h}\r\n\r\n"), 403),
        (
            "SM-25c",
            format!("CONNECT {h} HTTP/1.1\r\nHost: {h}\r\nContent-Length: 5\r\n\r\nhello"),
            400,
        ),
        ("R9-https", format!("GET https://{h}/ HTTP/1.1\r\nHost: {h}\r\n\r\n"), 400),
        ("R9-origin", format!("GET / HTTP/1.1\r\nHost: {h}\r\n\r\n"), 400),
        ("R14-trace", format!("TRACE {base} HTTP/1.1\r\nHost: {h}\r\n\r\n"), 405),
        ("U-010", format!("GET http://x@{h}/ HTTP/1.1\r\nHost: {h}\r\n\r\n"), 403),
    ];
    for (id, payload, want) in &cases {
        let resp = p.raw(payload.as_bytes(), W).await;
        assert_eq!(status(&resp), *want, "{id}: {resp}");
        assert_eq!(resp.matches("HTTP/1.1").count(), 1, "{id}: exactly one response");
    }
    assert!(origin.requests().is_empty(), "origin never saw any of: {:?}", origin.requests());
    p.stop().await;
    assert_eq!(p.log_lines().len(), cases.len(), "every rejected request logged exactly once");
}

#[tokio::test]
async fn sm20_malicious_origin_responses_become_502() {
    for bad in [
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\ntransfer-encoding: chunked\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nx: a\rb\r\ncontent-length: 0\r\n\r\n",
        "HTTP/1.1 2000 OK\r\n\r\n",
        "HTTP/1.1 200 OK\r\ncontent-length: 1\r\ncontent-length: 2\r\n\r\nx",
    ] {
        let origin = Origin::start(move |_| Reply::raw(bad)).await;
        let mut p = proxy("", &[]).await;
        let resp = p.raw(&get("good.test", origin.addr.port(), "/"), W).await;
        assert_eq!(status(&resp), 502, "{bad:?} -> {resp}");
        assert_eq!(resp.matches("HTTP/1.1").count(), 1, "client never sees a second response");
        p.stop().await;
    }
    // Two responses in one origin write: only the first (correctly framed) one reaches the client.
    let origin = Origin::start(|_| Reply::raw("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nokHTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nevil")).await;
    let mut p = proxy("", &[]).await;
    let resp = p.raw(&get("good.test", origin.addr.port(), "/"), W).await;
    assert!(resp.ends_with("\r\n\r\nok") && !resp.contains("evil"), "{resp}");
    p.stop().await;
}

#[tokio::test]
async fn i15_i16_connect_passthrough_and_policy() {
    // Raw echo: the tunneled bytes come back unchanged (the origin parses them as a request first).
    let origin = Origin::start(|req| Reply { echo: true, ..Reply::raw(req.to_vec()) }).await;
    let mut p = proxy("", &[("domains.txt", "evil.com\n"), ("url_patterns.txt", "good\n")]).await;
    let port = origin.addr.port();
    // Passthrough: only rules 1-3 apply, so the URL pattern "good" does not block a tunnel.
    let mut s = tokio::net::TcpStream::connect(p.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(format!("CONNECT good.test:{port} HTTP/1.1\r\nHost: good.test:{port}\r\n\r\nGET / HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 256];
    let mut got = Vec::new();
    while !String::from_utf8_lossy(&got).contains("GET / HTTP/1.1") {
        let n = tokio::time::timeout(W, s.read(&mut buf)).await.unwrap().unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    assert!(
        String::from_utf8_lossy(&got).starts_with("HTTP/1.1 200 Connection Established\r\n\r\n")
    );
    drop(s);
    let blocked = p
        .raw(
            format!("CONNECT evil.com:{port} HTTP/1.1\r\nHost: evil.com:{port}\r\n\r\n").as_bytes(),
            W,
        )
        .await;
    assert_eq!(status(&blocked), 403);
    p.stop().await;
    let mut strict = ProxyHarness::start(
        &base_config("").replace("connect_allowed = \"any\"", "connect_allowed = [443]"),
        &[],
        resolver(),
    )
    .await;
    let denied = strict
        .raw(
            format!("CONNECT good.test:{port} HTTP/1.1\r\nHost: good.test:{port}\r\n\r\n")
                .as_bytes(),
            W,
        )
        .await;
    assert_eq!(status(&denied), 403, "{denied}");
    assert!(denied.contains("port_not_allowed"));
    strict.stop().await;
}

#[tokio::test]
async fn i17_websocket_handshake_then_opaque_relay() {
    let origin = Origin::start(|_| Reply {
        echo: true,
        ..Reply::raw("HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: x\r\n\r\n")
    })
    .await;
    let mut p = proxy("", &[]).await;
    let port = origin.addr.port();
    let req = format!(
        "GET http://good.test:{port}/ws HTTP/1.1\r\nHost: good.test:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\nFRAME-BYTES"
    );
    let resp = p.raw(req.as_bytes(), Duration::from_secs(1)).await;
    assert!(resp.starts_with("HTTP/1.1 101"), "{resp}");
    assert!(resp.ends_with("FRAME-BYTES"), "frames relayed opaquely: {resp}");
    assert!(origin.requests()[0].to_ascii_lowercase().contains("upgrade: websocket"));
    p.stop().await;
}

#[tokio::test]
async fn i18_auth_required_success_and_lockout() {
    let hash = webfilter::auth::hash_password(b"pw").unwrap();
    let origin = Origin::start(|_| Reply::ok("ok")).await;
    let mut p =
        proxy(&format!("[proxy_auth]\nusername = \"u\"\npassword_hash = \"{hash}\"\n"), &[]).await;
    let port = origin.addr.port();
    let with = |cred: &str| {
        format!(
            "GET http://good.test:{port}/ HTTP/1.1\r\nHost: good.test:{port}\r\nProxy-Authorization: Basic {cred}\r\nConnection: close\r\n\r\n"
        )
    };
    let missing = p.raw(&get("good.test", port, "/"), W).await;
    assert_eq!(status(&missing), 407);
    assert!(missing.contains("proxy-authenticate: Basic realm=\"webfilter\""));
    assert_eq!(status(&p.raw(with("dTpwdw==").as_bytes(), W).await), 200, "u:pw");
    for _ in 0..5 {
        assert_eq!(status(&p.raw(with("dTp3cm9uZw==").as_bytes(), W).await), 407, "u:wrong");
    }
    assert_eq!(
        status(&p.raw(with("dTpwdw==").as_bytes(), W).await),
        429,
        "locked out even with the right password"
    );
    assert!(
        !origin.requests().iter().any(|r| r.to_ascii_lowercase().contains("proxy-authorization")),
        "never forwarded"
    );
    p.stop().await;
    let logs = p.log_lines();
    assert!(logs.iter().all(|l| !l.to_string().contains("dTpwdw")), "credentials never logged");
    assert!(logs.iter().any(|l| l["proxy_user"] == "u"));
    assert!(p.system_lines().iter().any(|v| v["kind"] == "auth_lockout"));
}

#[tokio::test]
async fn i19_graceful_shutdown_finishes_in_flight() {
    let origin =
        Origin::start(|_| Reply { delay: Duration::from_millis(500), ..Reply::ok("finished") })
            .await;
    let mut p = proxy("", &[]).await;
    let addr = p.addr;
    let port = origin.addr.port();
    let inflight =
        tokio::spawn(async move { raw_exchange(addr, &get("good.test", port, "/"), W).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    p.stop().await;
    let resp = inflight.await.unwrap();
    assert!(resp.ends_with("finished"), "in-flight request completed: {resp}");
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_err()
            || raw_exchange(
                addr,
                b"GET http://good.test/ HTTP/1.1\r\n\r\n",
                Duration::from_millis(300)
            )
            .await
            .is_empty(),
        "no longer accepting"
    );
    assert!(p.system_lines().iter().any(|v| v["kind"] == "proxy_stop"));
}

fn basic(user_pass: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(user_pass)
}

/// RV3-M4 / RV3-M3: malformed credentials and over-long user names cost no argon2 run and are
/// never counted, so they cannot lock anyone out or fill the lockout tables.
#[tokio::test]
async fn rv3_m4_malformed_and_oversized_credentials_are_not_counted() {
    let hash = webfilter::auth::hash_password(b"pw").unwrap();
    let origin = Origin::start(|_| Reply::ok("ok")).await;
    let mut p =
        proxy(&format!("[proxy_auth]\nusername = \"u\"\npassword_hash = \"{hash}\"\n"), &[]).await;
    let port = origin.addr.port();
    let with = |cred: &str| {
        format!(
            "GET http://good.test:{port}/ HTTP/1.1\r\nHost: good.test:{port}\r\nProxy-Authorization: Basic {cred}\r\nConnection: close\r\n\r\n"
        )
    };
    let no_colon = basic("no-colon-here");
    let long_name = basic(&format!("{}:pw", "x".repeat(200)));
    let creds = ["%%%not-base64", no_colon.as_str(), long_name.as_str()];
    for i in 0..15 {
        let resp = p.raw(with(creds[i % creds.len()]).as_bytes(), W).await;
        assert_eq!(status(&resp), 407, "attempt {i}: {resp}");
    }
    assert_eq!(status(&p.raw(with("dTpwdw==").as_bytes(), W).await), 200, "never locked out");
    p.stop().await;
    assert!(!p.system_lines().iter().any(|v| v["kind"] == "auth_lockout"));
}

/// RV3-L4: the `auth_lockout` event caps the attacker-supplied user name at 64 characters.
#[tokio::test]
async fn rv3_l4_lockout_event_caps_the_user_name() {
    let hash = webfilter::auth::hash_password(b"pw").unwrap();
    let name = "a".repeat(100);
    let mut p =
        proxy(&format!("[proxy_auth]\nusername = \"{name}\"\npassword_hash = \"{hash}\"\n"), &[])
            .await;
    let cred = basic(&format!("{name}:wrong"));
    let req = format!(
        "GET http://good.test:1/ HTTP/1.1\r\nHost: good.test:1\r\nProxy-Authorization: Basic {cred}\r\nConnection: close\r\n\r\n"
    );
    for _ in 0..5 {
        assert_eq!(status(&p.raw(req.as_bytes(), W).await), 407);
    }
    p.stop().await;
    let lockout = p.system_lines().into_iter().find(|v| v["kind"] == "auth_lockout").unwrap();
    let user = lockout["detail"]["user"].as_str().unwrap().to_owned();
    assert!(user.chars().count() <= 64, "capped: {user}");
    assert!(user.starts_with("aaaa"), "{user}");
}
