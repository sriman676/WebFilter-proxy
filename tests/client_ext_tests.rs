//! Phase 12: client enhancements (SPEC_EXT_CLIENT): robots corpus RB-xx, snapshot corpus SH-xx,
//! retry math, manifest verification, and E-78..E-82 driving the real client through the proxy.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{Origin, ProxyHarness, Reply, TestResolver, base_config, run_client as client};
use url::Url;
use webfilter::batch;
use webfilter::robots::Robots;
use webfilter::snapshot;

async fn proxy(lists: &[(&str, &str)]) -> ProxyHarness {
    let r = TestResolver::with(&[
        ("good.test", "127.0.0.1"),
        ("sub.good.test", "127.0.0.1"),
        ("evil.com", "127.0.0.1"),
    ]);
    ProxyHarness::start(&base_config(""), lists, r).await
}

fn path_of(req: &[u8]) -> String {
    String::from_utf8_lossy(req).split(' ').nth(1).unwrap_or("").to_owned()
}

fn resp(status: &str, ctype: &str, body: &[u8], extra: &str) -> Reply {
    let mut b = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\n{extra}\r\n",
        body.len()
    )
    .into_bytes();
    b.extend_from_slice(body);
    Reply::raw(b)
}

fn walk(dir: &Path) -> Vec<String> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy().into_owned();
        if e.file_type().unwrap().is_dir() {
            v.extend(walk(&e.path()).into_iter().map(|n| format!("{name}/{n}")));
        } else {
            v.push(name);
        }
    }
    v.sort();
    v
}

// --- RB corpus ----------------------------------------------------------------------------

fn unescape(s: &str) -> String {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match (b[i], b.get(i + 1)) {
            (b'\\', Some(b'n')) => (out.push(b'\n'), i += 2).1,
            (b'\\', Some(b'r')) => (out.push(b'\r'), i += 2).1,
            (b'\\', Some(b'x')) => {
                out.push(u8::from_str_radix(&s[i + 2..i + 4], 16).unwrap());
                i += 4;
            }
            (c, _) => (out.push(c), i += 1).1,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn rb_robots_corpus() {
    let corpus = std::fs::read_to_string("tests/corpus/robots_cases.tsv").unwrap();
    let mut n = 0;
    for line in corpus.lines().filter(|l| l.starts_with("RB-")) {
        let cols: Vec<&str> = line.split('\t').collect();
        let (id, text, agent, path, expected) = (cols[0], cols[1], cols[2], cols[3], cols[4]);
        let robots = match text {
            "HTTP 404 for robots.txt" => Robots::allow_all(),
            "HTTP 503 for robots.txt" => Robots::disallow_all(),
            "file larger than 512 KiB" => {
                let mut t = "User-agent: *\n".to_owned();
                t.push_str(&"Allow: /filler\n".repeat(60_000));
                t.push_str("Disallow: /a\n"); // beyond the cap: ignored
                Robots::parse(&t)
            }
            t => Robots::parse(&unescape(t)),
        };
        let allow = expected.starts_with("ALLOW") || expected.starts_with("parsed");
        assert_eq!(robots.allowed(agent, path), allow, "{id}");
        if id == "RB-08" {
            assert!(robots.delay(agent).unwrap() >= Duration::from_secs(5), "{id}");
        }
        n += 1;
    }
    assert_eq!(n, 15);
}

// --- SH corpus ----------------------------------------------------------------------------

fn base() -> Url {
    Url::parse("https://site.example/dir/page.html").unwrap()
}

/// Plan, map every same-site asset to a local name, rewrite.
fn snap(html: &str) -> (Vec<Url>, String) {
    let planned = snapshot::plan(html, &base(), false);
    let map: HashMap<String, String> = planned
        .iter()
        .filter(|u| snapshot::same_site(&base(), u, &[]))
        .map(|u| (u.to_string(), snapshot::local_name("page", u, "image/png")))
        .collect();
    (planned, snapshot::rewrite(html, &base(), &map, false))
}

#[test]
fn sh_snapshot_corpus() {
    let (_, o) = snap("<html><head></head><body><script>alert(1)</script></body></html>");
    assert!(!o.contains("<script") && !o.contains("alert"), "SH-01 {o}");
    let (p, o) = snap(r#"<img src="a.png" onerror="alert(1)">"#);
    assert_eq!(p.len(), 1);
    assert!(!o.contains("onerror") && o.contains("page_files/"), "SH-02 {o}");
    let (_, o) = snap(r#"<base href="http://evil.example/">"#);
    assert!(!o.contains("<base"), "SH-03 {o}");
    let (_, o) = snap(r#"<meta http-equiv="refresh" content="0;url=http://evil.example/">"#);
    assert!(!o.contains("refresh"), "SH-04 {o}");
    let (_, o) = snap(r#"<a href="javascript:alert(1)">x</a>"#);
    assert!(!o.contains("javascript:"), "SH-05 {o}");
    let (_, o) = snap(r#"<iframe src="http://evil.example/"></iframe>"#);
    assert!(!o.contains("<iframe") && !o.contains("evil.example"), "SH-06 {o}");
    let (p, o) = snap(r#"<link rel="stylesheet" href="//other.example/a.css">"#);
    assert!(
        p.iter().any(|u| u.host_str() == Some("other.example")) && !o.contains("other.example"),
        "SH-07 {o}"
    );
    let (p, o) = snap(r#"<img srcset="a.png 1x, b.png 2x">"#);
    assert_eq!(p.len(), 2, "SH-08");
    assert_eq!(o.matches("page_files/").count(), 2, "SH-08 {o}");
    let many: String = (0..100_000).map(|i| format!("<img src=\"/i/{i}.png\">")).collect();
    let (p, _) = snap(&many);
    assert!(p.len() >= snapshot::MAX_ASSETS, "SH-09 planned; the client caps fetching at 200");
    let (p, o) = snap(r#"<img src="../../../../etc/passwd">"#);
    assert_eq!(p[0].as_str(), "https://site.example/etc/passwd", "SH-10");
    let local = snapshot::local_name("page", &p[0], "image/png");
    assert!(
        local.starts_with("page_files/")
            && !local.contains("..")
            && local.matches('/').count() == 1,
        "SH-10 {local} {o}"
    );
    let css = "@import url(http://evil.example/x.css); a{background:url(data:image/png;base64,AAAA)} b{width:expression(alert(1))} c{behavior:url(x.htc)}";
    let out = snapshot::rewrite_css(css, &|_| None);
    assert!(!out.contains("evil.example"), "SH-11 {out}");
    assert!(out.contains("data:image/png;base64,AAAA"), "SH-12 {out}");
    assert!(!out.contains("expression") && !out.contains("behavior"), "SH-13 {out}");
    let (_, o) = snap("<svg><script>alert(1)</script></svg>");
    assert!(!o.contains("alert"), "SH-14 {o}");
    let (_, o) = snap(r#"<object data="x.swf"></object><embed src="x.swf">"#);
    assert!(!o.contains("<object") && !o.contains("<embed"), "SH-15 {o}");
    let (_, o) = snap(r#"<form action="http://evil.example/post"></form>"#);
    assert!(!o.contains("evil.example"), "SH-16 {o}");
    let _ = snap("<div><p><b>x</div></p><table><td>"); // SH-17: no panic
    let (_, o) = snap(&format!("<img src=\"a.png\" title=\"{}\">", "x".repeat(1_048_576)));
    assert!(o.len() < 100_000, "SH-18 attribute dropped");
    let (p, _) = snap(r#"<style>@import "a.css";</style>"#);
    assert_eq!(p[0].as_str(), "https://site.example/dir/a.css", "SH-19");
    for doc in [
        "<html><head><title>t</title></head><body><img src=\"http://other.example/x.png\"></body></html>",
        "<p>no head</p>",
    ] {
        let (_, o) = snap(doc);
        assert_eq!(o.matches("Content-Security-Policy").count(), 1, "SH-20 {o}");
        assert!(!o.contains("http://") && !o.contains("https://"), "SH-20 no external refs: {o}");
    }
    assert!(!snapshot::allowed_media("text/html"), "SH-22");
    // Fuzz regressions (F-19, F-20).
    let (_, o) = snap("<p>x</p><<<<0<script<");
    assert!(!o.contains("<script"), "F-19 trailing unterminated tag: {o}");
    for css in [
        "u<rl(http://evil.example/x.png)",
        "expressio<n(1)",
        "javascript:moz-binding",
        "behavio<r:url(x)",
    ] {
        let out = snapshot::rewrite_css(css, &|_| None).to_ascii_lowercase();
        for bad in ["expression(", "behavior:", "-moz-binding", "javascript:", "evil.example"] {
            assert!(!out.contains(bad), "F-20 {css:?} -> {out}");
        }
    }
}

// --- retry math, input file, manifest --------------------------------------------------------

#[test]
fn retry_policy_and_backoff() {
    for s in [408, 429, 502, 503, 504] {
        assert!(batch::retryable_status(s));
    }
    for s in [400, 401, 403, 404, 500, 501] {
        assert!(!batch::retryable_status(s));
    }
    let now = std::time::SystemTime::now();
    assert_eq!(batch::retry_after("7", now), Some(Duration::from_secs(7)));
    assert_eq!(batch::retry_after("-3", now), None);
    assert_eq!(batch::retry_after("soon", now), None);
    let later = httpdate::fmt_http_date(now + Duration::from_secs(30));
    assert!(batch::retry_after(&later, now).unwrap() >= Duration::from_secs(28));
    let cap = Duration::from_secs(60);
    assert_eq!(batch::backoff(1, None, cap, 1.0), Duration::from_millis(500));
    assert_eq!(batch::backoff(3, None, cap, 1.0), Duration::from_secs(2));
    assert_eq!(batch::backoff(30, None, cap, 1.0), cap);
    assert_eq!(batch::backoff(2, None, cap, 0.0), Duration::ZERO);
    assert_eq!(
        batch::backoff(1, Some(Duration::from_secs(600)), cap, 0.5),
        cap,
        "Retry-After capped"
    );
}

#[test]
fn input_file_parsing() {
    let (urls, invalid) = batch::parse_input_file(
        "\u{feff}# c\r\nhttp://a/\n\nhttp://a/\nhttp://b/ x\nhttp://c/\u{7}\nhttp://d/\n",
    );
    assert_eq!(urls, ["http://a/", "http://d/"]);
    assert_eq!(invalid, 2);
}

#[test]
fn manifest_lock_and_verification() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let file = out.join("a.html");
    std::fs::write(&file, "abc").unwrap();
    let path = dir.path().join("m.jsonl");
    let rec = batch::Record {
        url: "http://a/".into(),
        status: Some(200),
        bytes: 3,
        sha256: batch::file_sha256(&file),
        saved_path: Some(file.display().to_string()),
        blocked: false,
        error: None,
        finished_at: 1,
    };
    {
        let mut m = batch::Manifest::open(&path).unwrap();
        assert!(
            batch::Manifest::open(&path).is_err() || !cfg!(target_os = "linux"),
            "second run refused"
        );
        m.append(&rec).unwrap();
    }
    // Truncated trailing line from a crash is ignored.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all_compat(b"{\"url\":\"http://b/\",\"sta");
    let loaded = batch::load(&path);
    assert_eq!(loaded.len(), 1);
    assert!(batch::completed(&loaded["http://a/"], &out));
    // Outside the out dir, wrong size or hash: not completed.
    let outside = dir.path().join("x.html");
    std::fs::write(&outside, "abc").unwrap();
    let r2 = batch::Record { saved_path: Some(outside.display().to_string()), ..rec.clone() };
    assert!(!batch::completed(&r2, &out), "path outside out dir");
    std::fs::write(&file, "abd").unwrap();
    assert!(!batch::completed(&rec, &out), "tampered");
    // Stale lock of a dead pid is replaced.
    std::fs::write(format!("{}.lock", path.display()), "999999999").unwrap();
    assert!(batch::Manifest::open(&path).is_ok() || !cfg!(target_os = "linux"));
}

trait WriteAllCompat {
    fn write_all_compat(&mut self, b: &[u8]);
}
impl WriteAllCompat for std::fs::File {
    fn write_all_compat(&mut self, b: &[u8]) {
        std::io::Write::write_all(self, b).unwrap();
    }
}

// --- E-78 .. E-82 -----------------------------------------------------------------------------

#[tokio::test]
async fn e78_input_file_dedupe_retries_and_blocked_never_retried() {
    let flaps = Arc::new(AtomicUsize::new(0));
    let f = Arc::clone(&flaps);
    let origin = Origin::start(move |req| match path_of(req).as_str() {
        "/flap" if f.fetch_add(1, Ordering::SeqCst) / 2 < 2 => {
            resp("503 Service Unavailable", "text/html", b"busy", "retry-after: 0\r\n")
        }
        "/gone" => resp("404 Not Found", "text/html", b"no", ""),
        _ => Reply::ok("<p>fine</p>"),
    })
    .await;
    let mut p = proxy(&[("domains.txt", "evil.com\n")]).await;
    let out = tempfile::tempdir().unwrap();
    let port = origin.addr.port();
    let list = out.path().join("urls.txt");
    std::fs::write(
        &list,
        format!("# batch\nhttp://good.test:{port}/flap\nhttp://good.test:{port}/flap\nhttp://evil.com:{port}/\nhttp://good.test:{port}/gone\nbad line here\n"),
    )
    .unwrap();
    let dest = out.path().join("o");
    let r = client(
        p.addr,
        &dest,
        &[
            "--input-file",
            list.to_str().unwrap(),
            "--retries",
            "3",
            "--retry-max-delay",
            "1",
            "--json",
        ],
    )
    .await;
    assert_eq!(r.code, 1, "404 is an error: {} {}", r.stdout, r.stderr);
    let lines: Vec<serde_json::Value> =
        r.stdout.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 3, "deduplicated: {}", r.stdout);
    assert_eq!(lines[0]["attempts"], 3, "two 503s then 200");
    assert_eq!(lines[0]["status"], 200);
    assert_eq!(lines[1]["blocked"], true);
    assert_eq!(lines[1]["attempts"], 1, "BLOCKED never retried");
    assert_eq!(lines[2]["attempts"], 1, "404 never retried");
    assert!(r.stderr.contains("1 invalid line"), "{}", r.stderr);
    assert!(
        r.stderr.contains("summary: pages=1 assets=0 blocked=1 skipped=0 retries=2"),
        "{}",
        r.stderr
    );
    p.stop().await;
    assert_eq!(p.log_lines().iter().filter(|l| l["action"] == "blocked").count(), 1);
}

#[tokio::test]
async fn e79_manifest_resume_fetches_only_remaining() {
    let origin = Origin::start(|req| Reply::ok(&format!("<p>{}</p>", path_of(req)))).await;
    let mut p = proxy(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let port = origin.addr.port();
    let urls: Vec<String> = (1..=3).map(|i| format!("http://good.test:{port}/p{i}")).collect();
    let manifest = dir.path().join("m.jsonl");
    let m = manifest.to_str().unwrap();
    let r = client(p.addr, &out, &["--manifest", m, &urls[0]]).await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    // A crash (SIGKILL) mid-run leaves a truncated line; the lock file is gone with the process
    // or stale (dead pid).
    std::fs::OpenOptions::new()
        .append(true)
        .open(&manifest)
        .unwrap()
        .write_all_compat(b"{\"url\":\"http://good");
    let before = walk(&out);
    let first = std::fs::read(out.join(&before[0])).unwrap();
    let r =
        client(p.addr, &out, &["--manifest", m, "--resume", &urls[0], &urls[1], &urls[2]]).await;
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert!(r.stderr.contains("skipped=1"), "{}", r.stderr);
    let seen: Vec<String> = origin.requests().iter().map(|q| path_of(q.as_bytes())).collect();
    let mut seen = seen;
    seen[1..].sort();
    assert_eq!(seen, ["/p1", "/p2", "/p3"], "p1 not fetched again");
    assert_eq!(std::fs::read(out.join(&before[0])).unwrap(), first, "file identical");
    // Tampered file: refetched on the next resume.
    std::fs::write(out.join(&before[0]), "changed").unwrap();
    let r =
        client(p.addr, &out, &["--manifest", m, "--resume", &urls[0], &urls[1], &urls[2]]).await;
    assert_eq!(r.code, 0);
    assert_eq!(origin.requests().len(), 4, "only the tampered URL refetched");
    assert!(!dir.path().join("m.jsonl.lock").exists());
    p.stop().await;
}

#[tokio::test]
async fn e78_resume_partial_uses_if_range() {
    let body: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let b2 = body.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    let origin = Origin::start(move |req| {
        let r = String::from_utf8_lossy(req).to_ascii_lowercase();
        if c.fetch_add(1, Ordering::SeqCst) / 2 == 0 {
            // Promise everything, deliver half, then close.
            let mut b = format!("HTTP/1.1 200 OK\r\ncontent-type: text/html\r\netag: \"v1\"\r\ncontent-length: {}\r\n\r\n", b2.len()).into_bytes();
            b.extend_from_slice(&b2[..10_000]);
            return Reply::raw(b);
        }
        match r.split("range: bytes=").nth(1).and_then(|v| v.split('-').next()).and_then(|v| v.parse::<usize>().ok()) {
            Some(start) if r.contains("if-range: \"v1\"") => resp(
                "206 Partial Content",
                "text/html",
                &b2[start..],
                &format!("etag: \"v1\"\r\ncontent-range: bytes {start}-{}/{}\r\n", b2.len() - 1, b2.len()),
            ),
            _ => resp("200 OK", "text/html", &b2, "etag: \"v1\"\r\n"),
        }
    })
    .await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let url = format!("http://good.test:{}/big", origin.addr.port());
    let r = client(p.addr, out.path(), &["--resume-partial", "--retries", "0", &url]).await;
    assert_eq!(r.code, 1, "first run fails mid-body: {}", r.stdout);
    assert!(walk(out.path()).iter().any(|f| f.ends_with(".part")), "{:?}", walk(out.path()));
    let r = client(p.addr, out.path(), &["--resume-partial", "--retries", "0", &url]).await;
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    let name = webfilter::naming::output_filename(&url);
    assert_eq!(std::fs::read(out.path().join(&name)).unwrap(), body);
    assert!(origin.requests()[1].to_ascii_lowercase().contains("range: bytes=10000-"));
    assert!(!walk(out.path()).iter().any(|f| f.contains(".part")), "partial files removed");
    p.stop().await;
}

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n0000";

#[tokio::test]
async fn e80_e82_snapshot_assets_blocked_and_429() {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = Arc::clone(&hits);
    let origin = Origin::start(move |req| {
        let port = String::from_utf8_lossy(req).split("host: ").nth(1).and_then(|h| h.split(':').nth(1)).and_then(|p| p.split('\r').next()).unwrap_or("0").to_owned();
        match path_of(req).as_str() {
            "/page" => Reply::ok(&format!(
                r#"<html><head><link rel="stylesheet" href="/s.css"><script src="/x.js"></script></head><body onload="x()">
<img src="/a.png" onerror="x()"><img src="/slow.png"><img src="/html.png"><img src="http://evil.com:{port}/e.png">
<img src="http://other.test:{port}/o.png"><iframe src="/f"></iframe></body></html>"#
            )),
            "/s.css" => resp("200 OK", "text/css", b"@import \"t.css\"; body{background:url(/b.png)}", ""),
            "/t.css" => resp("200 OK", "text/css", b"p{color:red}", ""),
            "/slow.png" if h.fetch_add(1, Ordering::SeqCst) / 2 == 0 => resp("429 Too Many Requests", "text/plain", b"", "retry-after: 0\r\n"),
            "/html.png" => Reply::ok("<p>not an image</p>"),
            _ => resp("200 OK", "image/png", PNG, ""),
        }
    })
    .await;
    let mut p = proxy(&[("domains.txt", "evil.com\n")]).await;
    let out = tempfile::tempdir().unwrap();
    let port = origin.addr.port();
    let url = format!("http://good.test:{port}/page");
    let r = client(
        p.addr,
        out.path(),
        &[
            "--snapshot",
            "--snapshot-extra-host",
            "evil.com",
            "--retry-max-delay",
            "1",
            "--json",
            &url,
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    let j: serde_json::Value = serde_json::from_str(r.stdout.trim()).unwrap();
    let files = walk(out.path());
    let stem = webfilter::naming::output_filename(&url).trim_end_matches(".html").to_owned();
    assert_eq!(
        files.iter().filter(|f| f.starts_with(&format!("{stem}_files/"))).count(),
        5,
        "a, slow, b png + 2 css: {files:?}"
    );
    let page = std::fs::read_to_string(out.path().join(format!("{stem}.html"))).unwrap();
    assert_eq!(page.matches("Content-Security-Policy").count(), 1);
    assert!(
        !page.contains("<script")
            && !page.contains("onerror")
            && !page.contains("onload")
            && !page.contains("<iframe"),
        "{page}"
    );
    assert!(!page.contains("http://"), "no network references remain: {page}");
    let css = files.iter().find(|f| f.ends_with("s.css")).unwrap();
    let css = std::fs::read_to_string(out.path().join(css)).unwrap();
    assert!(!css.contains("/b.png") && css.contains("b.png"), "css refs local: {css}");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(j["snapshot_report"].as_str().unwrap()).unwrap())
            .unwrap();
    let omitted = report["omitted"].as_array().unwrap();
    let reason = |needle: &str| {
        omitted
            .iter()
            .find(|o| o["url"].as_str().unwrap().contains(needle))
            .map(|o| o["reason"].as_str().unwrap().to_owned())
    };
    assert!(reason("e.png").unwrap().starts_with("blocked"), "{report}");
    assert!(
        omitted
            .iter()
            .any(|o| o["url"].as_str().unwrap().contains("e.png") && o["event_id"].is_string())
    );
    assert_eq!(reason("o.png").unwrap(), "cross-site");
    assert!(reason("html.png").unwrap().contains("not allowed"), "SH-22 {report}");
    assert!(reason("x.js").is_none(), "scripts are not even planned");
    assert_eq!(hits.load(Ordering::SeqCst), 4, "429 retried once (handler runs twice per request)");
    assert!(r.stderr.contains("assets=5"), "{}", r.stderr);
    p.stop().await;
}

#[tokio::test]
async fn e81_crawl_robots_depth_traps_and_index() {
    let origin = Origin::start(|req| {
        let path = path_of(req);
        match path.as_str() {
            "/robots.txt" => resp("200 OK", "text/plain", b"User-agent: *\nDisallow: /private\n", ""),
            "/" => Reply::ok(
                &(r#"<a href="/a">a</a><a href="/private/x">p</a><a href="/doc.pdf">d</a><a href="http://evil.com/">e</a><a href="/a#frag">a2</a>"#.to_owned()
                    + &(0..8).map(|i| format!(r#"<a href="/q?i={i}">q</a>"#)).collect::<String>()
                    + r#"<a href="/1/2/3/4/5/6/7/8/9/10/11">deep</a>"#),
            ),
            "/a" => Reply::ok(r#"<a href="/b">b</a><a href="/">home</a>"#),
            "/b" => Reply::ok(r#"<a href="/c">c</a>"#),
            "/doc.pdf" => resp("200 OK", "application/pdf", b"%PDF", ""),
            _ => Reply::ok("<p>leaf</p>"),
        }
    })
    .await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let port = origin.addr.port();
    let start = format!("http://good.test:{port}/");
    let t0 = Instant::now();
    let r = client(p.addr, out.path(), &["--crawl-depth", "2", "--json", "-v", &start]).await;
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    let seen: Vec<String> = origin.requests().iter().map(|q| path_of(q.as_bytes())).collect();
    assert_eq!(seen[0], "/robots.txt", "robots first");
    assert!(!seen.iter().any(|s| s.starts_with("/private")), "robots respected: {seen:?}");
    assert!(!seen.contains(&"/c".to_owned()), "depth 2 stops before /c: {seen:?}");
    assert_eq!(
        seen.iter().filter(|s| s.starts_with("/q?")).count(),
        5,
        "query variants capped: {seen:?}"
    );
    assert!(!seen.iter().any(|s| s.starts_with("/1/")), "path depth capped");
    assert_eq!(seen.iter().filter(|s| *s == "/a").count(), 1, "fragment duplicates skipped");
    // Politeness: >= 250 ms between requests.
    assert!(t0.elapsed() >= Duration::from_millis(250 * (seen.len() as u64 - 1)));
    for why in ["robots.txt", "query variant limit", "path depth limit", "not text/html"] {
        assert!(r.stderr.contains(why), "{why}: {}", r.stderr);
    }
    let pages: Vec<serde_json::Value> =
        r.stdout.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert!(pages.iter().all(|p| p["crawl_depth"].is_u64()));
    let dir = out.path().join("good.test_crawl");
    let files = walk(&dir);
    assert!(files.contains(&"index.html".to_owned()), "{files:?}");
    let home = webfilter::naming::output_filename(&start);
    let a = webfilter::naming::output_filename(&format!("http://good.test:{port}/a"));
    let html = std::fs::read_to_string(dir.join(&home)).unwrap();
    assert!(
        html.contains(&format!("href=\"{a}#frag\"")) && html.contains(&format!("href=\"{a}\"")),
        "links rewritten: {html}"
    );
    assert!(html.contains("href=\"/private/x\""), "unsaved links left alone");
    let index = std::fs::read_to_string(dir.join("index.html")).unwrap();
    assert!(
        index.contains(&format!("href=\"{home}\"")) && index.contains("Content-Security-Policy")
    );
    // max-pages caps the crawl.
    let out2 = tempfile::tempdir().unwrap();
    let r = client(
        p.addr,
        out2.path(),
        &["--crawl-depth", "5", "--max-pages", "2", "--crawl-delay-ms", "0", &start],
    )
    .await;
    assert_eq!(r.code, 0);
    assert!(r.stderr.contains("summary: pages=2 "), "{}", r.stderr);
    p.stop().await;
}

#[tokio::test]
async fn e81_robots_unreachable_disallows_and_redirect_offsite_not_followed() {
    let origin = Origin::start(|req| match path_of(req).as_str() {
        "/robots.txt" => resp("503 Service Unavailable", "text/plain", b"", ""),
        _ => Reply::ok("<a href='/x'>x</a>"),
    })
    .await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let port = origin.addr.port();
    let r = client(
        p.addr,
        out.path(),
        &["--crawl-depth", "1", "--retries", "0", "-v", &format!("http://good.test:{port}/")],
    )
    .await;
    assert_eq!(origin.requests().len(), 1, "only robots.txt: {:?}", origin.requests());
    assert!(r.stderr.contains("robots.txt"), "{}", r.stderr);

    let origin2 = Origin::start(|req| match path_of(req).as_str() {
        "/robots.txt" => resp("404 Not Found", "text/plain", b"", ""),
        _ => {
            let port = String::from_utf8_lossy(req)
                .split("host: good.test:")
                .nth(1)
                .and_then(|p| p.split('\r').next())
                .unwrap_or("0")
                .to_owned();
            resp("302 Found", "text/html", b"", &format!("location: http://other.test:{port}/\r\n"))
        }
    })
    .await;
    let r = client(
        p.addr,
        out.path(),
        &[
            "--crawl-depth",
            "1",
            "--retries",
            "0",
            &format!("http://good.test:{}/", origin2.addr.port()),
        ],
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(r.stdout.contains("redirect out of scope"), "{}", r.stdout);
    assert_eq!(origin2.requests().len(), 2, "other.test never requested");
    p.stop().await;
}

// --- security review regressions (M4, L6) ---------------------------------------------------

#[test]
fn m4_css_sanitizer_is_linear() {
    let css = "expression(".repeat(1_048_576 / "expression(".len());
    let t0 = Instant::now();
    let out = snapshot::rewrite_css(&css, &|_| None);
    assert!(t0.elapsed() < Duration::from_secs(3), "took {:?}", t0.elapsed());
    assert!(!out.to_ascii_lowercase().contains("expression("));
    // Mixed case and every pattern still neutralized in one input.
    let out = snapshot::rewrite_css(
        "a{x:EXPRESSION(1);behaviour:url(a);BeHaViOr:url(b);-MOZ-binding:url(c);u:JavaScript:x}",
        &|_| None,
    )
    .to_ascii_lowercase();
    for bad in ["expression(", "behavior:", "behaviour:", "-moz-binding", "javascript:"] {
        assert!(!out.contains(bad), "{bad} in {out}");
    }
    assert_eq!(snapshot::rewrite_css("p{color:red} é", &|_| None), "p{color:red} é");
}

/// The `Host:` port of a request (the origin serves every test host on one port).
fn host_port(req: &[u8]) -> String {
    String::from_utf8_lossy(req)
        .to_ascii_lowercase()
        .split("host: ")
        .nth(1)
        .and_then(|h| h.split(':').nth(1))
        .and_then(|p| p.split('\r').next())
        .unwrap_or("0")
        .to_owned()
}

#[tokio::test]
async fn l6_snapshot_asset_redirect_off_site_is_omitted() {
    let origin = Origin::start(|req| match path_of(req).as_str() {
        "/page" => Reply::ok(r#"<html><body><img src="/a.png"><img src="/r.png"></body></html>"#),
        "/r.png" => resp(
            "302 Found",
            "text/plain",
            b"",
            &format!("location: http://evil.com:{}/o.png\r\n", host_port(req)),
        ),
        _ => resp("200 OK", "image/png", PNG, ""),
    })
    .await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let url = format!("http://good.test:{}/page", origin.addr.port());
    let r = client(p.addr, out.path(), &["--snapshot", "--retries", "0", "--json", &url]).await;
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    let seen: Vec<String> = origin.requests().iter().map(|q| path_of(q.as_bytes())).collect();
    assert!(!seen.iter().any(|s| s == "/o.png"), "off-site redirect followed: {seen:?}");
    let j: serde_json::Value = serde_json::from_str(r.stdout.trim()).unwrap();
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(j["snapshot_report"].as_str().unwrap()).unwrap())
            .unwrap();
    let omitted = report["omitted"].as_array().unwrap();
    assert!(
        omitted.iter().any(|o| o["url"].as_str().unwrap().ends_with("/r.png")
            && o["reason"].as_str().unwrap().contains("redirect out of scope")),
        "{report}"
    );
    assert_eq!(report["assets"], 1, "a.png kept: {report}");
    p.stop().await;
}

#[tokio::test]
async fn l6_crawl_redirect_to_robots_disallowed_path_not_fetched() {
    let origin = Origin::start(|req| match path_of(req).as_str() {
        "/robots.txt" => resp("200 OK", "text/plain", b"User-agent: *\nDisallow: /private\n", ""),
        "/" => Reply::ok(r#"<a href="/go">go</a>"#),
        "/go" => resp("302 Found", "text/html", b"", "location: /private/secret\r\n"),
        _ => Reply::ok("<p>secret</p>"),
    })
    .await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let start = format!("http://good.test:{}/", origin.addr.port());
    let r =
        client(p.addr, out.path(), &["--crawl-depth", "1", "--retries", "0", "-v", &start]).await;
    let seen: Vec<String> = origin.requests().iter().map(|q| path_of(q.as_bytes())).collect();
    assert!(seen.contains(&"/go".to_owned()), "{seen:?}");
    assert!(!seen.iter().any(|s| s.starts_with("/private")), "robots bypassed: {seen:?}");
    assert!(
        r.stderr.contains("/private/secret: robots.txt"),
        "reported as robots skip: {}",
        r.stderr
    );
    p.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn l6_part_files_never_written_through_symlinks() {
    let body: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let origin = Origin::start(move |_| {
        // Promise everything, deliver half, then close: the client keeps a partial.
        let mut b = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\netag: \"v1\"\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        b.extend_from_slice(&body[..10_000]);
        Reply::raw(b)
    })
    .await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let url = format!("http://good.test:{}/big", origin.addr.port());
    let name = webfilter::naming::output_filename(&url);
    let victim = elsewhere.path().join("victim");
    let victim_meta = elsewhere.path().join("victim.json");
    std::fs::write(&victim, "keep").unwrap();
    std::fs::write(&victim_meta, "keep").unwrap();
    std::os::unix::fs::symlink(&victim, out.path().join(format!(".{name}.part"))).unwrap();
    std::os::unix::fs::symlink(&victim_meta, out.path().join(format!(".{name}.part.json")))
        .unwrap();
    let r = client(p.addr, out.path(), &["--resume-partial", "--retries", "0", &url]).await;
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep", "written through .part link");
    assert_eq!(
        std::fs::read_to_string(&victim_meta).unwrap(),
        "keep",
        "written through .part.json link"
    );
    p.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn l6_snapshot_report_never_written_through_symlink() {
    let origin = Origin::start(|req| match path_of(req).as_str() {
        "/page" => Reply::ok(r#"<html><body><img src="/a.png"></body></html>"#),
        _ => resp("200 OK", "image/png", PNG, ""),
    })
    .await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let url = format!("http://good.test:{}/page", origin.addr.port());
    let stem = webfilter::naming::output_filename(&url).trim_end_matches(".html").to_owned();
    let victim = elsewhere.path().join("victim");
    std::fs::write(&victim, "keep").unwrap();
    let link = out.path().join(format!("{stem}_snapshot_report.json"));
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let r = client(p.addr, out.path(), &["--snapshot", "--json", &url]).await;
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep", "{} {}", r.stdout, r.stderr);
    assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    assert!(r.stderr.contains("symlink"), "refusal reported as a warning: {}", r.stderr);
    p.stop().await;
}
