//! Phase 10 (threat feeds, download scanning): feed corpus FC-xx, E-59..E-62, E-63..E-66 against a
//! fake clamd that speaks INSTREAM (the real ClamAV container runs in `just scan-e2e`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    Lab, Origin, ProxyHarness, Reply, TestPki, TestResolver, base_config, eicar, fake_clamd, status,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use webfilter::config::{FeedConfig, FeedFormat};
use webfilter::feeds::{
    Entry, FeedError, FeedManager, FeedUpdate, Fetcher, Store, parse_feed, sanity, url_digest,
};
use webfilter::scan::{
    Download, Scanner, content_encoded, download_name, magic, parse_clamd_reply, sanitize_signature,
};

const W: Duration = Duration::from_secs(10);

fn protect() -> Vec<String> {
    vec!["admin.example".into()]
}

fn accepted(format: FeedFormat, line: &str) -> Vec<Entry> {
    parse_feed(format, &format!("{line}\nok-filler.example\n"), &protect(), 100)
        .map(|(e, _)| e)
        .unwrap_or_default()
        .into_iter()
        .filter(|e| !matches!(e, Entry::Domain(d) | Entry::Host(d) if d.contains("filler")))
        .collect()
}

// ------------------------------------------------------------------------------------ corpus

#[test]
fn fc_domains_hosts_urls_ips() {
    use FeedFormat::*;
    assert_eq!(accepted(DomainsText, "evil.example"), vec![Entry::Domain("evil.example".into())]);
    assert_eq!(
        accepted(DomainsText, "*.evil.example"),
        vec![Entry::Domain("*.evil.example".into())]
    );
    assert_eq!(accepted(DomainsText, "EVIL.Example."), vec![Entry::Domain("evil.example".into())]);
    for bad in [
        "com",
        "localhost",
        "webfilter.local",
        "xn--bad-",
        "evil..example",
        "admin.example",
        "x.admin.example",
    ] {
        assert!(accepted(DomainsText, bad).is_empty(), "FC: {bad} must be rejected");
    }
    assert_eq!(
        accepted(Hostfile, "127.0.0.1 evil.example"),
        vec![Entry::Host("evil.example".into())]
    );
    assert!(accepted(Hostfile, "0.0.0.0 localhost").is_empty());
    assert!(accepted(Hostfile, "::1 ip6-localhost").is_empty());
    let a = accepted(UrlsText, "http://evil.example/a.exe");
    assert_eq!(a.len(), 1);
    assert_eq!(accepted(UrlsText, "http://evil.example/%61.exe"), a, "FC-13 canonical digest");
    for bad in ["ftp://evil.example/x", "http://user:pw@evil.example/", "javascript:alert(1)"] {
        assert!(accepted(UrlsText, bad).is_empty(), "{bad}");
    }
    let row =
        r#""1","2026-11-01 10:00:00","http://evil.example/a.exe","online","malware_download""#;
    assert_eq!(accepted(CsvUrlhaus, row), a, "FC-17");
    assert!(accepted(CsvUrlhaus, "\"1\",\"2\",\"http://evil.ex").is_empty(), "FC-18 broken row");
    assert_eq!(accepted(IpsText, "203.0.113.7"), vec![Entry::Ip("203.0.113.7/32".into())]);
    assert_eq!(accepted(IpsText, "203.0.113.0/24"), vec![Entry::Ip("203.0.113.0/24".into())]);
    for bad in ["10.0.0.1", "0.0.0.0/0", "127.0.0.1"] {
        assert!(accepted(IpsText, bad).is_empty(), "{bad}");
    }
}

#[test]
fn fc_file_level_guards() {
    let long = format!("{}.example", "a".repeat(5000));
    let (e, r) = parse_feed(
        FeedFormat::DomainsText,
        &format!(
            "\u{feff}good.example\r\nbad\0line.example\r\n{long}\r\nok.example\r\nfine.example\n"
        ),
        &[],
        10,
    )
    .unwrap();
    assert_eq!((e.len(), r.invalid), (3, 2), "FC-23/24/25");
    let many: String = (0..20).map(|i| format!("d{i}.example\n")).collect();
    assert!(
        matches!(parse_feed(FeedFormat::DomainsText, &many, &[], 10), Err(FeedError::Rejected(_))),
        "FC-26"
    );
    assert!(
        matches!(
            parse_feed(FeedFormat::DomainsText, "com\nnet\ngood.example\n", &[], 10),
            Err(FeedError::Rejected(_))
        ),
        "FC-30"
    );
    assert!(sanity(Some(1000), 400, false).is_err(), "FC-27");
    assert!(sanity(Some(1000), 2500, false).is_err(), "FC-28");
    assert!(sanity(None, 400, false).is_ok(), "FC-29");
    assert!(sanity(Some(1000), 400, true).is_ok(), "forced");
}

#[test]
fn store_promote_keeps_five_and_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path(), "f");
    let mut versions = Vec::new();
    for i in 0..7 {
        versions.push(store.promote(&[Entry::Domain(format!("v{i}.example"))]).unwrap());
    }
    assert_eq!(store.versions().len(), 5);
    assert_eq!(store.active().as_deref(), versions.last().map(String::as_str));
    let prev = store.rollback().unwrap();
    assert_eq!(prev, versions[5]);
    assert_eq!(store.load(&prev).unwrap(), vec![Entry::Domain("v5.example".into())]);
}

// ------------------------------------------------------------------------------------ feed server

fn feed_cfg(name: &str, url: &str, format: FeedFormat) -> FeedConfig {
    FeedConfig {
        name: name.into(),
        enabled: true,
        url: url.into(),
        format,
        refresh_secs: 3600,
        max_bytes: 1 << 20,
        max_entries: 1000,
        auth_header_file: Default::default(),
        expire_after_secs: 604_800,
    }
}

type Seen = Arc<Mutex<Vec<String>>>;

/// HTTPS feed origin: `/list` = `body`, `/redirect-http`, `/redirect-other` (to other.test).
async fn feed_server(
    pki: &TestPki,
    body: Arc<Mutex<String>>,
    seen: Seen,
    other_port: u16,
) -> Origin {
    Origin::start_tls(pki.leaf(&["feed.test", "other.test"], false), move |req| {
        let text = String::from_utf8_lossy(req).into_owned();
        seen.lock().unwrap().push(text.clone());
        let path = text.split(' ').nth(1).unwrap_or("");
        match path {
            "/list" => {
                let b = body.lock().unwrap().clone();
                Reply::raw(format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\netag: \"v1\"\r\n\r\n{b}", b.len()))
            }
            "/redirect-http" => Reply::raw("HTTP/1.1 302 Found\r\nlocation: http://feed.test/list\r\ncontent-length: 0\r\n\r\n"),
            "/redirect-other" => Reply::raw(format!("HTTP/1.1 302 Found\r\nlocation: https://other.test:{other_port}/list\r\ncontent-length: 0\r\n\r\n")),
            _ => Reply::raw("HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n"),
        }
    })
    .await
}

fn fetcher(
    pki: &TestPki,
    dir: &std::path::Path,
    allow_loopback: bool,
    resolver: Arc<TestResolver>,
) -> Fetcher {
    let ca = pki.write_ca(dir);
    Fetcher {
        tls: webfilter::tls::upstream_client_config(&[ca]).unwrap(),
        resolver,
        policy: webfilter::policy::DestPolicy::new(!allow_loopback, Vec::new()),
    }
}

#[tokio::test]
async fn e59_e60_e61_update_guard_rollback_and_proxy_hit() {
    let pki = TestPki::new();
    let lab = Lab::new();
    let body =
        Arc::new(Mutex::new((0..10).map(|i| format!("bad{i}.example\n")).collect::<String>()));
    let seen: Seen = Arc::default();
    let origin = feed_server(&pki, Arc::clone(&body), Arc::clone(&seen), 1).await;
    let url = format!("https://feed.test:{}/list", origin.addr.port());
    let resolver = TestResolver::with(&[("feed.test", "127.0.0.1")]);
    let root = lab.path().join("feeds");
    let mgr = FeedManager::new(
        vec![feed_cfg("bad", &url, FeedFormat::DomainsText)],
        root.clone(),
        vec![],
        Some(fetcher(&pki, lab.path(), true, resolver.clone())),
        None,
    );
    assert!(
        matches!(mgr.update("bad", false).await, Ok(FeedUpdate::Updated { entries: 10, .. })),
        "E-59"
    );
    // E-60: a 90 percent shrink and a poisoned version are refused; last good stays active.
    *body.lock().unwrap() = "bad0.example\n".into();
    assert!(matches!(mgr.update("bad", false).await, Err(FeedError::Rejected(_))));
    *body.lock().unwrap() = "com\nnet\norg\nlocalhost\n".into();
    assert!(matches!(mgr.update("bad", false).await, Err(FeedError::Rejected(_))));
    assert_eq!(mgr.active()["bad"].entries, 10, "last good kept");
    // Conditional GET carried the stored ETag.
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|r| r.to_ascii_lowercase().contains("if-none-match: \"v1\""))
    );
    // E-61: rollback restores the previous version.
    *body.lock().unwrap() = (0..12).map(|i| format!("bad{i}.example\n")).collect();
    assert!(mgr.update("bad", false).await.is_ok());
    assert_eq!(mgr.active()["bad"].entries, 12);
    mgr.rollback("bad").unwrap();
    assert_eq!(mgr.active()["bad"].entries, 10);

    // A proxy with the stored feed blocks listed names for profiles that use it.
    let feeds_dir = root.display().to_string();
    let config = base_config(&format!(
        "[[feeds]]\nname = \"bad\"\nenabled = true\nurl = \"{url}\"\nformat = \"domains_text\"\n[feeds_global]\ndir = \"{feeds_dir}\"\n[[profiles]]\nname = \"default\"\nfeeds = [\"bad\"]\n"
    ));
    let mut h =
        ProxyHarness::start(&config, &[], TestResolver::with(&[("bad3.example", "127.0.0.1")]))
            .await;
    let resp = h
        .raw(
            b"GET http://bad3.example/ HTTP/1.1\r\nHost: bad3.example\r\nConnection: close\r\n\r\n",
            W,
        )
        .await;
    assert_eq!(status(&resp), 403);
    assert!(resp.contains("x-webfilter-reason: feed_domain"));
    h.stop().await;
    let v = &h.log_lines()[0];
    assert_eq!(
        (v["rule_list"].as_str(), v["rule_id"].as_str()),
        (Some("bad"), Some("feed:bad:bad3.example"))
    );
}

#[tokio::test]
async fn e62_transport_attacks_refused_and_key_stays_on_its_host() {
    let pki = TestPki::new();
    let lab = Lab::new();
    let seen_b: Seen = Arc::default();
    let other =
        feed_server(&pki, Arc::new(Mutex::new("x.example\n".into())), Arc::clone(&seen_b), 1).await;
    let seen_a: Seen = Arc::default();
    let origin = feed_server(
        &pki,
        Arc::new(Mutex::new("a.example\n".into())),
        Arc::clone(&seen_a),
        other.addr.port(),
    )
    .await;
    let resolver = TestResolver::with(&[("feed.test", "127.0.0.1"), ("other.test", "127.0.0.1")]);
    let key = lab.path().join("key");
    std::fs::write(&key, "SECRETKEY\n").unwrap();
    let mk = |path: &str| FeedConfig {
        auth_header_file: key.clone(),
        ..feed_cfg(
            "f",
            &format!("https://feed.test:{}{path}", origin.addr.port()),
            FeedFormat::DomainsText,
        )
    };
    // Loopback/private feed hosts are refused by the destination policy (release behavior).
    let strict = FeedManager::new(
        vec![mk("/list")],
        lab.path().join("s"),
        vec![],
        Some(fetcher(&pki, lab.path(), false, resolver.clone())),
        None,
    );
    assert!(matches!(strict.update("f", false).await, Err(FeedError::Fetch(_))));
    // https -> http redirect refused.
    let m = FeedManager::new(
        vec![mk("/redirect-http")],
        lab.path().join("r"),
        vec![],
        Some(fetcher(&pki, lab.path(), true, resolver.clone())),
        None,
    );
    assert!(matches!(m.update("f", false).await, Err(FeedError::Fetch(_))));
    // Cross-host redirect works but never carries the API key.
    let m = FeedManager::new(
        vec![mk("/redirect-other")],
        lab.path().join("o"),
        vec![],
        Some(fetcher(&pki, lab.path(), true, resolver.clone())),
        None,
    );
    assert!(m.update("f", false).await.is_ok());
    assert!(
        seen_a.lock().unwrap().iter().any(|r| r.contains("SECRETKEY")),
        "key sent to its own host"
    );
    assert!(
        !seen_b.lock().unwrap().iter().any(|r| r.to_ascii_lowercase().contains("auth-key")),
        "never cross-host"
    );
    // A TLS certificate from another CA is refused.
    let foreign = TestPki::new();
    let m = FeedManager::new(
        vec![mk("/list")],
        lab.path().join("t"),
        vec![],
        Some(fetcher(&foreign, lab.path(), true, resolver)),
        None,
    );
    assert!(matches!(m.update("f", false).await, Err(FeedError::Fetch(_))));
}

#[test]
fn feed_url_digest_matches_canonical_variants() {
    let t = webfilter::normalize::canonicalize(
        "http://EVIL.example:80/a/../a.exe",
        webfilter::normalize::TargetContext::PlainAbsolute,
    )
    .unwrap();
    let (entries, _) =
        parse_feed(FeedFormat::UrlsText, "http://evil.example/a.exe\n", &[], 10).unwrap();
    assert_eq!(entries, vec![Entry::Url(hex::encode(url_digest(&t.url_norm)))]);
}

// ------------------------------------------------------------------------------------ scanning units

#[test]
fn clamd_reply_signature_name_and_magic() {
    assert_eq!(parse_clamd_reply("stream: OK\0"), Ok(None));
    assert_eq!(
        parse_clamd_reply("stream: Eicar-Test-Signature FOUND\0"),
        Ok(Some("Eicar-Test-Signature".into()))
    );
    assert_eq!(parse_clamd_reply("stream: \u{1b}[31mx\"y FOUND\n"), Ok(Some("__31mx_y".into())));
    assert!(parse_clamd_reply("INSTREAM size limit exceeded. ERROR\0").is_err());
    assert!(parse_clamd_reply("").is_err());
    assert_eq!(sanitize_signature(&"a".repeat(200)).len(), 64);
    assert_eq!(
        download_name(Some("attachment; filename=\"../../etc/pa\u{1b}sswd\""), "/x"),
        "etcpasswd"
    );
    assert_eq!(
        download_name(Some("attachment; filename*=UTF-8''r%C3%A9.exe"), "/x"),
        "r%C3%A9.exe"
    );
    assert_eq!(download_name(None, "/dl/setup.exe"), "setup.exe");
    assert_eq!(download_name(None, "/"), "download");
    assert!(
        magic(b"MZ\x90\x00") && magic(b"%PDF-1.7") && magic(b"PK\x03\x04") && !magic(b"<html>")
    );
}

// ------------------------------------------------------------------------------------ scanning e2e

fn clean_bytes() -> Vec<u8> {
    let mut v = b"MZ".to_vec();
    v.extend((0..50_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8));
    v
}

/// Opaque (brotli-looking) bytes: no magic, so only the encoding can make them eligible.
fn br_bytes() -> Vec<u8> {
    b"\x8b\x02\x80hello brotli\x03".to_vec()
}

async fn download_origin() -> Origin {
    Origin::start(|req| {
        let text = String::from_utf8_lossy(req).into_owned();
        let path = text.split(' ').nth(1).unwrap_or("").to_owned();
        let (ctype, body, extra) = match path.rsplit('/').next().unwrap_or("") {
            "eicar.exe" => ("application/octet-stream", eicar(), ""),
            "clean.exe" => ("application/octet-stream", clean_bytes(), ""),
            "magic" => ("text/plain", clean_bytes(), ""),
            "page.html" => ("text/html", b"<html>hi</html>".to_vec(), ""),
            "partial.exe" => ("application/octet-stream", clean_bytes(), "status206"),
            "gz.exe" => ("application/octet-stream", clean_bytes(), "content-encoding: gzip\r\n"),
            // Review M1: eligibility from Content-Disposition, Content-Encoding and `name.exe.`.
            "attach" => {
                ("text/plain", eicar(), "content-disposition: attachment; filename=\"x.ps1\"\r\n")
            }
            "br.bin" => ("text/plain", br_bytes(), "content-encoding: br\r\n"),
            "eicar.exe." => ("text/plain", eicar(), ""),
            _ => ("text/plain", Vec::new(), ""),
        };
        let line =
            if extra == "status206" { "HTTP/1.1 206 Partial Content" } else { "HTTP/1.1 200 OK" };
        let hdr = if extra.starts_with("content-") { extra } else { "" };
        let mut out = format!(
            "{line}\r\ncontent-type: {ctype}\r\n{hdr}content-length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(&body);
        Reply::raw(out)
    })
    .await
}

async fn scan_proxy(mode: &str, extra: &str, clamd: u16) -> ProxyHarness {
    let config = base_config(&format!(
        "[rules]\nblocked_extensions = []\n[scan]\nenabled = true\nmode = \"{mode}\"\ntemp_dir = \"scan_tmp\"\n{extra}\n[scan.clamd]\naddress = \"tcp:127.0.0.1:{clamd}\"\n[[profiles]]\nname = \"default\"\nscan_downloads = true\n"
    ));
    ProxyHarness::start(&config, &[], TestResolver::with(&[("dl.test", "127.0.0.1")])).await
}

async fn get(h: &ProxyHarness, port: u16, file: &str) -> String {
    let req = format!(
        "GET http://dl.test:{port}/{file} HTTP/1.1\r\nHost: dl.test:{port}\r\nConnection: close\r\n\r\n"
    );
    h.raw(req.as_bytes(), W).await
}

fn body_of(resp: &str) -> &[u8] {
    resp.split_once("\r\n\r\n").map_or(&[], |(_, b)| b.as_bytes())
}

#[tokio::test]
async fn e64_block_mode_blocks_eicar_and_delivers_clean_bytes_exactly() {
    let clamd = fake_clamd().await;
    let origin = download_origin().await;
    let mut h = scan_proxy("block", "", clamd).await;
    let port = origin.addr.port();
    let bad = get(&h, port, "eicar.exe").await;
    assert_eq!(status(&bad), 403);
    assert!(bad.contains("x-webfilter-reason: malware_detected"));
    assert!(!bad.contains("EICAR"), "the body is never forwarded");
    let raw = common::raw_exchange(h.addr, format!("GET http://dl.test:{port}/clean.exe HTTP/1.1\r\nHost: dl.test:{port}\r\nConnection: close\r\n\r\n").as_bytes(), W).await;
    assert_eq!(status(&raw), 200);
    let page = get(&h, port, "page.html").await;
    assert_eq!(status(&page), 200, "not eligible: streamed as usual");
    h.stop().await;
    let lines = h.log_lines();
    assert_eq!(lines[0]["scan_status"], "infected");
    assert_eq!(lines[0]["scan_signature"], "Eicar-Test-Signature");
    assert_eq!(lines[0]["body_sha256"], hex::encode(Sha256::digest(eicar())));
    assert_eq!(lines[1]["scan_status"], "clean");
    assert_eq!(lines[1]["body_sha256"], hex::encode(Sha256::digest(clean_bytes())));
    assert_eq!(lines[1]["body_bytes"], clean_bytes().len());
    assert!(lines[2]["scan_status"].is_null());
    let tmp: Vec<_> = std::fs::read_dir(h.lab.path().join("scan_tmp")).unwrap().collect();
    assert!(tmp.is_empty(), "temp files removed");
    let all = std::fs::read_to_string(h.lab.path().join("logs/webfilter.jsonl")).unwrap();
    assert!(!all.contains("EICAR-STANDARD"), "no body bytes in logs");
    assert!(h.system_lines().iter().any(|v| v["kind"] == "malware_detected"));
}

#[tokio::test]
async fn e64_clean_body_byte_identical_and_magic_eligibility() {
    let clamd = fake_clamd().await;
    let origin = download_origin().await;
    let mut h = scan_proxy("block", "", clamd).await;
    let port = origin.addr.port();
    let mut s = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    s.write_all(format!("GET http://dl.test:{port}/magic HTTP/1.1\r\nHost: dl.test:{port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(&out[split..], clean_bytes().as_slice(), "exactly the scanned bytes");
    h.stop().await;
    assert_eq!(h.log_lines()[0]["scan_status"], "clean", "MZ magic made text/plain eligible");
}

#[tokio::test]
async fn e63_detect_mode_delivers_and_logs_the_verdict() {
    let clamd = fake_clamd().await;
    let origin = download_origin().await;
    let mut h = scan_proxy("detect", "", clamd).await;
    let resp = get(&h, origin.addr.port(), "eicar.exe").await;
    assert_eq!(status(&resp), 200, "detect never blocks");
    assert_eq!(body_of(&resp), eicar().as_slice());
    h.stop().await;
    let v = &h.log_lines()[0];
    assert_eq!(
        (v["scan_status"].as_str(), v["action"].as_str()),
        (Some("infected"), Some("allowed"))
    );
    assert!(h.system_lines().iter().any(|v| v["kind"] == "malware_detected"));
}

#[tokio::test]
async fn e65_unscannable_matrix_follows_the_actions() {
    let clamd = fake_clamd().await;
    let origin = download_origin().await;
    let port = origin.addr.port();
    // block mode defaults: unscannable and unavailable both block.
    let mut h = scan_proxy("block", "max_bytes = 1000\ntemp_quota_bytes = 1000000", clamd).await;
    for (file, reason) in
        [("clean.exe", "unscannable"), ("partial.exe", "unscannable"), ("gz.exe", "unscannable")]
    {
        let r = get(&h, port, file).await;
        assert_eq!(status(&r), 403, "{file}");
        assert!(r.contains(&format!("x-webfilter-reason: {reason}")), "{file}: {r}");
    }
    h.stop().await;
    let mut h = scan_proxy(
        "block",
        "max_bytes = 1000\ntemp_quota_bytes = 1000000\nunscannable_action = \"allow\"",
        clamd,
    )
    .await;
    let r = common::raw_exchange(h.addr, format!("GET http://dl.test:{port}/clean.exe HTTP/1.1\r\nHost: dl.test:{port}\r\nConnection: close\r\n\r\n").as_bytes(), W).await;
    assert_eq!(status(&r), 200, "allowed although oversize");
    h.stop().await;
    assert_eq!(h.log_lines()[0]["scan_status"], "unscannable");
    // clamd down: scanner_unavailable.
    let mut h = scan_proxy("block", "", 9).await;
    let r = get(&h, port, "clean.exe").await;
    assert!(r.contains("x-webfilter-reason: scanner_unavailable"), "{r}");
    h.stop().await;
    assert_eq!(h.log_lines()[0]["scan_status"], "error");
}

#[test]
fn review_m1_eligibility_units() {
    let dir = tempfile::tempdir().unwrap();
    let cfg =
        webfilter::config::ScanConfig { temp_dir: dir.path().join("t"), ..Default::default() };
    let s = Scanner::new(cfg).unwrap();
    let base = Download { path: "/x", content_type: Some("text/plain"), ..Default::default() };
    assert!(!s.eligible(&base));
    for cd in [
        "attachment; filename=\"x.ps1\"",
        "attachment; filename=X.BAT",
        "attachment; filename=\"a;b.exe. \"",
        "attachment; filename=\"a.txt\"; filename*=UTF-8''evil%2Ejs",
    ] {
        let cds = [cd.to_owned()];
        assert!(s.eligible(&Download { dispositions: &cds, ..base }), "{cd}");
    }
    let cds = ["inline; filename=\"notes.txt\"".to_owned()];
    assert!(!s.eligible(&Download { dispositions: &cds, ..base }));
    assert!(s.eligible(&Download { encoded: true, ..base }), "encoded non-page body");
    for page in ["text/html; charset=utf-8", "text/css", "application/json"] {
        let d = Download { content_type: Some(page), encoded: true, ..base };
        assert!(!s.eligible(&d), "compressed {page} is browsing, not a download");
    }
    assert!(s.eligible(&Download { path: "/a.exe.", ..base }), "trailing dot");
    assert!(s.eligible(&Download { path: "/a.EXE..", ..base }));
    assert!(s.eligible(&Download { prefix: b"MZ", ..base }));
    assert!(content_encoded([&b"identity, br"[..]]) && content_encoded([&b"gzip"[..]]));
    assert!(content_encoded([&b"identity"[..], &b"deflate"[..]]), "duplicate headers");
    assert!(!content_encoded([&b" Identity "[..]]) && !content_encoded(std::iter::empty()));
}

#[tokio::test]
async fn review_m1_disposition_encoding_and_trailing_dot_cannot_skip_scanning() {
    let clamd = fake_clamd().await;
    let origin = download_origin().await;
    let port = origin.addr.port();
    let mut h = scan_proxy("block", "", clamd).await;
    let r = get(&h, port, "attach").await;
    assert_eq!(status(&r), 403, "text/plain + Content-Disposition .ps1: {r}");
    assert!(r.contains("x-webfilter-reason: malware_detected"));
    let r = get(&h, port, "br.bin").await;
    assert_eq!(status(&r), 403, "content-encoded body is unscannable: {r}");
    assert!(r.contains("x-webfilter-reason: unscannable"));
    let r = get(&h, port, "eicar.exe.").await;
    assert_eq!(status(&r), 403, "trailing dot: {r}");
    assert!(r.contains("x-webfilter-reason: malware_detected"));
    h.stop().await;
    let lines = h.log_lines();
    assert_eq!(lines[0]["scan_status"], "infected");
    assert_eq!(lines[0]["download_name"], "x.ps1");
    assert_eq!(lines[1]["scan_status"], "unscannable");
    assert_eq!(lines[2]["scan_status"], "infected");
    // The unscannable action decides: allow streams the encoded body unchanged.
    let mut h = scan_proxy("block", "unscannable_action = \"allow\"", clamd).await;
    let r = get(&h, port, "br.bin").await;
    assert_eq!(status(&r), 200, "{r}");
    // `raw` returns lossy UTF-8; compare the same view of the expected bytes.
    assert_eq!(body_of(&r), String::from_utf8_lossy(&br_bytes()).as_bytes());
    h.stop().await;
    assert_eq!(h.log_lines()[0]["scan_status"], "unscannable");
}

/// An origin that sends `head`, then `parts` with `pause` between them, and keeps the
/// connection open afterwards (so only correct framing ends the response).
async fn slow_origin(head: String, parts: Vec<Vec<u8>>, pause: Duration) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let (head, parts) = (head.clone(), parts.clone());
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut b = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&b[..n]),
                    }
                }
                if s.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                for (i, p) in parts.iter().enumerate() {
                    if i > 0 {
                        tokio::time::sleep(pause).await;
                    }
                    if s.write_all(p).await.is_err() {
                        return;
                    }
                }
                let _ = s.read(&mut b).await; // hold the connection open until the proxy closes it
            });
        }
    });
    port
}

#[tokio::test]
async fn review_l2_unscannable_allowed_bodies_arrive_complete() {
    let clamd = fake_clamd().await;
    let body = clean_bytes();
    let pause = Duration::from_millis(2500);
    let cl_head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\n\r\n",
        body.len()
    );
    let cl =
        slow_origin(cl_head, vec![body[..20_000].to_vec(), body[20_000..].to_vec()], pause).await;
    let mut wire = Vec::new();
    for c in body.chunks(4000) {
        wire.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        wire.extend_from_slice(c);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    let mid = 10_001; // inside a chunk
    let te_head = "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ntransfer-encoding: chunked\r\n\r\n";
    let chunked =
        slow_origin(te_head.into(), vec![wire[..mid].to_vec(), wire[mid..].to_vec()], pause).await;
    // The scan buffer times out mid-body; the unscannable download is allowed.
    let mut h =
        scan_proxy("block", "buffer_timeout_secs = 1\nunscannable_action = \"allow\"", clamd).await;
    for (port, what) in [(cl, "content-length"), (chunked, "chunked")] {
        let started = std::time::Instant::now();
        let mut s = tokio::net::TcpStream::connect(h.addr).await.unwrap();
        let req = format!(
            "GET http://dl.test:{port}/slow.exe HTTP/1.1\r\nHost: dl.test:{port}\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(W, s.read_to_end(&mut out)).await;
        assert!(started.elapsed() < Duration::from_secs(8), "{what}: waited for a timeout");
        assert!(out.starts_with(b"HTTP/1.1 200"), "{what}: {}", String::from_utf8_lossy(&out));
        let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(out[split..] == body[..], "{what}: body differs ({} bytes)", out.len() - split);
    }
    h.stop().await;
    let lines = h.log_lines();
    assert_eq!(lines.len(), 2);
    for v in lines {
        assert_eq!(v["scan_status"], "unscannable");
    }
}

#[tokio::test]
async fn e66_hash_blocklist_hot_reload() {
    let clamd = fake_clamd().await;
    let origin = download_origin().await;
    let lab_dir = tempfile::tempdir().unwrap();
    let list = lab_dir.path().join("hashes.txt");
    std::fs::write(&list, "# none yet\n").unwrap();
    let mut h =
        scan_proxy("block", &format!("hash_blocklist = \"{}\"", list.display()), clamd).await;
    let port = origin.addr.port();
    assert_eq!(status(&get(&h, port, "clean.exe").await), 200);
    tokio::time::sleep(Duration::from_millis(1100)).await; // distinct mtime
    std::fs::write(&list, format!("{}  # clean.exe\n", hex::encode(Sha256::digest(clean_bytes()))))
        .unwrap();
    let r = get(&h, port, "clean.exe").await;
    assert_eq!(status(&r), 403);
    assert!(r.contains("x-webfilter-reason: hash_blocklist"));
    h.stop().await;
    assert_eq!(h.log_lines()[1]["scan_status"], "blocklisted");
}

#[tokio::test]
async fn pt_10_9_profile_without_scan_downloads_is_not_scanned() {
    let clamd = fake_clamd().await;
    let origin = download_origin().await;
    let config = base_config(&format!(
        "[rules]\nblocked_extensions = []\n[scan]\nenabled = true\nmode = \"block\"\ntemp_dir = \"scan_tmp\"\n[scan.clamd]\naddress = \"tcp:127.0.0.1:{clamd}\"\n"
    ));
    let mut h =
        ProxyHarness::start(&config, &[], TestResolver::with(&[("dl.test", "127.0.0.1")])).await;
    assert_eq!(
        status(&get(&h, origin.addr.port(), "eicar.exe").await),
        200,
        "opt-in per profile (D-53)"
    );
    h.stop().await;
    assert!(h.log_lines()[0]["scan_status"].is_null());
}

/// `just scan-e2e`: E-63/E-64 against the real ClamAV daemon (`WEBFILTER_REAL_CLAMD=host:port`).
#[tokio::test]
#[ignore = "needs the ClamAV container (just scan-e2e)"]
async fn real_clamd_blocks_eicar_and_passes_clean_files() {
    let addr = std::env::var("WEBFILTER_REAL_CLAMD").expect("WEBFILTER_REAL_CLAMD");
    let port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
    let origin = download_origin().await;
    for mode in ["block", "detect"] {
        let mut h = scan_proxy(mode, "", port).await;
        let bad = get(&h, origin.addr.port(), "eicar.exe").await;
        let clean = get(&h, origin.addr.port(), "clean.exe").await;
        h.stop().await;
        let lines = h.log_lines();
        assert_eq!(lines[0]["scan_status"], "infected", "{mode}: {:?}", lines[0]);
        assert_eq!(lines[0]["scan_engine"], "clamav");
        assert_eq!(lines[1]["scan_status"], "clean");
        assert_eq!(status(&clean), 200);
        assert_eq!(status(&bad), if mode == "block" { 403 } else { 200 });
    }
}

/// E-67: a YARA rule hit is a verdict like any other (feature `yara`; rules are operator-trusted).
#[cfg(feature = "yara")]
#[tokio::test]
async fn e67_yara_rule_hit_blocks() {
    let origin = Origin::start(|_| {
        let body = "header WF_YARA_TEST_MARKER trailer";
        Reply::raw(format!("HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\n\r\n{body}", body.len()))
    })
    .await;
    let lab = tempfile::tempdir().unwrap();
    let rules = lab.path().join("yara");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("test.yar"),
        "rule wf_test_marker { strings: $a = \"WF_YARA_TEST_MARKER\" condition: $a }",
    )
    .unwrap();
    let config = base_config(&format!(
        "[rules]\nblocked_extensions = []\n[scan]\nenabled = true\nmode = \"block\"\ntemp_dir = \"scan_tmp\"\n[scan.yara]\nrules_dir = \"{}\"\n[[profiles]]\nname = \"default\"\nscan_downloads = true\n",
        rules.display()
    ));
    let mut h =
        ProxyHarness::start(&config, &[], TestResolver::with(&[("dl.test", "127.0.0.1")])).await;
    let r = get(&h, origin.addr.port(), "x.bin").await;
    assert_eq!(status(&r), 403, "{r}");
    h.stop().await;
    let v = &h.log_lines()[0];
    assert_eq!(
        (v["scan_engine"].as_str(), v["scan_signature"].as_str()),
        (Some("yara"), Some("wf_test_marker"))
    );
}
