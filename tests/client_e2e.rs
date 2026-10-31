//! Phase 3: the real `webfilter-client` binary through the real proxy (ClientRunner):
//! E-01, E-02, E-04, E-12, E-13, E-14, E-29, I-client-tls, exit codes, PT-3 basics.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{Origin, ProxyHarness, Reply, TestPki, TestResolver, base_config};

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

/// `ClientRunner`: run the client binary against `proxy` with `out` as out-dir.
async fn client(proxy: std::net::SocketAddr, out: &Path, args: &[&str]) -> Run {
    let o = tokio::process::Command::new(env!("CARGO_BIN_EXE_webfilter-client"))
        .arg("--proxy")
        .arg(format!("http://{proxy}"))
        .arg("--out-dir")
        .arg(out)
        .args(args)
        .env_remove("WEBFILTER_PROXY")
        .output()
        .await
        .unwrap();
    Run {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into(),
        stderr: String::from_utf8_lossy(&o.stderr).into(),
    }
}

fn files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

async fn proxy(lists: &[(&str, &str)]) -> ProxyHarness {
    let r = TestResolver::with(&[("good.test", "127.0.0.1"), ("evil.com", "127.0.0.1")]);
    ProxyHarness::start(&base_config(""), lists, r).await
}

#[tokio::test]
async fn e01_http_page_saved_with_spec_name() {
    let origin = Origin::start(|_| Reply::ok("<h1>hello</h1>")).await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let url = format!("http://good.test:{}/docs/index.html?x=1", origin.addr.port());
    let r = client(p.addr, out.path(), &[&url]).await;
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    let name = webfilter::naming::output_filename(&url);
    assert_eq!(files(out.path()), vec![name.clone()]);
    assert_eq!(std::fs::read_to_string(out.path().join(&name)).unwrap(), "<h1>hello</h1>");
    assert!(r.stdout.starts_with("OK 200 14 "), "{}", r.stdout);
    let seen = origin.requests()[0].to_ascii_lowercase();
    assert!(
        seen.contains("accept-encoding: identity")
            && seen.contains("user-agent: webfilter-client/")
    );
    p.stop().await;
    assert_eq!(p.log_lines()[0]["action"], "allowed");
}

#[tokio::test]
async fn e02_https_via_connect_passthrough_verified() {
    let pki = TestPki::new();
    let origin = Origin::start_tls(pki.leaf(&["good.test"], false), |_| Reply::ok("secure")).await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let ca = pki.write_ca(out.path());
    let url = format!("https://good.test:{}/s", origin.addr.port());
    let r = client(p.addr, &out.path().join("o"), &["--ca-cert", ca.to_str().unwrap(), &url]).await;
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert_eq!(
        std::fs::read_to_string(
            out.path().join("o").join(webfilter::naming::output_filename(&url))
        )
        .unwrap(),
        "secure"
    );
    p.stop().await;
    let log = &p.log_lines()[0];
    assert_eq!(
        (log["http_method"].as_str(), log["tls_intercepted"].as_bool()),
        (Some("CONNECT"), Some(false))
    );
}

#[tokio::test]
async fn i_client_tls_verification_matrix() {
    let pki = TestPki::new();
    let other = TestPki::new();
    let cases = [
        ("valid but CA not trusted (no --ca-cert)", pki.leaf(&["good.test"], false), false),
        ("wrong name", pki.leaf(&["other.test"], false), true),
        ("expired", pki.leaf(&["good.test"], true), true),
        ("signed by another CA", other.leaf(&["good.test"], false), true),
    ];
    let mut p = proxy(&[]).await;
    for (what, cert, trust) in cases {
        let origin = Origin::start_tls(cert, |_| Reply::ok("must not be saved")).await;
        let out = tempfile::tempdir().unwrap();
        let ca = pki.write_ca(out.path());
        let url = format!("https://good.test:{}/", origin.addr.port());
        let mut args = vec![];
        if trust {
            args.extend(["--ca-cert", ca.to_str().unwrap()]);
        }
        args.push(&url);
        let r = client(p.addr, &out.path().join("o"), &args).await;
        assert_eq!(r.code, 1, "{what}: {}", r.stdout);
        assert!(r.stdout.contains("tls:"), "{what}: {}", r.stdout);
        assert!(files(&out.path().join("o")).is_empty(), "{what}: nothing saved");
    }
    p.stop().await;
}

#[tokio::test]
async fn e04_blocked_http_and_https_exit_3_with_event_id() {
    let origin = Origin::start(|_| Reply::ok("never")).await;
    let mut p = proxy(&[("domains.txt", "evil.com\n")]).await;
    let out = tempfile::tempdir().unwrap();
    let port = origin.addr.port();
    let r = client(
        p.addr,
        out.path(),
        &[
            &format!("http://evil.com:{port}/"),
            &format!("https://evil.com:{port}/"),
            "--save-blocked",
        ],
    )
    .await;
    assert_eq!(r.code, 3, "{}", r.stdout);
    assert_eq!(r.stdout.matches("BLOCKED 403").count(), 2, "{}", r.stdout);
    assert!(origin.requests().is_empty());
    p.stop().await;
    for log in p.log_lines() {
        let id = log["event_id"].as_str().unwrap();
        assert!(r.stdout.contains(id), "event id {id} printed");
    }
    assert!(
        // the second block page is saved as `<stem>.blocked-1.html` (no-clobber)
        files(out.path()).iter().all(|f| f.contains(".blocked")),
        "{:?}",
        files(out.path())
    );
}

#[tokio::test]
async fn e12_e13_redirects_blocked_hop_loop_limit_and_bad_scheme() {
    let origin = Origin::start(|req| {
        let r = String::from_utf8_lossy(req).to_string();
        let path = r.split(' ').nth(1).unwrap_or("").to_owned();
        let to = |loc: &str| {
            Reply::raw(format!(
                "HTTP/1.1 302 Found\r\nlocation: {loc}\r\ncontent-length: 0\r\n\r\n"
            ))
        };
        match path.rsplit('/').next().unwrap_or("") {
            "to-evil" => to(&format!(
                "http://evil.com:{}/",
                r.split("host: good.test:").nth(1).unwrap_or("").split('\r').next().unwrap_or("0")
            )),
            "loop" => to("/loop"),
            "file" => to("file:///etc/passwd"),
            "ftp" => to("ftp://good.test/x"),
            n if n.starts_with('r') && n[1..].parse::<u32>().unwrap_or(9) < 5 => {
                to(&format!("/r{}", n[1..].parse::<u32>().unwrap_or(0) + 1))
            }
            _ => Reply::ok("end"),
        }
    })
    .await;
    let mut p = proxy(&[("domains.txt", "evil.com\n")]).await;
    let out = tempfile::tempdir().unwrap();
    let base = format!("http://good.test:{}", origin.addr.port());
    assert_eq!(
        client(p.addr, out.path(), &[&format!("{base}/to-evil")]).await.code,
        3,
        "blocked at the hop"
    );
    for (path, what) in [("/loop", "redirect loop"), ("/file", "file"), ("/ftp", "ftp")] {
        let r = client(p.addr, out.path(), &[&format!("{base}{path}")]).await;
        assert_eq!(r.code, 1, "{path}: {}", r.stdout);
        assert!(r.stdout.contains(what), "{path}: {}", r.stdout);
    }
    let r = client(p.addr, out.path(), &["--max-redirects", "2", &format!("{base}/r0")]).await;
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(files(out.path()).is_empty(), "nothing saved on redirect errors");
    let ok = client(p.addr, out.path(), &["--max-redirects", "5", &format!("{base}/r3")]).await;
    assert_eq!(ok.code, 0, "{}", ok.stdout);
    assert_eq!(
        files(out.path()),
        vec![webfilter::naming::output_filename(&format!("{base}/r3"))],
        "named after the ORIGINAL url"
    );
    p.stop().await;
}

#[tokio::test]
async fn e14_two_hundred_concurrent_fetches() {
    let origin = Origin::start(|req| Reply::ok(&format!("body {}", req.len()))).await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let urls: Vec<String> =
        (0..200).map(|i| format!("http://good.test:{}/page/{i}", origin.addr.port())).collect();
    let mut args = vec!["--jobs", "32", "-q"];
    args.extend(urls.iter().map(String::as_str));
    let r = client(p.addr, out.path(), &args).await;
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(files(out.path()).len(), 200);
    p.stop().await;
    let logs = p.log_lines();
    assert_eq!(logs.len(), 200, "200 valid log lines");
    assert!(logs.iter().all(|l| l["status"] == 200));
}

#[tokio::test]
async fn e29_no_clobber_and_symlink_not_followed() {
    let origin = Origin::start(|_| Reply::ok("fresh")).await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let url = format!("http://good.test:{}/same", origin.addr.port());
    let name = webfilter::naming::output_filename(&url);
    #[cfg(unix)]
    {
        let victim = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(victim.path(), "victim").unwrap();
        std::os::unix::fs::symlink(victim.path(), out.path().join(&name)).unwrap();
        assert_eq!(client(p.addr, out.path(), &[&url]).await.code, 0);
        assert_eq!(
            std::fs::read_to_string(victim.path()).unwrap(),
            "victim",
            "symlink target untouched"
        );
    }
    assert_eq!(client(p.addr, out.path(), &[&url]).await.code, 0);
    let stem = name.trim_end_matches(".html");
    assert!(files(out.path()).contains(&format!("{stem}-1.html")), "{:?}", files(out.path()));
    p.stop().await;
}

#[tokio::test]
async fn exit_codes_usage_size_and_mixed() {
    let origin = Origin::start(|_| Reply::ok(&"x".repeat(5000))).await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let url = format!("http://good.test:{}/big", origin.addr.port());
    assert_eq!(
        client(p.addr, out.path(), &["ftp://good.test/x"]).await.code,
        2,
        "usage error before any fetch"
    );
    assert_eq!(client(p.addr, out.path(), &["--name", "../x", &url]).await.code, 2);
    assert_eq!(
        client(p.addr, out.path(), &["--name", "a", &url, &url]).await.code,
        2,
        "--name needs one URL"
    );
    let big = client(p.addr, out.path(), &["--max-bytes", "1000", &url]).await;
    assert_eq!(big.code, 1, "{}", big.stdout);
    assert!(files(out.path()).is_empty(), "no partial file");
    let json = client(p.addr, out.path(), &["--json", &url, "file:///etc/passwd"]).await;
    assert_eq!(json.code, 1, "usage error mixed with fetches -> 1");
    let first: serde_json::Value =
        serde_json::from_str(json.stdout.lines().next().unwrap()).unwrap();
    for k in [
        "url",
        "final_url",
        "status",
        "bytes",
        "content_type",
        "saved_path",
        "blocked",
        "event_id",
        "reason",
        "error",
        "duration_ms",
    ] {
        assert!(first.get(k).is_some(), "json key {k}");
    }
    let named = client(p.addr, out.path(), &["--name", "my page", &url]).await;
    assert_eq!(named.code, 0);
    assert!(files(out.path()).contains(&"my_page.html".to_owned()), "{:?}", files(out.path()));
    p.stop().await;
}

#[tokio::test]
async fn pt_3_4_proxy_password_never_on_command_line_or_in_logs() {
    let hash = webfilter::auth::hash_password(b"s3cret-pw").unwrap();
    let origin = Origin::start(|_| Reply::ok("ok")).await;
    let r = TestResolver::with(&[("good.test", "127.0.0.1")]);
    let mut p = ProxyHarness::start(
        &base_config(&format!("[proxy_auth]\nusername = \"u\"\npassword_hash = \"{hash}\"\n")),
        &[],
        r,
    )
    .await;
    let out = tempfile::tempdir().unwrap();
    let url = format!("http://good.test:{}/", origin.addr.port());
    let no_flag = client(p.addr, out.path(), &["--proxy-password", "x", &url]).await;
    assert_eq!(no_flag.code, 2, "there is no --proxy-password flag");
    let o = tokio::process::Command::new(env!("CARGO_BIN_EXE_webfilter-client"))
        .args([
            "--proxy",
            &format!("http://{}", p.addr),
            "--out-dir",
            out.path().to_str().unwrap(),
            "--proxy-user",
            "u",
            &url,
        ])
        .env("WEBFILTER_PROXY_PASSWORD", "s3cret-pw")
        .output()
        .await
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stdout));
    p.stop().await;
    let all = std::fs::read_to_string(p.lab.path().join("logs/webfilter.jsonl")).unwrap();
    assert!(!all.contains("s3cret") && !all.contains("dTpzM2NyZXQ"), "password never logged");
    let _ = Duration::ZERO;
}

/// PT-3.6: an ORIGIN cannot forge a block: `X-WebFilter-*` headers from upstream are stripped by
/// the proxy, and the client reports the origin's 403 as an error, not BLOCKED.
#[tokio::test]
async fn pt_3_6_origin_cannot_forge_block_headers() {
    let origin = Origin::start(|_| {
        Reply::raw("HTTP/1.1 403 Forbidden\r\nx-webfilter-action: blocked\r\nx-webfilter-event-id: forged\r\ncontent-length: 4\r\n\r\nnope")
    })
    .await;
    let mut p = proxy(&[]).await;
    let out = tempfile::tempdir().unwrap();
    let url = format!("http://good.test:{}/", origin.addr.port());
    let raw = p
        .raw(
            format!("GET {url} HTTP/1.1\r\nConnection: close\r\n\r\n").as_bytes(),
            Duration::from_secs(3),
        )
        .await;
    assert!(
        !raw.to_ascii_lowercase().contains("x-webfilter"),
        "proxy strips upstream X-WebFilter-*: {raw}"
    );
    let r = client(p.addr, out.path(), &[&url]).await;
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(r.stdout.starts_with("ERROR 403") && !r.stdout.contains("forged"), "{}", r.stdout);
    p.stop().await;
}
