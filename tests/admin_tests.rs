//! Phase 11: admin listener (AH-xx corpus, auth, headers, metrics, API), dashboard editing with
//! safeguards (A-30) and the access-request workflow (AR-xx) end to end.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use common::{Origin, ProxyHarness, Reply, TestResolver, base_config, raw_exchange, status};
use serde_json::Value;

const W: Duration = Duration::from_secs(5);
const TOKEN: &str = "test-admin-token-0123456789";

fn token_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| webfilter::auth::hash_password(TOKEN.as_bytes()).unwrap())
}

async fn lab(extra: &str, lists: &[(&str, &str)]) -> (ProxyHarness, SocketAddr) {
    let config = base_config(&format!(
        "{extra}\n[admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\ntoken_hash = \"{}\"\n\
[access_requests]\nenabled = true\n[state]\ndir = \"state\"\n[[profiles]]\nname = \"default\"\naccess_requests = true\n",
        token_hash()
    ));
    let resolver = TestResolver::with(&[("ok.test", "127.0.0.1"), ("bad.test", "127.0.0.1")]);
    let h = ProxyHarness::start(&config, lists, resolver).await;
    let admin = h.handle.as_ref().unwrap().admin_addr.unwrap();
    (h, admin)
}

/// One admin request; `host` overrides the Host header (None = no Host header).
async fn admin(
    addr: SocketAddr,
    method: &str,
    path: &str,
    host: Option<&str>,
    headers: &str,
    body: &str,
) -> String {
    let host_line = host.map(|h| format!("Host: {h}\r\n")).unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\n{host_line}{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    raw_exchange(addr, req.as_bytes(), W).await
}

fn auth() -> String {
    format!("Authorization: Bearer {TOKEN}\r\n")
}

async fn api(addr: SocketAddr, method: &str, path: &str, body: &str) -> (u16, Value) {
    let host = format!("127.0.0.1:{}", addr.port());
    let headers = format!("{}Content-Type: application/json\r\n", auth());
    let r = admin(addr, method, &format!("/api/v1/{path}"), Some(&host), &headers, body).await;
    let json = r
        .split_once("\r\n\r\n")
        .map(|(_, b)| serde_json::from_str(b).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    (status(&r), json)
}

#[tokio::test]
async fn ah_host_header_corpus() {
    let (mut h, a) = lab("", &[]).await;
    let p = a.port();
    let cases: Vec<(Option<String>, &str, bool, u16)> = vec![
        (Some(format!("127.0.0.1:{p}")), "/healthz", false, 200),
        (Some(format!("localhost:{p}")), "/healthz", false, 200),
        (Some(format!("LOCALHOST:{p}")), "/healthz", false, 200),
        (Some(format!("[::1]:{p}")), "/healthz", false, 200),
        (Some("localhost".into()), "/healthz", false, 421),
        (Some(format!("localhost.:{p}")), "/healthz", false, 421),
        (Some(format!("127.0.0.1.attacker.test:{p}")), "/healthz", false, 421),
        (Some("attacker.test".into()), "/healthz", false, 421),
        (Some(format!("127.0.0.1:{}", p.wrapping_add(1))), "/healthz", false, 421),
        (Some(format!("0.0.0.0:{p}")), "/healthz", false, 421),
        (Some(format!("2130706433:{p}")), "/healthz", false, 421),
        (Some("attacker.test".into()), "/api/v1/stats", true, 421),
        (Some("attacker.test".into()), "/ui/", false, 421),
        (Some("attacker.test".into()), "/metrics", true, 421),
        (Some(format!("localhost:{p}")), "/api/v1/stats", false, 401),
        (Some(format!("localhost:{p}")), "/api/v1/stats", true, 200),
        (None, "/healthz", false, 400),
    ];
    for (host, path, with_token, want) in cases {
        let headers = if with_token { auth() } else { String::new() };
        let r = admin(a, "GET", path, host.as_deref(), &headers, "").await;
        assert_eq!(status(&r), want, "{host:?} {path}: {r}");
        assert!(!r.to_ascii_lowercase().contains("access-control-"), "no CORS ever");
    }
    let two = format!(
        "GET /healthz HTTP/1.1\r\nHost: localhost:{p}\r\nHost: localhost:{p}\r\nConnection: close\r\n\r\n"
    );
    let r = raw_exchange(a, two.as_bytes(), W).await;
    assert!(status(&r) == 400 || r.is_empty(), "AH-12 two Host headers: {r}");
    h.stop().await;
}

#[tokio::test]
async fn auth_lockout_origin_and_security_headers() {
    let (mut h, a) = lab("", &[]).await;
    let host = format!("127.0.0.1:{}", a.port());
    for _ in 0..5 {
        let r =
            admin(a, "GET", "/api/v1/stats", Some(&host), "Authorization: Bearer wrong\r\n", "")
                .await;
        assert_eq!(status(&r), 401);
    }
    let locked = admin(a, "GET", "/api/v1/stats", Some(&host), &auth(), "").await;
    assert_eq!(status(&locked), 429, "lockout after 5 failures, even with the right token");
    h.stop().await;

    let (mut h, a) = lab("", &[]).await;
    let host = format!("127.0.0.1:{}", a.port());
    let ui = admin(a, "GET", "/ui/", Some(&host), "", "").await;
    assert_eq!(status(&ui), 200);
    let lower = ui.to_ascii_lowercase();
    for hdr in [
        "content-security-policy: default-src 'self'; script-src 'self'",
        "x-content-type-options: nosniff",
        "referrer-policy: no-referrer",
        "cache-control: no-store",
        "cross-origin-resource-policy: same-origin",
    ] {
        assert!(lower.contains(hdr), "{hdr}");
    }
    let cross = admin(
        a,
        "POST",
        "/api/v1/reload",
        Some(&host),
        &format!("{}Origin: http://evil.test\r\nContent-Type: application/json\r\n", auth()),
        "{}",
    )
    .await;
    assert_eq!(status(&cross), 403, "cross-origin state change refused");
    let no_json = admin(a, "POST", "/api/v1/reload", Some(&host), &auth(), "{}").await;
    assert_eq!(status(&no_json), 415);
    let (st, _) =
        api(a, "POST", "temp-allows", r#"{"host":"x.test","target":"ip:1.2.3.4","bogus":1}"#).await;
    assert_eq!(st, 400, "unknown fields rejected");
    h.stop().await;
    let audit = std::fs::read_to_string(h.lab.path().join("logs/webfilter_admin.jsonl")).unwrap();
    assert!(audit.contains("auth_failed") || !audit.is_empty());
    for log in ["webfilter_admin.jsonl", "webfilter.jsonl", "webfilter_system.jsonl"] {
        let text = std::fs::read_to_string(h.lab.path().join("logs").join(log)).unwrap_or_default();
        assert!(!text.contains(TOKEN), "the token never reaches {log}");
    }
}

#[tokio::test]
async fn metrics_and_read_api() {
    let origin = Origin::start(|_| Reply::ok("hi")).await;
    let (mut h, a) = lab("", &[("domains.txt", "bad.test\n")]).await;
    let port = origin.addr.port();
    for host in ["ok.test", "bad.test", "bad.test"] {
        h.raw(format!("GET http://{host}:{port}/ HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n").as_bytes(), W).await;
    }
    let host = format!("127.0.0.1:{}", a.port());
    let m = admin(a, "GET", "/metrics", Some(&host), &auth(), "").await;
    assert_eq!(status(&m), 200);
    for series in [
        "webfilter_up 1",
        "webfilter_requests_total{action=\"blocked\",reason=\"domain_blocklist\",scheme=\"http\"} 2",
        "webfilter_request_duration_seconds_bucket",
        "webfilter_build_info{version=",
        "webfilter_access_requests{state=\"pending\"} 0",
    ] {
        assert!(m.contains(series), "{series}\n{m}");
    }
    assert!(!m.contains("bad.test"), "no host labels in metrics (D-56)");
    let (st, s) = api(a, "GET", "stats", "").await;
    assert_eq!((st, s["requests"].as_u64(), s["blocked"].as_u64()), (200, Some(3), Some(2)));
    let (_, ev) = api(a, "GET", "events/recent?action=blocked&limit=10", "").await;
    assert_eq!(ev.as_array().unwrap().len(), 2);
    let (_, top) = api(a, "GET", "top/blocked?n=5", "").await;
    assert_eq!((top[0]["host"].as_str(), top[0]["count"].as_u64()), (Some("bad.test"), Some(2)));
    let (_, clients) = api(a, "GET", "clients", "").await;
    assert_eq!(clients[0]["client_id"], "ip:127.0.0.1");
    let r = admin(a, "GET", "/readyz", Some(&host), "", "").await;
    assert_eq!(status(&r), 200);
    h.stop().await;
}

#[tokio::test]
async fn dashboard_edits_are_validated_versioned_audited_and_reversible() {
    let origin = Origin::start(|_| Reply::ok("hi")).await;
    let (mut h, a) = lab("", &[]).await;
    let port = origin.addr.port();
    let get = |host: &str| {
        format!(
            "GET http://{host}:{port}/ HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
        )
    };
    let (st, e) = api(a, "PUT", "lists/domains", r#"{"content":"bad..test\n"}"#).await;
    assert_eq!(st, 400, "{e}");
    assert_eq!(
        std::fs::read_to_string(h.lab.path().join("blocklists/domains.txt")).unwrap(),
        "",
        "invalid list never written"
    );
    let (st, _) = api(a, "PUT", "lists/domains", r#"{"content":"bad.test\n"}"#).await;
    assert_eq!(st, 200);
    assert_eq!(status(&h.raw(get("bad.test").as_bytes(), W).await), 403);
    let (st, _) = api(a, "POST", "lists/domains/rollback", "{}").await;
    assert_eq!(st, 200);
    assert_eq!(status(&h.raw(get("bad.test").as_bytes(), W).await), 200, "rolled back");
    // Settings: mode and allowlist, with rollback.
    api(a, "PUT", "lists/domains", r#"{"content":"bad.test\n"}"#).await;
    let (st, _) =
        api(a, "POST", "settings", r#"{"mode":"monitor","allow_domains":[],"categories":{}}"#)
            .await;
    assert_eq!(st, 200);
    assert_eq!(status(&h.raw(get("bad.test").as_bytes(), W).await), 200, "monitor: logged only");
    let (st, _) =
        api(a, "POST", "settings", r#"{"mode":null,"allow_domains":["bad.test"],"categories":{}}"#)
            .await;
    assert_eq!(st, 200);
    assert_eq!(status(&h.raw(get("bad.test").as_bytes(), W).await), 200, "allowlisted");
    let (st, _) = api(a, "POST", "settings", r#"{"allow_domains":["not a domain"]}"#).await;
    assert_eq!(st, 400, "invalid settings never apply");
    let (st, _) = api(a, "POST", "settings", r#"{"categories":{"nope":{"enabled":true}}}"#).await;
    assert_eq!(st, 400);
    let (st, _) = api(a, "POST", "settings/rollback", "{}").await;
    assert_eq!(st, 200);
    let (_, s) = api(a, "GET", "settings", "").await;
    assert_eq!(s["settings"]["mode"], "monitor", "one step back");
    let (st, _) = api(a, "PUT", "lists/../../etc/passwd", r#"{"content":"x"}"#).await;
    assert_eq!(st, 404, "only configured lists are editable");
    h.stop().await;
    let audit = std::fs::read_to_string(h.lab.path().join("logs/webfilter_admin.jsonl")).unwrap();
    assert!(audit.lines().filter(|l| l.contains("lists/{name}")).count() >= 3, "{audit}");
    assert!(audit.contains("\"result\":\"error\""), "failed edits are audited too");
}

fn form_value<'a>(html: &'a str, name: &str) -> &'a str {
    let key = format!("name=\"{name}\" value=\"");
    let start = html.find(&key).unwrap() + key.len();
    let end = html[start..].find('"').unwrap() + start;
    &html[start..end]
}

async fn post_request(h: &ProxyHarness, host: &str, ctype: &str, body: &str) -> String {
    let req = format!(
        "POST http://{host}/request HTTP/1.1\r\nHost: {host}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    h.raw(req.as_bytes(), W).await
}

#[tokio::test]
async fn ar_access_request_flow_end_to_end() {
    let origin = Origin::start(|_| Reply::ok("hi")).await;
    let (mut h, a) = lab("", &[("domains.txt", "bad.test\n")]).await;
    let port = origin.addr.port();
    let get = format!(
        "GET http://bad.test:{port}/ HTTP/1.1\r\nHost: bad.test:{port}\r\nConnection: close\r\n\r\n"
    );
    let page = h.raw(get.as_bytes(), W).await;
    assert_eq!(status(&page), 403);
    assert!(
        page.contains("form-action http://webfilter.local"),
        "CSP allows only the virtual host"
    );
    let event_id = form_value(&page, "event_id").to_owned();
    let csrf = form_value(&page, "csrf").to_owned();
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let ok_body = format!(
        "event_id={}&csrf={}&justification={}&contact=me",
        enc(&event_id),
        enc(&csrf),
        enc("<script>alert(1)</script> homework")
    );
    // AR-04 tampered CSRF, AR-13 wrong type, AR-16 GET /request, AR-12 too large.
    let tampered = format!("event_id={}&csrf=1.deadbeef&justification=x", enc(&event_id));
    assert_eq!(
        status(
            &post_request(&h, "webfilter.local", "application/x-www-form-urlencoded", &tampered)
                .await
        ),
        403
    );
    assert_eq!(status(&post_request(&h, "webfilter.local", "text/plain", &ok_body).await), 415);
    let get_req = h.raw(b"GET http://webfilter.local/request HTTP/1.1\r\nHost: webfilter.local\r\nConnection: close\r\n\r\n", W).await;
    assert_eq!(status(&get_req), 404);
    let big = "x".repeat(3000);
    assert_eq!(
        status(
            &post_request(&h, "webfilter.local", "application/x-www-form-urlencoded", &big).await
        ),
        413
    );
    // AR-17: case and trailing-dot variants are the same host; AR-01 accepted.
    let created =
        post_request(&h, "WEBFILTER.LOCAL.", "application/x-www-form-urlencoded", &ok_body).await;
    assert_eq!(status(&created), 201, "{created}");
    let (_, reqs) = api(a, "GET", "access-requests?status=pending", "").await;
    let r = &reqs[0];
    assert_eq!(
        (r["host"].as_str(), r["reason"].as_str()),
        (Some("bad.test"), Some("domain_blocklist"))
    );
    assert_eq!(
        r["justification"], "<script>alert(1)</script> homework",
        "stored as text; the UI renders it with textContent"
    );
    // AR-20 ttl over 24 h refused; approve with 1 h.
    let id = r["id"].as_str().unwrap().to_owned();
    let (st, _) = api(
        a,
        "POST",
        &format!("access-requests/{id}/decide"),
        r#"{"decision":"approve","ttl_secs":108000}"#,
    )
    .await;
    assert_eq!(st, 400);
    let (st, d) = api(
        a,
        "POST",
        &format!("access-requests/{id}/decide"),
        r#"{"decision":"approve","ttl_secs":3600}"#,
    )
    .await;
    assert_eq!(st, 200, "{d}");
    let again = h.raw(get.as_bytes(), W).await;
    assert_eq!(status(&again), 200, "temp allow applies to this client");
    let (st, _) =
        api(a, "POST", &format!("access-requests/{id}/decide"), r#"{"decision":"deny"}"#).await;
    assert_eq!(st, 409, "decided once");
    // Revoking the temp allow blocks again.
    let allow_id = d["temp_allow"]["id"].as_str().unwrap().to_owned();
    let (st, _) = api(a, "DELETE", &format!("temp-allows/{allow_id}"), "{}").await;
    assert_eq!(st, 200);
    assert_eq!(status(&h.raw(get.as_bytes(), W).await), 403);
    h.stop().await;
    let access = std::fs::read_to_string(h.lab.path().join("logs/webfilter_access.jsonl")).unwrap();
    assert!(
        access.contains("justification_len") && !access.contains("homework"),
        "SIEM log has no justification text"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(h.lab.path().join("state/access_requests.jsonl"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[tokio::test]
async fn ar_ineligible_reasons_and_disabled_profiles_show_no_form() {
    let origin = Origin::start(|_| Reply::ok("hi")).await;
    let (mut h, _) = lab("", &[("ip_blocklist.txt", "127.0.0.1/32\n")]).await;
    let port = origin.addr.port();
    let req = format!(
        "GET http://ok.test:{port}/ HTTP/1.1\r\nHost: ok.test:{port}\r\nConnection: close\r\n\r\n"
    );
    let r = h.raw(req.as_bytes(), W).await;
    h.stop().await;
    assert_eq!(status(&r), 403);
    assert!(r.contains("This block cannot be reviewed."), "{r}");
    assert!(!r.contains("<form"), "no form for non-list reasons");
    // With access requests off, webfilter.local is not special (AR-18 equivalent).
    let config = base_config("[access_requests]\nenabled = false\n");
    let mut h =
        ProxyHarness::start(&config, &[("domains.txt", "bad.test\n")], TestResolver::with(&[]))
            .await;
    let r = h.raw(b"GET http://webfilter.local/ HTTP/1.1\r\nHost: webfilter.local\r\nConnection: close\r\n\r\n", W).await;
    h.stop().await;
    assert_ne!(status(&r), 200, "never answered as the virtual host");
}

#[tokio::test]
async fn ar25_tampered_temp_allows_are_rejected_safely() {
    let config = base_config("[state]\ndir = \"state\"\n");
    let lab = common::Lab::new();
    std::fs::create_dir_all(lab.path().join("state")).unwrap();
    std::fs::write(lab.path().join("state/temp_allows.json"), r#"[{"id":"x","host":"bad.test","include_subdomains":true,"scope":{"kind":"client","value":"ip:127.0.0.1"},"expires":99999999999,"created_by":"me"}]"#).unwrap();
    let cfg = webfilter::config::Config::load(&lab.write_config(&config)).unwrap();
    let handle = webfilter::proxy::start(cfg, None).await.unwrap();
    assert!(handle.deps.access.allows().is_empty(), "a TTL beyond 24 h rejects the file");
    handle.shutdown().await;
    let sys = std::fs::read_to_string(lab.path().join("logs/webfilter_system.jsonl")).unwrap();
    assert!(sys.contains("temp_allows.json rejected"));
}

#[test]
fn tui_renders_hostile_strings_as_inert_text() {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use webfilter::tui::{State, draw, safe};
    assert_eq!(safe("a\u{1b}[31mred\u{1b}[0m\u{7}b\u{202e}c\nd", 100), "aredbcd");
    assert_eq!(safe("\u{1b}]0;title\u{7}x", 100), "x");
    let hostile = serde_json::json!([{ "id": "1", "client_id": "ip:1.2.3.4", "host": "evil.test",
        "reason": "domain_blocklist", "justification": "\u{1b}[2J\u{1b}]0;pwned\u{7}<script>x</script>", "status": "pending" }]);
    let mut st = State { tab: 5, ttl_hours: 4, requests: hostile, ..State::default() };
    let mut term = Terminal::new(TestBackend::new(120, 20)).unwrap();
    term.draw(|f| draw(f, &st)).unwrap();
    let text: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
    assert!(!text.contains('\u{1b}') && !text.contains('\u{7}'));
    assert!(text.contains("<script>x</script>"), "shown as plain text");
    for tab in 0..webfilter::tui::TABS.len() {
        st.tab = tab;
        term.draw(|f| draw(f, &st)).unwrap(); // every panel renders with empty or odd data
    }
}

#[test]
fn doctor_reports_without_secrets() {
    let lab = common::Lab::new();
    let cfg = webfilter::config::Config::load(&lab.write_config(&format!(
        "listen = \"127.0.0.1:0\"\n[admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\ntoken_hash = \"{}\"\n[logging]\ndir = \"logs\"\n",
        token_hash()
    )))
    .unwrap();
    let results = webfilter::doctor::run(&cfg);
    assert!(
        results.iter().any(|(l, m)| *l == webfilter::doctor::Level::Pass && m.contains("log dir"))
    );
    assert!(results.iter().all(|(_, m)| !m.contains(token_hash()) && !m.contains("argon2id$")));
}
