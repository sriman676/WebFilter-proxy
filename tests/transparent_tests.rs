//! Phase 7 (transparent mode) without root: E-51 equivalents of E-44..E-50 and the PT-7 cases,
//! with the original destination injected (`FixedOriginalDst`, D-43), plus E-48 against the
//! real `SO_ORIGINAL_DST` (a direct connection has no redirected destination).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]
#![cfg(target_os = "linux")]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{
    Lab, Origin, Reply, TestPki, TestResolver, raw_exchange, sni_ext, status, synthetic_hello,
};
use rustls::pki_types::ServerName;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use webfilter::proxy::transparent::{FixedOriginalDst, OriginalDst, parse_conntrack};

const W: Duration = Duration::from_secs(5);

struct T {
    lab: Lab,
    handle: Option<webfilter::proxy::ProxyHandle>,
    http: SocketAddr,
    tls: SocketAddr,
    proxy_ca: String,
}

impl T {
    async fn start(extra: &str, lists: &[(&str, &str)], orig: Arc<dyn OriginalDst>) -> Self {
        Self::start_private(false, extra, lists, orig).await
    }

    async fn start_private(
        deny_private: bool,
        extra: &str,
        lists: &[(&str, &str)],
        orig: Arc<dyn OriginalDst>,
    ) -> Self {
        let lab = Lab::new();
        for (name, body) in lists {
            lab.write_list(name, body);
        }
        let cfg = format!(
            "listen = \"127.0.0.1:0\"\n[ports]\nhttp_allowed = \"any\"\nconnect_allowed = \"any\"\n\
[destination]\ndeny_private_ranges = {deny_private}\n[logging]\ndir = \"logs\"\n\
[transparent]\nenabled = true\nacknowledge_lab_only = true\nhttp_listen = \"127.0.0.1:0\"\ntls_listen = \"127.0.0.1:0\"\n{extra}"
        );
        let cfg = webfilter::config::Config::load(&lab.write_config(&cfg)).unwrap();
        let resolver = TestResolver::with(&[
            ("site.test", "127.0.0.1"),
            ("tls.test", "127.0.0.1"),
            ("pass.test", "127.0.0.1"),
            ("elsewhere.test", "10.9.9.9"),
        ]);
        let handle = webfilter::proxy::start_with(
            cfg,
            Some(resolver as Arc<dyn webfilter::policy::Resolver>),
            Some(orig),
        )
        .await
        .unwrap();
        let (http, tls) = handle.transparent_addrs.unwrap();
        let proxy_ca = std::fs::read_to_string(lab.path().join("ca/ca.pem")).unwrap_or_default();
        Self { lab, handle: Some(handle), http, tls, proxy_ca }
    }

    async fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.shutdown().await;
        }
    }

    fn lines(&self, file: &str) -> Vec<Value> {
        std::fs::read_to_string(self.lab.path().join("logs").join(file))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

fn fixed(addr: SocketAddr) -> Arc<dyn OriginalDst> {
    Arc::new(FixedOriginalDst(addr))
}

fn ok_origin() -> impl Fn(&[u8]) -> Reply + Send + Sync + 'static {
    |_| Reply::ok("<html>origin</html>")
}

// ------------------------------------------------------------------------------------ HTTP

#[tokio::test]
async fn e44_transparent_http_forwarded_to_original_ip_and_logged() {
    let origin = Origin::start(ok_origin()).await;
    let mut t = T::start("", &[], fixed(origin.addr)).await;
    let resp = raw_exchange(
        t.http,
        b"GET /page?q=1 HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        W,
    )
    .await;
    assert_eq!(status(&resp), 200, "{resp}");
    t.stop().await;
    let seen = origin.requests();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("GET /page?q=1 HTTP/1.1\r\n"), "{}", seen[0]);
    assert!(
        seen[0].to_ascii_lowercase().contains(&format!("host: site.test:{}", origin.addr.port()))
    );
    let v = &t.lines("webfilter.jsonl")[0];
    assert_eq!(v["transparent"], true);
    assert_eq!(v["orig_dst_ip"], "127.0.0.1");
    assert_eq!(v["orig_dst_port"], origin.addr.port());
    assert_eq!(v["host_verified"], true);
    assert_eq!(v["dest_host"], "site.test");
    assert_eq!(v["dest_ip"], "127.0.0.1");
}

#[tokio::test]
async fn e44_blocked_domain_and_original_ip_rules() {
    let origin = Origin::start(ok_origin()).await;
    let mut t = T::start(
        "",
        &[("domains.txt", "site.test\n"), ("ip_blocklist.txt", "")],
        fixed(origin.addr),
    )
    .await;
    let resp =
        raw_exchange(t.http, b"GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n", W)
            .await;
    assert_eq!(status(&resp), 403);
    assert!(resp.contains("x-webfilter-reason: domain_blocklist"));
    t.stop().await;
    assert!(origin.requests().is_empty());
    // IP rules use the ORIGINAL destination even when the Host name is allowed (D-42).
    let mut t = T::start("", &[("ip_blocklist.txt", "127.0.0.1/32\n")], fixed(origin.addr)).await;
    let resp =
        raw_exchange(t.http, b"GET / HTTP/1.1\r\nHost: tls.test\r\nConnection: close\r\n\r\n", W)
            .await;
    assert_eq!(status(&resp), 403);
    assert!(resp.contains("x-webfilter-reason: ip_blocklist"));
    t.stop().await;
    assert!(origin.requests().is_empty());
}

#[tokio::test]
async fn e46_host_verification_strict_and_relaxed() {
    let origin = Origin::start(ok_origin()).await;
    let req = b"GET / HTTP/1.1\r\nHost: elsewhere.test\r\nConnection: close\r\n\r\n";
    let mut t = T::start("", &[], fixed(origin.addr)).await;
    let resp = raw_exchange(t.http, req, W).await;
    assert_eq!(status(&resp), 403);
    assert!(resp.contains("x-webfilter-reason: host_mismatch"));
    t.stop().await;
    assert!(origin.requests().is_empty(), "strict: never forwarded");
    let mut t = T::start("host_verify = \"relaxed\"\n", &[], fixed(origin.addr)).await;
    assert_eq!(status(&raw_exchange(t.http, req, W).await), 200);
    t.stop().await;
    assert_eq!(origin.requests().len(), 1, "relaxed: forwarded to the ORIGINAL IP, not 10.9.9.9");
    let v = &t.lines("webfilter.jsonl")[0];
    assert_eq!(v["host_verified"], false);
    assert_eq!(v["dest_ip"], "127.0.0.1");
}

#[tokio::test]
async fn pt_7_2_request_shape_rules() {
    let origin = Origin::start(ok_origin()).await;
    let mut t = T::start("", &[], fixed(origin.addr)).await;
    let port = origin.addr.port();
    let cases: Vec<(String, u16)> = vec![
        ("GET http://site.test/ HTTP/1.1\r\nHost: site.test\r\n\r\n".into(), 400), // absolute-form
        ("CONNECT site.test:443 HTTP/1.1\r\nHost: site.test:443\r\n\r\n".into(), 400),
        ("GET / HTTP/1.1\r\n\r\n".into(), 400), // no Host
        ("GET / HTTP/1.1\r\nHost: site.test\r\nHost: site.test\r\n\r\n".into(), 400),
        (format!("GET / HTTP/1.1\r\nHost: site.test:{}\r\n\r\n", port.wrapping_add(1)), 403),
        ("GET / HTTP/1.1\r\nHost: user@site.test\r\n\r\n".into(), 403),
        (format!("GET / HTTP/1.1\r\nHost: SITE.test.:{port}\r\nConnection: close\r\n\r\n"), 200),
        ("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".into(), 200), // IP literal = orig
    ];
    for (req, want) in &cases {
        let resp = raw_exchange(t.http, req.as_bytes(), W).await;
        assert_eq!(status(&resp), *want, "{req:?} -> {resp}");
    }
    t.stop().await;
    assert_eq!(origin.requests().len(), 2, "only the two valid requests reach the origin");
}

#[tokio::test]
async fn transparent_http_applies_destination_policy_to_the_original_ip() {
    let origin = Origin::start(ok_origin()).await;
    let mut t = T::start_private(true, "", &[], fixed(origin.addr)).await;
    let req = b"GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n";
    let resp = raw_exchange(t.http, req, W).await;
    assert_eq!(status(&resp), 403, "{resp}");
    assert!(resp.contains("x-webfilter-reason: private_range"));
    t.stop().await;
    assert!(origin.requests().is_empty());
}

// ------------------------------------------------------------------------------------ E-48 / loops

/// Simulates an un-redirected connection: the "original" destination is the listener itself.
struct NotRedirected;
impl OriginalDst for NotRedirected {
    fn original_dst(&self, s: &tokio::net::TcpStream) -> std::io::Result<SocketAddr> {
        s.local_addr()
    }
}

#[tokio::test]
async fn e48_direct_connections_closed_never_proxied() {
    for orig in [
        Arc::new(NotRedirected) as Arc<dyn OriginalDst>,
        Arc::new(webfilter::proxy::transparent::SoOriginalDst),
    ] {
        let mut t = T::start("", &[], orig).await;
        let http = raw_exchange(t.http, b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\n", W).await;
        assert!(http.is_empty(), "closed without an answer: {http}");
        let tls = raw_exchange(t.tls, &synthetic_hello(&[sni_ext("tls.test")]), W).await;
        assert!(tls.is_empty());
        t.stop().await;
        let failed = t
            .lines("webfilter_system.jsonl")
            .into_iter()
            .filter(|v| v["kind"] == "orig_dst_failed")
            .count();
        assert_eq!(failed, 2);
        assert!(t.lines("webfilter.jsonl").is_empty(), "no request was processed");
    }
}

#[tokio::test]
async fn e49_original_destination_is_the_proxy_itself_is_a_loop() {
    // Every proxy listener counts as "own": an original destination equal to one is a loop.
    let mut t = T::start("", &[], Arc::new(NotRedirected)).await;
    let addr = t.handle.as_ref().unwrap().local_addr;
    let own = t.handle.as_ref().unwrap().deps.policy.check_ip(addr.ip(), addr.port());
    assert_eq!(own, Err(webfilter::reason::Reason::LoopDetected));
    let own_tls = t.handle.as_ref().unwrap().deps.policy.check_ip(t.tls.ip(), t.tls.port());
    assert_eq!(own_tls, Err(webfilter::reason::Reason::LoopDetected));
    t.stop().await;
}

// ------------------------------------------------------------------------------------ TLS

struct TlsLab {
    t: T,
    origin: Origin,
    pki: TestPki,
}

async fn tls_lab(extra: &str, lists: &[(&str, &str)]) -> TlsLab {
    let pki = TestPki::new();
    let origin =
        Origin::start_tls(pki.leaf(&["tls.test", "pass.test", "127.0.0.1"], false), ok_origin())
            .await;
    let dir = tempfile::tempdir().unwrap().keep();
    let origin_ca = pki.write_ca(&dir);
    let extra = format!(
        "{extra}\n[tls]\nintercept = true\nca_dir = \"ca\"\nupstream_ca_bundle = \"{}\"\npassthrough_domains = [\"pass.test\"]\n",
        origin_ca.display()
    );
    let t = T::start(&extra, lists, fixed(origin.addr)).await;
    TlsLab { t, origin, pki }
}

async fn tls_get(
    addr: SocketAddr,
    name: &str,
    ca_pem: &str,
    host: &str,
) -> std::io::Result<String> {
    let s = tokio::net::TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from(name.to_owned()).unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(common::client_config(ca_pem, &[]))
        .connect(server_name, s)
        .await?;
    tls.write_all(
        format!("GET /inner HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(W, tls.read_to_end(&mut out)).await;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[tokio::test]
async fn e45_transparent_tls_intercepted_inner_url_filtered() {
    let mut l = tls_lab("", &[("url_patterns.txt", "/blocked\n")]).await;
    let host = format!("tls.test:{}", l.origin.addr.port());
    let resp = tls_get(l.t.tls, "tls.test", &l.t.proxy_ca, &host).await.unwrap();
    assert_eq!(status(&resp), 200, "{resp}");
    // The inner Host must equal the SNI host (D-22).
    let resp = tls_get(l.t.tls, "tls.test", &l.t.proxy_ca, "other.test").await.unwrap();
    assert_eq!(status(&resp), 403);
    l.t.stop().await;
    assert_eq!(l.origin.requests().len(), 1);
    let inner: Vec<Value> =
        l.t.lines("webfilter.jsonl").into_iter().filter(|v| v["http_method"] == "GET").collect();
    assert!(inner.iter().all(|v| v["transparent"] == true && v["tls_intercepted"] == true));
    assert_eq!(inner[0]["orig_dst_port"], l.origin.addr.port());
    assert_eq!(inner[0]["host_verified"], true);
    assert_eq!(inner[0]["tls_sni"], "tls.test");
}

#[tokio::test]
async fn e47_no_sni_and_ech_block_by_default_ip_only_relays() {
    let mut l = tls_lab("", &[]).await;
    // rustls sends no SNI for an IP-address server name.
    assert!(tls_get(l.t.tls, "127.0.0.1", &l.pki.ca_pem, "127.0.0.1").await.is_err());
    let ech = raw_exchange(
        l.t.tls,
        &synthetic_hello(&[sni_ext("public.test"), (0xfe0d, vec![0, 1, 2])]),
        W,
    )
    .await;
    assert!(ech.is_empty());
    l.t.stop().await;
    let reasons: Vec<Value> =
        l.t.lines("webfilter.jsonl").into_iter().map(|v| v["reason"].clone()).collect();
    assert!(reasons.contains(&Value::from("no_sni")), "{reasons:?}");
    assert!(reasons.contains(&Value::from("ech_blocked")), "{reasons:?}");
    // ip_only: relayed to the original destination with only IP rules; the client talks to
    // the real origin (its certificate, not a minted one).
    let mut l = tls_lab("no_sni_action = \"ip_only\"\n", &[]).await;
    let resp = tls_get(l.t.tls, "127.0.0.1", &l.pki.ca_pem, "127.0.0.1").await.unwrap();
    assert_eq!(status(&resp), 200, "{resp}");
    l.t.stop().await;
}

#[tokio::test]
async fn e50_passthrough_domain_replays_client_hello() {
    let mut l = tls_lab("", &[]).await;
    let host = format!("pass.test:{}", l.origin.addr.port());
    // Trusts only the ORIGIN CA: succeeds only if the proxy did not intercept.
    let resp = tls_get(l.t.tls, "pass.test", &l.pki.ca_pem, &host).await.unwrap();
    assert_eq!(status(&resp), 200, "{resp}");
    l.t.stop().await;
    let v = &l.t.lines("webfilter.jsonl")[0];
    assert_eq!(
        (v["transparent"].clone(), v["tls_intercepted"].clone()),
        (Value::from(true), Value::from(false))
    );
    assert_eq!(v["tls_sni"], "pass.test");
}

#[tokio::test]
async fn pt_7_3_sni_rules_and_non_tls_bytes() {
    let mut l = tls_lab("", &[("domains.txt", "tls.test\n")]).await;
    // A blocked SNI is closed before any handshake; uppercase/trailing-dot variants too.
    for sni in ["tls.test", "TLS.TEST", "tls.test."] {
        let out = raw_exchange(l.t.tls, &synthetic_hello(&[sni_ext(sni)]), W).await;
        assert!(out.is_empty(), "{sni}");
    }
    let out = raw_exchange(l.t.tls, b"GET / HTTP/1.1\r\nHost: tls.test\r\n\r\n", W).await;
    assert!(out.is_empty());
    l.t.stop().await;
    let lines = l.t.lines("webfilter.jsonl");
    assert!(lines.iter().filter(|v| v["reason"] == "domain_blocklist").count() >= 1);
    assert!(lines.iter().any(|v| v["reason"] == "non_tls_on_connect"));
    assert!(l.origin.requests().is_empty());
}

// ------------------------------------------------------------------------------------ units

#[test]
fn conntrack_lookup() {
    let table = "\
ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=93.184.216.34 sport=51234 dport=80 src=127.0.0.1 dst=10.0.0.2 sport=18880 dport=51234 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 10 SYN_SENT src=10.0.0.3 dst=1.1.1.1 sport=4000 dport=443 [UNREPLIED] src=1.1.1.1 dst=10.0.0.3 sport=443 dport=4000 mark=0 use=1
ipv6     10 tcp      6 431999 ESTABLISHED src=fd00::2 dst=2001:db8::80 sport=40000 dport=443 src=::1 dst=fd00::2 sport=18443 dport=40000 [ASSURED] mark=0 use=2
garbage line src=
";
    let local: SocketAddr = "127.0.0.1:18880".parse().unwrap();
    assert_eq!(
        parse_conntrack(table, "10.0.0.2:51234".parse().unwrap(), local),
        Some("93.184.216.34:80".parse().unwrap())
    );
    assert_eq!(
        parse_conntrack(table, "10.0.0.2:51235".parse().unwrap(), local),
        None,
        "other port"
    );
    assert_eq!(
        parse_conntrack(table, "10.0.0.3:4000".parse().unwrap(), local),
        None,
        "not redirected to our listener"
    );
    assert_eq!(
        parse_conntrack(table, "[fd00::2]:40000".parse().unwrap(), "[::1]:18443".parse().unwrap()),
        Some("[2001:db8::80]:443".parse().unwrap())
    );
}

#[test]
fn config_requires_acknowledgement_and_distinct_listeners() {
    let dir = tempfile::tempdir().unwrap();
    let parse = |extra: &str| {
        webfilter::config::Config::parse(
            &format!("listen = \"127.0.0.1:8080\"\n[transparent]\nenabled = true\n{extra}"),
            dir.path(),
            None,
        )
    };
    let err = parse("").unwrap_err().to_string();
    assert!(err.contains("acknowledge_lab_only"), "{err}");
    let err = parse("acknowledge_lab_only = true\nhttp_listen = \"127.0.0.1:8080\"\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("must differ"), "{err}");
}
