//! Phase 4 (TLS interception): U-tls, I-ca-perms, ClientHello peek, E-03, E-06, E-17, E-18,
//! E-34, non-TLS on CONNECT, E-30 canaries inside tunnels.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::{Origin, ProxyHarness, Reply, TestPki, TestResolver, base_config, status};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use webfilter::normalize::Host;
use webfilter::tls::{CaStore, LeafCache, Peek, is_passthrough, peek_client_hello};

const W: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------- U-tls / I-ca-perms

#[test]
fn ca_generate_perms_no_overwrite_and_reload() {
    let dir = tempfile::tempdir().unwrap();
    let ca_dir = dir.path().join("ca");
    let ca = CaStore::generate(&ca_dir).unwrap();
    assert!(ca.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&ca_dir.join("ca.key")), 0o600);
        assert_eq!(mode(&ca_dir), 0o700);
    }
    assert!(CaStore::generate(&ca_dir).is_err(), "never overwrites an existing CA");
    let again = CaStore::load(&ca_dir).unwrap();
    assert_eq!(again.cert_pem, ca.cert_pem);
    assert!(!format!("{again:?}").contains("PRIVATE"), "Debug never prints the key");
}

#[cfg(unix)]
#[test]
fn i_ca_perms_loose_key_and_symlink_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let ca_dir = dir.path().join("ca");
    CaStore::generate(&ca_dir).unwrap();
    let key = ca_dir.join("ca.key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(CaStore::load(&ca_dir).unwrap_err().to_string().contains("0600"));
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let real = dir.path().join("real.key");
    std::fs::rename(&key, &real).unwrap();
    std::os::unix::fs::symlink(&real, &key).unwrap();
    assert!(CaStore::load(&ca_dir).unwrap_err().to_string().contains("symlink"));
}

#[test]
fn leaf_san_validity_key_type_and_unique_serials() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CaStore::generate(&dir.path().join("ca")).unwrap();
    let mut serials = std::collections::HashSet::new();
    for host in [
        Host::Domain("good.test".into()),
        Host::Ipv4("10.1.2.3".parse().unwrap()),
        Host::Ipv6("2001:db8::1".parse().unwrap()),
    ] {
        let (chain, _) = ca.mint(&host).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(chain[0].as_ref()).unwrap();
        let san = cert.subject_alternative_name().unwrap().unwrap().value.general_names.clone();
        assert_eq!(san.len(), 1, "SAN = exactly the requested host");
        let lifetime =
            cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
        assert!((24 * 3600..=24 * 3600 + 600).contains(&lifetime), "about 24 h, got {lifetime}");
        assert_eq!(
            cert.public_key().algorithm.algorithm.to_id_string(),
            "1.2.840.10045.2.1",
            "EC key"
        );
        assert!(serials.insert(cert.raw_serial().to_vec()), "serials unique");
        assert!(!cert.is_ca());
    }
}

#[test]
fn leaf_cache_reuses_and_is_bounded_per_host() {
    let dir = tempfile::tempdir().unwrap();
    let leaves = LeafCache::new(CaStore::generate(&dir.path().join("ca")).unwrap());
    let a = leaves.server_config_for(&Host::Domain("a.test".into())).unwrap();
    let a2 = leaves.server_config_for(&Host::Domain("a.test".into())).unwrap();
    assert!(Arc::ptr_eq(&a, &a2), "cached");
    leaves.server_config_for(&Host::Domain("b.test".into())).unwrap();
    assert_eq!(leaves.cached(), 2);
}

#[test]
fn passthrough_patterns() {
    let p = vec!["*.bank.example".to_owned(), "update.microsoft.com".to_owned()];
    assert!(is_passthrough("www.bank.example", &p));
    assert!(!is_passthrough("bank.example", &p), "*. means subdomains only");
    assert!(is_passthrough("UPDATE.microsoft.com.", &p));
    assert!(!is_passthrough("evilupdate.microsoft.com", &p));
}

// ---------------------------------------------------------------- ClientHello peek

fn real_client_hello(sni: &str, alpn: &[&[u8]]) -> Vec<u8> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    let mut conn = rustls::ClientConnection::new(
        Arc::new(config),
        ServerName::try_from(sni.to_owned()).unwrap(),
    )
    .unwrap();
    let mut out = Vec::new();
    conn.write_tls(&mut out).unwrap();
    out
}

/// A hand-built ClientHello with the given extensions.
fn synthetic_hello(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut ext = Vec::new();
    for (kind, body) in extensions {
        ext.extend_from_slice(&kind.to_be_bytes());
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(body);
    }
    let mut hello = vec![0x03, 0x03];
    hello.extend_from_slice(&[7u8; 32]);
    hello.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    hello.extend_from_slice(&ext);
    let mut msg = vec![1, 0, (hello.len() >> 8) as u8, hello.len() as u8];
    msg.splice(1..2, [(hello.len() >> 16) as u8]);
    msg.extend_from_slice(&hello);
    let mut rec = vec![0x16, 0x03, 0x01, (msg.len() >> 8) as u8, msg.len() as u8];
    rec.extend_from_slice(&msg);
    rec
}

fn sni_ext(name: &str) -> (u16, Vec<u8>) {
    let mut entry = vec![0u8];
    entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
    entry.extend_from_slice(name.as_bytes());
    let mut body = (entry.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&entry);
    (0x0000, body)
}

#[test]
fn peek_real_and_synthetic_hellos() {
    let hello = real_client_hello("Good.Test", &[b"h2", b"http/1.1"]);
    let Peek::Hello(info) = peek_client_hello(&hello) else { panic!("parse") };
    assert_eq!(info.sni.as_deref(), Some("good.test"));
    assert_eq!(info.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert!(!info.ech_present);
    for cut in 1..hello.len() {
        assert_eq!(peek_client_hello(&hello[..cut]), Peek::Incomplete, "cut at {cut}");
    }
    let ech = synthetic_hello(&[sni_ext("public.test"), (0xfe0d, vec![0, 1, 2])]);
    let Peek::Hello(info) = peek_client_hello(&ech) else { panic!("ech parse") };
    assert!(info.ech_present);
    assert_eq!(peek_client_hello(b"GET / HTTP/1.1\r\n"), Peek::NotTls);
    assert_eq!(peek_client_hello(b"SSH-2.0-OpenSSH\r\n"), Peek::NotTls);
    assert!(
        matches!(
            peek_client_hello(&synthetic_hello(&[sni_ext("a.test"), sni_ext("b.test")])),
            Peek::Malformed(_)
        ),
        "two SNIs"
    );
    assert!(matches!(
        peek_client_hello(&synthetic_hello(&[sni_ext("bad name")])),
        Peek::Malformed(_)
    ));
    assert!(matches!(
        peek_client_hello(&[0x16, 0x03, 0x01, 0xff, 0xff]),
        Peek::Malformed(_) | Peek::Incomplete
    ));
}

// ---------------------------------------------------------------- end to end

struct Lab {
    pki: TestPki,
    proxy: ProxyHarness,
    ca_pem: String,
}

/// Proxy with interception on, trusting the origin test CA upstream.
async fn intercepting(extra: &str, lists: &[(&str, &str)]) -> Lab {
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap().keep();
    let origin_ca = pki.write_ca(&dir);
    let cfg = base_config(&format!(
        "{extra}\n[tls]\nintercept = true\nca_dir = \"{}\"\nupstream_ca_bundle = \"{}\"\npassthrough_domains = [\"pass.test\"]\n",
        dir.join("proxy-ca").display(),
        origin_ca.display()
    ));
    let resolver = TestResolver::with(&[
        ("good.test", "127.0.0.1"),
        ("pass.test", "127.0.0.1"),
        ("other.test", "127.0.0.1"),
    ]);
    let proxy = ProxyHarness::start(&cfg, lists, resolver).await;
    let ca_pem = std::fs::read_to_string(dir.join("proxy-ca/ca.pem")).unwrap();
    Lab { pki, proxy, ca_pem }
}

/// CONNECT through the proxy, then TLS with `sni`, trusting `ca_pem`.
async fn tunnel(
    proxy: SocketAddr,
    connect: &str,
    sni: &str,
    ca_pem: &str,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let mut s = tokio::net::TcpStream::connect(proxy).await?;
    s.write_all(format!("CONNECT {connect} HTTP/1.1\r\nHost: {connect}\r\n\r\n").as_bytes())
        .await?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        if s.read(&mut b).await? == 0 {
            return Err(std::io::Error::other("closed"));
        }
        head.push(b[0]);
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(sni.to_owned()).unwrap(), s)
        .await
}

async fn exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    s: &mut S,
    req: &str,
) -> String {
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(W, s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn e03_intercepted_https_inner_url_logged() {
    let mut lab = intercepting("", &[]).await;
    let origin =
        Origin::start_tls(lab.pki.leaf(&["good.test"], false), |_| Reply::ok("intercepted page"))
            .await;
    let port = origin.addr.port();
    let mut t = tunnel(lab.proxy.addr, &format!("good.test:{port}"), "good.test", &lab.ca_pem)
        .await
        .unwrap();
    let resp = exchange(&mut t, &format!("GET /inner/path?q=SECRETVALUE HTTP/1.1\r\nHost: good.test:{port}\r\nCookie: c=CANARYCOOKIE\r\nAuthorization: Bearer CANARYAUTH\r\nConnection: close\r\n\r\n")).await;
    assert!(resp.starts_with("HTTP/1.1 200") && resp.ends_with("intercepted page"), "{resp}");
    assert!(origin.requests()[0].starts_with("GET /inner/path?q=SECRETVALUE HTTP/1.1"));
    lab.proxy.stop().await;
    let logs = lab.proxy.log_lines();
    let inner = logs.iter().find(|l| l["http_method"] == "GET").unwrap();
    assert_eq!(inner["tls_intercepted"], true);
    assert_eq!(inner["tls_sni"], "good.test");
    assert_eq!(inner["url"], format!("https://good.test:{port}/inner/path"));
    let all = std::fs::read_to_string(lab.proxy.lab.path().join("logs/webfilter.jsonl")).unwrap();
    for canary in ["SECRETVALUE", "CANARYCOOKIE", "CANARYAUTH"] {
        assert!(!all.contains(canary), "E-30: {canary} leaked into logs");
    }
}

#[tokio::test]
async fn e03b_client_without_proxy_ca_fails_verification() {
    let mut lab = intercepting("", &[]).await;
    let origin = Origin::start_tls(lab.pki.leaf(&["good.test"], false), |_| Reply::ok("x")).await;
    let other_ca = TestPki::new().ca_pem;
    assert!(
        tunnel(
            lab.proxy.addr,
            &format!("good.test:{}", origin.addr.port()),
            "good.test",
            &other_ca
        )
        .await
        .is_err()
    );
    lab.proxy.stop().await;
}

#[tokio::test]
async fn e06_url_pattern_blocks_one_https_path() {
    let mut lab = intercepting("", &[("url_patterns.txt", "/private/\n")]).await;
    let origin =
        Origin::start_tls(lab.pki.leaf(&["good.test"], false), |_| Reply::ok("public")).await;
    let port = origin.addr.port();
    let mut t = tunnel(lab.proxy.addr, &format!("good.test:{port}"), "good.test", &lab.ca_pem)
        .await
        .unwrap();
    let blocked =
        exchange(&mut t, &format!("GET /private/x HTTP/1.1\r\nHost: good.test:{port}\r\n\r\n"))
            .await;
    assert_eq!(status(&blocked), 403, "{blocked}");
    assert!(blocked.contains("x-webfilter-reason: url_pattern"));
    let mut t = tunnel(lab.proxy.addr, &format!("good.test:{port}"), "good.test", &lab.ca_pem)
        .await
        .unwrap();
    let ok = exchange(
        &mut t,
        &format!("GET /public HTTP/1.1\r\nHost: good.test:{port}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(status(&ok), 200);
    assert_eq!(origin.requests().len(), 1, "the blocked path never reached the origin");
    lab.proxy.stop().await;
}

#[tokio::test]
async fn e17_bad_upstream_certificates_are_502() {
    let mut lab = intercepting("", &[]).await;
    let foreign = TestPki::new();
    for (what, cert) in [
        ("wrong name", lab.pki.leaf(&["other.test"], false)),
        ("expired", lab.pki.leaf(&["good.test"], true)),
        ("untrusted CA", foreign.leaf(&["good.test"], false)),
    ] {
        let origin = Origin::start_tls(cert, |_| Reply::ok("ORIGIN-DATA")).await;
        let port = origin.addr.port();
        let mut t = tunnel(lab.proxy.addr, &format!("good.test:{port}"), "good.test", &lab.ca_pem)
            .await
            .unwrap();
        let resp =
            exchange(&mut t, &format!("GET / HTTP/1.1\r\nHost: good.test:{port}\r\n\r\n")).await;
        assert_eq!(status(&resp), 502, "{what}: {resp}");
        assert!(resp.contains("upstream_cert_invalid"), "{what}: {resp}");
        assert!(!resp.contains("ORIGIN-DATA"), "{what}: no origin data leaks");
    }
    lab.proxy.stop().await;
}

#[tokio::test]
async fn e18_passthrough_domain_not_decrypted() {
    let mut lab = intercepting("", &[]).await;
    let origin =
        Origin::start_tls(lab.pki.leaf(&["pass.test"], false), |_| Reply::ok("direct")).await;
    let port = origin.addr.port();
    // The client must trust the ORIGIN's CA: the proxy does not terminate TLS for pass.test.
    let mut t = tunnel(lab.proxy.addr, &format!("pass.test:{port}"), "pass.test", &lab.pki.ca_pem)
        .await
        .unwrap();
    let resp = exchange(
        &mut t,
        &format!("GET / HTTP/1.1\r\nHost: pass.test:{port}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(resp.ends_with("direct"), "{resp}");
    drop(t); // a tunnel is logged when it ends
    tokio::time::sleep(Duration::from_millis(200)).await;
    lab.proxy.stop().await;
    let log = &lab.proxy.log_lines()[0];
    assert_eq!(
        (log["http_method"].as_str(), log["tls_intercepted"].as_bool()),
        (Some("CONNECT"), Some(false))
    );
}

#[tokio::test]
async fn e34_host_and_sni_mismatch_blocked() {
    let mut lab = intercepting("", &[]).await;
    let origin = Origin::start_tls(lab.pki.leaf(&["good.test"], false), |_| Reply::ok("x")).await;
    let port = origin.addr.port();
    let mut t = tunnel(lab.proxy.addr, &format!("good.test:{port}"), "good.test", &lab.ca_pem)
        .await
        .unwrap();
    let resp = exchange(&mut t, "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n").await;
    assert_eq!(status(&resp), 403);
    assert!(resp.contains("host_mismatch"));
    let mut t = tunnel(lab.proxy.addr, &format!("good.test:{port}"), "good.test", &lab.ca_pem)
        .await
        .unwrap();
    let resp = exchange(
        &mut t,
        &format!("GET https://other.test:{port}/ HTTP/1.1\r\nHost: good.test:{port}\r\n\r\n"),
    )
    .await;
    assert!(resp.contains("host_mismatch"), "absolute-form to another host: {resp}");
    assert!(
        tunnel(lab.proxy.addr, &format!("good.test:{port}"), "other.test", &lab.ca_pem)
            .await
            .is_err(),
        "SNI mismatch: no handshake"
    );
    assert!(origin.requests().is_empty(), "no fronting: the origin saw nothing");
    lab.proxy.stop().await;
    assert!(
        lab.proxy
            .log_lines()
            .iter()
            .any(|l| l["reason"] == "sni_mismatch" && l["action"] == "blocked")
    );
}

#[tokio::test]
async fn non_tls_on_connect_blocked_by_default() {
    let mut lab = intercepting("", &[]).await;
    let origin = Origin::start(|_| Reply::ok("plain")).await;
    let mut s = tokio::net::TcpStream::connect(lab.proxy.addr).await.unwrap();
    let port = origin.addr.port();
    let resp = exchange(
        &mut s,
        &format!(
            "CONNECT good.test:{port} HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\nHost: good.test\r\n\r\n"
        ),
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 200 Connection Established") && !resp.contains("plain"),
        "{resp}"
    );
    assert!(origin.requests().is_empty());
    lab.proxy.stop().await;
    assert!(lab.proxy.log_lines().iter().any(|l| l["reason"] == "non_tls_on_connect"));
}

#[cfg(unix)]
#[tokio::test]
async fn proxy_refuses_start_with_loose_ca_key() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let ca_dir = dir.path().join("ca");
    CaStore::generate(&ca_dir).unwrap();
    std::fs::set_permissions(ca_dir.join("ca.key"), std::fs::Permissions::from_mode(0o640))
        .unwrap();
    let lab = common::Lab::new();
    let path = lab.write_config(&base_config(&format!(
        "[tls]\nintercept = true\nca_dir = \"{}\"\n",
        ca_dir.display()
    )));
    let cfg = webfilter::config::Config::load(&path).unwrap();
    let err = webfilter::proxy::start(cfg, None).await.err().expect("must refuse to start");
    assert!(err.to_string().contains("0600"), "{err}");
}
