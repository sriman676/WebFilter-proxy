//! Phase 6 (HTTP/2 inside intercepted TLS): E-37..E-43, I-h2-valid, I-h2-flood and the PT-6
//! regressions. Origins and clients use the `h2` crate directly; flood cases write raw frames.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use common::{ProxyHarness, TestPki, TestResolver, base_config, status};
use h2::client::SendRequest;
use http::{Request, Response};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const W: Duration = Duration::from_secs(10);
type Seen = Arc<Mutex<Vec<(String, String)>>>; // (protocol, path)

// ------------------------------------------------------------------------------------ origin

/// A TLS origin offering `alpn`; serves h2 or a minimal HTTP/1.1 and records (protocol, path).
struct H2Origin {
    port: u16,
    seen: Seen,
}

fn body_for(path: &str) -> Vec<u8> {
    match path.strip_prefix("/big/") {
        Some(n) => (0..n.parse::<usize>().unwrap()).map(|i| (i % 251) as u8).collect(),
        None => format!("hello {path}").into_bytes(),
    }
}

async fn send_all(s: &mut h2::SendStream<Bytes>, mut data: Bytes) {
    while !data.is_empty() {
        s.reserve_capacity(data.len());
        let Some(Ok(cap)) = std::future::poll_fn(|cx| s.poll_capacity(cx)).await else { return };
        let n = cap.min(data.len());
        if s.send_data(data.split_to(n), false).is_err() {
            return;
        }
    }
    let _ = s.send_data(Bytes::new(), true);
}

async fn serve_h2<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(tls: S, seen: Seen) {
    let Ok(mut conn) = h2::server::handshake(tls).await else { return };
    while let Some(Ok((req, mut respond))) = conn.accept().await {
        let seen = Arc::clone(&seen);
        tokio::spawn(async move {
            let path = req.uri().path().to_owned();
            seen.lock().unwrap().push(("h2".into(), path.clone()));
            let mut body = req.into_body();
            while let Some(Ok(c)) = body.data().await {
                let _ = body.flow_control().release_capacity(c.len());
            }
            let ctype = if path == "/exe" { "application/x-msdownload" } else { "text/html" };
            let mut resp = Response::builder().status(200).header("content-type", ctype);
            if path == "/forge" {
                resp = resp.header("x-webfilter-action", "blocked");
            }
            let mut s = respond.send_response(resp.body(()).unwrap(), false).unwrap();
            send_all(&mut s, Bytes::from(body_for(&path))).await;
        });
    }
}

async fn serve_h1<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut tls: S, seen: Seen) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if tls.read(&mut b).await.unwrap_or(0) == 0 {
            return;
        }
        head.push(b[0]);
    }
    let line = String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_owned();
    let path = line.split(' ').nth(1).unwrap_or("").to_owned();
    seen.lock().unwrap().push(("http/1.1".into(), path.clone()));
    let body = body_for(&path);
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = tls.write_all(head.as_bytes()).await;
    let _ = tls.write_all(&body).await;
    let _ = tls.shutdown().await;
}

impl H2Origin {
    async fn start(
        certs: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
        alpn: &[&[u8]],
    ) -> Self {
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs.0, certs.1)
        .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Seen = Arc::default();
        let rec = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                let (acceptor, rec) = (acceptor.clone(), Arc::clone(&rec));
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(s).await else { return };
                    if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                        serve_h2(tls, rec).await;
                    } else {
                        serve_h1(tls, rec).await;
                    }
                });
            }
        });
        Self { port, seen }
    }

    fn seen(&self) -> Vec<(String, String)> {
        self.seen.lock().unwrap().clone()
    }
}

// ------------------------------------------------------------------------------------ lab

struct Lab {
    proxy: ProxyHarness,
    ca_pem: String,
    origin: H2Origin,
}

async fn lab(extra: &str, lists: &[(&str, &str)], origin_alpn: &[&[u8]]) -> Lab {
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap().keep();
    let origin_ca = pki.write_ca(&dir);
    let origin = H2Origin::start(pki.leaf(&["h2.test"], false), origin_alpn).await;
    let cfg = base_config(&format!(
        "{extra}\n[tls]\nintercept = true\nca_dir = \"{}\"\nupstream_ca_bundle = \"{}\"\n",
        dir.join("proxy-ca").display(),
        origin_ca.display()
    ));
    let resolver = TestResolver::with(&[("h2.test", "127.0.0.1"), ("other.test", "127.0.0.1")]);
    let proxy = ProxyHarness::start(&cfg, lists, resolver).await;
    let ca_pem = std::fs::read_to_string(dir.join("proxy-ca/ca.pem")).unwrap();
    Lab { proxy, ca_pem, origin }
}

const BOTH: &[&[u8]] = &[b"h2", b"http/1.1"];
const H1: &[&[u8]] = &[b"http/1.1"];

/// CONNECT h2.test:port, then TLS offering `alpn`, trusting the proxy CA.
async fn tunnel(
    proxy: SocketAddr,
    port: u16,
    ca_pem: &str,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let mut s = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let authority = format!("h2.test:{port}");
    s.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_ne!(s.read(&mut b).await.unwrap(), 0, "proxy closed during CONNECT");
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
    tokio_rustls::TlsConnector::from(common::client_config(ca_pem, alpn))
        .connect(ServerName::try_from("h2.test").unwrap(), s)
        .await
        .unwrap()
}

/// An h2 client through the proxy; `window` sets the client's stream window.
async fn h2_client(l: &Lab, window: Option<u32>) -> SendRequest<Bytes> {
    let tls = tunnel(l.proxy.addr, l.origin.port, &l.ca_pem, BOTH).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let mut b = h2::client::Builder::new();
    if let Some(w) = window {
        b.initial_window_size(w);
    }
    let (send, conn) = b.handshake(tls).await.unwrap();
    tokio::spawn(conn);
    send
}

fn get(port: u16, path: &str) -> Request<()> {
    Request::get(format!("https://h2.test:{port}{path}")).body(()).unwrap()
}

/// Send `req`; return (status, headers, body).
async fn fetch(
    send: &SendRequest<Bytes>,
    req: Request<()>,
) -> Result<(u16, http::HeaderMap, Vec<u8>), h2::Error> {
    let mut send = send.clone().ready().await?;
    let (resp, _) = send.send_request(req, true)?;
    let resp = tokio::time::timeout(W, resp).await.expect("response in time")?;
    let (parts, mut body) = resp.into_parts();
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    Ok((parts.status.as_u16(), parts.headers, out))
}

// ------------------------------------------------------------------------------------ E-37..E-40

#[tokio::test]
async fn e37_h2_end_to_end_logged_without_secrets() {
    let mut l = lab("", &[], BOTH).await;
    let send = h2_client(&l, None).await;
    let mut req = get(l.origin.port, "/page?token=CANARYQ");
    req.headers_mut().insert("cookie", "s=CANARYCOOKIE".parse().unwrap());
    req.headers_mut().insert("authorization", "Bearer CANARYAUTH".parse().unwrap());
    let (st, _, body) = fetch(&send, req).await.unwrap();
    assert_eq!(st, 200);
    assert_eq!(body, b"hello /page");
    drop(send);
    l.proxy.stop().await;
    assert_eq!(l.origin.seen(), vec![("h2".to_owned(), "/page".to_owned())]);
    let inner: Vec<_> =
        l.proxy.log_lines().into_iter().filter(|v| v["http_method"] == "GET").collect();
    assert_eq!(inner.len(), 1);
    let v = &inner[0];
    assert_eq!(v["http_version"], "2");
    assert_eq!(v["alpn"], "h2");
    assert_eq!(v["h2_stream_id"], 1);
    assert_eq!(v["tls_intercepted"], true);
    assert_eq!(v["uri_query_keys"], serde_json::json!(["token"]));
    let all = std::fs::read_to_string(l.proxy.lab.path().join("logs/webfilter.jsonl")).unwrap();
    for canary in ["CANARYQ", "CANARYCOOKIE", "CANARYAUTH"] {
        assert!(!all.contains(canary), "{canary} leaked (E-30 over h2)");
    }
}

#[tokio::test]
async fn e38_alpn_mirroring_matrix_never_translates() {
    for (client, origin, expect) in
        [(BOTH, BOTH, "h2"), (BOTH, H1, "http/1.1"), (H1, BOTH, "http/1.1"), (H1, H1, "http/1.1")]
    {
        let mut l = lab("", &[], origin).await;
        let mut tls = tunnel(l.proxy.addr, l.origin.port, &l.ca_pem, client).await;
        let negotiated =
            tls.get_ref().1.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned());
        if expect == "h2" {
            assert_eq!(negotiated.as_deref(), Some("h2"));
            let (send, conn) = h2::client::handshake(tls).await.unwrap();
            tokio::spawn(conn);
            assert_eq!(fetch(&send, get(l.origin.port, "/m")).await.unwrap().0, 200);
        } else {
            assert_ne!(negotiated.as_deref(), Some("h2"), "client {client:?} origin {origin:?}");
            let req = format!(
                "GET /m HTTP/1.1\r\nHost: h2.test:{}\r\nConnection: close\r\n\r\n",
                l.origin.port
            );
            tls.write_all(req.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            let _ = tokio::time::timeout(W, tls.read_to_end(&mut out)).await;
            assert_eq!(status(&String::from_utf8_lossy(&out)), 200);
        }
        l.proxy.stop().await;
        let protocols: Vec<String> = l
            .origin
            .seen()
            .into_iter()
            .filter(|(_, p)| p == "/m")
            .map(|(proto, _)| proto)
            .collect();
        assert_eq!(protocols, vec![expect.to_owned()], "client {client:?} origin {origin:?}");
    }
}

#[tokio::test]
async fn e39_concurrent_streams_decided_independently() {
    let mut l =
        lab("", &[("url_patterns.txt", "^https://h2\\.test(:\\d+)?/blocked/\n")], BOTH).await;
    let send = h2_client(&l, None).await;
    let port = l.origin.port;
    let tasks: Vec<_> = (0..50)
        .map(|i| {
            let send = send.clone();
            let path = if i % 5 == 0 { format!("/blocked/{i}") } else { format!("/ok/{i}") };
            tokio::spawn(
                async move { (path.clone(), fetch(&send, get(port, &path)).await.unwrap()) },
            )
        })
        .collect();
    for t in tasks {
        let (path, (st, headers, body)) = t.await.unwrap();
        if path.starts_with("/blocked/") {
            assert_eq!(st, 403, "{path}");
            assert_eq!(headers["x-webfilter-action"], "blocked");
            assert!(String::from_utf8_lossy(&body).contains("<html"), "block page over h2 (H11)");
        } else {
            assert_eq!((st, body), (200, format!("hello {path}").into_bytes()), "{path}");
        }
    }
    drop(send);
    l.proxy.stop().await;
    let seen = l.origin.seen();
    assert_eq!(seen.len(), 40, "blocked streams never reach the origin");
    assert!(seen.iter().all(|(proto, p)| proto == "h2" && p.starts_with("/ok/")));
}

/// E-83 (h2 x profiles x rate limits): every stream is admitted like an HTTP/1 request.
#[tokio::test]
async fn e83_h2_streams_share_profile_limits() {
    let profile = "[[profiles]]\nname = \"default\"\nextra_blocked_domains = [\"other.test\"]\n\
[profiles.rate]\nrequests_per_sec = 1\nburst = 5\n";
    let mut l = lab(profile, &[], BOTH).await;
    let send = h2_client(&l, None).await;
    let port = l.origin.port;
    let mut statuses = Vec::new();
    for i in 0..12 {
        let (st, headers, _) = fetch(&send, get(port, &format!("/ok/{i}"))).await.unwrap();
        if st == 429 {
            assert!(headers.contains_key("retry-after"));
        }
        statuses.push(st);
    }
    assert_eq!(
        statuses.iter().filter(|s| **s == 200).count(),
        4,
        "burst 5 = CONNECT + 4 streams: {statuses:?}"
    );
    assert_eq!(statuses.iter().filter(|s| **s == 429).count(), 8, "{statuses:?}");
    drop(send);
    l.proxy.stop().await;
    assert_eq!(l.origin.seen().len(), 4, "limited streams never reach the origin");
    let lines = l.proxy.log_lines();
    assert!(lines.iter().any(|v| v["reason"] == "rate_limited" && v["http_version"] == "2"));
}

#[tokio::test]
async fn e40_parallel_downloads_flow_control_intact() {
    let mut l = lab("", &[], BOTH).await;
    let send = h2_client(&l, None).await;
    let size = 4 * 1024 * 1024;
    let expect = Sha256::digest(body_for(&format!("/big/{size}")));
    let port = l.origin.port;
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let send = send.clone();
            tokio::spawn(
                async move { fetch(&send, get(port, &format!("/big/{size}"))).await.unwrap() },
            )
        })
        .collect();
    for t in tasks {
        let (st, _, body) = t.await.unwrap();
        assert_eq!(st, 200);
        assert_eq!(Sha256::digest(&body), expect);
    }
    drop(send);
    l.proxy.stop().await;
}

// ------------------------------------------------------------------------------------ I-h2-valid

#[tokio::test]
async fn i_h2_valid_authority_scheme_connect_and_forged_headers() {
    let mut l = lab("", &[("domains.txt", "")], BOTH).await;
    let send = h2_client(&l, None).await;
    let port = l.origin.port;
    // H4: :authority must be the CONNECT authority; a host header must match :authority.
    let (st, h, _) =
        fetch(&send, Request::get(format!("https://other.test:{port}/x")).body(()).unwrap())
            .await
            .unwrap();
    assert_eq!((st, h["x-webfilter-reason"].to_str().unwrap()), (403, "host_mismatch"));
    let mut req = get(port, "/y");
    req.headers_mut().insert("host", "other.test".parse().unwrap());
    assert_eq!(fetch(&send, req).await.unwrap().0, 403);
    // H1: :scheme must be https -> RST_STREAM(PROTOCOL_ERROR).
    let err = fetch(&send, Request::get(format!("http://h2.test:{port}/z")).body(()).unwrap())
        .await
        .unwrap_err();
    assert_eq!(err.reason(), Some(h2::Reason::PROTOCOL_ERROR));
    // H8: CONNECT over h2 is refused.
    let connect = Request::connect(format!("h2.test:{port}")).body(()).unwrap();
    let mut s = send.clone().ready().await.unwrap();
    let (resp, _) = s.send_request(connect, false).unwrap();
    assert_eq!(resp.await.unwrap_err().reason(), Some(h2::Reason::PROTOCOL_ERROR));
    // PF-3-01 over h2: an origin cannot forge proxy block headers.
    let (st, h, _) = fetch(&send, get(port, "/forge")).await.unwrap();
    assert_eq!(st, 200);
    assert!(h.get("x-webfilter-action").is_none());
    // Rule 6 over h2: a blocked content type after the response headers.
    drop(send);
    l.proxy.stop().await;
    assert!(
        l.origin.seen().iter().all(|(_, p)| p == "/forge"),
        "invalid streams never reach the origin"
    );
}

#[tokio::test]
async fn h2_response_content_type_rule_blocks() {
    let mut l =
        lab("[rules]\nblocked_content_types = [\"application/x-msdownload\"]\n", &[], BOTH).await;
    let send = h2_client(&l, None).await;
    let (st, h, body) = fetch(&send, get(l.origin.port, "/exe")).await.unwrap();
    assert_eq!((st, h["x-webfilter-reason"].to_str().unwrap()), (403, "content_type"));
    assert!(!body.starts_with(b"hello"), "the origin body is never forwarded");
    drop(send);
    l.proxy.stop().await;
}

// ------------------------------------------------------------------------------------ I-h2-flood

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Raw h2 over the intercepted tunnel: send `frames` after the preface; return the GOAWAY error
/// code the proxy sent (if any).
async fn raw_goaway(l: &Lab, frames: Vec<u8>) -> Option<u32> {
    let mut tls = tunnel(l.proxy.addr, l.origin.port, &l.ca_pem, BOTH).await;
    let mut out = webfilter::proxy::h2guard::PREFACE.to_vec();
    out.extend(frame(0x4, 0, 0, &[])); // SETTINGS
    out.extend(frames);
    let _ = tls.write_all(&out).await;
    let mut got = Vec::new();
    let _ = tokio::time::timeout(W, tls.read_to_end(&mut got)).await;
    let mut i = 0;
    while i + 9 <= got.len() {
        let len =
            (usize::from(got[i]) << 16) | (usize::from(got[i + 1]) << 8) | usize::from(got[i + 2]);
        if got[i + 3] == 0x7 && i + 9 + 8 <= got.len() {
            return Some(u32::from_be_bytes(got[i + 13..i + 17].try_into().unwrap()));
        }
        i += 9 + len;
    }
    None
}

const ENHANCE_YOUR_CALM: u32 = 0xb;

fn flood_events(l: &Lab) -> Vec<String> {
    l.proxy
        .system_lines()
        .into_iter()
        .filter(|v| v["kind"] == "h2_flood")
        .map(|v| v["detail"]["violation"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn e42_rapid_reset_goaway_and_other_connections_fine() {
    let mut l = lab("", &[], BOTH).await;
    let mut frames = Vec::new();
    for i in 0..300u32 {
        let id = 2 * i + 1;
        frames.extend(frame(
            0x1,
            0x4 | 0x1,
            id,
            &[0x82, 0x87, 0x84, 0x41, 0x07, b'h', b'2', b'.', b't', b'e', b's', b't'],
        ));
        frames.extend(frame(0x3, 0, id, &8u32.to_be_bytes())); // RST_STREAM(CANCEL)
    }
    assert_eq!(raw_goaway(&l, frames).await, Some(ENHANCE_YOUR_CALM));
    let send = h2_client(&l, None).await;
    assert_eq!(
        fetch(&send, get(l.origin.port, "/after")).await.unwrap().0,
        200,
        "other connections unaffected"
    );
    drop(send);
    l.proxy.stop().await;
    let ev = flood_events(&l);
    assert!(ev.iter().any(|v| v == "rapid_reset" || v == "reset_ratio"), "{ev:?}");
}

#[tokio::test]
async fn pt_6_2_continuation_flood_goaway() {
    let mut l = lab("", &[], BOTH).await;
    let mut frames = frame(0x1, 0, 1, &[0x82]); // HEADERS without END_HEADERS
    for _ in 0..40 {
        frames.extend(frame(0x9, 0, 1, &[0x82]));
    }
    let code = raw_goaway(&l, frames).await;
    l.proxy.stop().await;
    assert_eq!(code, Some(ENHANCE_YOUR_CALM));
    assert!(flood_events(&l).contains(&"continuation_flood".to_owned()));
}

#[tokio::test]
async fn pt_6_3_control_frame_flood_goaway() {
    let mut l = lab("", &[], BOTH).await;
    let mut frames = Vec::new();
    for i in 0..300u64 {
        frames.extend(frame(0x6, 0, 0, &i.to_be_bytes())); // PING
    }
    let code = raw_goaway(&l, frames).await;
    l.proxy.stop().await;
    assert_eq!(code, Some(ENHANCE_YOUR_CALM));
    assert!(flood_events(&l).contains(&"control_flood".to_owned()));
}

#[tokio::test]
async fn pt_6_3_slow_reader_stall_closes_connection() {
    let mut l = lab("[http2]\nstall_timeout_secs = 1\n", &[], BOTH).await;
    let send = h2_client(&l, Some(1024)).await;
    let mut s = send.clone().ready().await.unwrap();
    let (resp, _) = s.send_request(get(l.origin.port, "/big/4000000"), true).unwrap();
    let resp = tokio::time::timeout(W, resp).await.unwrap().unwrap();
    let _body = resp.into_body(); // never read: the proxy cannot send more than 1 KiB
    tokio::time::sleep(Duration::from_secs(3)).await;
    drop((send, s));
    l.proxy.stop().await;
    assert!(flood_events(&l).contains(&"flow_control_stall".to_owned()), "{:?}", flood_events(&l));
}

// ------------------------------------------------------------------------------------ E-43

#[tokio::test]
async fn e43_h2c_on_plain_listener_rejected() {
    let mut l = lab("", &[], BOTH).await;
    let preface = l.proxy.raw(webfilter::proxy::h2guard::PREFACE, Duration::from_secs(3)).await;
    assert!(
        preface.is_empty() || status(&preface) >= 400,
        "h2 preface must not be served: {preface}"
    );
    let upgrade = format!(
        "GET http://h2.test:{}/ HTTP/1.1\r\nHost: h2.test:{}\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n",
        l.origin.port, l.origin.port
    );
    assert_eq!(status(&l.proxy.raw(upgrade.as_bytes(), Duration::from_secs(3)).await), 400);
    l.proxy.stop().await;
    assert!(l.origin.seen().is_empty(), "the origin sees nothing");
    assert!(l.proxy.log_lines().iter().all(|v| v["reason"] == "invalid_request"));
}

// ------------------------------------------------------------------------------------ scanner

#[test]
fn scanner_counts_split_frames_and_never_panics() {
    use webfilter::proxy::h2guard::{FrameScanner, Limits, Peer, Violation};
    let limits = Limits {
        max_continuation_frames: 2,
        reset_limit: 3,
        control_frame_limit: 4,
        window: Duration::from_secs(10),
    };
    let now = std::time::Instant::now();
    let mut s = FrameScanner::new(limits, Peer::Origin, now);
    // WINDOW_UPDATE(0) split byte by byte counts as a control frame; a non-zero one does not.
    let wu0 = frame(0x8, 0, 1, &0u32.to_be_bytes());
    let wu1 = frame(0x8, 0, 1, &1u32.to_be_bytes());
    for _ in 0..4 {
        for b in &wu1 {
            assert_eq!(s.feed(std::slice::from_ref(b), now), None);
        }
    }
    let mut verdict = None;
    for _ in 0..5 {
        for b in &wu0 {
            verdict = verdict.or(s.feed(std::slice::from_ref(b), now));
        }
    }
    assert_eq!(verdict, Some(Violation::ControlFlood));
    // The window rolls over.
    let later = now + Duration::from_secs(11);
    let mut s = FrameScanner::new(limits, Peer::Client, now);
    assert_eq!(s.feed(webfilter::proxy::h2guard::PREFACE, now), None);
    for _ in 0..3 {
        assert_eq!(s.feed(&frame(0x3, 0, 1, &[0; 4]), now), None);
    }
    assert_eq!(s.feed(&frame(0x3, 0, 1, &[0; 4]), later), None, "new window");
    let mut s = FrameScanner::new(limits, Peer::Origin, now);
    let rst: Vec<u8> = (0..4).flat_map(|_| frame(0x3, 0, 1, &[0; 4])).collect();
    assert_eq!(s.feed(&rst, now), Some(Violation::RapidReset));
    let mut s = FrameScanner::new(limits, Peer::Origin, now);
    assert_eq!(s.local_resets(4, now), Some(Violation::RapidReset), "MadeYouReset counts");
    let mut s = FrameScanner::new(limits, Peer::Origin, now);
    let cont: Vec<u8> = frame(0x1, 0, 1, &[0x82])
        .into_iter()
        .chain((0..3).flat_map(|_| frame(0x9, 0, 1, &[0x82])))
        .collect();
    assert_eq!(s.feed(&cont, now), Some(Violation::ContinuationFlood));
    // Garbage never panics.
    let mut s = FrameScanner::new(limits, Peer::Client, now);
    let junk: Vec<u8> =
        (0..10_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let _ = s.feed(&junk, now);
}
