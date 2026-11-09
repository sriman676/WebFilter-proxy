//! Load generator and fast origin for `just load` (TEST_PLAN L-01..L-05, D-34). Offline, no
//! external tools. Lab/loopback use only.
//!
//!   loadgen origin [--tls CA_OUT [--h2]]          print the port, serve until killed (--h2: ALPN h2)
//!   loadgen run --url URL [--proxy ADDR] [--ca PEM] [--conns N] [--secs S] [--rate R]
//!   loadgen hold --proxy ADDR --url URL --conns N --secs S   (idle keep-alive connections)
//!
//! `run` prints one JSON line: requests, errors, rps, p50/p99/max latency (ms).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, missing_docs)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const BODY: &[u8] = b"<html><body>loadgen origin</body></html>";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn num(args: &[String], name: &str, default: u64) -> u64 {
    arg(args, name).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Read one head (until CRLFCRLF) into `buf`; return the head length.
async fn read_head<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok(i + 4);
        }
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn serve_origin<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) {
    let mut buf = Vec::new();
    let resp = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\n\r\n",
        BODY.len()
    );
    let mut out = resp.into_bytes();
    out.extend_from_slice(BODY);
    while let Ok(n) = read_head(&mut s, &mut buf).await {
        buf.drain(..n);
        if s.write_all(&out).await.is_err() {
            return;
        }
    }
}

/// h2 origin (h2spec target behind the proxy): every stream gets a 200 with a small body.
async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin>(s: S) {
    let Ok(mut conn) = h2::server::handshake(s).await else { return };
    while let Some(Ok((req, mut respond))) = conn.accept().await {
        tokio::spawn(async move {
            let mut body = req.into_body();
            while let Some(Ok(c)) = body.data().await {
                let _ = body.flow_control().release_capacity(c.len());
            }
            let resp = http::Response::builder()
                .status(200)
                .header("content-type", "text/html")
                .body(())
                .unwrap();
            if let Ok(mut s) = respond.send_response(resp, false) {
                let _ = s.send_data(bytes::Bytes::from_static(BODY), true);
            }
        });
    }
}

async fn origin(args: &[String]) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls = arg(args, "--tls").map(|ca_out| {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(&ca_out, cert.pem()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        config.alpn_protocols = if args.iter().any(|a| a == "--h2") {
            vec![b"h2".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    });
    println!("{}", listener.local_addr().unwrap().port());
    loop {
        let Ok((s, _)) = listener.accept().await else { continue };
        let _ = s.set_nodelay(true);
        let tls = tls.clone();
        tokio::spawn(async move {
            match tls {
                Some(a) => {
                    if let Ok(t) = a.accept(s).await {
                        if t.get_ref().1.alpn_protocol() == Some(b"h2") {
                            serve_h2(t).await;
                        } else {
                            serve_origin(t).await;
                        }
                    }
                }
                None => serve_origin(s).await,
            }
        });
    }
}

/// Parsed `http(s)://host:port/path`.
struct Url {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(u: &str) -> Url {
    let (https, rest) = match u.strip_prefix("https://") {
        Some(r) => (true, r),
        None => (false, u.strip_prefix("http://").expect("http(s) URL")),
    };
    let (auth, path) =
        rest.split_once('/').map_or((rest, "/".to_owned()), |(a, p)| (a, format!("/{p}")));
    let (host, port) = auth.rsplit_once(':').expect("explicit port");
    Url { https, host: host.to_owned(), port: port.parse().unwrap(), path }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// One client connection: plain to the origin, plain via the proxy (absolute-form), or CONNECT +
/// TLS through the proxy (intercepted, `ca` trusts the proxy CA).
async fn connect(
    u: &Url,
    proxy: Option<SocketAddr>,
    ca: Option<&Arc<rustls::ClientConfig>>,
) -> std::io::Result<(Box<dyn Io>, String)> {
    let authority = format!("{}:{}", u.host, u.port);
    match (proxy, u.https) {
        (None, _) => {
            let s = TcpStream::connect(&authority).await?;
            s.set_nodelay(true)?;
            Ok((Box::new(s), u.path.clone()))
        }
        (Some(p), false) => {
            let s = TcpStream::connect(p).await?;
            s.set_nodelay(true)?;
            Ok((Box::new(s), format!("http://{authority}{}", u.path)))
        }
        (Some(p), true) => {
            let mut s = TcpStream::connect(p).await?;
            s.set_nodelay(true)?;
            s.write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await?;
            let mut buf = Vec::new();
            read_head(&mut s, &mut buf).await?;
            if !buf.starts_with(b"HTTP/1.1 200") {
                return Err(std::io::Error::other("CONNECT refused"));
            }
            let config = Arc::clone(ca.expect("--ca for https"));
            let name = ServerName::try_from(u.host.clone()).unwrap();
            let t = tokio_rustls::TlsConnector::from(config).connect(name, s).await?;
            Ok((Box::new(t), u.path.clone()))
        }
    }
}

/// Send one keep-alive GET and read the whole response; error unless 200.
async fn request(
    s: &mut Box<dyn Io>,
    target: &str,
    host: &str,
    buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    s.write_all(
        format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: loadgen\r\n\r\n").as_bytes(),
    )
    .await?;
    let n = read_head(s, buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
    let ok = head.starts_with("http/1.1 200");
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .ok_or_else(|| std::io::Error::other("no content-length"))?;
    let mut tmp = [0u8; 4096];
    while buf.len() < n + len {
        let r = s.read(&mut tmp).await?;
        if r == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&tmp[..r]);
    }
    buf.drain(..n + len);
    if ok {
        Ok(())
    } else {
        Err(std::io::Error::other(head.lines().next().unwrap_or("").to_owned()))
    }
}

async fn run(args: &[String]) {
    let u = Arc::new(parse_url(&arg(args, "--url").expect("--url")));
    let proxy: Option<SocketAddr> = arg(args, "--proxy").map(|p| p.parse().unwrap());
    let ca = arg(args, "--ca").map(|path| {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_file(path).unwrap()).unwrap();
        let mut c = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(c)
    });
    let conns = num(args, "--conns", 64);
    let secs = num(args, "--secs", 10);
    let rate = num(args, "--rate", 0); // total req/s; 0 = as fast as possible
    let errors = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let end = start + Duration::from_secs(secs);
    let tasks: Vec<_> = (0..conns)
        .map(|i| {
            let (u, ca, errors) = (Arc::clone(&u), ca.clone(), Arc::clone(&errors));
            tokio::spawn(async move {
                let mut lat = Vec::new();
                let interval =
                    (rate > 0).then(|| Duration::from_secs_f64(conns as f64 / rate as f64));
                let host = format!("{}:{}", u.host, u.port);
                let mut next = start
                    + interval.map_or(Duration::ZERO, |iv| iv.mul_f64(i as f64 / conns as f64));
                let mut conn = None;
                let mut buf = Vec::new();
                while Instant::now() < end {
                    if let Some(iv) = interval {
                        tokio::time::sleep_until(next.into()).await;
                        next += iv;
                    }
                    if conn.is_none() {
                        match connect(&u, proxy, ca.as_ref()).await {
                            Ok(c) => conn = Some(c),
                            Err(_) => {
                                errors.fetch_add(1, Ordering::Relaxed);
                                tokio::time::sleep(Duration::from_millis(10)).await;
                                continue;
                            }
                        }
                    }
                    let (s, target) = conn.as_mut().unwrap();
                    let t0 = Instant::now();
                    match request(s, target, &host, &mut buf).await {
                        Ok(()) => lat.push(t0.elapsed().as_micros() as u64),
                        Err(_) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                            conn = None;
                            buf.clear();
                        }
                    }
                }
                lat
            })
        })
        .collect();
    let mut lat: Vec<u64> = Vec::new();
    for t in tasks {
        lat.extend(t.await.unwrap());
    }
    let elapsed = start.elapsed().as_secs_f64();
    lat.sort_unstable();
    let pct = |p: f64| {
        lat.get(((lat.len() as f64 * p) as usize).min(lat.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0) as f64
            / 1000.0
    };
    println!(
        "{{\"requests\":{},\"errors\":{},\"rps\":{:.0},\"p50_ms\":{:.3},\"p99_ms\":{:.3},\"max_ms\":{:.3}}}",
        lat.len(),
        errors.load(Ordering::Relaxed),
        lat.len() as f64 / elapsed,
        pct(0.50),
        pct(0.99),
        lat.last().copied().unwrap_or(0) as f64 / 1000.0
    );
}

async fn hold(args: &[String]) {
    let u = parse_url(&arg(args, "--url").expect("--url"));
    let proxy: SocketAddr = arg(args, "--proxy").expect("--proxy").parse().unwrap();
    let conns = num(args, "--conns", 1000);
    let mut open = Vec::new();
    let mut buf = Vec::new();
    for _ in 0..conns {
        if let Ok((mut s, target)) = connect(&u, Some(proxy), None).await
            && request(&mut s, &target, &format!("{}:{}", u.host, u.port), &mut buf).await.is_ok()
        {
            open.push(s);
        }
        buf.clear();
    }
    println!("{{\"held\":{}}}", open.len());
    tokio::time::sleep(Duration::from_secs(num(args, "--secs", 10))).await;
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("origin") => origin(&args).await,
        Some("run") => run(&args).await,
        Some("hold") => hold(&args).await,
        _ => eprintln!("usage: loadgen origin|run|hold ... (see source header)"),
    }
}
