//! CONNECT (SPEC 4.9): passthrough (only rules 1-3 apply, 4.6) or interception (TLS terminated
//! with a minted leaf, inner requests through the full pipeline), and the opaque bidirectional
//! relay used by tunnels and websockets (SPEC 4.15 (7)).
#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout};

use super::ProxyDeps;
use super::http1::{BodyFraming, RequestHead, ResponseHead, forward_headers, write_head};
use super::io::fill;
use super::pipeline::{
    Fail, Outcome, Tunnel, Upstream, UpstreamBox, Via, client_gone, connect_upstream, fail,
    note_decision, note_target, resolve, resolved_rule, send_block, send_limit, serve_connection,
    upstream_tls, write_all,
};
use crate::config::EchAction;
use crate::filter::{Action, Phase};
use crate::logger::RequestEvent;
use crate::normalize::{NormalizedTarget, TargetContext, canonicalize};
use crate::policy::{PortKind, check_port};
use crate::profiles::Profile;
use crate::reason::Reason;
use crate::tls::{ClientHelloInfo, Peek, Prefixed, is_passthrough, peek_client_hello};

/// Relay buffer size.
pub const RELAY_BUF: usize = 16 * 1024;

/// Copy one direction until EOF, error, or `idle` without activity in EITHER direction.
async fn pump<R, W>(mut r: R, mut w: W, idle: Duration, start: Instant, last: &AtomicU64) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; RELAY_BUF];
    let mut total = 0u64;
    let now_ms = || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let idle_ms = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX);
    loop {
        match timeout(idle, r.read(&mut buf)).await {
            Err(_) if now_ms().saturating_sub(last.load(Ordering::Relaxed)) >= idle_ms => break,
            Err(_) => continue, // the other direction is active
            Ok(Ok(0) | Err(_)) => break,
            Ok(Ok(n)) => {
                last.store(now_ms(), Ordering::Relaxed);
                let data = buf.get(..n).unwrap_or(&[]);
                if !matches!(timeout(idle, w.write_all(data)).await, Ok(Ok(()))) {
                    break;
                }
                total += n as u64;
            }
        }
    }
    let _ = timeout(Duration::from_secs(1), w.shutdown()).await;
    total
}

/// Relay bytes both ways until both sides close or the tunnel is idle for `idle`.
/// Returns `(a_to_b, b_to_a)` byte counts.
pub async fn relay<A, B>(a: A, b: B, idle: Duration) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let start = Instant::now();
    let last = AtomicU64::new(0);
    tokio::join!(pump(ar, bw, idle, start, &last), pump(br, aw, idle, start, &last))
}

/// Handle `CONNECT host:port`: policy, rules 1-3, then passthrough or interception.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_connect<S>(
    client: &mut S,
    buf: &mut Vec<u8>,
    head: &RequestHead,
    ev: &mut RequestEvent,
    deps: &Arc<ProxyDeps>,
    peer: IpAddr,
    id: &str,
    profile: &Arc<Profile>,
) -> Result<Outcome, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    ev.url_scheme = "https".into();
    let t = canonicalize(&head.target, TargetContext::ConnectAuthority).map_err(|e| {
        fail(
            if e.reason() == Reason::UserinfoInUrl { 403 } else { 400 },
            e.reason(),
            "invalid CONNECT target",
        )
    })?;
    note_target(ev, &t);
    check_port(PortKind::Connect, t.port, &deps.cfg.ports)
        .map_err(|r| fail(403, r, "port not allowed"))?;
    // `CONNECT webfilter.local:443` with interception: the proxy is the origin (O6).
    if super::vhost::is_vhost(deps, &t) && deps.leaves.is_some() {
        let who = (id.to_owned(), Arc::clone(profile));
        return intercept_tunnel(client, buf, t, Vec::new(), ev, deps, peer, who).await;
    }
    let d = deps.evaluate(&t, Phase::ConnectPreDns, profile, id);
    note_decision(ev, &d);
    if d.is_block() {
        send_block(client, ev, &d, deps).await;
        return Ok(Outcome::Done);
    }
    let ips = resolve(&t, ev, deps).await?;
    if let Some(d) = resolved_rule(deps, &t, &ips, profile, id) {
        note_decision(ev, &d);
        if d.is_block() {
            send_block(client, ev, &d, deps).await;
            return Ok(Outcome::Done);
        }
    }
    // Open tunnels per client (D-51); held until the tunnel ends.
    let _tunnel = match profile.rate.map(|r| deps.limiter.acquire_tunnel(id, &r)) {
        Some(Err(r)) => {
            deps.stats.record_limit(&profile.name, r.reason);
            send_limit(client, ev, &r, deps).await;
            return Ok(Outcome::Done);
        }
        slot => slot,
    };
    let intercept = deps.leaves.is_some()
        && !is_passthrough(&t.host.to_string(), &deps.cfg.tls.passthrough_domains);
    if intercept {
        let who = (id.to_owned(), Arc::clone(profile));
        return intercept_tunnel(client, buf, t, ips, ev, deps, peer, who).await;
    }
    let (mut upstream, ip) = connect_upstream(&ips, t.port, deps).await?;
    ev.dest_ip = Some(ip.to_string());
    passthrough_tunnel(client, buf, &t, &mut upstream, ev, deps).await
}

/// The CONNECT answer.
const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// Passthrough (SPEC 4.9): answer 200, peek the ClientHello (bounded, with the handshake
/// timeout) and apply the SNI rule (D-22, review 2 M3) even when ECH is present, then
/// `tls.ech_action` (review 3 M2, A-51), then relay with the peeked bytes sent upstream first.
/// Non-TLS bytes are refused per `block_non_tls_connect` when interception is enabled (a
/// passthrough domain); with interception off they are tunneled as before (4.9).
async fn passthrough_tunnel<S, U>(
    client: &mut S,
    buf: &mut Vec<u8>,
    t: &NormalizedTarget,
    upstream: &mut U,
    ev: &mut RequestEvent,
    deps: &ProxyDeps,
) -> Result<Outcome, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let handshake = Duration::from_secs(deps.cfg.timeouts.tls_handshake);
    write_all(client, ESTABLISHED, handshake).await.map_err(|_| client_gone())?;
    ev.status = 200;
    match read_hello(client, buf, Instant::now() + handshake).await? {
        Some(hello) => {
            ev.tls_sni.clone_from(&hello.sni);
            ev.ech_present = hello.ech_present;
            // The bytes go to the CONNECT host's IP unread, so an ECH extension (real or junk)
            // must not exempt the outer SNI from the comparison (review 3 M2).
            check_sni(&hello, t, ev, false)?;
            if hello.ech_present && deps.cfg.tls.ech_action == EchAction::Block {
                ev.action = Action::Block.as_str();
                return Err(Fail {
                    status: None,
                    reason: Reason::EchBlocked,
                    error: "ECH hides the server name (R-05)",
                });
            }
        }
        None if deps.cfg.block_non_tls_connect && deps.leaves.is_some() => {
            return Err(non_tls(ev));
        }
        None => {}
    }
    open_tunnel(client, buf, upstream, b"", ev, deps).await
}

/// Non-TLS bytes on a CONNECT tunnel with `block_non_tls_connect`.
fn non_tls(ev: &mut RequestEvent) -> Fail {
    ev.action = Action::Block.as_str();
    Fail { status: None, reason: Reason::NonTlsOnConnect, error: "non-TLS traffic on CONNECT" }
}

/// D-22: a present SNI must name the CONNECT host (case-insensitive, trailing dot ignored).
/// With `ech_exempts` (interception only, D-21) an ECH outer SNI is a cover name and is not
/// compared; passthrough always compares (review 3 M2).
fn check_sni(
    hello: &ClientHelloInfo,
    t: &NormalizedTarget,
    ev: &mut RequestEvent,
    ech_exempts: bool,
) -> Result<(), Fail> {
    let connect_host = t.host.to_string();
    let connect_host =
        connect_host.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.');
    let exempt = ech_exempts && hello.ech_present;
    if !exempt
        && let Some(sni) = &hello.sni
        && !sni.trim_end_matches('.').eq_ignore_ascii_case(connect_host)
    {
        ev.tls_sni.clone_from(&hello.sni);
        ev.action = Action::Block.as_str();
        return Err(Fail {
            status: None,
            reason: Reason::SniMismatch,
            error: "SNI differs from the CONNECT host",
        });
    }
    Ok(())
}

/// Send `answer` to the client, forward bytes the client already sent after its head (they
/// belong to the tunnel), then relay both ways until close or idle.
pub(crate) async fn open_tunnel<S, U>(
    client: &mut S,
    buf: &mut Vec<u8>,
    upstream: &mut U,
    answer: &[u8],
    ev: &mut RequestEvent,
    deps: &ProxyDeps,
) -> Result<Outcome, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let idle = Duration::from_secs(deps.cfg.timeouts.tunnel_idle);
    write_all(client, answer, idle).await.map_err(|_| client_gone())?;
    let early = std::mem::take(buf);
    if !early.is_empty() {
        let _ = write_all(upstream, &early, idle).await;
    }
    let (out, inn) = relay(client, upstream, idle).await;
    ev.bytes_out += early.len() as u64 + out;
    ev.bytes_in += inn;
    Ok(Outcome::Done)
}

/// Read the ClientHello at the start of a tunnel. `Ok(None)` means the bytes are not TLS.
pub(crate) async fn read_hello<S>(
    client: &mut S,
    buf: &mut Vec<u8>,
    deadline: Instant,
) -> Result<Option<ClientHelloInfo>, Fail>
where
    S: AsyncRead + Unpin,
{
    loop {
        match peek_client_hello(buf) {
            Peek::Incomplete => {
                if !matches!(fill(client, buf, deadline).await, Ok(n) if n > 0) {
                    return Err(Fail {
                        status: None,
                        reason: Reason::Timeout,
                        error: "no ClientHello",
                    });
                }
            }
            Peek::Hello(h) => return Ok(Some(h)),
            Peek::Malformed(e) => {
                return Err(Fail { status: None, reason: Reason::InvalidRequest, error: e });
            }
            Peek::NotTls => return Ok(None),
        }
    }
}

/// Interception (SPEC 4.9): answer 200, peek the ClientHello (TLS vs non-TLS, SNI, ECH), check
/// SNI against the CONNECT host (D-21, D-22), then [`intercept`].
#[allow(clippy::too_many_arguments)]
async fn intercept_tunnel<S>(
    client: &mut S,
    buf: &mut Vec<u8>,
    t: NormalizedTarget,
    ips: Vec<IpAddr>,
    ev: &mut RequestEvent,
    deps: &Arc<ProxyDeps>,
    peer: IpAddr,
    (client_id, profile): (String, Arc<Profile>),
) -> Result<Outcome, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let handshake = Duration::from_secs(deps.cfg.timeouts.tls_handshake);
    write_all(client, ESTABLISHED, handshake).await.map_err(|_| client_gone())?;
    ev.status = 200;
    let Some(hello) = read_hello(client, buf, Instant::now() + handshake).await? else {
        if deps.cfg.block_non_tls_connect {
            return Err(non_tls(ev));
        }
        // Not TLS and allowed: tunnel opaquely (SPEC 4.9).
        let (mut upstream, ip) = connect_upstream(&ips, t.port, deps).await?;
        ev.dest_ip = Some(ip.to_string());
        return open_tunnel(client, buf, &mut upstream, b"", ev, deps).await;
    };
    check_sni(&hello, &t, ev, true)?;
    let tunnel = Tunnel {
        host: t.host,
        port: t.port,
        ips,
        sni: None,
        ech: false,
        user: ev.proxy_user.clone(),
        orig_dst: None,
        host_verified: None,
        client_id,
        profile,
    };
    intercept(client, buf, hello, tunnel, ev, deps, SocketAddr::new(peer, ev.src_port)).await
}

/// Terminate TLS with a minted leaf after ALPN mirroring (D-40) and serve the inner requests
/// through the full pipeline (HTTP/1) or the h2 core. The tunnel's event is logged when it ends;
/// every inner request gets its own event.
pub(crate) async fn intercept<S>(
    client: &mut S,
    buf: &mut Vec<u8>,
    hello: ClientHelloInfo,
    mut tunnel: Tunnel,
    ev: &mut RequestEvent,
    deps: &Arc<ProxyDeps>,
    peer: SocketAddr,
) -> Result<Outcome, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    ev.tls_sni.clone_from(&hello.sni);
    ev.ech_present = hello.ech_present;
    let handshake = Duration::from_secs(deps.cfg.timeouts.tls_handshake);
    let leaves = deps.leaves.as_ref().ok_or(Fail {
        status: None,
        reason: Reason::InternalError,
        error: "no CA",
    })?;
    // ALPN mirroring (D-40): a client offering h2 makes us ask the origin first; the client is
    // then offered exactly the protocol the origin selected, so both sides always match.
    // No upstream (the virtual host) means no probe and HTTP/1.1 only.
    let (alpn, h2_upstream) = if hello.alpn.iter().any(|p| p == b"h2") && !tunnel.ips.is_empty() {
        let offer: Vec<Vec<u8>> = [&b"h2"[..], b"http/1.1"]
            .into_iter()
            .filter(|p| hello.alpn.iter().any(|c| c == p))
            .map(<[u8]>::to_vec)
            .collect();
        let no_page = |f: Fail| Fail { status: None, ..f }; // nothing can be answered in clear
        let (tcp, ip) = connect_upstream(&tunnel.ips, tunnel.port, deps).await.map_err(no_page)?;
        ev.dest_ip = Some(ip.to_string());
        let up = upstream_tls(tcp, &tunnel.host, deps, Some(offer)).await.map_err(no_page)?;
        match up.get_ref().1.alpn_protocol().map(<[u8]>::to_vec) {
            Some(p) if p == b"h2" => (vec![p], Some((up, ip))),
            selected => (selected.into_iter().collect(), None), // probe dropped; h1 per request
        }
    } else {
        (hello.alpn.iter().filter(|p| p.as_slice() == b"http/1.1").cloned().collect(), None)
    };
    let config = leaves.server_config_for(&tunnel.host, alpn).map_err(|_| Fail {
        status: None,
        reason: Reason::InternalError,
        error: "leaf minting failed",
    })?;
    let stream = Prefixed::new(std::mem::take(buf), &mut *client);
    let tls = timeout(handshake, tokio_rustls::TlsAcceptor::from(config).accept(stream))
        .await
        .map_err(|_| Fail {
            status: None,
            reason: Reason::Timeout,
            error: "client TLS handshake timeout",
        })?
        .map_err(|_| Fail {
            status: None,
            reason: Reason::InvalidRequest,
            error: "client TLS handshake failed",
        })?;
    ev.tls_intercepted = true;
    let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    ev.alpn = Some(if negotiated.as_deref() == Some(b"h2") { "h2" } else { "http/1.1" }.into());
    tunnel.sni = hello.sni;
    tunnel.ech = hello.ech_present;
    let tunnel = Arc::new(tunnel);
    match h2_upstream {
        Some((up, ip)) if negotiated.as_deref() == Some(b"h2") => {
            super::h2::serve(tls, up, ip, peer, Arc::clone(deps), tunnel).await;
        }
        // Type-erase the stream: serving a tunnel is recursive (it shares the pipeline), and a
        // concrete nested type would never be finite.
        _ => serve_tunnel(Box::new(tls), peer, Arc::clone(deps), tunnel).await,
    }
    Ok(Outcome::Done)
}

/// Serve an intercepted tunnel. The explicit `dyn Future + Send` return type breaks the
/// recursion between the pipeline and tunnels for type inference and `Send` checking.
fn serve_tunnel<'a>(
    tls: Box<dyn Upstream + 'a>,
    peer: SocketAddr,
    deps: Arc<ProxyDeps>,
    tunnel: Arc<Tunnel>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
    Box::pin(serve_connection(tls, peer, deps, Via::Tunnel(tunnel)))
}

/// After a `101 Switching Protocols` for a validated websocket handshake (D-23): forward the
/// response head, then relay opaque frames.
pub(crate) async fn relay_websocket<S>(
    client: &mut S,
    buf: &mut Vec<u8>,
    mut upstream: UpstreamBox,
    up_buf: Vec<u8>,
    resp: &ResponseHead,
    ev: &mut RequestEvent,
    deps: &Arc<ProxyDeps>,
) -> Result<Outcome, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut headers = forward_headers(&resp.headers, true);
    headers.push(("connection".into(), b"upgrade".to_vec()));
    let mut out = Vec::new();
    write_head(
        &format!("HTTP/1.1 {} {}", resp.status, resp.reason),
        &headers,
        BodyFraming::None,
        &mut out,
    );
    out.extend_from_slice(&up_buf);
    ev.status = 101;
    open_tunnel(client, buf, &mut upstream, &out, ev, deps).await
}
