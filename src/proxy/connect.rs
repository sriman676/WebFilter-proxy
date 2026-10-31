//! CONNECT passthrough (SPEC 4.9 with `intercept=false`; only rules 1-3 apply, 4.6) and the
//! opaque bidirectional relay used by tunnels and websockets (SPEC 4.15 (7)).
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};

use super::ProxyDeps;
use super::http1::{BodyFraming, RequestHead, ResponseHead, forward_headers, write_head};
use super::pipeline::{
    Fail, Outcome, client_gone, connect_upstream, fail, note_decision, note_target, resolve,
    send_block, write_all,
};
use crate::filter::Phase;
use crate::logger::RequestEvent;
use crate::normalize::{TargetContext, canonicalize};
use crate::policy::{PortKind, check_port};
use crate::reason::Reason;

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

/// Handle `CONNECT host:port` without interception.
pub(crate) async fn handle_connect<S>(
    client: &mut S,
    buf: &mut Vec<u8>,
    head: &RequestHead,
    ev: &mut RequestEvent,
    deps: &Arc<ProxyDeps>,
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
    let d = deps.evaluate(&t, Phase::ConnectPreDns);
    note_decision(ev, &d);
    if d.is_block() {
        send_block(client, ev, &d, deps).await;
        return Ok(Outcome::Done);
    }
    let ips = resolve(&t, ev, deps).await?;
    if let Some(d) = ips
        .iter()
        .map(|ip| deps.evaluate(&t, Phase::Resolved { ip: *ip }))
        .find(|d| d.reason != Reason::None)
    {
        note_decision(ev, &d);
        if d.is_block() {
            send_block(client, ev, &d, deps).await;
            return Ok(Outcome::Done);
        }
    }
    let (mut upstream, ip) = connect_upstream(&ips, t.port, deps).await?;
    ev.dest_ip = Some(ip.to_string());
    ev.status = 200;
    open_tunnel(
        client,
        buf,
        &mut upstream,
        b"HTTP/1.1 200 Connection Established\r\n\r\n",
        ev,
        deps,
    )
    .await
}

/// Send `answer` to the client, forward bytes the client already sent after its head (they
/// belong to the tunnel), then relay both ways until close or idle.
async fn open_tunnel<S>(
    client: &mut S,
    buf: &mut Vec<u8>,
    upstream: &mut TcpStream,
    answer: &[u8],
    ev: &mut RequestEvent,
    deps: &ProxyDeps,
) -> Result<Outcome, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
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

/// After a `101 Switching Protocols` for a validated websocket handshake (D-23): forward the
/// response head, then relay opaque frames.
pub(crate) async fn relay_websocket<S>(
    client: &mut S,
    buf: &mut Vec<u8>,
    mut upstream: TcpStream,
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
