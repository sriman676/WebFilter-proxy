//! HTTP/2 inside intercepted TLS (SPEC 4.16, D-40): the client and the origin both negotiated
//! `h2` (ALPN mirroring), so every client stream maps to one stream on the single upstream
//! connection of this tunnel (D-07). Each stream runs the SPEC 4.2 pipeline with rules H1-H11
//! in place of the HTTP/1 framing steps; `h2` enforces the frame layer and H2/H3/H6/H7/H9/H10,
//! `h2guard` the flood limits (D-45).
#![forbid(unsafe_code)]

use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::{Reason as H2Reason, RecvStream, SendStream};
use http::{HeaderMap, Request, Response, Version};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};

use super::ProxyDeps;
use super::h2guard::{GuardState, Guarded, Peer, Violation};
use super::pipeline::{
    Fail, Tunnel, block_html, client_gone, error_headers, fail, host_equals, note_decision,
    note_fail, note_target, resolved_rule,
};
use super::response::{error_html, page_headers};
use crate::config::Http2Config;
use crate::config::ScanMode;
use crate::filter::Phase;
use crate::logger::{RequestEvent, SysEvent};
use crate::normalize::{NormalizedTarget, TargetContext, TargetError, canonicalize};
use crate::reason::Reason;
use crate::scan::Verdict;

/// Close a connection with no open streams after this long without input (SPEC 4.16).
const IDLE: Duration = Duration::from_secs(60);
/// Time allowed to flush a GOAWAY.
const CLOSE_GRACE: Duration = Duration::from_secs(1);

/// Server role towards the client, with the `[http2]` limits.
fn server_builder(c: &Http2Config) -> h2::server::Builder {
    let mut b = h2::server::Builder::new();
    b.initial_window_size(c.initial_stream_window)
        .initial_connection_window_size(c.initial_conn_window)
        .max_frame_size(c.max_frame_size)
        .max_header_list_size(c.max_header_list_size)
        .header_table_size(4096)
        .max_concurrent_streams(c.max_concurrent_streams)
        .max_concurrent_reset_streams(c.reset_limit as usize)
        .max_pending_accept_reset_streams(c.reset_limit as usize)
        .max_local_error_reset_streams(Some(c.reset_limit as usize));
    b
}

/// Client role towards the origin: same limits, push disabled (H8).
fn client_builder(c: &Http2Config) -> h2::client::Builder {
    let mut b = h2::client::Builder::new();
    b.initial_window_size(c.initial_stream_window)
        .initial_connection_window_size(c.initial_conn_window)
        .max_frame_size(c.max_frame_size)
        .max_header_list_size(c.max_header_list_size)
        .header_table_size(4096)
        .max_concurrent_reset_streams(c.reset_limit as usize)
        .max_pending_accept_reset_streams(c.reset_limit as usize)
        .max_local_error_reset_streams(Some(c.reset_limit as usize))
        .enable_push(false);
    b
}

/// What every stream task of one connection shares.
struct Conn {
    deps: Arc<ProxyDeps>,
    tunnel: Arc<Tunnel>,
    peer: SocketAddr,
    dest_ip: IpAddr,
    upstream: h2::client::SendRequest<Bytes>,
    guard: Arc<GuardState>,
}

/// Serve an h2 client connection over `upstream`, the verified TLS connection on which the
/// origin selected `h2`.
pub(crate) async fn serve<C, U>(
    client: C,
    upstream: U,
    dest_ip: IpAddr,
    peer: SocketAddr,
    deps: Arc<ProxyDeps>,
    tunnel: Arc<Tunnel>,
) where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let cfg = &deps.cfg.http2;
    let handshake = Duration::from_secs(deps.cfg.timeouts.tls_handshake);
    let origin_guard = Arc::new(GuardState::default());
    let up = Guarded::new(upstream, cfg, Peer::Origin, Arc::clone(&origin_guard));
    let Ok(Ok((send, up_conn))) = timeout(handshake, client_builder(cfg).handshake(up)).await
    else {
        return;
    };
    let up_driver = {
        let (deps, guard) = (Arc::clone(&deps), Arc::clone(&origin_guard));
        tokio::spawn(async move {
            tokio::select! {
                _ = up_conn => {}
                v = guard.tripped() => flood_event(&deps, v, "origin", &guard),
            }
        })
    };
    let guard = Arc::new(GuardState::default());
    let io = Guarded::new(client, cfg, Peer::Client, Arc::clone(&guard));
    if let Ok(Ok(mut conn)) = timeout(handshake, server_builder(cfg).handshake(io)).await {
        let shared = Arc::new(Conn {
            deps: Arc::clone(&deps),
            tunnel,
            peer,
            dest_ip,
            upstream: send,
            guard,
        });
        drive(&mut conn, &shared).await;
    }
    up_driver.abort();
}

/// Accept streams until the connection ends; enforce the flood guard, the per-connection stream
/// budget and the idle timeout.
async fn drive<T>(conn: &mut h2::server::Connection<T, Bytes>, shared: &Arc<Conn>)
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let cfg = &shared.deps.cfg.http2;
    let mut streams = JoinSet::new();
    let mut accepted = 0u64;
    let mut closing = false;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            next = conn.accept() => match next {
                Some(Ok((req, respond))) => {
                    accepted += 1;
                    streams.spawn(stream(req, respond, Arc::clone(shared)));
                    if accepted >= u64::from(cfg.max_streams_per_connection) && !closing {
                        closing = true;
                        conn.graceful_shutdown();
                    }
                }
                Some(Err(e)) => {
                    // h2's own flood limits answer with ENHANCE_YOUR_CALM; account for them too.
                    if e.reason() == Some(H2Reason::ENHANCE_YOUR_CALM) {
                        flood_event(&shared.deps, Violation::Library, "client", &shared.guard);
                    }
                    break;
                }
                None => break,
            },
            v = shared.guard.tripped() => {
                conn.abrupt_shutdown(H2Reason::ENHANCE_YOUR_CALM);
                flood_event(&shared.deps, v, "client", &shared.guard);
                let _ = timeout(CLOSE_GRACE, poll_fn(|cx| conn.poll_closed(cx))).await;
                break;
            }
            _ = tick.tick() => {
                let idle = !conn.has_streams() && shared.guard.idle_for() >= IDLE;
                if (idle || shared.deps.shutting_down()) && !closing {
                    closing = true;
                    conn.graceful_shutdown();
                }
            }
            Some(_) = streams.join_next(), if !streams.is_empty() => {}
        }
    }
}

/// GOAWAY(ENHANCE_YOUR_CALM) was sent: system event + stats counter (D-45).
fn flood_event(deps: &ProxyDeps, v: Violation, side: &str, guard: &GuardState) {
    deps.stats.record_h2_flood();
    deps.telemetry.h2_flood(v.as_str());
    deps.logger.system().event(
        SysEvent::H2Flood,
        serde_json::json!({
            "violation": v.as_str(),
            "side": side,
            "streams": guard.streams.load(std::sync::atomic::Ordering::Relaxed),
        }),
    );
}

/// One client stream: pipeline, one log event.
async fn stream(
    req: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    c: Arc<Conn>,
) {
    let started = Instant::now();
    let tn = &c.tunnel;
    let mut ev = c.deps.new_event(c.peer);
    ev.tls_intercepted = true;
    ev.tls_sni.clone_from(&tn.sni);
    ev.ech_present = tn.ech;
    ev.proxy_user.clone_from(&tn.user);
    ev.alpn = Some("h2".into());
    ev.http_version = "2".into();
    ev.h2_stream_id = Some(respond.stream_id().as_u32());
    ev.http_method = req.method().as_str().to_owned();
    ev.user_agent =
        req.headers().get("user-agent").map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    if let Err(f) = exchange(req, &mut respond, &mut ev, &c).await {
        match f.status {
            Some(status) => {
                let html = error_html(status, f.reason, &ev.event_id);
                let _ = send_page(
                    &mut respond,
                    status,
                    f.reason,
                    &ev.event_id,
                    html,
                    &error_headers(status),
                );
            }
            None if f.reason == Reason::InvalidRequest => {
                respond.send_reset(H2Reason::PROTOCOL_ERROR);
                c.guard.local_reset(); // the client caused this reset (MadeYouReset)
            }
            None => respond.send_reset(H2Reason::INTERNAL_ERROR),
        }
        note_fail(&mut ev, &f);
    }
    ev.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    c.deps.finish(ev);
}

/// A stream-level protocol error: RST_STREAM(PROTOCOL_ERROR), logged as `invalid_request`.
fn stream_error(error: &'static str) -> Fail {
    Fail { status: None, reason: Reason::InvalidRequest, error }
}

/// H1, H4, H5, H8: pseudo-headers, authority and path for this tunnel.
fn target(req: &http::request::Parts, tn: &Tunnel) -> Result<NormalizedTarget, Fail> {
    if req.method == http::Method::CONNECT {
        return Err(stream_error("CONNECT over h2 (H8)"));
    }
    if req.method == http::Method::TRACE {
        return Err(fail(405, Reason::MethodNotAllowed, "TRACE"));
    }
    if req.uri.scheme_str() != Some("https") {
        return Err(stream_error(":scheme must be https (H1)"));
    }
    let authority = req.uri.authority().ok_or(stream_error("missing :authority (H1)"))?;
    let path = req.uri.path_and_query().ok_or(stream_error("missing :path (H1)"))?;
    if !path.as_str().starts_with('/') {
        return Err(stream_error(":path must be origin-form (H5)"));
    }
    let host = tn.host.to_string();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ctx = TargetContext::InterceptedOrigin { connect_host: host, port: tn.port };
    let t = canonicalize(path.as_str(), ctx).map_err(|e| match e {
        TargetError::HostMismatch => {
            fail(403, Reason::HostMismatch, "target does not match the CONNECT authority")
        }
        _ => stream_error("invalid :path (H5)"),
    })?;
    let mut hosts = req.headers.get_all(http::header::HOST).iter();
    let host_header_ok = match (hosts.next(), hosts.next()) {
        (None, _) => true,
        (Some(h), None) => h.as_bytes().eq_ignore_ascii_case(authority.as_str().as_bytes()),
        (Some(_), Some(_)) => return Err(stream_error("multiple host headers")),
    };
    if !host_equals(authority.as_str().as_bytes(), &t) || !host_header_ok {
        return Err(fail(
            403,
            Reason::HostMismatch,
            ":authority does not match the CONNECT authority (H4)",
        ));
    }
    Ok(t)
}

/// Request headers to the origin / response headers to the client: no connection-specific,
/// proxy or `x-webfilter-*` fields (H3, PF-3-01); `:authority` replaces `host`.
fn forward_headers(src: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src {
        let n = name.as_str();
        let drop = matches!(
            n,
            "host"
                | "connection"
                | "proxy-connection"
                | "keep-alive"
                | "transfer-encoding"
                | "upgrade"
        ) || n.starts_with("proxy-")
            || n.starts_with("x-webfilter-")
            || (n == "te" && value.as_bytes() != b"trailers");
        if !drop {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// A proxy page as an h2 response (H11).
fn send_page(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: u16,
    reason: Reason,
    event_id: &str,
    html: String,
    extra: &[(&'static str, String)],
) -> Result<(), h2::Error> {
    let mut resp = Response::builder().status(status);
    for (name, value) in page_headers(status, reason, event_id).iter().chain(extra) {
        resp = resp.header(*name, value.as_str());
    }
    let resp = resp.header("content-length", html.len()).body(()).unwrap_or_default();
    respond.send_response(resp, false)?.send_data(Bytes::from(html), true)
}

async fn send_block(
    respond: &mut h2::server::SendResponse<Bytes>,
    ev: &mut RequestEvent,
    d: &crate::filter::Decision,
    deps: &ProxyDeps,
) {
    let (html, extra) = block_html(ev, d, deps);
    let _ = send_page(respond, 403, d.reason, &ev.event_id, html, &extra);
    ev.status = 403;
}

/// Pipeline steps for one stream (SPEC 4.2 with H1-H11).
async fn exchange(
    req: Request<RecvStream>,
    respond: &mut h2::server::SendResponse<Bytes>,
    ev: &mut RequestEvent,
    c: &Conn,
) -> Result<(), Fail> {
    let deps = &c.deps;
    let (parts, body) = req.into_parts();
    let t = target(&parts, &c.tunnel)?;
    note_target(ev, &t);
    ev.dest_ip = Some(c.dest_ip.to_string());
    let profile = &c.tunnel.profile;
    ev.client_id = Some(c.tunnel.client_id.clone());
    ev.profile = Some(profile.name.clone());
    let _inflight = match deps.admit(&c.tunnel.client_id, profile) {
        Ok(permit) => permit,
        Err(r) => {
            let html = error_html(r.status, r.reason, &ev.event_id);
            let extra = [("retry-after", r.retry_after.to_string())];
            let _ = send_page(respond, r.status, r.reason, &ev.event_id, html, &extra);
            note_fail(ev, &fail(r.status, r.reason, "limit exceeded"));
            return Ok(());
        }
    };
    let d = deps.evaluate(&t, Phase::PreDns, profile, &c.tunnel.client_id);
    note_decision(ev, &d);
    if d.is_block() {
        send_block(respond, ev, &d, deps).await;
        return Ok(());
    }
    if let Some(d) = resolved_rule(deps, &t, &c.tunnel.ips, profile, &c.tunnel.client_id) {
        note_decision(ev, &d);
        if d.is_block() {
            send_block(respond, ev, &d, deps).await;
            return Ok(());
        }
    }

    // Rebuilt from the checked target (D-09) on this tunnel's upstream connection.
    let uri = format!("https://{}{}", t.authority(), t.origin_form());
    let mut up_req = Request::builder()
        .method(parts.method.clone())
        .uri(uri)
        .version(Version::HTTP_2)
        .body(())
        .map_err(|_| stream_error("unrepresentable request"))?;
    *up_req.headers_mut() = forward_headers(&parts.headers);
    let upstream_err = || fail(502, Reason::UpstreamError, "upstream h2 error");
    let mut sender = c.upstream.clone().ready().await.map_err(|_| upstream_err())?;
    let end = body.is_end_stream();
    let (resp_fut, up_send) = sender.send_request(up_req, end).map_err(|_| upstream_err())?;
    let stall = Duration::from_secs(deps.cfg.http2.stall_timeout_secs);
    let upload =
        async { if end { Ok(0) } else { pump(body, up_send, stall, None, &mut |_| {}).await } };
    let response =
        timeout(Duration::from_secs(deps.cfg.timeouts.upstream_response_header), resp_fut);
    let (sent, resp) = tokio::join!(upload, response);
    ev.bytes_out = sent.map_err(|e| match e {
        PumpError::Stall => fail(504, Reason::Timeout, "upstream stalled"),
        PumpError::Closed => client_gone(),
    })?;
    let resp = resp
        .map_err(|_| fail(504, Reason::Timeout, "upstream timeout"))?
        .map_err(|_| upstream_err())?; // includes H10 violations detected by h2

    let (rparts, rbody) = resp.into_parts();
    // One unambiguous Content-Type or 502, as in HTTP/1 (D-08, review 2 M2).
    let content_type = crate::util::content_type(
        rparts.headers.get_all(http::header::CONTENT_TYPE).iter().map(|v| v.as_bytes()),
    )
    .map_err(|_| fail(502, Reason::UpstreamError, "ambiguous upstream Content-Type"))?;
    ev.http_content_type = content_type.as_deref().map(|c| crate::util::media_type(c).to_owned());
    let phase = Phase::ResponseHeaders { content_type: content_type.as_deref() };
    let d = deps.evaluate(&t, phase, profile, &c.tunnel.client_id);
    if d.reason != Reason::None {
        note_decision(ev, &d);
    }
    if d.is_block() {
        send_block(respond, ev, &d, deps).await; // dropping `rbody` resets the upstream stream
        return Ok(());
    }

    let mut rbody = rbody;
    let mut first = None;
    // Download inspection (D-53) on intercepted h2 streams.
    if let Some(scanner) = deps.scanner.as_ref().filter(|_| {
        profile.scan_downloads == Some(true)
            && parts.method == http::Method::GET
            && rparts.status.is_success()
    }) {
        // Accumulate DATA frames up to the magic prefix (a 1-byte first frame must not hide
        // it, review M1); every byte read is kept and forwarded as one chunk.
        let idle = Duration::from_secs(deps.cfg.timeouts.upstream_body_idle);
        let mut acc = bytes::BytesMut::new();
        while acc.len() < super::scanning::PREFIX && !rbody.is_end_stream() {
            match timeout(idle, rbody.data()).await {
                Err(_) => return Err(fail(504, Reason::Timeout, "upstream body idle")),
                Ok(None) => break,
                Ok(Some(r)) => acc.extend_from_slice(&r.map_err(|_| upstream_err())?),
            }
        }
        first = (!acc.is_empty()).then(|| acc.freeze());
        let prefix = first.as_deref().unwrap_or(&[]);
        let prefix = prefix.get(..prefix.len().min(super::scanning::PREFIX)).unwrap_or(&[]);
        let dispositions: Vec<String> = rparts
            .headers
            .get_all(http::header::CONTENT_DISPOSITION)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect();
        let encoded = crate::scan::content_encoded(
            rparts.headers.get_all(http::header::CONTENT_ENCODING).iter().map(|v| v.as_bytes()),
        );
        let download = crate::scan::Download {
            path: &t.path,
            content_type: content_type.as_deref(),
            dispositions: &dispositions,
            encoded,
            prefix,
        };
        if scanner.eligible(&download) {
            let cd = dispositions.first().map(String::as_str);
            ev.download_name = Some(crate::scan::download_name(cd, &t.path));
            return scan_stream(respond, ev, c, profile, scanner, &rparts, first, rbody).await;
        }
    }

    let mut out = Response::builder().status(rparts.status).body(()).map_err(|_| upstream_err())?;
    *out.headers_mut() = forward_headers(&rparts.headers);
    let end = rbody.is_end_stream() && first.is_none();
    let down = respond.send_response(out, end).map_err(|_| client_gone())?;
    ev.status = rparts.status.as_u16();
    if !end {
        ev.bytes_in =
            pump(rbody, down, stall, first, &mut |_| {}).await.map_err(|e| relay_fail(c, e))?;
    }
    Ok(())
}

/// A response-relay failure; a stalled client trips the flood guard (D-45).
fn relay_fail(c: &Conn, e: PumpError) -> Fail {
    if e == PumpError::Stall {
        c.guard.trip(Violation::Stall);
    }
    Fail { status: None, reason: Reason::UpstreamError, error: "response body relay failed" }
}

/// Scan an eligible h2 download: detect tees while relaying, block buffers first (P4).
#[allow(clippy::too_many_arguments)]
async fn scan_stream(
    respond: &mut h2::server::SendResponse<Bytes>,
    ev: &mut RequestEvent,
    c: &Conn,
    profile: &crate::profiles::Profile,
    scanner: &crate::scan::Scanner,
    rparts: &http::response::Parts,
    first: Option<Bytes>,
    mut rbody: RecvStream,
) -> Result<(), Fail> {
    use super::scanning::{decision, known_unscannable, malware_event, note_verdict};
    let deps = &c.deps;
    let stall = Duration::from_secs(deps.cfg.http2.stall_timeout_secs);
    let length = rparts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse().ok());
    let encoded = crate::scan::content_encoded(
        rparts.headers.get_all(http::header::CONTENT_ENCODING).iter().map(|v| v.as_bytes()),
    );
    let early = known_unscannable(rparts.status.as_u16(), encoded, length, scanner.cfg.max_bytes);
    let mut slot = match early {
        Some(why) => Err(Verdict::Unscannable(why)),
        None => scanner.begin().await.map_err(Verdict::Unscannable),
    };
    let head = |len: Option<u64>| {
        let mut out = Response::builder().status(rparts.status).body(()).unwrap_or_default();
        *out.headers_mut() = forward_headers(&rparts.headers);
        out.headers_mut().remove(http::header::CONTENT_LENGTH);
        if let Some(n) = len {
            out.headers_mut().insert(http::header::CONTENT_LENGTH, n.into());
        }
        out
    };
    if scanner.cfg.mode == ScanMode::Detect || slot.is_err() {
        if let (Err(v), ScanMode::Block) = (&slot, scanner.cfg.mode)
            && let Some(d) = decision(scanner, v, profile)
        {
            note_verdict(ev, v, None, 0);
            note_decision(ev, &d);
            send_block(respond, ev, &d, deps).await;
            return Ok(());
        }
        let down = respond.send_response(head(length), false).map_err(|_| client_gone())?;
        ev.status = rparts.status.as_u16();
        let mut tap = |chunk: &[u8]| {
            if let Ok(s) = slot.as_mut() {
                let _ = s.write(chunk);
            }
        };
        ev.bytes_in =
            pump(rbody, down, stall, first, &mut tap).await.map_err(|e| relay_fail(c, e))?;
        match slot {
            Ok(mut s) => {
                let (v, sha) = scanner.finish(&mut s).await;
                note_verdict(ev, &v, Some(sha), s.bytes);
            }
            Err(v) => note_verdict(ev, &v, None, 0),
        }
        malware_event(deps, ev);
        return Ok(());
    }
    // Block mode: buffer within max_bytes and buffer_timeout_secs, scan, then deliver or refuse.
    let Ok(mut s) = slot else { return Err(client_gone()) };
    let mut held: Vec<Bytes> = Vec::new();
    let limit = Duration::from_secs(scanner.cfg.buffer_timeout_secs);
    let buffered = timeout(limit, async {
        let mut next = first;
        loop {
            let chunk = match next.take() {
                Some(b) => b,
                None => match rbody.data().await {
                    Some(r) => r.map_err(|_| ())?,
                    None => return Ok(true),
                },
            };
            let _ = rbody.flow_control().release_capacity(chunk.len());
            if s.write(&chunk).is_err() {
                held.push(chunk);
                return Ok(false);
            }
        }
    })
    .await;
    let complete = match buffered {
        Ok(Ok(done)) => done,
        Ok(Err(())) => return Err(upstream_err_fail()),
        Err(_) => {
            s.stop("scan buffer timeout");
            false
        }
    };
    let (v, sha) = scanner.finish(&mut s).await;
    note_verdict(ev, &v, Some(sha), s.bytes);
    malware_event(deps, ev);
    if let Some(d) = decision(scanner, &v, profile)
        && d.is_block()
    {
        note_decision(ev, &d);
        send_block(respond, ev, &d, deps).await;
        return Ok(());
    }
    let mut down = respond
        .send_response(head(complete.then_some(s.bytes)), false)
        .map_err(|_| client_gone())?;
    ev.status = rparts.status.as_u16();
    let mut sent = 0u64;
    let chunks = s.chunks().map_err(|_| client_gone())?;
    for chunk in chunks.map(|r| r.map(Bytes::from)).chain(held.into_iter().map(Ok)) {
        let chunk = chunk.map_err(|_| client_gone())?;
        sent += chunk.len() as u64;
        send_chunk(&mut down, chunk, stall).await.map_err(|e| relay_fail(c, e))?;
    }
    if complete {
        down.send_data(Bytes::new(), true).map_err(|_| client_gone())?;
    } else {
        sent += pump(rbody, down, stall, None, &mut |_| {}).await.map_err(|e| relay_fail(c, e))?;
    }
    ev.bytes_in = sent;
    Ok(())
}

fn upstream_err_fail() -> Fail {
    fail(502, Reason::UpstreamError, "upstream h2 error")
}

#[derive(Debug, PartialEq, Eq)]
enum PumpError {
    /// No flow-control credit for `stall_timeout_secs`.
    Stall,
    /// Either side reset or closed.
    Closed,
}

/// Send one chunk as the receiver's flow-control credit allows.
async fn send_chunk(
    to: &mut SendStream<Bytes>,
    mut chunk: Bytes,
    stall: Duration,
) -> Result<(), PumpError> {
    while !chunk.is_empty() {
        to.reserve_capacity(chunk.len());
        let cap = timeout(stall, poll_fn(|cx| to.poll_capacity(cx)))
            .await
            .map_err(|_| PumpError::Stall)?
            .ok_or(PumpError::Closed)?
            .map_err(|_| PumpError::Closed)?;
        let piece = chunk.split_to(cap.min(chunk.len()));
        if !piece.is_empty() {
            to.send_data(piece, false).map_err(|_| PumpError::Closed)?;
        }
    }
    Ok(())
}

/// Relay DATA (and trailers) honoring the receiver's flow control: input credit is released
/// only after the bytes were handed to the other side, so memory stays bounded by the windows.
/// `first` is a chunk already read from `from`; `tap` sees every chunk (download scanning).
async fn pump(
    mut from: RecvStream,
    mut to: SendStream<Bytes>,
    stall: Duration,
    first: Option<Bytes>,
    tap: &mut (dyn FnMut(&[u8]) + Send),
) -> Result<u64, PumpError> {
    let mut total = 0u64;
    let mut next = first;
    loop {
        let chunk = match next.take() {
            Some(b) => b,
            None => match from.data().await {
                Some(r) => r.map_err(|_| PumpError::Closed)?,
                None => break,
            },
        };
        let len = chunk.len();
        tap(&chunk);
        send_chunk(&mut to, chunk, stall).await?;
        total += len as u64;
        from.flow_control().release_capacity(len).map_err(|_| PumpError::Closed)?;
    }
    match from.trailers().await.map_err(|_| PumpError::Closed)? {
        Some(trailers) => to.send_trailers(forward_headers(&trailers)),
        None => to.send_data(Bytes::new(), true),
    }
    .map_err(|_| PumpError::Closed)?;
    Ok(total)
}
