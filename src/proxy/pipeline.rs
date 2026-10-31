//! The per-request pipeline (SPEC 4.2): every request on a connection is validated, canonicalized,
//! policy-checked and filtered (D-10), then forwarded on a fresh upstream connection (D-07)
//! rebuilt only from normalized fields (D-09). Exactly one log event per request.
#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};

use super::ProxyDeps;
use super::http1::{
    BodyFraming, HeadError, HttpVersion, RequestHead, ResponseHead, forward_headers,
    is_websocket_upgrade, parse_request_head, parse_response_head, response_framing, single,
    tokens, validate_request, write_head,
};
pub(crate) use super::io::write_all;
use super::io::{IoError, copy_body, read_head};
use super::response::{BlockInfo, error_page, page};
use crate::filter::{Action, Decision, Phase};
use crate::logger::RequestEvent;
use crate::normalize::{NormalizedTarget, Scheme, TargetContext, canonicalize};
use crate::policy::{PolicyVerdict, PortKind, check_destination, check_port};
use crate::reason::Reason;

/// How a request ended (before logging).
pub(crate) enum Outcome {
    /// A response was relayed; reuse the client connection only if `keep_alive`.
    Forwarded { keep_alive: bool },
    /// We answered (block page) or switched to a relay; close afterwards.
    Done,
}

/// A request-level failure. `status: None` means a response was already started, so the
/// connection is just closed (never a second response, SPEC 4.15 (5)).
#[derive(Debug)]
pub(crate) struct Fail {
    pub status: Option<u16>,
    pub reason: Reason,
    pub error: &'static str,
}

pub(crate) fn fail(status: u16, reason: Reason, error: &'static str) -> Fail {
    Fail { status: Some(status), reason, error }
}

pub(crate) fn head_fail(e: HeadError) -> Fail {
    let reason = if e == HeadError::MethodNotAllowed {
        Reason::MethodNotAllowed
    } else {
        Reason::InvalidRequest
    };
    fail(e.status(), reason, "invalid request head")
}

pub(crate) fn upstream_fail(e: &IoError) -> Fail {
    match e {
        IoError::Timeout => fail(504, Reason::Timeout, "upstream timeout"),
        _ => fail(502, Reason::UpstreamError, "upstream error"),
    }
}

/// Query parameter names only (D-18).
fn query_keys(t: &NormalizedTarget) -> Vec<String> {
    let query = t.query.as_deref().unwrap_or("");
    query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| kv.split('=').next().unwrap_or("").to_owned())
        .collect()
}

fn client_wants_keep_alive(h: &RequestHead) -> bool {
    let conn = tokens(&h.headers, "connection");
    match h.version {
        HttpVersion::Http11 => !conn.iter().any(|t| t == "close"),
        HttpVersion::Http10 => conn.iter().any(|t| t == "keep-alive"),
    }
}

/// R7: a `Host` header, if present, must equal the target authority (default port normalized).
fn host_matches(h: &RequestHead, t: &NormalizedTarget) -> bool {
    let Some(host) = single(&h.headers, "host") else { return true };
    let host = String::from_utf8_lossy(host).to_ascii_lowercase();
    let default = format!(":{}", t.scheme.default_port());
    host.strip_suffix(&default).unwrap_or(&host) == t.authority()
}

/// Fill the target fields of a log event.
pub(crate) fn note_target(ev: &mut RequestEvent, t: &NormalizedTarget) {
    ev.url = t.url_norm.clone();
    ev.url_scheme = t.scheme.as_str().to_owned();
    ev.dest_host = t.host.to_string();
    ev.dest_port = t.port;
    ev.uri_path = t.path.clone();
    ev.uri_query_keys = query_keys(t);
    ev.suspicious_encoding = t.suspicious_encoding;
}

/// Copy a decision into the log event.
pub(crate) fn note_decision(ev: &mut RequestEvent, d: &Decision) {
    ev.action = d.action.as_str();
    ev.would_block |= d.would_block;
    if d.reason != Reason::None {
        ev.reason = d.reason.as_str();
        ev.rule_id.clone_from(&d.rule_id);
        ev.rule_list.clone_from(&d.rule_list);
    }
}

/// Write a response page with the configured client write timeout.
pub(crate) async fn send<S: AsyncWrite + Unpin>(client: &mut S, bytes: &[u8], deps: &ProxyDeps) {
    let _ =
        timeout(Duration::from_secs(deps.cfg.timeouts.client_head_read), client.write_all(bytes))
            .await;
}

/// Send the block page for a decision (SPEC 4.7).
pub(crate) async fn send_block<S: AsyncWrite + Unpin>(
    client: &mut S,
    ev: &mut RequestEvent,
    d: &Decision,
    deps: &ProxyDeps,
) {
    let info = BlockInfo {
        url: &ev.url,
        host: &ev.dest_host,
        reason: d.reason,
        rule_id: d.rule_id.as_deref(),
        category: d.category.as_deref(),
        event_id: &ev.event_id,
        timestamp: &ev.timestamp,
    };
    let html = deps.block_page.render(&info);
    send(client, &page(403, d.reason, &ev.event_id, &html, &[]), deps).await;
    ev.status = 403;
}

/// Answer a failure with an error page (unless a response was already started) and log it.
pub(crate) async fn send_fail<S: AsyncWrite + Unpin>(
    client: &mut S,
    ev: &mut RequestEvent,
    f: &Fail,
    deps: &ProxyDeps,
) {
    if let Some(status) = f.status {
        let extra: Vec<(&str, String)> = match status {
            503 => vec![("retry-after", "5".into())],
            407 => vec![("proxy-authenticate", "Basic realm=\"webfilter\"".into())],
            _ => vec![],
        };
        send(client, &error_page(status, f.reason, &ev.event_id, &extra), deps).await;
        ev.status = status;
    }
    ev.reason = f.reason.as_str();
    ev.error = Some(f.error.to_owned());
    if matches!(
        f.reason,
        Reason::UserinfoInUrl
            | Reason::HostMismatch
            | Reason::PortNotAllowed
            | Reason::PrivateRange
    ) {
        ev.action = Action::Block.as_str();
    }
}

/// Serve one client connection until it closes, fails or must be closed.
pub async fn serve_connection<S>(mut client: S, peer: SocketAddr, deps: Arc<ProxyDeps>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut buf = Vec::new();
    let mut idle_secs = deps.cfg.timeouts.client_head_read;
    while !deps.shutting_down() {
        let deadline = Instant::now() + Duration::from_secs(idle_secs);
        idle_secs = deps.cfg.timeouts.client_keepalive_idle;
        let limits = deps.limits;
        let mut ev = deps.new_event(peer);
        let started = Instant::now();
        let head =
            match read_head(&mut client, &mut buf, deadline, |b| parse_request_head(b, &limits))
                .await
            {
                Ok(Some(h)) => h,
                Ok(None) | Err(IoError::Closed | IoError::Io(_)) => return,
                Err(e) => {
                    if let IoError::Framing(h) = e {
                        send_fail(&mut client, &mut ev, &head_fail(h), &deps).await;
                        deps.finish(ev);
                    }
                    return; // timeouts close silently (slow-client defense)
                }
            };
        ev.http_method.clone_from(&head.method);
        ev.http_version = head.version.as_str().to_owned();
        ev.user_agent =
            single(&head.headers, "user-agent").map(|v| String::from_utf8_lossy(v).into_owned());

        let outcome = handle_request(&mut client, &mut buf, &head, &mut ev, &deps, peer.ip()).await;
        ev.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let keep_alive = match outcome {
            Ok(Outcome::Forwarded { keep_alive }) => keep_alive,
            Ok(Outcome::Done) => false,
            Err(f) => {
                send_fail(&mut client, &mut ev, &f, &deps).await;
                false
            }
        };
        deps.finish(ev);
        if !keep_alive {
            let _ = timeout(Duration::from_secs(1), client.shutdown()).await;
            return;
        }
    }
}

async fn handle_request<S>(
    client: &mut S,
    buf: &mut Vec<u8>,
    head: &RequestHead,
    ev: &mut RequestEvent,
    deps: &Arc<ProxyDeps>,
    peer: IpAddr,
) -> Result<Outcome, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // 2. Validate. 3. Auth. 4. TRACE (in validate) and target forms.
    let framing = validate_request(head).map_err(head_fail)?;
    deps.authorize(head, ev, peer).await?;
    if head.method == "CONNECT" {
        return super::connect::handle_connect(client, buf, head, ev, deps).await;
    }
    // 5. Canonicalize (4.5); plain listener accepts only http absolute-form (R9).
    let t = canonicalize(&head.target, TargetContext::PlainAbsolute).map_err(|e| {
        fail(
            if e.reason() == Reason::UserinfoInUrl { 403 } else { 400 },
            e.reason(),
            "invalid request target",
        )
    })?;
    note_target(ev, &t);
    if t.scheme != Scheme::Http {
        return Err(fail(
            400,
            Reason::InvalidRequest,
            "https absolute-form on the plain listener (R9)",
        ));
    }
    if !host_matches(head, &t) {
        return Err(fail(400, Reason::InvalidRequest, "Host does not match the target (R7)"));
    }
    let websocket = is_websocket_upgrade(head);
    if websocket {
        ev.upgrade = Some("websocket".into());
    }

    // 7. Port policy. 8. Pre-DNS rules: a blocked name is never resolved.
    check_port(PortKind::Http, t.port, &deps.cfg.ports)
        .map_err(|r| fail(403, r, "port not allowed"))?;
    let d = deps.evaluate(&t, Phase::PreDns);
    note_decision(ev, &d);
    if d.is_block() {
        send_block(client, ev, &d, deps).await;
        return Ok(Outcome::Done);
    }

    // 6/9. Resolve once; validate every address; rule 3 per address.
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

    // 10. Fresh upstream connection, request rebuilt from normalized fields (D-07, D-09).
    let (mut upstream, ip) = connect_upstream(&ips, t.port, deps).await?;
    ev.dest_ip = Some(ip.to_string());
    let mut headers = forward_headers(&head.headers, websocket);
    headers.insert(0, ("host".into(), t.authority().into_bytes()));
    headers.push((
        "connection".into(),
        if websocket { b"upgrade".to_vec() } else { b"close".to_vec() },
    ));
    let mut out = Vec::new();
    write_head(
        &format!("{} {} HTTP/1.1", head.method, t.origin_form()),
        &headers,
        framing,
        &mut out,
    );
    let idle = Duration::from_secs(deps.cfg.timeouts.upstream_body_idle);
    write_all(&mut upstream, &out, idle).await.map_err(|e| upstream_fail(&e))?;

    let resp_deadline =
        || Instant::now() + Duration::from_secs(deps.cfg.timeouts.upstream_response_header);
    let mut up_buf = Vec::new();
    let mut final_resp = None;
    if framing != BodyFraming::None
        && tokens(&head.headers, "expect").iter().any(|t| t == "100-continue")
    {
        // R13: relay 100 Continue only when the origin sends it; never synthesize.
        let resp = read_response(&mut upstream, &mut up_buf, resp_deadline(), deps).await?;
        if resp.status == 100 {
            write_all(client, b"HTTP/1.1 100 Continue\r\n\r\n", idle)
                .await
                .map_err(|_| client_gone())?;
        } else {
            final_resp = Some(resp); // the origin answered without wanting the body
        }
    }
    let body_sent = final_resp.is_none();
    if body_sent {
        ev.bytes_out = copy_body(client, buf, &mut upstream, framing, deps.limits.compat, idle)
            .await
            .map_err(|e| match e {
                IoError::Framing(h) => head_fail(h),
                other => upstream_fail(&other),
            })?;
    }

    // 11. Response: skip interim 1xx, validate framing, rule 6, stream.
    let resp = match final_resp {
        Some(r) => r,
        None => loop {
            let r = read_response(&mut upstream, &mut up_buf, resp_deadline(), deps).await?;
            if !(100..200).contains(&r.status) || (r.status == 101 && websocket) {
                break r;
            }
        },
    };
    if resp.status == 101 {
        return super::connect::relay_websocket(client, buf, upstream, up_buf, &resp, ev, deps)
            .await;
    }
    let resp_framing = response_framing(&resp, &head.method)
        .map_err(|_| fail(502, Reason::UpstreamError, "bad upstream framing"))?;
    let content_type =
        single(&resp.headers, "content-type").map(|v| String::from_utf8_lossy(v).into_owned());
    ev.http_content_type =
        content_type.as_deref().map(|c| c.split(';').next().unwrap_or("").trim().to_owned());
    let d = deps.evaluate(&t, Phase::ResponseHeaders { content_type: content_type.as_deref() });
    if d.reason != Reason::None {
        note_decision(ev, &d);
    }
    if d.is_block() {
        send_block(client, ev, &d, deps).await; // upstream headers discarded, body never forwarded
        return Ok(Outcome::Done);
    }

    let keep_alive = body_sent
        && client_wants_keep_alive(head)
        && resp_framing != BodyFraming::CloseDelimited
        && !deps.shutting_down();
    let mut resp_headers = forward_headers(&resp.headers, false);
    if !keep_alive {
        resp_headers.push(("connection".into(), b"close".to_vec()));
    }
    let wire_framing =
        if resp_framing == BodyFraming::CloseDelimited { BodyFraming::None } else { resp_framing };
    let mut out = Vec::new();
    write_head(
        &format!("HTTP/1.1 {} {}", resp.status, resp.reason),
        &resp_headers,
        wire_framing,
        &mut out,
    );
    write_all(client, &out, idle).await.map_err(|_| client_gone())?;
    ev.status = resp.status;
    ev.bytes_in = copy_body(&mut upstream, &mut up_buf, client, resp_framing, false, idle)
        .await
        .map_err(|e| Fail { status: None, ..upstream_fail(&e) })?;
    Ok(Outcome::Forwarded { keep_alive })
}

fn client_gone() -> Fail {
    Fail { status: None, reason: Reason::None, error: "client connection closed" }
}

/// Resolve once and validate every address (D-11).
pub(crate) async fn resolve(
    t: &NormalizedTarget,
    ev: &mut RequestEvent,
    deps: &ProxyDeps,
) -> Result<Vec<IpAddr>, Fail> {
    match check_destination(t, deps.resolver.as_ref(), &deps.policy).await {
        PolicyVerdict::Allow(ips) => Ok(ips),
        PolicyVerdict::Deny(Reason::LoopDetected) => {
            Err(fail(508, Reason::LoopDetected, "loop detected"))
        }
        PolicyVerdict::Deny(r @ Reason::PrivateRange) => {
            ev.action = Action::Block.as_str();
            Err(fail(403, r, "destination not allowed"))
        }
        PolicyVerdict::Deny(r) => Err(fail(502, r, "name resolution failed")),
    }
}

async fn read_response(
    upstream: &mut TcpStream,
    buf: &mut Vec<u8>,
    deadline: Instant,
    deps: &ProxyDeps,
) -> Result<ResponseHead, Fail> {
    let limits = deps.limits;
    match read_head(upstream, buf, deadline, |b| parse_response_head(b, &limits)).await {
        Ok(Some(r)) => Ok(r),
        Ok(None) => Err(fail(502, Reason::UpstreamError, "upstream closed without a response")),
        Err(e) => Err(upstream_fail(&e)),
    }
}

/// Try the validated IPs in order (D-38); never re-resolve (D-11).
pub(crate) async fn connect_upstream(
    ips: &[IpAddr],
    port: u16,
    deps: &ProxyDeps,
) -> Result<(TcpStream, IpAddr), Fail> {
    let limit = Duration::from_secs(deps.cfg.timeouts.upstream_connect);
    let mut last = fail(502, Reason::UpstreamError, "connect failed");
    for ip in ips {
        match timeout(limit, TcpStream::connect(SocketAddr::new(*ip, port))).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok((s, *ip));
            }
            Ok(Err(_)) => last = fail(502, Reason::UpstreamError, "connect failed"),
            Err(_) => last = fail(504, Reason::Timeout, "connect timeout"),
        }
    }
    Err(last)
}
