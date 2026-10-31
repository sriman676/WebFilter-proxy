//! The per-request pipeline (SPEC 4.2): every request on a connection is validated, canonicalized,
//! policy-checked and filtered (D-10), then forwarded on a fresh upstream connection (D-07)
//! rebuilt only from normalized fields (D-09). Exactly one log event per request. The same
//! pipeline serves requests inside intercepted TLS tunnels (SPEC 4.9).
#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
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
use crate::normalize::{Host, NormalizedTarget, Scheme, TargetContext, TargetError, canonicalize};
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

pub(crate) fn client_gone() -> Fail {
    Fail { status: None, reason: Reason::None, error: "client connection closed" }
}

/// Any upstream byte stream (plain TCP or verified TLS).
pub(crate) trait Upstream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Upstream for T {}
pub(crate) type UpstreamBox = Box<dyn Upstream>;

/// An intercepted tunnel: inner requests are origin-form for this CONNECT authority, go only to
/// the addresses validated at CONNECT time, and over verified TLS (D-20, D-22).
#[derive(Debug, Clone)]
pub struct Tunnel {
    /// CONNECT host.
    pub host: Host,
    /// CONNECT port.
    pub port: u16,
    /// Addresses validated at CONNECT (never re-resolved, D-11).
    pub ips: Vec<IpAddr>,
    /// ClientHello SNI.
    pub sni: Option<String>,
    /// ClientHello carried ECH (D-21).
    pub ech: bool,
    /// Authenticated CONNECT user.
    pub user: Option<String>,
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

/// The `Host` value equals the target authority (case-insensitive, default port normalized).
pub(crate) fn host_equals(host: &[u8], t: &NormalizedTarget) -> bool {
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

/// The rendered block page for a decision (SPEC 4.7).
pub(crate) fn block_html(ev: &RequestEvent, d: &Decision, deps: &ProxyDeps) -> String {
    deps.block_page.render(&BlockInfo {
        url: &ev.url,
        host: &ev.dest_host,
        reason: d.reason,
        rule_id: d.rule_id.as_deref(),
        category: d.category.as_deref(),
        event_id: &ev.event_id,
        timestamp: &ev.timestamp,
    })
}

/// Send the block page for a decision (SPEC 4.7).
pub(crate) async fn send_block<S: AsyncWrite + Unpin>(
    client: &mut S,
    ev: &mut RequestEvent,
    d: &Decision,
    deps: &ProxyDeps,
) {
    let html = block_html(ev, d, deps);
    send(client, &page(403, d.reason, &ev.event_id, &html, &[]), deps).await;
    ev.status = 403;
}

/// Extra headers of an error status.
pub(crate) fn error_headers(status: u16) -> Vec<(&'static str, String)> {
    match status {
        503 => vec![("retry-after", "5".into())],
        407 => vec![("proxy-authenticate", "Basic realm=\"webfilter\"".into())],
        _ => vec![],
    }
}

/// Record a failure in the log event (status, reason, error, block action).
pub(crate) fn note_fail(ev: &mut RequestEvent, f: &Fail) {
    if let Some(status) = f.status {
        ev.status = status;
    }
    ev.reason = f.reason.as_str();
    ev.error = Some(f.error.to_owned());
    if matches!(
        f.reason,
        Reason::UserinfoInUrl
            | Reason::HostMismatch
            | Reason::SniMismatch
            | Reason::PortNotAllowed
            | Reason::PrivateRange
    ) {
        ev.action = Action::Block.as_str();
    }
}

/// Answer a failure with an error page (unless a response was already started) and log it.
pub(crate) async fn send_fail<S: AsyncWrite + Unpin>(
    client: &mut S,
    ev: &mut RequestEvent,
    f: &Fail,
    deps: &ProxyDeps,
) {
    if let Some(status) = f.status {
        send(client, &error_page(status, f.reason, &ev.event_id, &error_headers(status)), deps)
            .await;
    }
    note_fail(ev, f);
}

/// Serve one client connection (or one intercepted tunnel) until it closes or must be closed.
pub async fn serve_connection<S>(
    mut client: S,
    peer: SocketAddr,
    deps: Arc<ProxyDeps>,
    tunnel: Option<Arc<Tunnel>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut buf = Vec::new();
    let mut idle_secs = deps.cfg.timeouts.client_head_read;
    while !deps.shutting_down() {
        let deadline = Instant::now() + Duration::from_secs(idle_secs);
        idle_secs = deps.cfg.timeouts.client_keepalive_idle;
        let limits = deps.limits;
        let mut ev = deps.new_event(peer);
        if let Some(tn) = &tunnel {
            ev.tls_intercepted = true;
            ev.tls_sni.clone_from(&tn.sni);
            ev.ech_present = tn.ech;
            ev.proxy_user.clone_from(&tn.user);
            ev.alpn = Some("http/1.1".into());
        }
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

        let outcome = handle_request(
            &mut client,
            &mut buf,
            &head,
            &mut ev,
            &deps,
            peer.ip(),
            tunnel.as_deref(),
        )
        .await;
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

/// Target form, canonicalization and Host rules for a plain-listener request (R7, R9).
fn plain_target(head: &RequestHead) -> Result<NormalizedTarget, Fail> {
    let t = canonicalize(&head.target, TargetContext::PlainAbsolute).map_err(|e| {
        fail(
            if e.reason() == Reason::UserinfoInUrl { 403 } else { 400 },
            e.reason(),
            "invalid request target",
        )
    })?;
    if t.scheme != Scheme::Http {
        return Err(fail(
            400,
            Reason::InvalidRequest,
            "https absolute-form on the plain listener (R9)",
        ));
    }
    if single(&head.headers, "host").is_some_and(|h| !host_equals(h, &t)) {
        return Err(fail(400, Reason::InvalidRequest, "Host does not match the target (R7)"));
    }
    Ok(t)
}

/// Inside a tunnel: origin-form (or matching absolute-form) for the CONNECT authority, and an
/// HTTP/1.1 `Host` equal to it (R7, D-22).
fn tunnel_target(head: &RequestHead, tn: &Tunnel) -> Result<NormalizedTarget, Fail> {
    let host = tn.host.to_string();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ctx = TargetContext::InterceptedOrigin { connect_host: host, port: tn.port };
    let t = canonicalize(&head.target, ctx).map_err(|e| match e {
        TargetError::HostMismatch => {
            fail(403, Reason::HostMismatch, "target does not match the CONNECT authority")
        }
        e => fail(
            if e.reason() == Reason::UserinfoInUrl { 403 } else { 400 },
            e.reason(),
            "invalid request target",
        ),
    })?;
    let host_ok = match single(&head.headers, "host") {
        Some(h) => host_equals(h, &t),
        None => head.version == HttpVersion::Http10,
    };
    if !host_ok {
        return Err(fail(
            403,
            Reason::HostMismatch,
            "Host does not match the CONNECT authority (D-22)",
        ));
    }
    Ok(t)
}

async fn handle_request<S>(
    client: &mut S,
    buf: &mut Vec<u8>,
    head: &RequestHead,
    ev: &mut RequestEvent,
    deps: &Arc<ProxyDeps>,
    peer: IpAddr,
    tunnel: Option<&Tunnel>,
) -> Result<Outcome, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // 2. Validate. 3. Auth (on the plain listener; tunnels inherit the CONNECT identity).
    let framing = validate_request(head).map_err(head_fail)?;
    let t = match tunnel {
        Some(tn) => {
            if head.method == "CONNECT" {
                return Err(fail(400, Reason::InvalidRequest, "CONNECT inside a tunnel"));
            }
            tunnel_target(head, tn)?
        }
        None => {
            deps.authorize(head, ev, peer).await?;
            if head.method == "CONNECT" {
                return super::connect::handle_connect(client, buf, head, ev, deps, peer).await;
            }
            let t = plain_target(head);
            if let Ok(t) = &t {
                note_target(ev, t);
            }
            let t = t?;
            check_port(PortKind::Http, t.port, &deps.cfg.ports)
                .map_err(|r| fail(403, r, "port not allowed"))?;
            t
        }
    };
    note_target(ev, &t);
    let websocket = is_websocket_upgrade(head);
    if websocket {
        ev.upgrade = Some("websocket".into());
    }

    // 8. Pre-DNS rules: a blocked name is never resolved.
    let d = deps.evaluate(&t, Phase::PreDns);
    note_decision(ev, &d);
    if d.is_block() {
        send_block(client, ev, &d, deps).await;
        return Ok(Outcome::Done);
    }
    // 6/9. Resolve once (tunnels reuse the CONNECT-time addresses); rule 3 per address.
    let ips = match tunnel {
        Some(tn) => tn.ips.clone(),
        None => resolve(&t, ev, deps).await?,
    };
    if let Some(d) = resolved_rule(deps, &t, &ips) {
        note_decision(ev, &d);
        if d.is_block() {
            send_block(client, ev, &d, deps).await;
            return Ok(Outcome::Done);
        }
    }
    // 10. Fresh upstream connection (D-07), verified TLS inside tunnels (D-20).
    let (tcp, ip) = connect_upstream(&ips, t.port, deps).await?;
    ev.dest_ip = Some(ip.to_string());
    let upstream: UpstreamBox = match tunnel {
        Some(tn) => Box::new(upstream_tls(tcp, &tn.host, deps, None).await?),
        None => Box::new(tcp),
    };
    forward(client, buf, head, ev, deps, &t, framing, websocket, upstream).await
}

/// The first non-allow decision of rule 3 over the validated addresses.
pub(crate) fn resolved_rule(
    deps: &ProxyDeps,
    t: &NormalizedTarget,
    ips: &[IpAddr],
) -> Option<Decision> {
    ips.iter()
        .map(|ip| deps.evaluate(t, Phase::Resolved { ip: *ip }))
        .find(|d| d.reason != Reason::None)
}

/// TLS to the origin, SNI = CONNECT host, certificate always verified (D-20). `alpn` replaces
/// the default `http/1.1` offer (ALPN mirroring, D-40).
pub(crate) async fn upstream_tls(
    tcp: TcpStream,
    host: &Host,
    deps: &ProxyDeps,
    alpn: Option<Vec<Vec<u8>>>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Fail> {
    let name = match host {
        Host::Domain(d) => ServerName::try_from(d.clone()),
        Host::Ipv4(v4) => Ok(ServerName::from(IpAddr::V4(*v4))),
        Host::Ipv6(v6) => Ok(ServerName::from(IpAddr::V6(*v6))),
    }
    .map_err(|_| fail(502, Reason::UpstreamError, "invalid server name"))?;
    let config = match alpn {
        Some(alpn) => {
            let mut c = (*deps.upstream_tls).clone();
            c.alpn_protocols = alpn;
            Arc::new(c)
        }
        None => Arc::clone(&deps.upstream_tls),
    };
    let connector = tokio_rustls::TlsConnector::from(config);
    let handshake =
        timeout(Duration::from_secs(deps.cfg.timeouts.tls_handshake), connector.connect(name, tcp));
    match handshake.await {
        Err(_) => Err(fail(504, Reason::Timeout, "upstream TLS handshake timeout")),
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            let cert_problem =
                e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()).is_some_and(|r| {
                    matches!(
                        r,
                        rustls::Error::InvalidCertificate(_)
                            | rustls::Error::NoCertificatesPresented
                    )
                });
            Err(if cert_problem {
                fail(502, Reason::UpstreamCertInvalid, "upstream certificate invalid")
            } else {
                fail(502, Reason::UpstreamError, "upstream TLS failed")
            })
        }
    }
}

/// Steps 10-11: send the rebuilt request, relay `100 Continue`, stream the body, validate the
/// response, apply rule 6 and stream it back.
#[allow(clippy::too_many_arguments)]
async fn forward<S>(
    client: &mut S,
    buf: &mut Vec<u8>,
    head: &RequestHead,
    ev: &mut RequestEvent,
    deps: &Arc<ProxyDeps>,
    t: &NormalizedTarget,
    framing: BodyFraming,
    websocket: bool,
    mut upstream: UpstreamBox,
) -> Result<Outcome, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
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
    let d = deps.evaluate(t, Phase::ResponseHeaders { content_type: content_type.as_deref() });
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
    upstream: &mut UpstreamBox,
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
