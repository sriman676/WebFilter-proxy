//! The reserved access-request virtual host (SPEC_EXT_OPS O6, D-59): `webfilter.local` is
//! answered by the proxy itself, before DNS, destination policy and list rules, and only when
//! access requests are enabled. Routes: GET `/`, POST `/request`, GET `/status/<id>`; anything
//! else is 404. It is never forwarded upstream.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use super::ProxyDeps;
use super::http1::{BodyFraming, RequestHead, single};
use super::io::{IoError, copy_body_tap};
use super::pipeline::{Fail, Outcome, send};
use super::response::{html_escape, page};
use crate::logger::{RequestEvent, SysEvent};
use crate::normalize::NormalizedTarget;
use crate::profiles::Profile;
use crate::reason::Reason;

/// Largest accepted form body (AR-12).
pub const MAX_FORM: usize = 2048;

/// Whether `t` is the reserved virtual host (default port of its scheme only, AR-18).
pub(crate) fn is_vhost(deps: &ProxyDeps, t: &NormalizedTarget) -> bool {
    let cfg = &deps.cfg.access_requests;
    cfg.enabled
        && t.host
            .domain()
            .is_some_and(|d| d.trim_end_matches('.').eq_ignore_ascii_case(&cfg.virtual_host))
        && t.port == t.scheme.default_port()
}

fn doc(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{t}</title>\
<style>body{{font-family:sans-serif;max-width:40em;margin:4em auto}}</style></head><body><h1>{t}</h1>{body}</body></html>",
        t = html_escape(title)
    )
}

async fn reply<S: AsyncWrite + Unpin>(
    client: &mut S,
    ev: &mut RequestEvent,
    deps: &ProxyDeps,
    status: u16,
    title: &str,
    body: &str,
) {
    let html = doc(title, body);
    send(client, &page(status, Reason::None, &ev.event_id, &html, &[]), deps).await;
    ev.status = status;
}

/// Serve one request to the virtual host.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve<S>(
    client: &mut S,
    buf: &mut Vec<u8>,
    head: &RequestHead,
    ev: &mut RequestEvent,
    deps: &Arc<ProxyDeps>,
    client_id: &str,
    profile: &Profile,
    framing: BodyFraming,
    t: &NormalizedTarget,
) -> Result<Outcome, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let cfg = &deps.cfg.access_requests;
    let enabled_for_client = profile.access_requests == Some(true);
    match (head.method.as_str(), t.path.as_str()) {
        ("GET", "/") => {
            reply(
                client,
                ev,
                deps,
                200,
                "WebFilter access requests",
                "<p>Use the form on a block page to ask for access.</p>",
            )
            .await;
        }
        ("GET", p) if p.starts_with("/status/") => {
            let id = p.trim_start_matches("/status/");
            match deps.access.request(id).filter(|r| r.client_id == client_id) {
                Some(r) => {
                    let body = format!(
                        "<p>Request <code>{}</code> for <code>{}</code>: <strong>{}</strong></p>",
                        html_escape(&r.id),
                        html_escape(&r.host),
                        html_escape(&r.status)
                    );
                    reply(client, ev, deps, 200, "Access request", &body).await;
                }
                None => reply(client, ev, deps, 404, "Not found", "<p>Unknown request.</p>").await,
            }
        }
        ("POST", "/request") => {
            if !enabled_for_client {
                reply(
                    client,
                    ev,
                    deps,
                    403,
                    "Not available",
                    "<p>Access requests are not enabled for you.</p>",
                )
                .await;
                return Ok(Outcome::Done);
            }
            let form = single(&head.headers, "content-type").is_some_and(|v| {
                v.split(|b| *b == b';').next().is_some_and(|m| {
                    m.trim_ascii().eq_ignore_ascii_case(b"application/x-www-form-urlencoded")
                })
            });
            if !form {
                reply(
                    client,
                    ev,
                    deps,
                    415,
                    "Unsupported",
                    "<p>Send the form from the block page.</p>",
                )
                .await;
                return Ok(Outcome::Done);
            }
            if matches!(framing, BodyFraming::ContentLength(n) if n > MAX_FORM as u64) {
                reply(client, ev, deps, 413, "Too large", "<p>The request is too large.</p>").await;
                return Ok(Outcome::Done);
            }
            let mut body = Vec::new();
            let mut tap = |c: &[u8]| {
                body.extend_from_slice(c);
                body.len() <= MAX_FORM
            };
            let idle = Duration::from_secs(deps.cfg.timeouts.client_head_read);
            match copy_body_tap(
                client,
                buf,
                &mut tokio::io::sink(),
                framing,
                deps.limits.compat,
                idle,
                false,
                &mut tap,
            )
            .await
            {
                Ok(_) => {}
                Err(IoError::Closed) if body.len() > MAX_FORM => {
                    reply(client, ev, deps, 413, "Too large", "<p>The request is too large.</p>")
                        .await;
                    return Ok(Outcome::Done);
                }
                Err(_) => {
                    return Err(Fail {
                        status: None,
                        reason: Reason::InvalidRequest,
                        error: "form body",
                    });
                }
            }
            let fields: Vec<(String, String)> =
                url::form_urlencoded::parse(&body).into_owned().collect();
            let field =
                |k: &str| fields.iter().find(|(n, _)| n == k).map_or("", |(_, v)| v.as_str());
            match deps.access.submit(
                client_id,
                field("event_id"),
                field("csrf"),
                field("justification"),
                field("contact"),
                cfg.per_client_per_hour,
                cfg.max_pending_per_client,
            ) {
                Ok(r) => {
                    deps.logger.system().event(
                        SysEvent::AccessRequestCreated,
                        serde_json::json!({ "id": r.id, "host": r.host }),
                    );
                    deps.logger.access(serde_json::json!({
                        "request_id": r.id, "event_id": r.event_id, "client_id": r.client_id, "host": r.host,
                        "reason": r.reason, "status": r.status, "decided_by": null, "ttl_secs": null,
                        "justification_len": r.justification.chars().count(),
                    }));
                    let body = format!(
                        "<p>Your request <code>{}</code> for <code>{}</code> was sent to the administrator.</p><p><a href=\"/status/{}\">Check its status</a></p>",
                        html_escape(&r.id),
                        html_escape(&r.host),
                        html_escape(&r.id)
                    );
                    reply(client, ev, deps, 201, "Request sent", &body).await;
                }
                Err(refused) => {
                    let body = format!("<p>{}</p>", html_escape(refused.message));
                    reply(client, ev, deps, refused.status, "Request not accepted", &body).await;
                }
            }
        }
        _ => reply(client, ev, deps, 404, "Not found", "<p>Unknown page.</p>").await,
    }
    Ok(Outcome::Done)
}
