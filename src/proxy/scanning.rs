//! Download inspection on the HTTP/1 path (SPEC_EXT_POLICY P4, D-53): `detect` tees the stream
//! to a temp file and logs the verdict after delivery; `block` buffers, scans and then delivers
//! exactly the scanned bytes or a 403. Unscannable cases follow `unscannable_action`.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, timeout};

use super::ProxyDeps;
use super::http1::{
    BodyFraming, ChunkedDecoder, ResponseHead, forward_headers, single, write_head,
};
use super::io::{IoError, copy_body_tap, fill};
use super::pipeline::{
    Fail, Outcome, UpstreamBox, client_gone, note_decision, send_block, upstream_fail, write_all,
};
use crate::config::{ScanAction, ScanMode};
use crate::filter::Decision;
use crate::logger::{RequestEvent, SysEvent};
use crate::profiles::Profile;
use crate::reason::Reason;
use crate::scan::{Scanner, Slot, Verdict};

/// Bytes inspected for magic numbers.
pub const PREFIX: usize = 512;

/// The first decoded payload bytes, reading a little more from upstream if needed (raw buffer
/// <= 8 KiB). Nothing is consumed.
pub(crate) async fn payload_prefix<R: AsyncRead + Unpin>(
    upstream: &mut R,
    up_buf: &mut Vec<u8>,
    framing: BodyFraming,
    compat: bool,
    idle: Duration,
) -> Vec<u8> {
    let decode = |raw: &[u8]| -> Vec<u8> {
        match framing {
            BodyFraming::Chunked => {
                let mut out = Vec::new();
                let _ = ChunkedDecoder::new(compat).feed(raw, &mut out);
                out
            }
            BodyFraming::ContentLength(n) => raw
                .get(..usize::try_from(n).unwrap_or(usize::MAX).min(raw.len()))
                .unwrap_or(raw)
                .to_vec(),
            _ => raw.to_vec(),
        }
    };
    let enough = |p: &[u8]| {
        p.len() >= PREFIX || matches!(framing, BodyFraming::ContentLength(n) if p.len() as u64 >= n)
    };
    let mut prefix = decode(up_buf);
    while !enough(&prefix) && up_buf.len() < 8192 && framing != BodyFraming::None {
        match fill(upstream, up_buf, Instant::now() + idle).await {
            Ok(n) if n > 0 => prefix = decode(up_buf),
            _ => break,
        }
    }
    prefix.truncate(PREFIX);
    prefix
}

pub(crate) fn note_verdict(ev: &mut RequestEvent, v: &Verdict, sha: Option<String>, bytes: u64) {
    ev.scan_status = Some(v.status().into());
    ev.body_sha256 = sha;
    ev.body_bytes = Some(bytes);
    match v {
        Verdict::Infected { engine, signature } => {
            ev.scan_engine = Some((*engine).into());
            ev.scan_signature = Some(signature.clone());
        }
        Verdict::Blocklisted => ev.scan_engine = Some("hash".into()),
        Verdict::Unscannable(why) | Verdict::Unavailable(why) => ev.error = Some((*why).into()),
        Verdict::Clean => {}
    }
}

/// The block decision for a verdict, if it blocks under `[scan]` (`None` = deliver).
pub(crate) fn decision(scanner: &Scanner, v: &Verdict, profile: &Profile) -> Option<Decision> {
    let (reason, id) = match v {
        Verdict::Clean => return None,
        Verdict::Infected { engine, signature } => {
            (Reason::MalwareDetected, format!("scan:{engine}:{signature}"))
        }
        Verdict::Blocklisted => (Reason::HashBlocklist, "scan:hash".into()),
        Verdict::Unscannable(_) if scanner.cfg.on_unscannable() == ScanAction::Block => {
            (Reason::Unscannable, "scan:unscannable".into())
        }
        Verdict::Unavailable(_) if scanner.cfg.on_unavailable() == ScanAction::Block => {
            (Reason::ScannerUnavailable, "scan:unavailable".into())
        }
        Verdict::Unscannable(_) | Verdict::Unavailable(_) => return None,
    };
    Some(Decision::block(profile.mode, reason, id, "scan"))
}

pub(crate) fn malware_event(deps: &ProxyDeps, ev: &RequestEvent) {
    if ev.scan_status.as_deref() == Some("infected")
        || ev.scan_status.as_deref() == Some("blocklisted")
    {
        deps.logger.system().event(
            SysEvent::MalwareDetected,
            serde_json::json!({
                "event_id": ev.event_id, "client_id": ev.client_id, "host": ev.dest_host,
                "status": ev.scan_status, "signature": ev.scan_signature, "sha256": ev.body_sha256,
            }),
        );
    }
}

/// Why this response cannot be scanned before reading it (P4).
pub(crate) fn known_unscannable(
    status: u16,
    encoding: Option<&[u8]>,
    length: Option<u64>,
    max: u64,
) -> Option<&'static str> {
    let encoded = encoding.is_some_and(|v| !v.eq_ignore_ascii_case(b"identity"));
    if status == 206 {
        Some("partial content (206)")
    } else if encoded {
        Some("content-encoded body")
    } else if length.is_some_and(|n| n > max) {
        Some("larger than scan.max_bytes")
    } else {
        None
    }
}

fn head_bytes(resp: &ResponseHead, framing: BodyFraming, close: bool) -> Vec<u8> {
    let mut headers = forward_headers(&resp.headers, false);
    headers.retain(|(n, _)| n != "content-length");
    if close {
        headers.push(("connection".into(), b"close".to_vec()));
    }
    let mut out = Vec::new();
    write_head(&format!("HTTP/1.1 {} {}", resp.status, resp.reason), &headers, framing, &mut out);
    out
}

/// Inspect and forward an eligible download (connection closed afterwards).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward<S>(
    client: &mut S,
    ev: &mut RequestEvent,
    deps: &Arc<ProxyDeps>,
    profile: &Profile,
    scanner: &Scanner,
    resp: &ResponseHead,
    framing: BodyFraming,
    mut upstream: UpstreamBox,
    mut up_buf: Vec<u8>,
) -> Result<Outcome, Fail>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let idle = Duration::from_secs(deps.cfg.timeouts.upstream_body_idle);
    let length = match framing {
        BodyFraming::ContentLength(n) => Some(n),
        _ => None,
    };
    let encoding = single(&resp.headers, "content-encoding");
    let early = known_unscannable(resp.status, encoding, length, scanner.cfg.max_bytes);
    let mut slot = match early {
        Some(why) => Err(Verdict::Unscannable(why)),
        None => scanner.begin().await.map_err(Verdict::Unscannable),
    };
    if scanner.cfg.mode == ScanMode::Detect || slot.is_err() {
        // Detect mode (or nothing to record): stream unchanged, verdict afterwards. Block mode
        // only gets here for unscannable responses, which `unscannable_action` decides first.
        if let (Err(v), ScanMode::Block) = (&slot, scanner.cfg.mode)
            && let Some(d) = decision(scanner, v, profile)
        {
            note_verdict(ev, v, None, 0);
            note_decision(ev, &d);
            send_block(client, ev, &d, deps).await;
            return Ok(Outcome::Done);
        }
        let wire = if framing == BodyFraming::CloseDelimited { BodyFraming::None } else { framing };
        write_all(client, &head_bytes(resp, wire, true), idle).await.map_err(|_| client_gone())?;
        ev.status = resp.status;
        let mut tap = |c: &[u8]| {
            if let Ok(s) = slot.as_mut() {
                let _ = s.write(c);
            }
            true
        };
        ev.bytes_in =
            copy_body_tap(&mut upstream, &mut up_buf, client, framing, false, idle, true, &mut tap)
                .await
                .map_err(|e| Fail { status: None, ..upstream_fail(&e) })?;
        match slot {
            Ok(mut s) => {
                let (v, sha) = scanner.finish(&mut s).await;
                note_verdict(ev, &v, Some(sha), s.bytes);
            }
            Err(v) => note_verdict(ev, &v, None, 0),
        }
        malware_event(deps, ev);
        return Ok(Outcome::Done);
    }

    // Block mode: buffer (bounded in size and time), scan, then deliver or refuse.
    let Ok(slot_ref) = slot.as_mut() else { return Err(client_gone()) };
    let mut held = Vec::new(); // the chunk that crossed max_bytes/quota, kept for `allow`
    let limit = Duration::from_secs(scanner.cfg.buffer_timeout_secs);
    let buffered = {
        let mut tap = |c: &[u8]| {
            let ok = slot_ref.write(c).is_ok();
            if !ok {
                held.extend_from_slice(c);
            }
            ok
        };
        let mut sink = tokio::io::sink();
        timeout(
            limit,
            copy_body_tap(
                &mut upstream,
                &mut up_buf,
                &mut sink,
                framing,
                false,
                idle,
                false,
                &mut tap,
            ),
        )
        .await
    };
    let complete = match buffered {
        Err(_) => {
            slot_ref.stop("scan buffer timeout");
            false
        }
        Ok(Ok(_)) => true,
        Ok(Err(IoError::Closed)) if slot_ref.stopped().is_some() => false,
        Ok(Err(e)) => return Err(upstream_fail(&e)),
    };
    let slot: Slot = match slot {
        Ok(s) => s,
        Err(_) => return Err(client_gone()),
    };
    let mut slot = slot;
    let (v, sha) = scanner.finish(&mut slot).await;
    note_verdict(ev, &v, Some(sha), slot.bytes);
    malware_event(deps, ev);
    if let Some(d) = decision(scanner, &v, profile)
        && d.is_block()
    {
        note_decision(ev, &d);
        send_block(client, ev, &d, deps).await; // upstream headers discarded, body never sent
        return Ok(Outcome::Done);
    }
    // Deliver exactly the stored bytes; an incomplete (unscannable, allowed) body continues as a
    // close-delimited stream after them.
    let framing_out =
        if complete { BodyFraming::ContentLength(slot.bytes) } else { BodyFraming::None };
    write_all(client, &head_bytes(resp, framing_out, true), idle)
        .await
        .map_err(|_| client_gone())?;
    ev.status = resp.status;
    let mut sent = slot.deliver(client, idle).await.map_err(|_| client_gone())?;
    if !complete {
        write_all(client, &held, idle).await.map_err(|_| client_gone())?;
        sent += held.len() as u64;
        sent += copy_body_tap(
            &mut upstream,
            &mut up_buf,
            client,
            framing,
            false,
            idle,
            false,
            &mut |_| true,
        )
        .await
        .map_err(|e| Fail { status: None, ..upstream_fail(&e) })?;
    }
    ev.bytes_in = sent;
    Ok(Outcome::Done)
}
