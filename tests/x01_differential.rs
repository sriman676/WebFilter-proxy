//! X-01 (TEST_PLAN 4b): our head validator + framer vs hyper's HTTP/1 server parser.
//! Whatever we ACCEPT, hyper must accept with the same method, target, headers and body length.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;

use tokio::io::AsyncWriteExt;
use webfilter::proxy::http1::*;

const LIMITS: Limits =
    Limits { max_head_bytes: 65536, max_headers: 100, max_uri_bytes: 8192, compat: false };

#[derive(Debug, PartialEq, Eq)]
struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, Vec<u8>)>,
    body_len: usize,
}

/// Feed `wire` to a hyper HTTP/1 server over an in-memory pipe; return what it parsed.
async fn hyper_sees(wire: Vec<u8>) -> Option<Seen> {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let seen: Arc<Mutex<Option<Seen>>> = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&seen);
    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let slot = Arc::clone(&slot);
        async move {
            let method = req.method().to_string();
            let target = req.uri().to_string();
            let mut headers: Vec<(String, Vec<u8>)> = req
                .headers()
                .iter()
                .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
                .collect();
            headers.sort();
            let body_len =
                req.into_body().collect().await.map(|b| b.to_bytes().len()).unwrap_or(usize::MAX);
            slot.lock().unwrap().get_or_insert(Seen { method, target, headers, body_len });
            Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
        }
    });
    // half_close: our write side closes after the request; hyper must still process it.
    let conn = hyper::server::conn::http1::Builder::new()
        .half_close(true)
        .serve_connection(TokioIo::new(server), svc);
    let writer = async move {
        let _ = client.write_all(&wire).await;
        let _ = client.shutdown().await;
        let mut sink = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut client, &mut sink).await;
    };
    let _ =
        tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(conn, writer) }).await;
    seen.lock().unwrap().take()
}

/// Our verdict plus the body we append so both parsers see a complete message.
fn ours(input: &[u8]) -> Option<(RequestHead, Vec<u8>, usize)> {
    let (head, n) = parse_request_head(input, &LIMITS).ok()?;
    let framing = validate_request(&head).ok()?;
    if head.method == "CONNECT" {
        return None; // hyper treats CONNECT as an upgrade; covered by I-tests instead
    }
    // The pipeline only proceeds with a target that canonicalizes (SPEC 4.5); so must this oracle.
    webfilter::normalize::canonicalize(
        &head.target,
        webfilter::normalize::TargetContext::PlainAbsolute,
    )
    .ok()?;
    let mut wire = input.get(..n)?.to_vec();
    let body_len = match framing {
        BodyFraming::None => 0,
        BodyFraming::ContentLength(len) if len <= 64 => {
            wire.extend(std::iter::repeat_n(b'x', len as usize));
            len as usize
        }
        BodyFraming::ContentLength(_) => return None, // keep cases small
        BodyFraming::Chunked => {
            wire.extend_from_slice(b"3\r\nabc\r\n0\r\n\r\n");
            3
        }
        BodyFraming::CloseDelimited => return None,
    };
    Some((head, wire, body_len))
}

fn compare(input: &[u8], rt: &tokio::runtime::Runtime) -> Result<(), String> {
    let Some((head, wire, body_len)) = ours(input) else { return Ok(()) };
    let theirs = rt
        .block_on(hyper_sees(wire))
        .ok_or_else(|| format!("we accept, hyper rejects: {:?}", String::from_utf8_lossy(input)))?;
    let mut our_headers = head.headers.clone();
    our_headers.sort();
    // Compare targets canonically (hyper prints an empty path as "/").
    let canon = |t: &str| {
        webfilter::normalize::canonicalize(t, webfilter::normalize::TargetContext::PlainAbsolute)
            .map(|t| t.url_norm)
            .unwrap_or_else(|e| format!("rejected: {e}"))
    };
    let theirs = Seen { target: canon(&theirs.target), ..theirs };
    let want =
        Seen { method: head.method, target: canon(&head.target), headers: our_headers, body_len };
    if theirs == want {
        Ok(())
    } else {
        Err(format!(
            "disagree on {:?}\nours  {want:?}\nhyper {theirs:?}",
            String::from_utf8_lossy(input)
        ))
    }
}

const BASES: &[&str] = &[
    "GET http://a.test/ HTTP/1.1\r\nHost: a.test\r\n\r\n",
    "POST http://a.test/p?q=1 HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\n\r\n",
    "POST http://a.test/ HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\n\r\n",
    "PUT http://a.test/x HTTP/1.0\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    "GET http://a.test/ HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    "DELETE http://a.test/%41?x HTTP/1.1\r\nHost: a.test\r\nX-A: 1\r\nX-B:\t2 \r\nExpect: 100-continue\r\n\r\n",
];

const INTERESTING: &[u8] = b" \t\r\n:,;0a5-\x00\x7f\x80\x0b\"";

fn mutate(base: &[u8], ops: &[(u8, usize, u8)]) -> Vec<u8> {
    let mut v = base.to_vec();
    for &(kind, pos, byte) in ops {
        if v.is_empty() {
            break;
        }
        let pos = pos % v.len();
        match kind % 4 {
            0 => v.insert(pos, INTERESTING[byte as usize % INTERESTING.len()]),
            1 => {
                v.remove(pos);
            }
            2 => v[pos] = INTERESTING[byte as usize % INTERESTING.len()],
            _ => {
                // duplicate the header line containing pos
                let start = v[..pos].iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
                let end =
                    v[pos..].iter().position(|b| *b == b'\n').map_or(v.len(), |i| pos + i + 1);
                let line = v[start..end].to_vec();
                v.splice(end..end, line);
            }
        }
    }
    v
}

#[test]
fn x01_corpus_bases_agree_with_hyper() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for b in BASES {
        assert!(ours(b.as_bytes()).is_some(), "base must be accepted: {b:?}");
        compare(b.as_bytes(), &rt).unwrap();
    }
}

/// Deterministic mutation campaign (xorshift seed) that also proves it is not vacuous: a
/// meaningful number of mutated heads must be accepted and then agree with hyper.
#[test]
fn x01_mutated_heads_never_accepted_differently() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let (mut accepted, mut failures) = (0, Vec::new());
    for i in 0..20_000 {
        let base = BASES[i % BASES.len()].as_bytes();
        let ops: Vec<(u8, usize, u8)> =
            (0..1 + next() % 3).map(|_| (next() as u8, next() as usize, next() as u8)).collect();
        let input = mutate(base, &ops);
        if ours(&input).is_some() {
            accepted += 1;
            if let Err(e) = compare(&input, &rt) {
                failures.push(e);
            }
        }
    }
    assert!(failures.is_empty(), "{} disagreements, first: {}", failures.len(), failures[0]);
    assert!(accepted >= 1000, "only {accepted} mutated heads accepted; campaign too weak");
    println!("X-01: {accepted} accepted mutated heads, all agree with hyper");
}
