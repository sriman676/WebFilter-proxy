//! U-http (R1-R15, response side), SM-01..SM-25 at parser level, chunked codec (SPEC 4.3/4.15).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use proptest::prelude::*;
use webfilter::proxy::http1::*;

const LIMITS: Limits =
    Limits { max_head_bytes: 65536, max_headers: 100, max_uri_bytes: 8192, compat: false };

fn req(head: &str) -> Result<(RequestHead, usize), HeadError> {
    parse_request_head(head.as_bytes(), &LIMITS)
}

/// Parse + validate a request head (what the pipeline does before anything else).
fn check(head: &str) -> Result<BodyFraming, HeadError> {
    let (h, _) = req(head)?;
    validate_request(&h)
}

fn get(extra: &str) -> String {
    format!("GET http://a.test/ HTTP/1.1\r\nHost: a.test\r\n{extra}\r\n")
}

fn post(extra: &str) -> String {
    format!("POST http://a.test/ HTTP/1.1\r\nHost: a.test\r\n{extra}\r\n")
}

fn invalid(r: Result<BodyFraming, HeadError>) -> bool {
    matches!(r, Err(HeadError::Invalid(_)))
}

#[test]
fn well_formed_request_parses_with_lowercase_names() {
    let (h, n) =
        req("GET http://a.test/x?y=1 HTTP/1.1\r\nHost: a.test\r\nUser-Agent:  curl/8 \r\n\r\nNEXT")
            .unwrap();
    assert_eq!(
        n,
        "GET http://a.test/x?y=1 HTTP/1.1\r\nHost: a.test\r\nUser-Agent:  curl/8 \r\n\r\n".len(),
        "pipelined bytes untouched"
    );
    assert_eq!(
        (h.method.as_str(), h.target.as_str(), h.version),
        ("GET", "http://a.test/x?y=1", HttpVersion::Http11)
    );
    assert_eq!(
        h.headers,
        vec![("host".into(), b"a.test".to_vec()), ("user-agent".into(), b"curl/8".to_vec())]
    );
    assert_eq!(validate_request(&h), Ok(BodyFraming::None));
}

#[test]
fn incomplete_and_split_heads() {
    let full = get("");
    for cut in 0..full.len() {
        assert_eq!(req(&full[..cut]).unwrap_err(), HeadError::Incomplete, "cut at {cut}");
    }
}

#[test]
fn r1_cl_and_te_together_sm01_sm02_sm21() {
    assert!(invalid(check(&post("Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"))));
    assert!(invalid(check(&post("Transfer-Encoding: chunked\r\nContent-Length: 4\r\n"))));
    assert!(invalid(check(&get("Content-Length: 0\r\nTransfer-Encoding: chunked\r\n"))));
}

#[test]
fn r2_content_length_forms_sm04_sm05_sm06() {
    assert_eq!(check(&post("Content-Length: 5\r\n")), Ok(BodyFraming::ContentLength(5)));
    assert_eq!(
        check(&post("Content-Length: 9223372036854775807\r\n")),
        Ok(BodyFraming::ContentLength(i64::MAX as u64))
    );
    for bad in
        ["5, 5", "+5", "0x5", "-1", "", "5 5", "9223372036854775808", "99999999999999999999", "５"]
    {
        assert!(
            check(&post(&format!("Content-Length: {bad}\r\n"))).is_err(),
            "Content-Length: {bad:?}"
        );
    }
    assert!(invalid(check(&post("Content-Length: 5\r\nContent-Length: 6\r\n"))));
    assert!(invalid(check(&post("Content-Length: 5\r\nContent-Length: 5\r\n"))));
    // trailing whitespace is OWS and trimmed by both parsers (SM-06 "5 " is the same value 5)
    assert_eq!(check(&post("Content-Length: 5 \r\n")), Ok(BodyFraming::ContentLength(5)));
}

#[test]
fn r3_transfer_encoding_forms_sm03_sm23() {
    assert_eq!(check(&post("Transfer-Encoding: chunked\r\n")), Ok(BodyFraming::Chunked));
    assert_eq!(
        check(&post("Transfer-Encoding: CHUNKED\r\n")),
        Ok(BodyFraming::Chunked),
        "case-insensitive is allowed"
    );
    for bad in
        ["xchunked", "chunked, identity", "identity", "gzip, chunked", "chunked;q=1", "chunk ed"]
    {
        assert!(check(&post(&format!("Transfer-Encoding: {bad}\r\n"))).is_err(), "TE {bad:?}");
    }
    assert!(check(&post("Transfer-Encoding : chunked\r\n")).is_err(), "space before colon");
    assert!(
        check(&post("Transfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n")).is_err(),
        "duplicated TE"
    );
    assert!(check(&post("Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n")).is_err());
    let http10 = "POST http://a.test/ HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert!(invalid(check(http10)), "TE on HTTP/1.0");
    let ka10 = "GET http://a.test/ HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";
    assert_eq!(check(ka10), Ok(BodyFraming::None));
}

#[test]
fn r3_tab_after_colon_is_ows() {
    // `Transfer-Encoding:\tchunked`: the tab is optional whitespace, the value is exactly chunked.
    assert_eq!(check(&post("Transfer-Encoding:\tchunked\r\n")), Ok(BodyFraming::Chunked));
}

#[test]
fn r4_r5_whitespace_folding_bare_crlf_nul_sm07_to_sm09() {
    assert!(req(&get("X-A: 1\r\n continued\r\n")).is_err(), "obs-fold");
    assert!(req(&get("X-A: 1\r\n\tcontinued\r\n")).is_err(), "obs-fold tab");
    assert!(req("GET http://a.test/ HTTP/1.1\nHost: a.test\n\n").is_err(), "bare LF");
    assert!(req(&get("X-A: a\rb\r\n")).is_err(), "bare CR in value");
    assert!(req(&get("X-A: a\0b\r\n")).is_err(), "NUL in value");
    assert!(req(&get("X\0A: b\r\n")).is_err(), "NUL in name");
    assert!(req(&get("X-A: a\x01b\r\n")).is_err(), "control in value");
    assert!(req(&get("X A: b\r\n")).is_err(), "space in name");
    assert!(req(&get("X-A\t: b\r\n")).is_err(), "tab before colon");
    assert!(req(&get(": novalue\r\n")).is_err(), "empty name");
    assert!(req(&get("NoColon\r\n")).is_err());
    assert!(req("\r\nGET http://a.test/ HTTP/1.1\r\n\r\n").is_err(), "leading empty line");
}

#[test]
fn r5_obs_text_allowed_in_values() {
    assert!(req(&get("X-Name: caf\u{e9}\r\n")).is_ok());
}

#[test]
fn r6_versions_and_request_line_sm18() {
    assert_eq!(req("GET http://a.test/ HTTP/1.2\r\n\r\n").unwrap_err(), HeadError::Version);
    assert_eq!(req("GET http://a.test/ HTTP/0.9\r\n\r\n").unwrap_err(), HeadError::Version);
    assert_eq!(req("GET http://a.test/ HTTP/2.0\r\n\r\n").unwrap_err(), HeadError::Version);
    assert_eq!(HeadError::Version.status(), 505);
    for bad in [
        "GET  http://a.test/ HTTP/1.1\r\n\r\n",
        "GET http://a.test/  HTTP/1.1\r\n\r\n",
        "get http://a.test/ HTTP/1.1\r\n\r\n",
        "GET http://a.test/ http/1.1\r\n\r\n",
        "GET http://a.test/\r\n\r\n",
        "GET\thttp://a.test/ HTTP/1.1\r\n\r\n",
        "G(T http://a.test/ HTTP/1.1\r\n\r\n",
    ] {
        assert!(matches!(req(bad), Err(HeadError::Invalid(_))), "{bad:?}");
    }
}

#[test]
fn r7_single_host_sm11() {
    assert!(invalid(check(&get("Host: a.test\r\n"))), "two identical Host");
    assert!(invalid(check(&get("Host: b.test\r\n"))), "two different Host");
    assert!(
        req("GET http://a.test/ HTTP/1.1\r\nHost : a.test\r\n\r\n").is_err(),
        "space before colon"
    );
}

#[test]
fn r8_connection_must_not_name_framing_headers_sm10() {
    for v in ["close, Content-Length", "transfer-encoding", "Host"] {
        assert!(invalid(check(&get(&format!("Connection: {v}\r\n")))), "Connection: {v}");
    }
    assert!(check(&get("Connection: close, X-Custom\r\n")).is_ok());
}

#[test]
fn r10_upgrade_only_websocket_sm13() {
    assert!(invalid(check(&get(
        "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAA\r\n"
    ))));
    assert!(
        invalid(check(&get("Upgrade: websocket\r\n"))),
        "websocket without Connection: upgrade"
    );
    assert!(invalid(check(&get("Connection: upgrade\r\nUpgrade: websocket, h2c\r\n"))));
    let ws = get("Connection: Upgrade\r\nUpgrade: WebSocket\r\n");
    assert!(check(&ws).is_ok());
    assert!(is_websocket_upgrade(&req(&ws).unwrap().0));
}

#[test]
fn r12_limits_sm24() {
    let many: String = (0..101).map(|i| format!("X-{i}: v\r\n")).collect();
    assert_eq!(req(&get(&many)).unwrap_err(), HeadError::TooLarge);
    let hundred: String = (0..98).map(|i| format!("X-{i}: v\r\n")).collect();
    assert!(req(&get(&hundred)).is_ok(), "100 headers including Host are fine");
    let uri = format!("GET http://a.test/{} HTTP/1.1\r\n\r\n", "a".repeat(9 * 1024));
    assert_eq!(req(&uri).unwrap_err(), HeadError::UriTooLong);
    assert_eq!(HeadError::UriTooLong.status(), 414);
    let big = get(&format!("X-Big: {}\r\n", "b".repeat(70 * 1024)));
    assert_eq!(req(&big).unwrap_err(), HeadError::TooLarge);
    assert_eq!(HeadError::TooLarge.status(), 431);
    let long_name = get(&format!("{}: v\r\n", "N".repeat(9 * 1024)));
    assert!(
        req(&long_name).is_ok(),
        "an 8 KiB+ name inside the 64 KiB head is not itself an error"
    );
    let no_end = "GET http://a.test/ HTTP/1.1\r\nX: ".to_owned() + &"y".repeat(70_000);
    assert_eq!(
        req(&no_end).unwrap_err(),
        HeadError::TooLarge,
        "never-ending head is cut at the limit"
    );
}

#[test]
fn r14_trace_and_connect_sm25() {
    assert_eq!(
        check("TRACE http://a.test/ HTTP/1.1\r\nHost: a.test\r\n\r\n"),
        Err(HeadError::MethodNotAllowed)
    );
    assert_eq!(HeadError::MethodNotAllowed.status(), 405);
    assert!(
        invalid(check("CONNECT a.test:443 HTTP/1.1\r\nContent-Length: 5\r\n\r\n")),
        "CONNECT with body"
    );
    assert!(invalid(check("CONNECT a.test:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")));
    assert_eq!(
        check("CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n"),
        Ok(BodyFraming::None)
    );
    assert!(
        check("PROPFIND http://a.test/ HTTP/1.1\r\nHost: a.test\r\n\r\n").is_ok(),
        "other tokens allowed"
    );
}

#[test]
fn forward_headers_strip_hop_by_hop_and_proxy_headers() {
    let (h, _) = req(&get(
        "Connection: close, X-Hop\r\nX-Hop: 1\r\nKeep-Alive: 5\r\nProxy-Authorization: Basic x\r\nProxy-Connection: keep-alive\r\nTE: gzip\r\nTrailer: X\r\nUpgrade: websocket\r\nX-Keep: yes\r\nCookie: c=1\r\n",
    ))
    .unwrap();
    let forwarded = forward_headers(&h.headers, false);
    let names: Vec<&str> = forwarded.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["x-keep", "cookie"], "host is rebuilt from the normalized target (D-09)");
    let (h, _) = req(&get("TE: trailers\r\n")).unwrap();
    assert!(
        forward_headers(&h.headers, false).iter().any(|(n, _)| n == "te"),
        "TE: trailers kept (R11)"
    );
}

#[test]
fn write_head_regenerates_framing() {
    let mut out = Vec::new();
    write_head(
        "GET /x HTTP/1.1",
        &vec![("host".into(), b"a.test".to_vec())],
        BodyFraming::Chunked,
        &mut out,
    );
    assert_eq!(out, b"GET /x HTTP/1.1\r\nhost: a.test\r\ntransfer-encoding: chunked\r\n\r\n");
    let (h, n) = req(std::str::from_utf8(&out).unwrap()).unwrap();
    assert_eq!(
        (n, request_framing(&h)),
        (out.len(), Ok(BodyFraming::Chunked)),
        "our own output re-parses identically"
    );
}

// ---- compat mode (A-25): tolerates harmless oddities, never relaxes anti-smuggling rules ----

const COMPAT: Limits = Limits { compat: true, ..LIMITS };

#[test]
fn compat_accepts_lowercase_method_and_uppercases_it() {
    let (h, _) =
        parse_request_head(b"get http://a.test/ HTTP/1.1\r\nHost: a.test\r\n\r\n", &COMPAT)
            .unwrap();
    assert_eq!(h.method, "GET");
    assert!(req("get http://a.test/ HTTP/1.1\r\n\r\n").is_err(), "strict mode still rejects");
}

#[test]
fn compat_strips_chunk_extensions_but_not_garbage() {
    let mut d = ChunkedDecoder::new(true);
    let mut out = Vec::new();
    d.feed(b"5;name=\"v\"\r\nhello\r\n0;x\r\n\r\n", &mut out).unwrap();
    assert!(d.is_done());
    assert_eq!(out, b"hello");
    for bad in [&b"5;a\x00b\r\nhello\r\n"[..], b";x\r\n", b"FFFFFFFFFFFFFFFFF;x\r\n"] {
        assert!(
            ChunkedDecoder::new(true).feed(bad, &mut Vec::new()).is_err(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    let mut long_line = b"5;".to_vec();
    long_line.extend(std::iter::repeat_n(b'a', MAX_CHUNK_SIZE_LINE));
    assert!(
        ChunkedDecoder::new(true).feed(&long_line, &mut Vec::new()).is_err(),
        "extension length bounded"
    );
}

#[test]
fn compat_never_relaxes_anti_smuggling_rules() {
    let compat_check = |head: &str| {
        parse_request_head(head.as_bytes(), &COMPAT).and_then(|(h, _)| validate_request(&h))
    };
    for bad in [
        post("Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"),
        post("Content-Length: 5\r\nContent-Length: 5\r\n"),
        post("Transfer-Encoding: xchunked\r\n"),
        post("Transfer-Encoding : chunked\r\n"),
        get("X-A: 1\r\n continued\r\n"),
        get("X-A: a\rb\r\n"),
        get("X-A: a\0b\r\n"),
        get("Connection: transfer-encoding\r\n"),
        get("Host: b.test\r\n"),
        "GET  http://a.test/ HTTP/1.1\r\n\r\n".to_owned(),
        "GET http://a.test/ HTTP/1.1\nHost: a.test\n\n".to_owned(),
    ] {
        assert!(compat_check(&bad).is_err(), "compat must still reject {bad:?}");
    }
}

// ---- response side ----

fn resp(head: &str) -> Result<ResponseHead, HeadError> {
    parse_response_head(head.as_bytes(), &LIMITS).map(|(h, _)| h)
}

#[test]
fn response_heads_and_framing() {
    let h = resp("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n").unwrap();
    assert_eq!((h.status, h.reason.as_str()), (200, "OK"));
    assert_eq!(response_framing(&h, "GET"), Ok(BodyFraming::ContentLength(3)));
    assert_eq!(response_framing(&h, "HEAD"), Ok(BodyFraming::None), "HEAD never has a body");
    assert_eq!(
        response_framing(
            &resp("HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n").unwrap(),
            "GET"
        ),
        Ok(BodyFraming::None)
    );
    assert_eq!(
        response_framing(&resp("HTTP/1.1 304 Not Modified\r\n\r\n").unwrap(), "GET"),
        Ok(BodyFraming::None)
    );
    assert_eq!(
        response_framing(&resp("HTTP/1.1 100 Continue\r\n\r\n").unwrap(), "POST"),
        Ok(BodyFraming::None)
    );
    assert_eq!(
        response_framing(&resp("HTTP/1.0 200 OK\r\n\r\n").unwrap(), "GET"),
        Ok(BodyFraming::CloseDelimited)
    );
    assert_eq!(
        response_framing(
            &resp("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap(),
            "GET"
        ),
        Ok(BodyFraming::Chunked)
    );
    assert!(resp("HTTP/1.1 200\r\n\r\n").is_ok(), "empty reason allowed");
}

#[test]
fn response_rejections_sm20() {
    for bad in [
        "HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX: a\0b\r\n\r\n",
        "HTTP/1.1 20 OK\r\n\r\n",
        "HTTP/1.1 2000 OK\r\n\r\n",
        "HTTP/1.1 600 Bad\r\n\r\n",
        "HTTP/1.1 OK 200\r\n\r\n",
        "HTTP/1.1  200 OK\r\n\r\n",
        "HTTP/1.1 200 OK\nX: 1\n\n",
        "XTTP/1.1 200 OK\r\n\r\n",
        "HTTP/1.1 200 OK\r\n continued\r\n\r\n",
    ] {
        assert!(resp(bad).is_err(), "{bad:?}");
    }
    for bad in [
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
    ] {
        assert!(response_framing(&resp(bad).unwrap(), "GET").is_err(), "{bad:?}");
    }
}

// ---- chunked codec ----

fn decode(input: &[u8]) -> Result<(Vec<u8>, usize, bool), HeadError> {
    let mut d = ChunkedDecoder::default();
    let mut out = Vec::new();
    let n = d.feed(input, &mut out)?;
    Ok((out, n, d.is_done()))
}

#[test]
fn chunked_decode_basic_trailers_and_leftover() {
    let (out, n, done) =
        decode(b"5\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\nGET /next").unwrap();
    assert_eq!((out.as_slice(), done), (&b"hello world"[..], true));
    assert_eq!(
        n,
        b"5\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\n".len(),
        "next request bytes not consumed"
    );
    let (out, _, done) = decode(b"A\r\n0123456789\r\n0\r\n\r\n").unwrap();
    assert_eq!((out.len(), done), (10, true), "uppercase hex");
}

#[test]
fn chunked_decode_rejections_sm17() {
    for bad in [
        &b"5;ext=abc\r\nhello\r\n0\r\n\r\n"[..],
        b"FFFFFFFFFFFFFFFFF\r\n",
        b"10000000000000000\r\n",
        b"5\r\nhelloX\r\n",
        b"5\nhello\r\n",
        b"5\r\nhello\n0\r\n\r\n",
        b"\r\nhello",
        b"z\r\n",
        b" 5\r\nhello\r\n",
        b"5 \r\nhello\r\n",
        b"0\r\nBad Trailer\r\n\r\n",
        b"0\r\nX: a\rb\r\n\r\n",
        b"5\rX",
    ] {
        assert!(decode(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
    }
    let mut big_trailer = b"0\r\n".to_vec();
    big_trailer.extend(std::iter::repeat_n(b'a', MAX_TRAILER_BYTES + 10));
    assert!(decode(&big_trailer).is_err(), "trailer size bounded");
}

#[test]
fn chunked_missing_terminator_is_not_done() {
    let (out, _, done) = decode(b"5\r\nhello\r\n").unwrap();
    assert_eq!((out.as_slice(), done), (&b"hello"[..], false));
}

#[test]
fn encode_chunk_roundtrip_and_empty() {
    let mut wire = Vec::new();
    encode_chunk(b"", &mut wire);
    assert!(wire.is_empty(), "an empty chunk would end the body");
    encode_chunk(b"abc", &mut wire);
    wire.extend_from_slice(LAST_CHUNK);
    assert_eq!(wire, b"3\r\nabc\r\n0\r\n\r\n");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// X-03 (local): any body, any chunking, fed in any split, decodes back exactly.
    #[test]
    fn chunked_roundtrip_any_split(body in prop::collection::vec(any::<u8>(), 0..2000),
                                   sizes in prop::collection::vec(1usize..300, 1..20),
                                   split in 1usize..64) {
        let mut wire = Vec::new();
        let mut rest = body.as_slice();
        for s in sizes.iter().cycle() {
            if rest.is_empty() { break; }
            let (a, b) = rest.split_at((*s).min(rest.len()));
            encode_chunk(a, &mut wire);
            rest = b;
        }
        wire.extend_from_slice(LAST_CHUNK);
        let mut d = ChunkedDecoder::default();
        let mut out = Vec::new();
        let mut consumed = 0;
        for piece in wire.chunks(split) {
            let mut off = 0;
            while off < piece.len() && !d.is_done() {
                off += d.feed(&piece[off..], &mut out).unwrap();
            }
            consumed += off;
        }
        prop_assert!(d.is_done());
        prop_assert_eq!(consumed, wire.len());
        prop_assert_eq!(out, body);
    }

    /// F-04 smoke: the head parser never panics and never accepts a head with bare CR/LF or NUL.
    #[test]
    fn request_head_total(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        if let Ok((h, n)) = parse_request_head(&bytes, &LIMITS) {
            let head = &bytes[..n];
            prop_assert!(!head.contains(&0));
            prop_assert!(head.ends_with(b"\r\n\r\n"));
            prop_assert!(!h.method.is_empty());
        }
        let _ = parse_response_head(&bytes, &LIMITS);
    }
}

#[test]
fn websocket_upgrade_survives_connection_naming_it() {
    // Regression (found by I-17): `Connection: Upgrade` names `upgrade` as hop-by-hop; a validated
    // websocket handshake must still forward `Upgrade: websocket`.
    let (h, _) = req(&get("Connection: Upgrade\r\nUpgrade: websocket\r\n")).unwrap();
    assert!(
        forward_headers(&h.headers, true).iter().any(|(n, v)| n == "upgrade" && v == b"websocket")
    );
    assert!(!forward_headers(&h.headers, false).iter().any(|(n, _)| n == "upgrade"));
}
