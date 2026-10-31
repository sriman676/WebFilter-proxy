//! F-04: raw bytes into the request-head parser and validator (strict and compat modes).
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::proxy::http1::{BodyFraming, Limits, parse_request_head, validate_request, write_head};

fuzz_target!(|data: &[u8]| {
    for compat in [false, true] {
        let limits = Limits { max_head_bytes: 8192, max_headers: 64, max_uri_bytes: 2048, compat };
        if let Ok((head, used)) = parse_request_head(data, &limits) {
            let raw = &data[..used];
            assert!(raw.ends_with(b"\r\n\r\n") && !raw.contains(&0));
            if let Ok(framing) = validate_request(&head) {
                // What we would forward re-parses to the same head and framing (no desync).
                let mut out = Vec::new();
                let line = format!("{} {} HTTP/1.1", head.method, head.target);
                write_head(&line, &head.headers, framing, &mut out);
                let strict = Limits { compat: false, max_head_bytes: 1 << 20, ..limits };
                let (again, n) = parse_request_head(&out, &strict).expect("our own output must parse");
                assert_eq!(n, out.len());
                assert_eq!(again.method, head.method);
                if !matches!(framing, BodyFraming::ContentLength(_) | BodyFraming::Chunked) {
                    assert_eq!(again.headers, head.headers);
                }
            }
        }
    }
});
