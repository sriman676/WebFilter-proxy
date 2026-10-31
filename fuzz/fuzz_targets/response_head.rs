//! F-08: raw bytes into the response-head parser and response framing.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::proxy::http1::{Limits, parse_response_head, response_framing};

fuzz_target!(|data: &[u8]| {
    let limits = Limits { max_head_bytes: 8192, max_headers: 64, max_uri_bytes: 2048, compat: false };
    if let Ok((head, used)) = parse_response_head(data, &limits) {
        assert!((100..=599).contains(&head.status));
        assert!(data[..used].ends_with(b"\r\n\r\n") && !data[..used].contains(&0));
        for method in ["GET", "HEAD", "POST"] {
            let _ = response_framing(&head, method);
        }
    }
});
