//! F-01: raw request-target strings into the canonicalizer (all contexts).
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::normalize::{canonicalize, TargetContext};

fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(data) {
        for ctx in [
            TargetContext::PlainAbsolute,
            TargetContext::ConnectAuthority,
            TargetContext::InterceptedOrigin { connect_host: "good.test", port: 443 },
        ] {
            if let Ok(t) = canonicalize(raw, ctx) {
                // Idempotence (P-01) and a CRLF-free forwarded line (D-09).
                assert!(!t.origin_form().contains(['\r', '\n', ' ']));
                assert_eq!(canonicalize(&t.url_norm, TargetContext::PlainAbsolute).ok().as_ref(), Some(&t));
            }
        }
    }
});
