//! F-15: arbitrary clamd replies: no panic; signatures are always sanitized.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::scan::parse_clamd_reply;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(sig)) = parse_clamd_reply(&String::from_utf8_lossy(data)) {
        assert!((1..=64).contains(&sig.len()));
        assert!(sig.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)));
    }
});
