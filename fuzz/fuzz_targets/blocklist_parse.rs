//! F-02: arbitrary bytes as domain, pattern and IP list files.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::blocklist::{parse_domains, parse_ips, parse_patterns};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_domains(text);
        let _ = parse_patterns(text);
        let _ = parse_ips(text);
    }
});
