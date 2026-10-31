//! F-06: arbitrary `Location` values against a fixed base: only http/https results with a host.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(location) = std::str::from_utf8(data) {
        let base = url::Url::parse("https://good.test/a/b?c=1").unwrap();
        if let Ok(next) = webfilter::client::next_hop(&base, location) {
            assert!(matches!(next.scheme(), "http" | "https") && next.host_str().is_some());
        }
    }
});
