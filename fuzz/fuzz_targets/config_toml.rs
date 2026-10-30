//! Fuzz the config parser: arbitrary input must never panic (SPEC 9).
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = webfilter::config::Config::parse(text, std::path::Path::new("/nonexistent"), None);
    }
});
