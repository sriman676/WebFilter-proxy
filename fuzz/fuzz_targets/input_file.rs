//! F-22: arbitrary input files: no panic; every URL is non-empty, unique, single-line and free of
//! whitespace and control characters.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use webfilter::batch;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (urls, _) = batch::parse_input_file(&text);
    let mut seen = HashSet::new();
    for u in &urls {
        assert!(!u.is_empty() && !u.starts_with('#'));
        assert!(!u.chars().any(|c| c.is_control() || c.is_whitespace()));
        assert!(seen.insert(u));
    }
});
