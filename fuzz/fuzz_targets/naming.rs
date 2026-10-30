//! F-03: arbitrary URL strings into the output file namer; the invariant must always hold.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(url) = std::str::from_utf8(data) {
        let name = webfilter::naming::output_filename(url);
        let stem = name.strip_suffix(".html").unwrap();
        assert!(stem.len() <= 128 && !name.contains("..") && !name.contains(['/', '\']));
        assert!(stem.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)));
        assert!(stem.as_bytes()[0].is_ascii_alphanumeric());
    }
});
