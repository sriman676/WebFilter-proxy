//! F-05: arbitrary user input into the client's URL intake and the output namer.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(data) {
        if let Ok((url, _)) = webfilter::client::parse_input(raw) {
            assert!(matches!(url.scheme(), "http" | "https"));
            assert!(url.username().is_empty() && url.password().is_none(), "userinfo always stripped");
            let name = webfilter::naming::output_filename(url.as_str());
            assert!(name.ends_with(".html") && !name.contains(['/', '\\']) && !name.contains(".."));
        }
    }
});
