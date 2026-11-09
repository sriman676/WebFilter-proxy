//! F-16: arbitrary Content-Disposition values and paths: the download name never contains a
//! path separator or control character and is at most 128 characters.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::scan::download_name;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (cd, path) = text.split_once('\n').unwrap_or((&text, "/"));
    let name = download_name(Some(cd), path);
    assert!(!name.is_empty() && name.chars().count() <= 128);
    assert!(!name.chars().any(|c| c.is_control() || "/\\".contains(c)));
    assert!(name != "." && name != "..");
});
