//! F-20: arbitrary CSS through the reference scanner and rewriter: no panic; rewriting with an
//! empty map leaves no `@import` or `url()` to another host.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::snapshot;

fuzz_target!(|data: &[u8]| {
    let css = String::from_utf8_lossy(data);
    let refs = snapshot::css_refs(&css);
    let out = snapshot::rewrite_css(&css, &|_| None);
    let lower = out.to_ascii_lowercase();
    assert!(!lower.contains("expression(") && !lower.contains("behavior:"));
    if refs.iter().all(|(_, r)| !r.starts_with("data:")) {
        assert!(snapshot::css_refs(&out).iter().all(|(_, r)| r.is_empty() || r.starts_with("data:")));
    }
});
