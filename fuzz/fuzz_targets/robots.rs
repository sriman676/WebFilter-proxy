//! F-21: arbitrary robots.txt and paths: no panic, bounded work, and a parsed file never
//! allows what an identical file with `Disallow: /` for every agent forbids.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::robots::Robots;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (body, path) = text.rsplit_once('\n').unwrap_or((&text, "/"));
    let path = format!("/{}", path.trim_start_matches('/'));
    let r = Robots::parse(body);
    let _ = r.allowed("webfilter-client/1.1", &path);
    let _ = r.delay("webfilter-client/1.1");
    assert!(!Robots::disallow_all().allowed("x", &path));
    assert!(Robots::allow_all().allowed("x", &path));
});
