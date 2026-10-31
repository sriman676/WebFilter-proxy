//! F-12: arbitrary bytes as a request head on the transparent HTTP listener (Host + origin-form
//! target against a fixed original destination).
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::proxy::http1::{Limits, parse_request_head};
use webfilter::proxy::transparent::http_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::new(&webfilter::config::LimitsConfig::default(), false);
    if let Ok((head, _)) = parse_request_head(data, &limits) {
        let orig = std::net::SocketAddr::from(([93, 184, 216, 34], 80));
        if let Ok(t) = http_target(&head, orig) {
            assert_eq!(t.port, 80, "the port is always the original port");
            assert!(t.path.starts_with('/'));
        }
    }
});
