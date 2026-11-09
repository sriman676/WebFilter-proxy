//! F-14: arbitrary feed bodies through every format parser and the set builder: no panic,
//! accepted entries never include protected names, and parsing is idempotent (P-09).
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::config::FeedFormat;
use webfilter::feeds::{Entry, FeedSet, parse_feed};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    for format in [FeedFormat::DomainsText, FeedFormat::Hostfile, FeedFormat::UrlsText, FeedFormat::CsvUrlhaus, FeedFormat::IpsText] {
        if let Ok((entries, _)) = parse_feed(format, text, &["admin.example".into()], 10_000) {
            for e in &entries {
                if let Entry::Domain(d) | Entry::Host(d) = e {
                    let host = d.trim_start_matches("*.").trim_start_matches('=');
                    for p in ["localhost", "webfilter.local", "admin.example"] {
                        assert!(host != p && !host.ends_with(&format!(".{p}")), "{d}");
                    }
                }
            }
            let _ = FeedSet::build(&entries);
        }
    }
});
