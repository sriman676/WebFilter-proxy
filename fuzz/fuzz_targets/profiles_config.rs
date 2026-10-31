//! F-13: arbitrary `[[users]]`/`[[clients]]`/`[[profiles]]` text through config validation and
//! `PolicySet::build`, then identity resolution for a few addresses. Never panics.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::config::Config;
use webfilter::profiles::PolicySet;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let dir = std::env::temp_dir().join("wf-fuzz-profiles");
    let _ = std::fs::create_dir_all(dir.join("blocklists"));
    for f in ["domains.txt", "url_patterns.txt", "ip_blocklist.txt"] {
        let _ = std::fs::write(dir.join("blocklists").join(f), "");
    }
    if let Ok(cfg) = Config::parse(text, &dir, None) {
        let ps = PolicySet::build(&cfg).expect("validated config must build");
        for ip in ["127.0.0.1", "10.1.2.3", "::1", "2001:db8::1", "::ffff:10.0.0.1"] {
            let (id, profile) = ps.resolve(ip.parse().unwrap(), None);
            assert!(id.starts_with("ip:") && !profile.name.is_empty());
        }
    }
});
