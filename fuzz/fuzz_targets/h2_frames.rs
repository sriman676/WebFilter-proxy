//! F-10: arbitrary bytes, split at arbitrary points, into the HTTP/2 flood-guard frame scanner.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use webfilter::proxy::h2guard::{FrameScanner, Limits, Peer};

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_continuation_frames: 16,
        reset_limit: 100,
        control_frame_limit: 200,
        window: Duration::from_secs(10),
    };
    let now = Instant::now();
    let (split, rest) = data.split_first().map_or((0, data), |(s, r)| (usize::from(*s), r));
    for peer in [Peer::Client, Peer::Origin] {
        let mut s = FrameScanner::new(limits, peer, now);
        let (a, b) = rest.split_at(split.min(rest.len()));
        let _ = s.feed(a, now);
        let _ = s.feed(b, now + Duration::from_secs(split as u64 % 20));
    }
});
