//! F-09: chunked decoder on malformed input (never panics, never over-reads) and an
//! encode/decode round trip with fuzzer-chosen chunking and split points.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::proxy::http1::{ChunkedDecoder, LAST_CHUNK, encode_chunk};

fuzz_target!(|data: &[u8]| {
    // 1. Arbitrary bytes: consumed count is bounded by the input.
    for compat in [false, true] {
        let mut d = ChunkedDecoder::new(compat);
        let mut out = Vec::new();
        if let Ok(n) = d.feed(data, &mut out) {
            assert!(n <= data.len() && out.len() <= data.len());
        }
    }
    // 2. Round trip: first byte picks the chunk size, second the split size.
    let (Some(&a), Some(&b)) = (data.first(), data.get(1)) else { return };
    let body = &data[2..];
    let mut wire = Vec::new();
    for chunk in body.chunks(usize::from(a).max(1)) {
        encode_chunk(chunk, &mut wire);
    }
    wire.extend_from_slice(LAST_CHUNK);
    let mut d = ChunkedDecoder::default();
    let mut out = Vec::new();
    for piece in wire.chunks(usize::from(b).max(1)) {
        let mut off = 0;
        while off < piece.len() && !d.is_done() {
            off += d.feed(&piece[off..], &mut out).unwrap();
        }
    }
    assert!(d.is_done());
    assert_eq!(out, body);
});
