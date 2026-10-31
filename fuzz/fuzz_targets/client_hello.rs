//! F-11: arbitrary bytes into the ClientHello peek (SNI/ALPN/ECH), as seen at the start of a tunnel.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::tls::{Peek, peek_client_hello};

fuzz_target!(|data: &[u8]| {
    if let Peek::Hello(info) = peek_client_hello(data) {
        if let Some(sni) = info.sni {
            assert!(!sni.is_empty() && sni.bytes().all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase()));
        }
    }
});
