//! F-23: arbitrary bytes as a rule-plugin module: refused at load, or every call ends in
//! no-opinion, block or a contained error (fuel and memory bounded), never a panic or hang.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use libfuzzer_sys::fuzz_target;
use webfilter::config::PluginConfig;
use webfilter::plugins::Plugins;

fuzz_target!(|data: &[u8]| {
    let path = std::env::temp_dir().join(format!("wf-fuzz-plugin-{}.wasm", std::process::id()));
    std::fs::write(&path, data).unwrap();
    let cfg = PluginConfig {
        name: "fuzz".into(),
        path: path.clone(),
        enabled: true,
        fuel: 100_000,
        max_memory_bytes: 1 << 20,
        ..PluginConfig::default()
    };
    if let Ok(set) = Plugins::load(&[cfg]) {
        let started = std::time::Instant::now();
        let _ = set.check(br#"{"v":1,"phase":"request","host":"x.test","path":"/a"}"#);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
});
