//! Phase 14: WASM rule plugins (SPEC_EXT_OPS O10): E-84 blocking, E-85 hostile modules, E-86
//! plugins never override other decisions. Needs `--features plugins` (`just plugins-test`).
#![cfg(feature = "plugins")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{
    Origin, ProxyHarness, Reply, TestResolver, base_config, raw_exchange, reason, status,
};
use webfilter::config::{Config, PluginConfig, PluginOnError};
use webfilter::plugins::{Outcome, Plugins};

/// The shipped example (`plugins/examples/block_keyword.wat`): blocks views containing `/ads`.
const KEYWORD: &str = include_str!("../plugins/examples/block_keyword.wat");

fn module(decide_body: &str, extra: &str) -> String {
    format!(
        r#"(module {extra}
  (memory (export "memory") 1)
  (func (export "wf_alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "wf_decide") (param i32) (param i32) (result i32) {decide_body}))"#
    )
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let p = dir.join(format!("{name}.wat"));
    std::fs::write(&p, text).unwrap();
    p
}

fn cfg(name: &str, path: &Path, on_error: PluginOnError) -> PluginConfig {
    PluginConfig {
        name: name.into(),
        path: path.to_path_buf(),
        enabled: true,
        on_error,
        ..PluginConfig::default()
    }
}

fn plugin_toml(name: &str, path: &Path, on_error: &str) -> String {
    format!(
        "[[plugins]]\nname = \"{name}\"\npath = \"{}\"\nenabled = true\non_error = \"{on_error}\"\n",
        path.display()
    )
}

fn get_req(host: &str, port: u16) -> String {
    format!(
        "GET http://{host}:{port}/ HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    )
}

async fn proxy(extra: &str, lists: &[(&str, &str)]) -> ProxyHarness {
    let r = TestResolver::with(&[
        ("ok.test", "127.0.0.1"),
        ("bad.test", "127.0.0.1"),
        ("vip.test", "127.0.0.1"),
    ]);
    ProxyHarness::start(&base_config(extra), lists, r).await
}

#[tokio::test]
async fn e84_plugin_blocks_by_view_and_logs_rule_id() {
    let dir = tempfile::tempdir().unwrap();
    let kw = write(dir.path(), "kw", KEYWORD);
    let origin = Origin::start(|_| Reply::ok("fine")).await;
    let port = origin.addr.port();
    let mut h = proxy(&plugin_toml("kw", &kw, "block"), &[]).await;
    let blocked = h.get("ok.test", port, "/ads/banner").await;
    assert_eq!(status(&blocked), 403, "{blocked}");
    assert_eq!(reason(&blocked), "plugin_rule");
    assert_eq!(status(&h.get("ok.test", port, "/news").await), 200);
    // Query values never reach the plugin: `/ads` only in a query value does not match.
    assert_eq!(status(&h.get("ok.test", port, "/q?x=/ads").await), 200);
    h.stop().await;
    let lines = h.log_lines();
    assert_eq!(
        (lines[0]["rule_id"].as_str(), lines[0]["rule_list"].as_str()),
        (Some("plugin:kw"), Some("plugins"))
    );
    assert_eq!(origin.requests().len(), 2, "blocked request never reached the origin");
    let sys = h.system_lines();
    assert!(sys.iter().any(|l| l["kind"] == "plugins_loaded"), "{sys:?}");

    // Monitor mode: logged as would_block, delivered.
    let mut h =
        proxy(&format!("mode = \"monitor\"\n{}", plugin_toml("kw", &kw, "block")), &[]).await;
    assert_eq!(status(&h.get("ok.test", port, "/ads/x").await), 200);
    h.stop().await;
    assert_eq!(h.log_lines()[0]["would_block"], true);
}

#[test]
fn e85_hostile_modules_are_refused_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let cases = [
        ("wasi", r#"(module (import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "wf_alloc") (param i32) (result i32) (i32.const 0))
            (func (export "wf_decide") (param i32 i32) (result i32) (i32.const 0)))"#.to_owned()),
        ("noexport", r#"(module (memory (export "memory") 1) (func (export "wf_alloc") (param i32) (result i32) (i32.const 0)))"#.to_owned()),
        ("badtype", r#"(module (memory (export "memory") 1)
            (func (export "wf_alloc") (param i32) (result i32) (i32.const 0))
            (func (export "wf_decide") (param i64) (result i32) (i32.const 0)))"#.to_owned()),
        ("bigmem", module("(i32.const 0)", "").replace("(memory (export \"memory\") 1)", "(memory (export \"memory\") 100)")),
        ("startloop", module("(i32.const 0)", "(func $s (loop $l (br $l))) (start $s)")),
        ("garbage", "\0asm\x01\0\0\0\x05garbage".to_owned()),
    ];
    for (name, text) in cases {
        let p = write(d, name, &text);
        let err = Plugins::load(&[cfg(name, &p, PluginOnError::Block)]).unwrap_err();
        assert!(err.starts_with(name), "{name}: {err}");
    }
    let big = d.join("big.wasm");
    std::fs::write(&big, vec![0u8; 5 * 1024 * 1024]).unwrap();
    assert!(
        Plugins::load(&[cfg("big", &big, PluginOnError::Block)]).unwrap_err().contains("4 MiB")
    );
    // Disabled plugins are not even read.
    let mut off = cfg("off", &d.join("missing.wat"), PluginOnError::Block);
    off.enabled = false;
    assert!(Plugins::load(&[off]).unwrap().is_empty());
}

#[test]
fn e85_runtime_faults_are_contained_and_follow_on_error() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let view = br#"{"v":1,"path":"/x"}"#;
    let faults = [
        ("loop", module("(loop $l (br $l)) (i32.const 0)", "")),
        ("grow", module("(memory.grow (i32.const 1000))", "")),
        ("trap", module("(unreachable)", "")),
        ("result", module("(i32.const 7)", "")),
        ("recurse", module("(call $r) (i32.const 0)", "(func $r (call $r))")),
        (
            "oob",
            module("(i32.const 0)", "").replace(
                "(i32.const 1024))\n  (func (export \"wf_decide\")",
                "(i32.const 70000))\n  (func (export \"wf_decide\")",
            ),
        ),
    ];
    for (name, text) in faults {
        let p = write(d, name, &text);
        for (on_error, block) in [(PluginOnError::Block, true), (PluginOnError::Allow, false)] {
            let set =
                Plugins::load(&[cfg(name, &p, on_error)]).unwrap_or_else(|e| panic!("{name}: {e}"));
            let started = std::time::Instant::now();
            match set.check(view) {
                Some(Outcome::Error { plugin, block: b, .. }) => {
                    assert_eq!((plugin.as_str(), b), (name, block), "{name}")
                }
                other => panic!("{name}: {other:?}"),
            }
            assert!(started.elapsed() < Duration::from_secs(2), "{name} bounded");
            assert_eq!(set.stats()[0].3, 1, "{name} error counted");
        }
    }
}

#[tokio::test]
async fn e85_proxy_fail_closed_and_open_with_rate_limited_error_log() {
    let dir = tempfile::tempdir().unwrap();
    let trap = write(dir.path(), "trap", &module("(unreachable)", ""));
    let origin = Origin::start(|_| Reply::ok("fine")).await;
    let port = origin.addr.port();
    let mut h = proxy(&plugin_toml("trap", &trap, "block"), &[]).await;
    for _ in 0..3 {
        let r = h.get("ok.test", port, "/").await;
        assert_eq!(status(&r), 403);
        assert_eq!(reason(&r), "plugin_error");
    }
    h.stop().await;
    let errors = h.system_lines().into_iter().filter(|l| l["kind"] == "plugin_error").count();
    assert_eq!(errors, 1, "logged at most once a minute");
    let mut h = proxy(&plugin_toml("trap", &trap, "allow"), &[]).await;
    assert_eq!(status(&h.get("ok.test", port, "/").await), 200, "fail open when configured");
    h.stop().await;
}

#[tokio::test]
async fn e86_plugins_only_add_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let kw = write(dir.path(), "kw", KEYWORD);
    let never = write(dir.path(), "never", &module("(i32.const 0)", ""));
    let origin = Origin::start(|_| Reply::ok("fine")).await;
    let port = origin.addr.port();
    let toml =
        format!("{}{}", plugin_toml("never", &never, "block"), plugin_toml("kw", &kw, "block"));
    let lists = [("domains.txt", "bad.test\n")];
    let extra = format!("[rules]\nallow_domains = [\"vip.test\"]\n{toml}");
    let mut h = proxy(&extra, &lists).await;
    // A plugin that never blocks cannot lift a list block.
    let r = h.get("bad.test", port, "/").await;
    assert_eq!((status(&r), reason(&r).as_str()), (403, "domain_blocklist"), "{r}");
    // Allowlisted hosts skip plugins.
    assert_eq!(status(&h.get("vip.test", port, "/ads/x").await), 200);
    // Config order: the second plugin still runs after a no-opinion first one.
    assert_eq!(status(&h.get("ok.test", port, "/ads/x").await), 403);
    // Reload with a broken plugin keeps the previous set.
    std::fs::write(&kw, "(module garbage").unwrap();
    assert!(h.handle.as_ref().unwrap().deps.reload_policies().is_err());
    assert_eq!(status(&h.get("ok.test", port, "/ads/y").await), 403, "old set still active");
    let stats = h.handle.as_ref().unwrap().deps.plugins.load().stats();
    assert_eq!(
        stats.iter().map(|s| (s.0.as_str(), s.2)).collect::<Vec<_>>(),
        [("never", 0), ("kw", 2)]
    );
    h.stop().await;
}

/// RV2-L3: a broken plugin on reload keeps only the old plugin set; new policies still apply.
#[tokio::test]
async fn rv2_l3_broken_plugin_does_not_hold_back_new_policies() {
    let dir = tempfile::tempdir().unwrap();
    let kw = write(dir.path(), "kw", KEYWORD);
    let origin = Origin::start(|_| Reply::ok("fine")).await;
    let port = origin.addr.port();
    let mut h = proxy(&plugin_toml("kw", &kw, "block"), &[]).await;
    assert_eq!(status(&h.get("bad.test", port, "/news").await), 200);
    let path = h.lab.path().join("config.toml");
    let base = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!(
            "{base}\n[[profiles]]\nname = \"default\"\nextra_blocked_domains = [\"bad.test\"]\n"
        ),
    )
    .unwrap();
    std::fs::write(&kw, "(module garbage").unwrap();
    let err = h.handle.as_ref().unwrap().deps.reload_policies().unwrap_err();
    assert!(err.contains("plugins"), "{err}");
    let r = h.get("bad.test", port, "/news").await;
    assert_eq!(status(&r), 403, "the new profile is active: {r}");
    let r = h.get("ok.test", port, "/ads/x").await;
    assert_eq!((status(&r), reason(&r).as_str()), (403, "plugin_rule"), "old plugin kept: {r}");
    h.stop().await;
    let reloads: Vec<_> =
        h.system_lines().into_iter().filter(|v| v["kind"] == "policy_reloaded").collect();
    assert_eq!(reloads.len(), 1);
    assert_eq!(reloads[0]["detail"]["ok"], true);
    assert!(reloads[0]["detail"]["plugins_error"].is_string(), "{:?}", reloads[0]);
}

/// RV2-L2: fuel is bounded in config (a slow plugin would otherwise hold a call for seconds).
#[test]
fn rv2_l2_fuel_above_the_bound_is_rejected() {
    let lab = common::Lab::new();
    let kw = write(lab.path(), "kw", KEYWORD);
    let toml = |fuel: u64| format!("{}fuel = {fuel}\n", plugin_toml("kw", &kw, "block"));
    let err = Config::parse(&toml(1_000_000_000), lab.path(), None).unwrap_err();
    assert!(err.to_string().contains("plugins.fuel"), "{err}");
    let ok = Config::parse(&toml(100_000_000), lab.path(), None);
    assert!(ok.is_ok(), "{ok:?}");
}

/// RV2-L2: fuel-burning plugin calls never stall a worker, so unrelated requests stay fast.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rv2_l2_slow_plugins_do_not_stall_unrelated_requests() {
    let dir = tempfile::tempdir().unwrap();
    let spin = write(dir.path(), "spin", &module("(loop $l (br $l)) (i32.const 0)", ""));
    let origin = Origin::start(|_| Reply::ok("fine")).await;
    let port = origin.addr.port();
    let toml = format!("{}fuel = 100000000\n", plugin_toml("spin", &spin, "block"));
    let mut h = proxy(&toml, &[("domains.txt", "bad.test\n")]).await;
    let addr = h.addr;
    let slow: Vec<_> = (0..20)
        .map(|_| {
            let r = get_req("ok.test", port);
            tokio::spawn(
                async move { raw_exchange(addr, r.as_bytes(), Duration::from_secs(30)).await },
            )
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(100)).await;
    // A list block never runs plugins; it must not wait behind the fuel-burning calls.
    let started = std::time::Instant::now();
    let unrelated = get_req("bad.test", port);
    let r = raw_exchange(addr, unrelated.as_bytes(), Duration::from_secs(10)).await;
    let took = started.elapsed();
    assert_eq!((status(&r), reason(&r).as_str()), (403, "domain_blocklist"), "{r}");
    assert!(took < Duration::from_secs(3), "unrelated request stalled for {took:?}");
    for t in slow {
        let r = t.await.unwrap();
        assert_eq!((status(&r), reason(&r).as_str()), (403, "plugin_error"), "{r}");
    }
    h.stop().await;
}
