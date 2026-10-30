//! `webfilter-proxy check-config` drives the real binary: exit 0 on valid, 2 on invalid (SPEC 6).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::process::Command;

use common::{Lab, repo_root};

fn check_config(path: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_webfilter-proxy"))
        .arg("--config")
        .arg(path)
        .arg("check-config")
        .output()
        .unwrap()
}

#[test]
fn check_config_accepts_shipped_example() {
    let out = check_config(&repo_root().join("config/config.example.toml"));
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn check_config_rejects_invalid_with_exit_2() {
    let lab = Lab::new();
    let path = lab.write_config("listen = \"0.0.0.0:8080\"\n");
    let out = check_config(&path);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("listen"));
}

#[test]
fn check_config_missing_file_exit_2() {
    let lab = Lab::new();
    let out = check_config(&lab.path().join("nope.toml"));
    assert_eq!(out.status.code(), Some(2));
}
