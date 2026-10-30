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

fn proxy(args: &[&str], stdin: &str) -> std::process::Output {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_webfilter-proxy"))
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn blocklist_test_subcommand_reports_rule() {
    let cfg = repo_root().join("config/config.example.toml");
    let cfg = cfg.to_str().unwrap();
    let out = proxy(&["--config", cfg, "blocklist", "test", "http://good.test/x.EXE"], "");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("action:  blocked") && stdout.contains("rule:    ext:.exe"),
        "{stdout}"
    );
    let out = proxy(&["--config", cfg, "blocklist", "test", "http://user@good.test/"], "");
    assert!(String::from_utf8_lossy(&out.stdout).contains("rejected: userinfo_in_url"));
}

#[test]
fn hash_password_roundtrip() {
    let out = proxy(&["hash-password"], "s3cret\n");
    assert_eq!(out.status.code(), Some(0));
    let hash = String::from_utf8(out.stdout).unwrap();
    assert!(webfilter::auth::verify_password(hash.trim(), b"s3cret"));
    assert_eq!(proxy(&["hash-password"], "").status.code(), Some(1), "empty password refused");
}
