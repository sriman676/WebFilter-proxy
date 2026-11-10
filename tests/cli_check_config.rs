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

#[test]
fn e35_ca_generate_export_and_no_overwrite() {
    let lab = Lab::new();
    let ca_dir = lab.path().join("ca");
    let cfg = lab.write_config(&format!("[tls]\nca_dir = \"{}\"\n", ca_dir.display()));
    let cfg = cfg.to_str().unwrap();
    assert_eq!(proxy(&["--config", cfg, "ca", "generate"], "").status.code(), Some(0));
    let export = proxy(&["--config", cfg, "ca", "export"], "");
    let pem = String::from_utf8(export.stdout).unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----") && !pem.contains("PRIVATE"), "{pem}");
    assert_eq!(
        proxy(&["--config", cfg, "ca", "generate"], "").status.code(),
        Some(1),
        "never overwrites"
    );
}

/// Review 3 L2: `check-config` refuses an unimplemented option set to a non-default value.
#[test]
fn rv3_l2_check_config_rejects_unimplemented_on_error_block() {
    let lab = Lab::new();
    let out = check_config(&lab.write_config("on_error = \"block\"\n"));
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("on_error") && stderr.contains("not implemented"), "{stderr}");
}

/// Review 3 L5: `ca generate` refuses a symlinked `ca_dir` and writes nothing through it.
#[cfg(unix)]
#[test]
fn rv3_l5_ca_generate_refuses_symlinked_ca_dir() {
    use std::os::unix::fs::PermissionsExt;
    let lab = Lab::new();
    let real = lab.path().join("elsewhere");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let ca_dir = lab.path().join("ca");
    std::os::unix::fs::symlink(&real, &ca_dir).unwrap();
    let cfg = lab.write_config(&format!("[tls]\nca_dir = \"{}\"\n", ca_dir.display()));
    let out = proxy(&["--config", cfg.to_str().unwrap(), "ca", "generate"], "");
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!real.join("ca.key").exists(), "nothing written through the link");
}
