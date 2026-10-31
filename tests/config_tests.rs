//! U-cfg: valid/invalid configs (unknown key, bad port, non-loopback without auth, bad perms,
//! relative paths). TEST_PLAN section "Unit".
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use std::path::Path;

use common::{Lab, repo_root};
use webfilter::config::{Config, ConfigError, Mode, PortSet};

const FAKE_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";

fn parse_in(lab: &Lab, body: &str) -> Result<Config, ConfigError> {
    Config::parse(body, lab.path(), Some(Path::new("/home/tester")))
}

fn invalid_key(r: Result<Config, ConfigError>) -> String {
    match r {
        Err(ConfigError::Invalid { key, .. }) => key,
        other => panic!("expected Invalid, got {other:?}"),
    }
}

fn parse_err(r: Result<Config, ConfigError>) -> String {
    match r {
        Err(ConfigError::Parse(msg)) => msg,
        other => panic!("expected Parse error, got {other:?}"),
    }
}

#[test]
fn u_cfg_shipped_example_is_valid_and_hardened() {
    let cfg = Config::load(&repo_root().join("config/config.example.toml")).unwrap();
    assert!(cfg.destination.deny_private_ranges, "D-36: shipped example must be hardened");
    assert!(cfg.listen.ip().is_loopback());
    assert!(!cfg.tls.intercept && !cfg.transparent.enabled && !cfg.admin.enabled);
}

#[test]
fn u_cfg_code_defaults_match_example_except_hardening() {
    let base = repo_root().join("config");
    let defaults = Config::parse("", &base, Some(Path::new("/h"))).unwrap();
    let text = std::fs::read_to_string(base.join("config.example.toml")).unwrap();
    let example = Config::parse(&text, &base, Some(Path::new("/h"))).unwrap();
    assert!(!defaults.destination.deny_private_ranges, "D-36 code default is false");
    assert_eq!(defaults.mode, Mode::Enforce);
    assert_eq!(defaults.listen, example.listen);
    assert_eq!(defaults.worker_threads, example.worker_threads);
    assert_eq!(defaults.limits, example.limits);
    assert_eq!(defaults.timeouts, example.timeouts);
    assert_eq!(defaults.ports, example.ports);
    assert_eq!(defaults.logging, example.logging);
    assert_eq!(defaults.blocklists, example.blocklists);
    assert_eq!(defaults.rules, example.rules);
    assert_eq!(defaults.tls, example.tls);
    assert_eq!(defaults.http2, example.http2);
    assert_eq!(defaults.transparent, example.transparent);
    assert_eq!(defaults.admin, example.admin);
}

#[test]
fn u_cfg_unknown_top_level_key_rejected() {
    let lab = Lab::new();
    assert!(parse_err(parse_in(&lab, "bogus_key = 1\n")).contains("bogus_key"));
}

#[test]
fn u_cfg_unknown_nested_key_rejected() {
    let lab = Lab::new();
    let msg = parse_err(parse_in(&lab, "[limits]\nmax_conections = 5\n"));
    assert!(msg.contains("max_conections"), "{msg}");
}

#[test]
fn u_cfg_malformed_toml_rejected() {
    let lab = Lab::new();
    parse_err(parse_in(&lab, "listen = \n"));
}

#[test]
fn u_cfg_bad_enum_value_rejected() {
    let lab = Lab::new();
    parse_err(parse_in(&lab, "mode = \"block\"\n"));
}

#[test]
fn u_cfg_bad_ports_rejected() {
    let lab = Lab::new();
    for bad in ["[0]", "[70000]", "[-1]", "[]", "\"all\"", "\"ANY\""] {
        let body = format!("[ports]\nhttp_allowed = {bad}\n");
        parse_err(parse_in(&lab, &body));
    }
    let msg = parse_err(parse_in(&lab, "[ports]\nconnect_allowed = [443, 70000]\n"));
    assert!(msg.contains("70000"), "{msg}");
}

#[test]
fn u_cfg_port_any_and_list_accepted() {
    let lab = Lab::new();
    let cfg = parse_in(&lab, "[ports]\nhttp_allowed = \"any\"\nconnect_allowed = [443]\n").unwrap();
    assert_eq!(cfg.ports.http_allowed, PortSet::Any);
    assert!(cfg.ports.http_allowed.allows(25));
    assert!(!cfg.ports.http_allowed.allows(0));
    assert!(cfg.ports.connect_allowed.allows(443));
    assert!(!cfg.ports.connect_allowed.allows(8443));
}

#[test]
fn u_cfg_non_loopback_listen_requires_auth() {
    let lab = Lab::new();
    for addr in ["0.0.0.0:8080", "[::]:8080", "192.0.2.1:8080", "[::ffff:127.0.0.1]:8080"] {
        let body = format!("listen = \"{addr}\"\n");
        assert_eq!(invalid_key(parse_in(&lab, &body)), "listen", "{addr}");
    }
    let body = format!(
        "listen = \"0.0.0.0:8080\"\n[proxy_auth]\nusername = \"analyst\"\npassword_hash = \"{FAKE_HASH}\"\n"
    );
    parse_in(&lab, &body).unwrap();
}

#[test]
fn u_cfg_ipv6_loopback_listen_ok() {
    let lab = Lab::new();
    parse_in(&lab, "listen = \"[::1]:8080\"\n").unwrap();
}

#[test]
fn u_cfg_proxy_auth_fields_validated() {
    let lab = Lab::new();
    let bad_hash = "[proxy_auth]\nusername = \"a\"\npassword_hash = \"plaintext\"\n";
    assert_eq!(invalid_key(parse_in(&lab, bad_hash)), "proxy_auth.password_hash");
    let bad_user = format!("[proxy_auth]\nusername = \"a:b\"\npassword_hash = \"{FAKE_HASH}\"\n");
    assert_eq!(invalid_key(parse_in(&lab, &bad_user)), "proxy_auth.username");
    parse_err(parse_in(&lab, "[proxy_auth]\nusername = \"a\"\n"));
}

#[test]
fn u_cfg_proxy_auth_hash_not_in_debug() {
    let lab = Lab::new();
    let body = format!("[proxy_auth]\nusername = \"a\"\npassword_hash = \"{FAKE_HASH}\"\n");
    let cfg = parse_in(&lab, &body).unwrap();
    assert!(!format!("{cfg:?}").contains("argon2id"));
}

#[test]
fn u_cfg_zero_limits_rejected() {
    let lab = Lab::new();
    for (section, key) in [
        ("limits", "max_connections"),
        ("limits", "max_head_bytes"),
        ("timeouts", "client_head_read"),
        ("logging", "queue_capacity"),
        ("http2", "reset_limit"),
    ] {
        let body = format!("[{section}]\n{key} = 0\n");
        assert_eq!(invalid_key(parse_in(&lab, &body)), format!("{section}.{key}"));
    }
}

#[test]
fn u_cfg_h2_frame_size_bounds() {
    let lab = Lab::new();
    let r = parse_in(&lab, "[http2]\nmax_frame_size = 1024\n");
    assert_eq!(invalid_key(r), "http2.max_frame_size");
}

#[test]
fn u_cfg_relative_paths_resolve_against_config_dir() {
    let lab = Lab::new();
    let path = lab.write_config("[logging]\ndir = \"logs\"\n");
    let cfg = Config::load(&path).unwrap();
    assert_eq!(cfg.logging.dir, lab.path().join("logs"));
    assert_eq!(cfg.blocklists.domains, lab.path().join("blocklists/domains.txt"));
    assert!(cfg.blocklists.domains.is_absolute());
}

#[test]
fn u_cfg_tilde_expands_to_home_and_tilde_user_rejected() {
    let lab = Lab::new();
    let home = lab.path().join("home"); // absolute on every platform
    let cfg = Config::parse("[logging]\ndir = \"~/wf-logs\"\n", lab.path(), Some(&home)).unwrap();
    assert_eq!(cfg.logging.dir, home.join("wf-logs"));
    let r = parse_in(&lab, "[logging]\ndir = \"~root/logs\"\n");
    assert_eq!(invalid_key(r), "logging.dir");
    let r = Config::parse("[logging]\ndir = \"~/x\"\n", lab.path(), None);
    assert_eq!(invalid_key(r), "logging.dir");
    // ca_dir is resolved (and checked) only when intercepting.
    let r = Config::parse("[tls]\nintercept = true\nca_dir = \"~/x\"\n", lab.path(), None);
    assert_eq!(invalid_key(r), "tls.ca_dir");
}

#[test]
fn u_cfg_missing_blocklist_rejected() {
    let lab = Lab::new();
    let r = parse_in(&lab, "[blocklists]\ndomains = \"nope.txt\"\n");
    assert_eq!(invalid_key(r), "blocklists.domains");
    let r = parse_in(&lab, "[blocklists]\nurl_patterns = \".\"\n");
    assert_eq!(invalid_key(r), "blocklists.url_patterns");
}

#[test]
fn u_cfg_missing_upstream_ca_bundle_rejected() {
    let lab = Lab::new();
    let r = parse_in(&lab, "[tls]\nupstream_ca_bundle = \"missing.pem\"\n");
    assert_eq!(invalid_key(r), "tls.upstream_ca_bundle");
}

#[cfg(unix)]
#[test]
fn u_cfg_ca_dir_permissions_enforced() {
    use std::os::unix::fs::PermissionsExt;
    let lab = Lab::new();
    let ca = lab.path().join("ca");
    std::fs::create_dir(&ca).unwrap();
    let body = format!("[tls]\nintercept = true\nca_dir = \"{}\"\n", ca.display());
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(invalid_key(parse_in(&lab, &body)), "tls.ca_dir");
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o700)).unwrap();
    parse_in(&lab, &body).unwrap();
}

#[cfg(unix)]
#[test]
fn u_cfg_ca_dir_symlink_refused() {
    let lab = Lab::new();
    let real = lab.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = lab.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let body = format!("[tls]\nintercept = true\nca_dir = \"{}\"\n", link.display());
    assert_eq!(invalid_key(parse_in(&lab, &body)), "tls.ca_dir");
}

#[test]
fn u_cfg_transparent_requires_acknowledgement() {
    let lab = Lab::new();
    let r = parse_in(&lab, "[transparent]\nenabled = true\n");
    assert_eq!(invalid_key(r), "transparent.acknowledge_lab_only");
    parse_in(&lab, "[transparent]\nenabled = true\nacknowledge_lab_only = true\n").unwrap();
}

#[test]
fn u_cfg_admin_must_be_loopback() {
    let lab = Lab::new();
    let r = parse_in(&lab, "[admin]\nlisten = \"0.0.0.0:9090\"\n");
    assert_eq!(invalid_key(r), "admin.listen");
}

#[test]
fn u_cfg_worker_threads_zero_means_cpus() {
    let lab = Lab::new();
    let cfg = parse_in(&lab, "").unwrap();
    assert!(cfg.effective_worker_threads() >= 1);
    let cfg = parse_in(&lab, "worker_threads = 3\n").unwrap();
    assert_eq!(cfg.effective_worker_threads(), 3);
}

#[test]
fn u_cfg_missing_file_is_read_error() {
    let lab = Lab::new();
    let r = Config::load(&lab.path().join("absent.toml"));
    assert!(matches!(r, Err(ConfigError::Read { .. })));
}

// ---- Regression tests for Phase 0 security review (docs/pentest/phase-0/FINDINGS.md) ----

#[test]
fn pf_0_02_parse_error_does_not_echo_source_line() {
    // A typo next to a secret must not print the secret (D-18).
    let lab = Lab::new();
    let body = "[proxy_auth]\nusername = \"a\"\npassword_hash = \"$argon2id$SECRETVALUE\" junk\n";
    let msg = parse_err(parse_in(&lab, body));
    assert!(!msg.contains("SECRETVALUE"), "{msg}");
    assert!(msg.contains("line 3"), "{msg}");
}

#[test]
fn pf_0_03_limit_upper_bounds_enforced() {
    let lab = Lab::new();
    for (section, key, value) in [
        ("http2", "initial_stream_window", "2147483648"),
        ("http2", "initial_conn_window", "4294967295"),
        ("http2", "max_concurrent_streams", "4294967295"),
        ("limits", "max_head_bytes", "9223372036854775807"),
        ("limits", "max_headers", "100000"),
        ("limits", "max_uri_bytes", "1048577"),
    ] {
        let body = format!("[{section}]\n{key} = {value}\n");
        assert_eq!(invalid_key(parse_in(&lab, &body)), format!("{section}.{key}"));
    }
}

#[test]
fn pf_0_04_ca_dir_not_resolved_unless_intercepting() {
    let lab = Lab::new();
    // Default ca_dir is `~/...`; without HOME this must still load when intercept is off.
    Config::parse("", lab.path(), None).unwrap();
}

#[test]
fn pf_0_04_empty_or_relative_home_rejected() {
    let lab = Lab::new();
    for home in ["", "relative/home"] {
        let r = Config::parse("[logging]\ndir = \"~/logs\"\n", lab.path(), Some(Path::new(home)));
        assert_eq!(invalid_key(r), "logging.dir", "HOME={home:?}");
    }
}

#[test]
fn pf_0_05_admin_enabled_requires_token_hash() {
    let lab = Lab::new();
    let r = parse_in(&lab, "[admin]\nenabled = true\n");
    assert_eq!(invalid_key(r), "admin.token_hash");
    let ok = format!("[admin]\nenabled = true\ntoken_hash = \"{FAKE_HASH}\"\n");
    parse_in(&lab, &ok).unwrap();
}

#[test]
fn pf_0_06_oversized_or_non_regular_config_file_rejected() {
    let lab = Lab::new();
    let big = lab.write_config(&format!("# {}\n", "x".repeat(1024 * 1024)));
    assert!(matches!(Config::load(&big), Err(ConfigError::Read { .. })));
    assert!(matches!(Config::load(lab.path()), Err(ConfigError::Read { .. })));
}

#[test]
fn pf_0_07_user_hashes_redacted_in_debug_and_errors() {
    let lab = Lab::new();
    let hash = webfilter::auth::hash_password(b"pw").unwrap();
    let users = format!("[[users]]\nusername = \"u\"\npassword_hash = \"{hash}\"\n");
    let cfg = parse_in(&lab, &users).unwrap();
    assert!(!format!("{cfg:?}").contains(&hash));
    let err =
        parse_in(&lab, "[[users]]\nusername = \"u\"\npassword_hash = \"TOPSECRET\"\n").unwrap_err();
    assert!(!err.to_string().contains("TOPSECRET"));
}

// ---- PT-1.5: config abuse -> clean error, never a panic ----

#[test]
fn pt_1_5_duplicate_nested_and_wrongly_typed_keys_rejected() {
    let lab = Lab::new();
    parse_err(parse_in(&lab, "mode = \"enforce\"\nmode = \"monitor\"\n"));
    parse_err(parse_in(&lab, "[limits]\n[limits]\n"));
    parse_err(parse_in(&lab, &format!("x = {}{}\n", "[".repeat(5000), "]".repeat(5000))));
    parse_err(parse_in(&lab, &format!("{}=1\n", "a.".repeat(5000))));
    parse_err(parse_in(&lab, "worker_threads = \"many\"\n"));
    parse_err(parse_in(&lab, "worker_threads = -1\n"));
    parse_err(parse_in(&lab, "[limits]\nmax_connections = 1e9\n"));
}

#[test]
fn pt_1_5_traversal_and_symlinked_paths_resolve_without_panic() {
    let lab = Lab::new();
    let r =
        parse_in(&lab, "[blocklists]\ndomains = \"../../../../../../etc/shadow-does-not-exist\"\n");
    assert_eq!(invalid_key(r), "blocklists.domains");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            lab.path().join("blocklists/domains.txt"),
            lab.path().join("link.txt"),
        )
        .unwrap();
        parse_in(&lab, "[blocklists]\ndomains = \"link.txt\"\n").unwrap(); // operator-chosen symlink is allowed
        std::os::unix::fs::symlink(lab.path().join("nowhere"), lab.path().join("dangling.txt"))
            .unwrap();
        assert_eq!(
            invalid_key(parse_in(&lab, "[blocklists]\ndomains = \"dangling.txt\"\n")),
            "blocklists.domains"
        );
    }
}
