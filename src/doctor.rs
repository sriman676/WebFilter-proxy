//! `webfilter-proxy doctor` (SPEC_EXT_OPS O7, D-65): self-checks that print PASS/WARN/FAIL and
//! exit 0/1/2. Never prints secrets (no tokens, hashes or key material; paths only).
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::config::Config;

/// Check outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Fine.
    Pass,
    /// Works, but worth a look.
    Warn,
    /// Broken.
    Fail,
}

impl Level {
    /// Printed label.
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Pass => "PASS",
            Level::Warn => "WARN",
            Level::Fail => "FAIL",
        }
    }
}

#[cfg(unix)]
fn mode(path: &std::path::Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn mode(_: &std::path::Path) -> Option<u32> {
    None
}

/// Run every check against a loaded (hence valid) configuration.
pub fn run(cfg: &Config) -> Vec<(Level, String)> {
    let mut out = vec![(Level::Pass, "configuration is valid".to_owned())];
    let mut add = |l: Level, m: String| out.push((l, m));

    // Listen ports bindable (or already ours).
    let mut ports = vec![("listen", cfg.listen)];
    if cfg.admin.enabled {
        ports.push(("admin.listen", cfg.admin.listen));
    }
    if cfg.transparent.enabled {
        ports.extend([
            ("transparent.http_listen", cfg.transparent.http_listen),
            ("transparent.tls_listen", cfg.transparent.tls_listen),
        ]);
    }
    for (key, addr) in ports {
        match std::net::TcpListener::bind(addr) {
            Ok(_) => add(Level::Pass, format!("{key} {addr} is free")),
            Err(e) => add(
                Level::Warn,
                format!("{key} {addr} cannot be bound now ({e}); is the proxy already running?"),
            ),
        }
    }

    // CA key permissions when intercepting.
    if cfg.tls.intercept {
        match crate::tls::CaStore::load(&cfg.tls.ca_dir) {
            Ok(_) => add(
                Level::Pass,
                format!("CA in {} loads (key 0600, owner, no symlink)", cfg.tls.ca_dir.display()),
            ),
            Err(e) => add(Level::Fail, format!("CA: {e}")),
        }
    }

    // State directory.
    match mode(&cfg.state.dir) {
        Some(0o700) => add(Level::Pass, format!("state dir {} is 0700", cfg.state.dir.display())),
        Some(m) => add(
            Level::Warn,
            format!("state dir {} is {m:o}; expected 0700", cfg.state.dir.display()),
        ),
        None if cfg.state.dir.exists() => {
            add(Level::Pass, format!("state dir {} exists", cfg.state.dir.display()))
        }
        None => add(
            Level::Warn,
            format!("state dir {} does not exist yet (created on start)", cfg.state.dir.display()),
        ),
    }

    // Log directory writable.
    let probe = cfg.logging.dir.join(".doctor-probe");
    match std::fs::create_dir_all(&cfg.logging.dir).and_then(|()| std::fs::write(&probe, b"ok")) {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            add(Level::Pass, format!("log dir {} is writable", cfg.logging.dir.display()));
        }
        Err(e) => add(Level::Fail, format!("log dir {}: {e}", cfg.logging.dir.display())),
    }

    // Scanning engines.
    if cfg.scan.enabled {
        if let Some(c) = &cfg.scan.clamd {
            let (level, msg) = clamd_ping(&c.address);
            add(level, msg);
        }
        match crate::scan::Scanner::new(cfg.scan.clone()) {
            Ok(_) => add(Level::Pass, "scan temp dir and YARA rules (if any) ready".into()),
            Err(e) => add(Level::Fail, format!("scan: {e}")),
        }
    }

    // Feed hosts resolve.
    for f in cfg.feeds.iter().filter(|f| f.enabled) {
        let host = url::Url::parse(&f.url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_default();
        let resolves = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 443))
            .is_ok_and(|mut a| a.next().is_some());
        if resolves {
            add(Level::Pass, format!("feed {}: {host} resolves", f.name));
        } else {
            add(Level::Warn, format!("feed {}: {host} does not resolve", f.name));
        }
    }

    // Transparent prerequisites.
    if cfg.transparent.enabled {
        let linux = cfg!(target_os = "linux");
        add(
            if linux { Level::Pass } else { Level::Fail },
            format!("transparent mode on {} (Linux required)", std::env::consts::OS),
        );
    }
    if cfg.admin.enabled && !crate::auth::is_argon2id_phc(&cfg.admin.token_hash.0) {
        add(Level::Fail, "admin.token_hash is not an argon2id hash".into());
    }
    out
}

/// clamd `zPING` -> `PONG`.
fn clamd_ping(address: &str) -> (Level, String) {
    let reply = match address.split_once(':') {
        Some(("tcp", addr)) => addr
            .parse()
            .ok()
            .and_then(|a| TcpStream::connect_timeout(&a, Duration::from_secs(3)).ok())
            .and_then(|s| s.set_read_timeout(Some(Duration::from_secs(3))).ok().map(|()| s))
            .and_then(ping),
        #[cfg(unix)]
        Some(("unix", path)) => std::os::unix::net::UnixStream::connect(path)
            .ok()
            .and_then(|s| s.set_read_timeout(Some(Duration::from_secs(3))).ok().map(|()| s))
            .and_then(ping),
        _ => None,
    };
    match reply {
        Some(r) if r.starts_with("PONG") => {
            (Level::Pass, format!("clamd at {address} answers PING"))
        }
        _ => (
            Level::Fail,
            format!(
                "clamd at {address} does not answer PING (max_bytes must not exceed its StreamMaxLength)"
            ),
        ),
    }
}

fn ping<S: Read + Write>(mut s: S) -> Option<String> {
    s.write_all(b"zPING\0").ok()?;
    let mut buf = [0u8; 16];
    let n = s.read(&mut buf).ok()?;
    Some(String::from_utf8_lossy(buf.get(..n)?).into_owned())
}
