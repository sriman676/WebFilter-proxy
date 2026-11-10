//! Dashboard editing with safeguards (A-30): only blocklist files, category on/off/schedules,
//! extra allowlist entries and the global mode. Every change is validated before it applies,
//! versioned under `state/versions/` (10 kept) and can be rolled back in one call. TLS,
//! destination policy, ports and auth stay file-only.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crate::blocklist::{
    BlocklistHandle, ReloadOutcome, parse_domain_entry, parse_domains, parse_ips, parse_patterns,
};
use crate::config::BlocklistConfig;
use crate::profiles::Settings;
use crate::util::LockExt;
use crate::util::unix_now;

/// Versions kept per edited item.
pub const KEEP: usize = 10;
/// Largest list accepted from the dashboard.
pub const MAX_LIST_BYTES: usize = 8 * 1024 * 1024;

/// List kinds (each with its own grammar).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// `domains.txt` grammar.
    Domains,
    /// `url_patterns.txt` grammar.
    UrlPatterns,
    /// `ip_blocklist.txt` grammar.
    Ips,
}

/// An editable list: `domains`, `url_patterns`, `ip_blocklist`, or `category/<name>/<kind>`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ListTarget {
    /// API name.
    pub name: String,
    /// Grammar.
    pub kind: Kind,
    /// File (never chosen by the client; only configured files are editable).
    #[serde(skip)]
    pub path: PathBuf,
}

/// Every editable list from the configuration.
pub fn targets(cfg: &BlocklistConfig) -> Vec<ListTarget> {
    let mut v = vec![
        ListTarget { name: "domains".into(), kind: Kind::Domains, path: cfg.domains.clone() },
        ListTarget {
            name: "url_patterns".into(),
            kind: Kind::UrlPatterns,
            path: cfg.url_patterns.clone(),
        },
        ListTarget { name: "ip_blocklist".into(), kind: Kind::Ips, path: cfg.ip_blocklist.clone() },
    ];
    for c in &cfg.categories {
        for (suffix, kind, path) in [
            ("domains", Kind::Domains, &c.domains),
            ("url_patterns", Kind::UrlPatterns, &c.url_patterns),
            ("ip_blocklist", Kind::Ips, &c.ip_blocklist),
        ] {
            if !path.as_os_str().is_empty() {
                v.push(ListTarget {
                    name: format!("category/{}/{suffix}", c.name),
                    kind,
                    path: path.clone(),
                });
            }
        }
    }
    v
}

/// Parse `text` with the list's grammar; the error is shown to the editor.
pub fn validate(kind: Kind, text: &str) -> Result<usize, String> {
    if text.len() > MAX_LIST_BYTES {
        return Err("list larger than 8 MiB".into());
    }
    let r = match kind {
        Kind::Domains => parse_domains(text).map(|p| p.entries),
        Kind::UrlPatterns => parse_patterns(text).map(|p| p.entries),
        Kind::Ips => parse_ips(text).map(|p| p.entries),
    };
    r.map_err(|e| e.to_string())
}

fn versions_dir(state: &Path, item: &str) -> PathBuf {
    state.join("versions").join(item.replace('/', "__"))
}

/// Version file names of `item`, newest first.
pub fn versions(state: &Path, item: &str) -> Vec<String> {
    let mut v: Vec<(u64, String)> = std::fs::read_dir(versions_dir(state, item))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    Some((n.strip_prefix('v')?.split('.').next()?.parse().ok()?, n))
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort_unstable_by(|a, b| b.cmp(a));
    v.into_iter().map(|(_, n)| n).collect()
}

/// Serializes every edit, version and rollback (concurrent PUT/rollback, review L5).
static EDIT_LOCK: Mutex<()> = Mutex::new(());

fn edit_lock() -> MutexGuard<'static, ()> {
    EDIT_LOCK.lock_or_recover()
}

/// Replace `path` atomically: a randomly named sibling created with `create_new` (never follows
/// a planted file or symlink), with the original file's permissions (0600 for a new file),
/// synced, then renamed into place.
fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut rnd = [0u8; 12];
    getrandom::fill(&mut rnd).map_err(|e| std::io::Error::other(e.to_string()))?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}.wf-tmp", hex::encode(rnd)));
    let original = std::fs::metadata(path).ok().map(|m| m.permissions());
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    let written = (|| {
        f.write_all(data)?;
        if let Some(p) = original {
            f.set_permissions(p)?;
        }
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// Keep a copy of the current content of `item` before it changes.
fn snapshot(state: &Path, item: &str, current: &[u8]) -> std::io::Result<()> {
    let dir = versions_dir(state, item);
    std::fs::create_dir_all(&dir)?;
    let newest = versions(state, item)
        .first()
        .and_then(|v| v.strip_prefix('v')?.split('.').next()?.parse::<u64>().ok());
    let ts = newest.map_or(unix_now(), |n| unix_now().max(n + 1));
    write_atomic(&dir.join(format!("v{ts}.txt")), current)?;
    for old in versions(state, item).into_iter().skip(KEEP) {
        let _ = std::fs::remove_file(dir.join(old));
    }
    Ok(())
}

/// Replace a list file: validate, version the old content, write, reload; on a failed reload the
/// old content is restored.
pub fn save_list(
    state: &Path,
    lists: &BlocklistHandle,
    t: &ListTarget,
    text: &str,
) -> Result<usize, String> {
    let _guard = edit_lock();
    let entries = validate(t.kind, text)?;
    let old = std::fs::read(&t.path).map_err(|e| format!("cannot read the list: {e}"))?;
    snapshot(state, &t.name, &old).map_err(|e| format!("cannot keep a version: {e}"))?;
    write_atomic(&t.path, text.as_bytes()).map_err(|e| format!("cannot write the list: {e}"))?;
    if let ReloadOutcome::Failed(e) = lists.reload() {
        let _ = write_atomic(&t.path, &old);
        let _ = lists.reload();
        return Err(format!("reload failed, previous list restored: {e}"));
    }
    Ok(entries)
}

/// Restore the newest kept version of a list (the current content is versioned first).
pub fn rollback_list(
    state: &Path,
    lists: &BlocklistHandle,
    t: &ListTarget,
) -> Result<String, String> {
    let _guard = edit_lock();
    let version = versions(state, &t.name).into_iter().next().ok_or("no earlier version")?;
    let path = versions_dir(state, &t.name).join(&version);
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&path); // consumed: the next rollback goes one step further back
    save_list_unversioned(lists, t, &text)?;
    Ok(version)
}

fn save_list_unversioned(
    lists: &BlocklistHandle,
    t: &ListTarget,
    text: &str,
) -> Result<(), String> {
    validate(t.kind, text)?;
    let old = std::fs::read(&t.path).map_err(|e| e.to_string())?;
    write_atomic(&t.path, text.as_bytes()).map_err(|e| e.to_string())?;
    if let ReloadOutcome::Failed(e) = lists.reload() {
        let _ = write_atomic(&t.path, &old);
        let _ = lists.reload();
        return Err(e);
    }
    Ok(())
}

/// Load `state/settings.json`; an invalid file is ignored with a warning.
pub fn load_settings(state: &Path) -> (Settings, Option<String>) {
    match std::fs::read(state.join("settings.json")) {
        Err(_) => (Settings::default(), None),
        Ok(bytes) => match serde_json::from_slice::<Settings>(&bytes) {
            Ok(s) => (s, None),
            Err(_) => {
                (Settings::default(), Some("settings.json rejected (schema); defaults used".into()))
            }
        },
    }
}

/// Validate settings against the configuration.
pub fn validate_settings(s: &Settings, cfg: &BlocklistConfig) -> Result<(), String> {
    if s.allow_domains.len() > 1000 {
        return Err("at most 1000 allowlist entries".into());
    }
    for d in &s.allow_domains {
        parse_domain_entry(d).map_err(|e| format!("allow_domains: {e}"))?;
    }
    let offset = crate::schedule::parse_offset(&cfg.utc_offset)?;
    for (name, o) in &s.categories {
        if !cfg.categories.iter().any(|c| &c.name == name) {
            return Err(format!("unknown category {name:?}"));
        }
        if let Some(active) = &o.active {
            crate::schedule::Schedule::parse(active, offset).map_err(|e| format!("{name}: {e}"))?;
        }
    }
    Ok(())
}

/// Persist settings (the previous file is versioned first).
pub fn save_settings(state: &Path, s: &Settings) -> Result<(), String> {
    let _guard = edit_lock();
    std::fs::create_dir_all(state).map_err(|e| e.to_string())?;
    let path = state.join("settings.json");
    let old = std::fs::read(&path).unwrap_or_else(|_| b"{}".to_vec());
    snapshot(state, "settings", &old).map_err(|e| e.to_string())?;
    let data = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
    write_atomic(&path, &data).map_err(|e| e.to_string())
}

/// The newest kept settings version (consumed), for rollback.
pub fn previous_settings(state: &Path) -> Result<Settings, String> {
    let _guard = edit_lock();
    let version = versions(state, "settings").into_iter().next().ok_or("no earlier version")?;
    let path = versions_dir(state, "settings").join(&version);
    let s = serde_json::from_slice::<Settings>(&std::fs::read(&path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&path);
    let data = serde_json::to_vec_pretty(&s).map_err(|e| e.to_string())?;
    write_atomic(&state.join("settings.json"), &data).map_err(|e| e.to_string())?;
    Ok(s)
}
