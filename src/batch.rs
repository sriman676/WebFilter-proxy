//! Batch fetching (SPEC_EXT_CLIENT C1/C2, D-60): input files, the retry policy, and the JSONL
//! manifest with a lock file and verified resume. Manifest paths are never trusted: a recorded
//! file only counts when it resolves inside the canonical output directory and its size and
//! SHA-256 still match.
#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

/// Lines read from an input file.
pub const MAX_LINES: usize = 100_000;
/// Longest input line.
pub const MAX_LINE: usize = 1024 * 1024;
/// Most retries.
pub const MAX_RETRIES: u32 = 10;

/// URLs from an input file: `#` comments, blank lines skipped, duplicates removed (order kept).
/// Returns (urls, invalid line count).
pub fn parse_input_file(text: &str) -> (Vec<String>, usize) {
    let mut seen = HashSet::new();
    let mut urls = Vec::new();
    let mut invalid = 0;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    for (n, line) in text.split('\n').enumerate() {
        if n >= MAX_LINES {
            invalid += 1;
            break;
        }
        let line = line.strip_suffix('\r').unwrap_or(line).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > MAX_LINE
            || line.chars().any(char::is_control)
            || line.contains(char::is_whitespace)
        {
            invalid += 1;
            continue;
        }
        if seen.insert(line.to_owned()) {
            urls.push(line.to_owned());
        }
    }
    (urls, invalid)
}

/// Statuses retried (C2).
pub fn retryable_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 502 | 503 | 504)
}

/// `Retry-After` as a delay: integer seconds or an HTTP date; invalid or negative values ignored.
pub fn retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let v = value.trim();
    if let Ok(secs) = v.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    httpdate::parse_http_date(v).ok().and_then(|t| t.duration_since(now).ok())
}

/// Delay before retry `attempt` (1-based): full jitter over 500 ms x 2^(attempt-1), capped;
/// a server `Retry-After` wins when present (also capped).
pub fn backoff(attempt: u32, server: Option<Duration>, cap: Duration, jitter: f64) -> Duration {
    if let Some(s) = server {
        return s.min(cap);
    }
    let base = Duration::from_millis(500).saturating_mul(1u32 << attempt.saturating_sub(1).min(16));
    base.min(cap).mul_f64(jitter.clamp(0.0, 1.0))
}

/// One manifest record (C2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Record {
    /// URL as requested.
    pub url: String,
    /// Final status.
    pub status: Option<u16>,
    /// Saved bytes.
    pub bytes: u64,
    /// SHA-256 of the saved file.
    pub sha256: Option<String>,
    /// Saved file.
    pub saved_path: Option<String>,
    /// Blocked by the proxy.
    pub blocked: bool,
    /// Error.
    pub error: Option<String>,
    /// Unix seconds.
    pub finished_at: u64,
}

/// An open manifest with its lock.
pub struct Manifest {
    path: PathBuf,
    lock: PathBuf,
    file: std::fs::File,
}

fn pid_alive(pid: u32) -> bool {
    if cfg!(target_os = "linux") {
        Path::new(&format!("/proc/{pid}")).exists()
    } else {
        true // cannot tell: treat the lock as held
    }
}

impl Manifest {
    /// Open for appending, taking `<path>.lock` (a stale lock of a dead process is replaced).
    pub fn open(path: &Path) -> Result<Self, String> {
        let lock = PathBuf::from(format!("{}.lock", path.display()));
        let take = || std::fs::OpenOptions::new().write(true).create_new(true).open(&lock);
        let mut handle = match take() {
            Ok(f) => f,
            Err(_) => {
                let held =
                    std::fs::read_to_string(&lock).ok().and_then(|s| s.trim().parse::<u32>().ok());
                if held.is_some_and(pid_alive) {
                    return Err(format!("{} is locked by a running process", path.display()));
                }
                std::fs::remove_file(&lock).map_err(|e| e.to_string())?;
                take().map_err(|e| e.to_string())?
            }
        };
        handle.write_all(std::process::id().to_string().as_bytes()).map_err(|e| e.to_string())?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        // A crash may have left a truncated last line: start the next record on a fresh line.
        let ends_open =
            std::fs::read(path).ok().and_then(|b| b.last().copied()).is_some_and(|c| c != b'\n');
        if ends_open {
            file.write_all(b"\n").map_err(|e| e.to_string())?;
        }
        Ok(Self { path: path.to_path_buf(), lock, file })
    }

    /// Append one record with a single write.
    pub fn append(&mut self, r: &Record) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(r).map_err(std::io::Error::other)?;
        line.push(b'\n');
        self.file.write_all(&line)
    }

    /// Flush to disk (end of run).
    pub fn sync(&self) -> std::io::Result<()> {
        self.file.sync_all()
    }

    /// The manifest path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Manifest {
    fn drop(&mut self) {
        let _ = self.file.sync_all();
        let _ = std::fs::remove_file(&self.lock);
    }
}

/// The last record per URL (truncated or invalid lines ignored).
pub fn load(path: &Path) -> HashMap<String, Record> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Record>(l).ok())
        .map(|r| (r.url.clone(), r))
        .collect()
}

/// SHA-256 of a file.
pub fn file_sha256(path: &Path) -> Option<String> {
    std::fs::read(path).ok().map(|b| hex::encode(Sha256::digest(b)))
}

/// Whether `r` is a completed download that is still intact inside `out_dir` (C2 resume).
pub fn completed(r: &Record, out_dir: &Path) -> bool {
    let (Some(saved), Some(sha)) = (&r.saved_path, &r.sha256) else { return false };
    if r.error.is_some() || r.blocked {
        return false;
    }
    let Ok(root) = out_dir.canonicalize() else { return false };
    let Ok(file) = Path::new(saved).canonicalize() else { return false };
    file.starts_with(&root)
        && std::fs::metadata(&file).is_ok_and(|m| m.is_file() && m.len() == r.bytes)
        && file_sha256(&file).as_deref() == Some(sha.as_str())
}
