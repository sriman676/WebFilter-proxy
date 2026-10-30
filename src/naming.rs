//! Output file naming and safe writing (SPEC 5.3). Pure naming; fuzzed by F-03.
//!
//! Invariant (P-02): every name matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.html$`, contains no
//! `..`, no separators and no Windows-reserved part.
#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};
use url::Url;

use crate::normalize::decode_once;

/// Stem length that triggers truncation.
pub const MAX_STEM: usize = 120;
/// Highest collision suffix tried.
pub const MAX_COLLISIONS: u32 = 999;

fn sha8(data: &str) -> String {
    hex::encode(Sha256::digest(data.as_bytes())).chars().take(8).collect()
}

fn is_reserved(part: &str) -> bool {
    let p = part.to_ascii_uppercase();
    matches!(p.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((p.starts_with("COM") || p.starts_with("LPT"))
            && p.len() == 4
            && p.as_bytes().get(3).is_some_and(|d| (b'1'..=b'9').contains(d)))
}

/// Step 7: keep `[A-Za-z0-9._-]`, collapse `_` runs, turn `..` runs into `_`, trim, ensure an
/// alphanumeric first char.
fn sanitize(stem: &str) -> String {
    fn collapse(s: &str, run: char, replace: &str, min_run: usize) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c != run {
                out.push(c);
                continue;
            }
            let mut n = 1;
            while chars.next_if_eq(&run).is_some() {
                n += 1;
            }
            if n >= min_run { out.push_str(replace) } else { out.push(c) }
        }
        out
    }
    let mapped: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
        .collect();
    let s = collapse(&mapped, '_', "_", 1);
    let s = collapse(&s, '.', "_", 2);
    let s = collapse(&s, '_', "_", 1);
    let s = s.trim_matches(['.', '_', '-']).to_owned();
    if s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) { s } else { format!("h{s}") }
}

/// Split the raw path and query out of a URL string, exactly as typed (no dot-segment resolution).
fn raw_path_query(url: &str) -> (&str, Option<&str>) {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let rest = rest.split('#').next().unwrap_or("");
    let path_start = rest.find(['/', '?']).unwrap_or(rest.len());
    let after_authority = rest.get(path_start..).unwrap_or("");
    match after_authority.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (after_authority, None),
    }
}

/// The output file name for the URL the user typed (SPEC 5.3 steps 1-10). `https://` is added
/// when no scheme is given. Path segments are taken as typed; `.`/`..` segments are dropped,
/// never resolved (oracle: `tests/corpus/filename_cases.tsv`, A-21).
///
/// ```
/// assert_eq!(webfilter::naming::output_filename("https://Example.COM./a/B.HTM"), "example.com_a_B.html");
/// assert_eq!(webfilter::naming::output_filename("example.com/a/../b"), "example.com_a_b.html");
/// ```
pub fn output_filename(original: &str) -> String {
    let original =
        if original.contains("://") { original.to_owned() } else { format!("https://{original}") };
    let parsed = Url::parse(&original).ok();
    let host = match parsed.as_ref().and_then(Url::host) {
        Some(url::Host::Domain(d)) => {
            let d = d.to_ascii_lowercase();
            d.strip_suffix('.').unwrap_or(&d).to_owned()
        }
        Some(url::Host::Ipv4(v4)) => v4.to_string(),
        Some(url::Host::Ipv6(v6)) => format!("ipv6-{}", v6.to_string().replace(':', "-")),
        None => String::new(),
    };
    let port = parsed.as_ref().and_then(Url::port).map(|p| format!("_p{p}")).unwrap_or_default();
    let (raw_path, raw_query) = raw_path_query(&original);
    let mut segments: Vec<String> = raw_path
        .split('/')
        .map(decode_once)
        .filter(|s| !s.is_empty() && s != "." && s != "..")
        .collect();
    if let Some(last) = segments.last_mut() {
        let lower = last.to_ascii_lowercase();
        if let Some(ext) = [".html", ".htm"].into_iter().find(|e| lower.ends_with(e)) {
            last.truncate(last.len() - ext.len());
        }
    }
    let path = segments.join("_");
    let query =
        raw_query.filter(|q| !q.is_empty()).map(|q| format!("_q{}", sha8(q))).unwrap_or_default();
    let raw = format!(
        "{host}{port}{}{query}",
        if path.is_empty() { String::new() } else { format!("_{path}") }
    );

    let mut stem = sanitize(&raw);
    if stem.len() > MAX_STEM {
        let head: String = stem.chars().take(110).collect();
        stem = format!("{}_{}", head.trim_end_matches(['.', '_', '-']), sha8(&stem));
    }
    if stem.split('.').any(is_reserved) {
        stem = format!("r_{stem}");
    }
    format!("{stem}.html")
}

/// Step 11: write `data` (at most `max` bytes) to a new file in `out_dir`, never overwriting and
/// never following a symlink at the final component; on collision try `<stem>-1.html` .. `-999`.
pub fn write_unique(out_dir: &Path, name: &str, data: impl Read, max: u64) -> io::Result<PathBuf> {
    let dir = fs::canonicalize(out_dir)?;
    let stem = name.strip_suffix(".html").unwrap_or(name);
    // Unique temp name: a stale or concurrent `.part` never blocks or clobbers another writer.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nonce = format!("{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed));
    let temp = dir.join(format!(".{stem}.{nonce}.part"));
    let result = write_temp(&temp, data, max).and_then(|()| link_unique(&dir, stem, &temp));
    let _ = fs::remove_file(&temp);
    result
}

fn write_temp(temp: &Path, data: impl Read, max: u64) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(temp)?;
    let copied = io::copy(&mut data.take(max.saturating_add(1)), &mut file)?;
    if copied > max {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!("response exceeds {max} bytes"),
        ));
    }
    file.flush()?;
    file.sync_all()
}

fn link_unique(dir: &Path, stem: &str, temp: &Path) -> io::Result<PathBuf> {
    for n in 0..=MAX_COLLISIONS {
        let name = if n == 0 { format!("{stem}.html") } else { format!("{stem}-{n}.html") };
        let target = dir.join(name);
        match fs::hard_link(temp, &target) {
            Ok(()) => return Ok(target),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("{stem}: more than {MAX_COLLISIONS} collisions"),
    ))
}
