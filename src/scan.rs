//! Download hashing and scanning (SPEC_EXT_POLICY P4, D-53, D-54): eligibility by extension,
//! media type or magic bytes; SHA-256 always; hash blocklist; ClamAV `INSTREAM`; YARA behind the
//! `yara` feature. Bodies go to 0600 temp files with random names in a 0700 directory, within a
//! byte quota and a concurrency cap. Nothing is ever executed and no body byte is ever logged.
#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::{ClamdConfig, ScanConfig};

/// Temp file prefix (startup cleanup removes leftovers).
const TEMP_PREFIX: &str = "wfscan-";
/// Longest clamd reply read.
const MAX_REPLY: usize = 1024;
/// How long a download waits for a scan slot before it is unscannable.
const QUEUE_WAIT: Duration = Duration::from_secs(5);
/// Compressed page types that are not download candidates merely for being encoded (A-47).
const PAGE_TYPES: &[&str] = &[
    "text/html",
    "application/xhtml+xml",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/json",
    "image/svg+xml",
];

/// The scan result of one download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No engine found anything.
    Clean,
    /// An engine reported a signature.
    Infected {
        /// `clamav` or `yara`.
        engine: &'static str,
        /// Sanitized signature name.
        signature: String,
    },
    /// The SHA-256 is on the hash blocklist.
    Blocklisted,
    /// Could not be scanned (oversize, quota, 206, encoded, timeout...).
    Unscannable(&'static str),
    /// A scanner was unreachable or answered nonsense.
    Unavailable(&'static str),
}

impl Verdict {
    /// `scan_status` log value.
    pub fn status(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Infected { .. } => "infected",
            Self::Blocklisted => "blocklisted",
            Self::Unscannable(_) => "unscannable",
            Self::Unavailable(_) => "error",
        }
    }
}

/// Signature names are logged only as `[A-Za-z0-9._-]{1,64}` (P4).
pub fn sanitize_signature(raw: &str) -> String {
    let s: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' })
        .take(64)
        .collect();
    if s.is_empty() { "unknown".into() } else { s }
}

/// One clamd reply line: `Ok(None)` clean, `Ok(Some(sig))` found, `Err` anything else (F-15).
pub fn parse_clamd_reply(reply: &str) -> Result<Option<String>, &'static str> {
    let line = reply.trim_end_matches(['\0', '\n', '\r']);
    let body = line.strip_prefix("stream: ").ok_or("unexpected clamd reply")?;
    if body == "OK" {
        return Ok(None);
    }
    if let Some(sig) = body.strip_suffix(" FOUND") {
        return Ok(Some(sanitize_signature(sig)));
    }
    if body.contains("size limit exceeded") {
        return Err("clamd stream size limit exceeded");
    }
    Err("clamd error reply")
}

/// `Content-Disposition` parameters split on `;` outside quoted strings.
fn disposition_params(cd: &str) -> Vec<&str> {
    let (mut parts, mut start, mut quoted, mut escaped) = (Vec::new(), 0, false, false);
    for (i, c) in cd.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => {
                parts.push(cd.get(start..i).unwrap_or(""));
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(cd.get(start..).unwrap_or(""));
    parts
}

/// Every `filename=` / `filename*=` value of a `Content-Disposition` header, unquoted (the
/// RFC 5987 charset prefix removed; `filename*` stays percent-encoded).
fn disposition_filenames(cd: &str) -> impl Iterator<Item = (bool, String)> + '_ {
    disposition_params(cd).into_iter().filter_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        let k = k.trim().to_ascii_lowercase();
        if k != "filename" && k != "filename*" {
            return None;
        }
        let v = v.trim();
        let v = match v.strip_prefix('"') {
            Some(inner) => {
                let inner = inner.strip_suffix('"').unwrap_or(inner);
                let mut out = String::with_capacity(inner.len());
                let mut chars = inner.chars();
                while let Some(c) = chars.next() {
                    out.push(if c == '\\' { chars.next().unwrap_or('\\') } else { c });
                }
                out
            }
            None => v.to_owned(),
        };
        let v = v.rsplit_once("''").map_or(v.as_str(), |(_, rest)| rest).to_owned();
        Some((k == "filename*", v))
    })
}

/// Lossy percent-decoding (only for matching extensions, never for paths).
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        let hex = b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
        match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
            Some(v) if c == b'%' => {
                out.push(v);
                i += 3;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether the `Content-Encoding` header values name anything but `identity` (any header,
/// any list member; an empty value counts as encoded). Encoded bodies are unscannable (P4).
pub fn content_encoded<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> bool {
    values
        .into_iter()
        .flat_map(|v| v.split(|b| *b == b','))
        .any(|t| !t.trim_ascii().eq_ignore_ascii_case(b"identity"))
}

/// The download name from `Content-Disposition` (`filename=`) or the URL path: control
/// characters and separators removed, <= 128 chars, never used as a path (F-16).
pub fn download_name(content_disposition: Option<&str>, path: &str) -> String {
    let from_header =
        content_disposition.and_then(|cd| disposition_filenames(cd).next().map(|(_, v)| v));
    let raw = from_header.unwrap_or_else(|| path.rsplit('/').next().unwrap_or("").to_owned());
    let clean: String =
        raw.chars().filter(|c| !c.is_control() && !"/\\:*?\"<>|".contains(*c)).take(128).collect();
    let clean = clean.trim_matches(['.', ' ']).to_owned();
    if clean.is_empty() { "download".into() } else { clean }
}

/// Magic-byte eligibility (P4 list).
pub fn magic(prefix: &[u8]) -> bool {
    const MAGIC: &[&[u8]] = &[
        b"MZ",
        b"\x7fELF",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"PK\x03\x04",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        b"%PDF",
        b"Rar!",
        b"7z\xbc\xaf\x27\x1c",
        b"\x1f\x8b",
        b"#!",
    ];
    MAGIC.iter().any(|m| prefix.starts_with(m))
}

/// SHA-256 hex list with mtime-based hot reload (E-66).
#[derive(Debug, Default)]
struct HashList {
    path: PathBuf,
    state: Mutex<(Option<SystemTime>, HashSet<[u8; 32]>)>,
}

impl HashList {
    fn contains(&self, digest: &[u8; 32]) -> bool {
        if self.path.as_os_str().is_empty() {
            return false;
        }
        let stamp = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.0 != stamp {
            let mut set = HashSet::new();
            if let Ok(text) = std::fs::read_to_string(&self.path) {
                for line in text.lines().map(|l| l.split('#').next().unwrap_or("").trim()) {
                    let mut d = [0u8; 32];
                    if hex::decode_to_slice(line, &mut d).is_ok() {
                        set.insert(d);
                    }
                }
            }
            *s = (stamp, set);
        }
        s.1.contains(digest)
    }
}

/// What eligibility looks at for one 2xx GET response.
#[derive(Debug, Default, Clone, Copy)]
pub struct Download<'a> {
    /// The request path (no query).
    pub path: &'a str,
    /// The response `Content-Type`.
    pub content_type: Option<&'a str>,
    /// Every `Content-Disposition` header value.
    pub dispositions: &'a [String],
    /// Any non-identity `Content-Encoding` ([`content_encoded`]).
    pub encoded: bool,
    /// The first decoded payload bytes (up to 512).
    pub prefix: &'a [u8],
}

/// The scanning service (INTERFACES `ScanPipeline`).
pub struct Scanner {
    /// `[scan]`.
    pub cfg: ScanConfig,
    slots: Arc<Semaphore>,
    used: Arc<AtomicU64>,
    hashes: HashList,
    #[cfg(feature = "yara")]
    yara: Option<yara_x::Rules>,
}

/// Prepare the temp directory: 0700, not a symlink, leftovers from a crash removed (PT-10.6).
pub fn prepare_temp_dir(dir: &Path) -> std::io::Result<()> {
    if let Ok(m) = std::fs::symlink_metadata(dir)
        && !m.is_dir()
    {
        return Err(std::io::Error::other("scan.temp_dir is not a directory (symlinks refused)"));
    }
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    for e in std::fs::read_dir(dir)?.filter_map(Result::ok) {
        if e.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            let _ = std::fs::remove_file(e.path());
        }
    }
    Ok(())
}

impl Scanner {
    /// Build from `[scan]` (temp dir prepared, YARA rules compiled).
    pub fn new(cfg: ScanConfig) -> Result<Self, String> {
        prepare_temp_dir(&cfg.temp_dir).map_err(|e| format!("scan.temp_dir: {e}"))?;
        #[cfg(feature = "yara")]
        let yara = match &cfg.yara {
            Some(y) => Some(compile_yara(&y.rules_dir)?),
            None => None,
        };
        Ok(Self {
            slots: Arc::new(Semaphore::new(cfg.max_concurrent)),
            used: Arc::new(AtomicU64::new(0)),
            hashes: HashList { path: cfg.hash_blocklist.clone(), state: Mutex::default() },
            #[cfg(feature = "yara")]
            yara,
            cfg,
        })
    }

    /// Whether a file name ends with an eligible extension (case-insensitive; trailing dots,
    /// whitespace and control characters ignored, as Windows does).
    fn eligible_name(&self, name: &str) -> bool {
        let name = name
            .trim_end_matches(|c: char| c == '.' || c.is_whitespace() || c.is_control())
            .to_ascii_lowercase();
        self.cfg.extensions.iter().any(|e| {
            let e = e.trim().to_ascii_lowercase();
            e.len() > 1 && name.ends_with(&e)
        })
    }

    /// Eligible by URL or `Content-Disposition` extension, media type, any non-identity
    /// `Content-Encoding` (then unscannable) or magic bytes (P4, review M1).
    pub fn eligible(&self, d: &Download<'_>) -> bool {
        let ext = self.eligible_name(d.path.rsplit('/').next().unwrap_or(""))
            || d.dispositions.iter().flat_map(|cd| disposition_filenames(cd)).any(|(star, v)| {
                self.eligible_name(&v) || (star && self.eligible_name(&percent_decode(&v)))
            });
        let media =
            d.content_type.map(|c| c.split(';').next().unwrap_or("").trim().to_ascii_lowercase());
        let ctype = media
            .as_deref()
            .is_some_and(|m| self.cfg.content_types.iter().any(|c| c.eq_ignore_ascii_case(m)));
        // An encoded body hides its magic bytes: treat it as a download candidate (and so as
        // unscannable) unless it is an ordinary compressed page type (A-47).
        let page = media.as_deref().is_some_and(|m| PAGE_TYPES.contains(&m));
        ext || ctype || (d.encoded && !page) || (self.cfg.magic && magic(d.prefix))
    }

    /// A scan slot with a fresh 0600 temp file, or why not (concurrency queue <= 5 s).
    pub async fn begin(&self) -> Result<Slot, &'static str> {
        let permit = tokio::time::timeout(QUEUE_WAIT, Arc::clone(&self.slots).acquire_owned())
            .await
            .map_err(|_| "scan concurrency exhausted")?
            .map_err(|_| "scanner closed")?;
        let mut name = [0u8; 16];
        getrandom::fill(&mut name).map_err(|_| "no randomness")?;
        let path = self.cfg.temp_dir.join(format!("{TEMP_PREFIX}{}", hex::encode(name)));
        let mut opts = std::fs::OpenOptions::new();
        opts.create_new(true).read(true).write(true); // O_EXCL: never follows a planted symlink
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path).map_err(|_| "cannot create a scan temp file")?;
        Ok(Slot {
            file: Some(file),
            path,
            hasher: Sha256::new(),
            bytes: 0,
            max: self.cfg.max_bytes,
            quota: self.cfg.temp_quota_bytes,
            used: Arc::clone(&self.used),
            reserved: 0,
            stopped: None,
            _permit: permit,
        })
    }

    /// Hash blocklist, then clamd, then YARA, over the stored bytes.
    pub async fn finish(&self, slot: &mut Slot) -> (Verdict, String) {
        let digest: [u8; 32] = std::mem::take(&mut slot.hasher).finalize().into();
        let sha = hex::encode(digest);
        if let Some(why) = slot.stopped {
            return (Verdict::Unscannable(why), sha);
        }
        if let Some(f) = slot.file.as_mut() {
            let _ = f.flush();
        }
        if self.hashes.contains(&digest) {
            return (Verdict::Blocklisted, sha);
        }
        if let Some(c) = &self.cfg.clamd {
            match clamd_scan(c, &slot.path).await {
                Ok(Some(signature)) => {
                    return (Verdict::Infected { engine: "clamav", signature }, sha);
                }
                Ok(None) => {}
                Err(e) if e.contains("size limit") => return (Verdict::Unscannable(e), sha),
                Err(e) => return (Verdict::Unavailable(e), sha),
            }
        }
        #[cfg(feature = "yara")]
        if let (Some(rules), Some(y)) = (&self.yara, &self.cfg.yara) {
            match yara_scan(rules, &slot.path, Duration::from_secs(y.timeout_secs)) {
                Ok(Some(signature)) => {
                    return (Verdict::Infected { engine: "yara", signature }, sha);
                }
                Ok(None) => {}
                Err(e) => return (Verdict::Unavailable(e), sha),
            }
        }
        (Verdict::Clean, sha)
    }
}

/// One download being recorded; the temp file is removed on drop.
pub struct Slot {
    file: Option<std::fs::File>,
    path: PathBuf,
    hasher: Sha256,
    /// Bytes seen (also past the recording cap).
    pub bytes: u64,
    max: u64,
    quota: u64,
    used: Arc<AtomicU64>,
    reserved: u64,
    stopped: Option<&'static str>,
    _permit: OwnedSemaphorePermit,
}

impl Slot {
    /// Record a decoded body chunk. Past `max_bytes` or the temp quota recording stops and the
    /// download becomes unscannable; `Err` tells block mode to stop buffering.
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), &'static str> {
        self.hasher.update(chunk);
        self.bytes = self.bytes.saturating_add(chunk.len() as u64);
        if self.stopped.is_some() {
            return Err("stopped");
        }
        let n = chunk.len() as u64;
        let why = if self.bytes > self.max {
            Some("larger than scan.max_bytes")
        } else if self.used.fetch_add(n, Ordering::Relaxed).saturating_add(n) > self.quota {
            self.used.fetch_sub(n, Ordering::Relaxed);
            Some("scan temp quota exhausted")
        } else {
            self.reserved += n;
            match self.file.as_mut().map(|f| f.write_all(chunk)) {
                Some(Ok(())) => None,
                _ => Some("scan temp file write failed"),
            }
        };
        match why {
            Some(w) => {
                self.stopped = Some(w);
                Err(w)
            }
            None => Ok(()),
        }
    }

    /// Whether recording stopped (oversize/quota).
    pub fn stopped(&self) -> Option<&'static str> {
        self.stopped
    }

    /// Mark unscannable for a reason found by the caller (e.g. timeout).
    pub fn stop(&mut self, why: &'static str) {
        self.stopped.get_or_insert(why);
    }

    /// Stream the stored bytes to `dst` (block mode delivers exactly what was scanned).
    pub async fn deliver<W: AsyncWrite + Unpin>(
        &self,
        dst: &mut W,
        idle: Duration,
    ) -> std::io::Result<u64> {
        let mut f = tokio::fs::File::open(&self.path).await?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = f.read(&mut buf).await?;
            if n == 0 {
                return Ok(total);
            }
            let data = buf.get(..n).unwrap_or(&[]);
            tokio::time::timeout(idle, dst.write_all(data))
                .await
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
            total += n as u64;
        }
    }

    /// The stored bytes in chunks (h2 delivery).
    pub fn chunks(&self) -> std::io::Result<impl Iterator<Item = std::io::Result<Vec<u8>>>> {
        let mut f = std::fs::File::open(&self.path)?;
        Ok(std::iter::from_fn(move || {
            let mut buf = vec![0u8; 16 * 1024];
            match f.read(&mut buf) {
                Ok(0) => None,
                Ok(n) => {
                    buf.truncate(n);
                    Some(Ok(buf))
                }
                Err(e) => Some(Err(e)),
            }
        }))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.file = None;
        self.used.fetch_sub(self.reserved, Ordering::Relaxed);
        let _ = std::fs::remove_file(&self.path);
    }
}

/// clamd `INSTREAM` (R-13): `zINSTREAM\0`, `<u32 BE len><data>` chunks, zero-length end, one reply.
async fn clamd_scan(c: &ClamdConfig, file: &Path) -> Result<Option<String>, &'static str> {
    let limit = Duration::from_secs(c.timeout_secs);
    tokio::time::timeout(limit, async {
        match c.address.split_once(':') {
            #[cfg(unix)]
            Some(("unix", path)) => {
                let s =
                    tokio::net::UnixStream::connect(path).await.map_err(|_| "clamd unreachable")?;
                instream(s, file, c.chunk_bytes).await
            }
            Some(("tcp", addr)) => {
                let s =
                    tokio::net::TcpStream::connect(addr).await.map_err(|_| "clamd unreachable")?;
                instream(s, file, c.chunk_bytes).await
            }
            _ => Err("bad clamd address"),
        }
    })
    .await
    .map_err(|_| "clamd timeout")?
}

async fn instream<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    file: &Path,
    chunk: usize,
) -> Result<Option<String>, &'static str> {
    let io = |_| "clamd I/O error";
    s.write_all(b"zINSTREAM\0").await.map_err(io)?;
    let mut f = std::fs::File::open(file).map_err(|_| "scan temp file vanished")?;
    let mut buf = vec![0u8; chunk];
    loop {
        let n = f.read(&mut buf).map_err(|_| "scan temp file read failed")?;
        let len = u32::try_from(n).map_err(|_| "chunk too large")?;
        s.write_all(&len.to_be_bytes()).await.map_err(io)?;
        if n == 0 {
            break;
        }
        s.write_all(buf.get(..n).unwrap_or(&[])).await.map_err(io)?;
    }
    s.flush().await.map_err(io)?;
    let mut reply = Vec::new();
    let mut tmp = [0u8; 256];
    while reply.len() < MAX_REPLY && !reply.contains(&0) && !reply.contains(&b'\n') {
        let n = s.read(&mut tmp).await.map_err(io)?;
        if n == 0 {
            break;
        }
        reply.extend_from_slice(tmp.get(..n).unwrap_or(&[]));
    }
    parse_clamd_reply(&String::from_utf8_lossy(&reply))
}

#[cfg(feature = "yara")]
fn compile_yara(dir: &Path) -> Result<yara_x::Rules, String> {
    let mut compiler = yara_x::Compiler::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("scan.yara.rules_dir: {e}"))?;
    for e in entries.filter_map(Result::ok) {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "yar" || x == "yara") {
            let src = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            compiler.add_source(src.as_str()).map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    Ok(compiler.build())
}

#[cfg(feature = "yara")]
fn yara_scan(
    rules: &yara_x::Rules,
    file: &Path,
    timeout: Duration,
) -> Result<Option<String>, &'static str> {
    let data = std::fs::read(file).map_err(|_| "scan temp file read failed")?;
    let mut scanner = yara_x::Scanner::new(rules);
    scanner.set_timeout(timeout);
    let results = scanner.scan(&data).map_err(|_| "yara scan failed or timed out")?;
    Ok(results.matching_rules().next().map(|r| sanitize_signature(r.identifier())))
}
