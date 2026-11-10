//! Small shared helpers (A-31 redundancy cleanup): poison-tolerant locking, wall-clock seconds,
//! media-type extraction and the `[a-z0-9_-]{1,32}` name rule used by config sections.
#![forbid(unsafe_code)]

use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

/// `Mutex::lock` that keeps working after a panicking holder (panic isolation, SPEC 9): the
/// protected data are counters and caches that stay usable.
pub trait LockExt<T> {
    /// Lock, recovering the guard from a poisoned mutex.
    fn lock_or_recover(&self) -> MutexGuard<'_, T>;
}

impl<T> LockExt<T> for Mutex<T> {
    fn lock_or_recover(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Seconds since the Unix epoch (0 if the clock is before it).
pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The media type of a `Content-Type` value: parameters dropped, trimmed, case kept.
///
/// ```
/// assert_eq!(webfilter::util::media_type(" Text/HTML ; charset=utf-8"), "Text/HTML");
/// ```
pub fn media_type(content_type: &str) -> &str {
    content_type.split(';').next().unwrap_or("").trim()
}

/// A response `Content-Type` that browsers could read differently than the proxy (review 2 M2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("ambiguous Content-Type")]
pub struct AmbiguousContentType;

/// The one unambiguous `Content-Type` of a response (D-08): more than one header, or a value
/// that is a comma-separated list (a comma outside a quoted string), is rejected, because
/// browsers use the last valid entry while a rule would see another one.
///
/// ```
/// use webfilter::util::content_type;
/// let one: [&[u8]; 1] = [b"text/html; charset=\"a,b\""];
/// assert_eq!(content_type(one).unwrap().as_deref(), Some("text/html; charset=\"a,b\""));
/// assert!(content_type([&b"text/plain, application/x-msdownload"[..]]).is_err());
/// assert!(content_type([&b"text/plain"[..], &b"text/plain"[..]]).is_err());
/// assert_eq!(content_type(std::iter::empty::<&[u8]>()), Ok(None));
/// ```
pub fn content_type<'a, I>(values: I) -> Result<Option<String>, AmbiguousContentType>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut it = values.into_iter();
    let Some(first) = it.next() else { return Ok(None) };
    if it.next().is_some() {
        return Err(AmbiguousContentType);
    }
    let (mut quoted, mut escaped) = (false, false);
    for &b in first {
        match b {
            _ if escaped => escaped = false,
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            b',' if !quoted => return Err(AmbiguousContentType),
            _ => {}
        }
    }
    Ok(Some(String::from_utf8_lossy(first).into_owned()))
}

/// Names of profiles, feeds, categories and plugins: `[a-z0-9_-]{1,32}`.
pub fn valid_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_lock_recovery() {
        assert!(
            valid_name("kids_2-x")
                && !valid_name("")
                && !valid_name("Kids")
                && !valid_name(&"a".repeat(33))
        );
        let m = std::sync::Arc::new(Mutex::new(1));
        let m2 = std::sync::Arc::clone(&m);
        let _ = std::thread::spawn(move || {
            let _g = m2.lock_or_recover();
            panic!("poison");
        })
        .join();
        assert!(m.is_poisoned());
        assert_eq!(*m.lock_or_recover(), 1);
    }
}
