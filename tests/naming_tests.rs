//! U-fn-*, P-02, PT-1.8: `tests/corpus/filename_cases.tsv`, collisions, safe writes.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use proptest::prelude::*;
use regex::Regex;
use webfilter::naming::{output_filename, write_unique};

fn invariant() -> Regex {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.html$").unwrap()
}

fn assert_invariant(name: &str) {
    assert!(invariant().is_match(name), "{name:?} breaks the invariant regex");
    assert!(!name.contains(".."), "{name:?} contains ..");
    let reserved = |p: &str| {
        let p = p.to_ascii_uppercase();
        matches!(p.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (p.len() == 4
                && (p.starts_with("COM") || p.starts_with("LPT"))
                && p.as_bytes()[3].is_ascii_digit()
                && p.as_bytes()[3] != b'0')
    };
    assert!(
        !name.trim_end_matches(".html").split('.').any(reserved),
        "{name:?} has a reserved part"
    );
}

#[test]
fn filename_corpus_matches_exactly() {
    let text = std::fs::read_to_string(common::repo_root().join("tests/corpus/filename_cases.tsv"))
        .unwrap();
    let mut n = 0;
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let (input, expected) = line.split_once('\t').unwrap();
        let got = output_filename(input);
        assert_eq!(got, expected, "input {input:?}");
        assert_invariant(&got);
        n += 1;
    }
    assert!(n >= 27, "corpus has {n} cases");
}

#[test]
fn reserved_names_on_every_part() {
    for host in ["com1.example", "lpt9.example", "aux.example", "x.prn.example"] {
        let name = output_filename(&format!("https://{host}/"));
        assert!(name.starts_with("r_"), "{host} -> {name}");
    }
    assert!(!output_filename("https://com0.example/").starts_with("r_"));
}

#[test]
fn write_unique_never_overwrites_and_suffixes() {
    let dir = tempfile::tempdir().unwrap();
    let a = write_unique(dir.path(), "x.html", &b"one"[..], 100).unwrap();
    let b = write_unique(dir.path(), "x.html", &b"two"[..], 100).unwrap();
    let c = write_unique(dir.path(), "x.html", &b"three"[..], 100).unwrap();
    assert_eq!(a.file_name().unwrap(), "x.html");
    assert_eq!(b.file_name().unwrap(), "x-1.html");
    assert_eq!(c.file_name().unwrap(), "x-2.html");
    assert_eq!(std::fs::read(&a).unwrap(), b"one");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
        .collect();
    assert!(leftovers.is_empty(), "temp files removed");
}

#[test]
fn write_unique_enforces_max_bytes_and_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let err = write_unique(dir.path(), "big.html", &[0u8; 101][..], 100).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::FileTooLarge);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "no final file and no temp file");
    assert!(
        write_unique(dir.path(), "ok.html", &[0u8; 100][..], 100).is_ok(),
        "exactly max is allowed"
    );
}

#[cfg(unix)]
#[test]
fn write_unique_does_not_follow_symlink_at_final_component() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim.txt");
    std::fs::write(&victim, "original").unwrap();
    std::os::unix::fs::symlink(&victim, dir.path().join("x.html")).unwrap();
    let written = write_unique(dir.path(), "x.html", &b"attacker"[..], 100).unwrap();
    assert_eq!(written.file_name().unwrap(), "x-1.html");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "original", "symlink target untouched");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// P-02: the invariant holds for arbitrary hosts, paths and queries.
    #[test]
    fn p02_invariant_always_holds(host in "[a-z0-9]{1,20}(\\.[a-z0-9]{1,20}){0,3}",
                                  path in "(/[^/?#]{0,40}){0,8}",
                                  query in proptest::option::of("[^#]{0,60}")) {
        let raw = format!("https://{host}{path}{}", query.map(|q| format!("?{q}")).unwrap_or_default());
        assert_invariant(&output_filename(&raw));
    }
}
