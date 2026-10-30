//! Shared integration-test harness (TEST_PLAN harness). Grows per phase: test origins,
//! test PKI, injected resolver, proxy start on port 0.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// A temporary lab directory holding a config file and empty blocklists.
pub struct Lab {
    pub dir: tempfile::TempDir,
}

impl Lab {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let lists = dir.path().join("blocklists");
        std::fs::create_dir(&lists).unwrap();
        for f in ["domains.txt", "url_patterns.txt", "ip_blocklist.txt"] {
            std::fs::write(lists.join(f), "").unwrap();
        }
        Self { dir }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Write `config.toml` into the lab and return its path.
    pub fn write_config(&self, body: &str) -> PathBuf {
        let p = self.path().join("config.toml");
        std::fs::write(&p, body).unwrap();
        p
    }
}

/// Repository root (for shipped config files).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
