#!/usr/bin/env python3
"""P0 pentest check: sensitive paths must be git-ignored, tracked source must not be.

Python >= 3.10, standard library only. Uses `git check-ignore`, so it tests the real rules.
"""
import subprocess
import sys
import pathlib

root = pathlib.Path(__file__).resolve().parent.parent

MUST_IGNORE = [
    # keys / certificates / keystores (D-19, CLAUDE.md "never commit keys")
    "ca.key", "config/ca.pem", "tls/leaf.key", "x/client.p12", "x/ca.cer",
    "x/bundle.pfx", "x/ca.der", "x/ca.crt", "x/keystore.jks", "x/leaf.csr", "x/ca.srl",
    "id_ed25519", "id_rsa.pub", "debug.log",
    # secrets / env
    ".env", ".env.local", "config/config.toml", "config/admin.token",
    # runtime data (ENVIRONMENT.md "Directories created at runtime")
    "logs/webfilter.jsonl", "logs/webfilter_system.jsonl", "output/example.com.html",
    "state/temp_allow.json", "feeds/urlhaus.txt", "target/debug/x",
    "fuzz/artifacts/crash-1", "fuzz/target/x", "fuzz/corpus/config_toml/seed",
    "docs/pentest/phase-0/raw/gitleaks.json",
    # coverage artefacts
    "default.profraw", "lcov.info",
]
MUST_TRACK = [
    "Cargo.toml", "Cargo.lock", "config/config.example.toml", "config/demo.toml",
    "logs/.gitkeep", "src/lib.rs", "tests/corpus/url_bypass_cases.tsv",
    "docs/pentest/phase-0/REPORT.md", "fuzz/Cargo.toml", "fuzz/fuzz_targets/config_toml.rs",
]


def ignored(path: str) -> bool:
    r = subprocess.run(["git", "check-ignore", "-q", "--no-index", path], cwd=root)
    return r.returncode == 0


errs = [f"NOT ignored: {p}" for p in MUST_IGNORE if not ignored(p)]
errs += [f"wrongly ignored: {p}" for p in MUST_TRACK if ignored(p)]
if errs:
    print("GITIGNORE-CHECK FAIL")
    for e in errs:
        print(" -", e)
    sys.exit(1)
print(f"GITIGNORE-CHECK PASS ({len(MUST_IGNORE)} ignored, {len(MUST_TRACK)} tracked)")
