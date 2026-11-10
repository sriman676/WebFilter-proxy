#!/usr/bin/env python3
"""Documentation consistency checker (`just docs-check`). Python >= 3.10, stdlib only."""
import re, sys, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
rd = lambda p: (root / p).read_text() if (root / p).exists() else ""
docs = {p.name: p.read_text() for p in list(root.glob("docs/*.md")) + list(root.glob("tests/corpus/*.md")) + [root / "CLAUDE.md"]}
briefs = {p.name: p.read_text() for p in sorted(root.glob("docs/phases/PHASE-*.md"))}
tsv = rd("tests/corpus/url_bypass_cases.tsv")
text = "\n".join(docs.values()) + "\n" + "\n".join(briefs.values()) + "\n" + tsv
errs = []

# 1. IDs defined/referenced
defined = set(m.group(1) for m in re.finditer(r"^\| (D-\d+|PT-\d+\.\d+|E-\d+|T-\d+|R-\d+|G-\d+|SM-\d+) \|", text, re.M))
defined |= set(m.group(1) for m in re.finditer(r"^(U-\d{3})\t", tsv, re.M))
refs = set(re.findall(r"\b(D-\d+|PT-\d+\.\d+|E-\d+|T-\d+|R-\d+|G-\d+|SM-\d+|U-\d{3})\b", text))
missing = sorted(r for r in refs if r not in defined)
if missing: errs.append("Referenced but never defined: " + ", ".join(missing))

# 2. every threat has a test reference
for m in re.finditer(r"^\| (T-\d+) \|(.*)$", docs.get("THREAT_MODEL.md", ""), re.M):
    if not re.search(r"\b(E-\d+|I-[\w-]+|PT-\d+\.\d+|U-[\w-]+|F-\d+|SM-\d+|S-\d+|P-\d+|L-\d+)", m.group(2)):
        errs.append(f"{m.group(1)} has no test/pentest reference")

# 3. docs budgets (D-48)
if len(list(root.glob('docs/*.md'))) > 19: errs.append(f"docs/ holds {len(list(root.glob('docs/*.md')))} files (cap 19, D-48)")
for name, body in docs.items():
    words = len(body.split())
    limit = 700 if name == "CLAUDE.md" else 4500
    if name.endswith(".md") and not name.endswith("_cases.md") and words > limit:
        errs.append(f"{name} has {words} words (budget {limit})")
for name, body in briefs.items():
    if len(body.split()) > 900: errs.append(f"{name} exceeds 900 words")

# 4. every docs/*.md is listed in INDEX; phase briefs exist and PT ranges match PENTEST_PLAN
index = docs.get("INDEX.md", "")
for name in docs:
    if not name.endswith("_cases.md") and name not in ("CLAUDE.md", "INDEX.md") and name not in index:
        errs.append(f"{name} is not listed in docs/INDEX.md")
for n in range(0, 15):
    f = f"PHASE-{n}.md"
    if f not in briefs: errs.append(f"missing phase brief {f}"); continue
    if n:
        mx = max((int(x.split('.')[1]) for x in defined if x.startswith(f"PT-{n}.")), default=0)
        m = re.search(rf"PT-{n}\.1 \.\. PT-{n}\.(\d+)", briefs[f])
        if not m or int(m.group(1)) != mx: errs.append(f"{f}: pentest range does not match PENTEST_PLAN (max PT-{n}.{mx})")

# 5. toolchain pin consistency (D-46)
pin = re.search(r"^RUST_PIN=(\S+)", docs.get("ENVIRONMENT.md", ""), re.M)
if not pin: errs.append("ENVIRONMENT.md lacks RUST_PIN")
else:
    v = pin.group(1)
    checks = {"rust-toolchain.toml": r'channel\s*=\s*"([^"]+)"', "Cargo.toml": r'rust-version\s*=\s*"([^"]+)"', "clippy.toml": r'msrv\s*=\s*"([^"]+)"'}
    for f, rx in checks.items():
        m = re.search(rx, rd(f))
        if not m or m.group(1) != v: errs.append(f"{f} toolchain ({m.group(1) if m else 'missing'}) != RUST_PIN {v}")

# 5b. markdown tables: every row has the header's number of unescaped pipes
for name, body in {**docs, **briefs}.items():
    lines = body.split("\n"); i = 0
    while i < len(lines):
        if lines[i].startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[i + 1]):
            n0 = len(re.findall(r"(?<!\\)\|", lines[i])); j = i + 2
            while j < len(lines) and lines[j].startswith("|"):
                if len(re.findall(r"(?<!\\)\|", lines[j])) != n0: errs.append(f"{name}:{j+1} table row has wrong column count (escape pipes as \\|)")
                j += 1
            i = j
        else: i += 1

# 6. release must keep panic=unwind; edition pinned
cargo = rd("Cargo.toml")
if 'panic = "abort"' in cargo: errs.append('Cargo.toml sets panic = "abort" (breaks panic isolation)')
if 'edition = "2024"' not in cargo: errs.append("Cargo.toml edition is not 2024")

# 7. every E-test is assigned to a phase brief or ACCEPTANCE; test-ID prefixes referenced exist in TEST_PLAN
def expand_e(t):
    ids = set()
    for m in re.finditer(r"E-((?:\d+(?:\.\.(?:E-)?\d+)?)(?:,\d+(?:\.\.\d+)?)*)", t):
        for tok in m.group(1).split(","):
            r = re.match(r"(\d+)\.\.(?:E-)?(\d+)", tok)
            if r: ids |= set(range(int(r.group(1)), int(r.group(2)) + 1))
            elif re.match(r"\d+", tok): ids.add(int(re.match(r"\d+", tok).group(0)))
    return ids
tp = docs.get("TEST_PLAN.md", "")
def_e = {int(m.group(1)) for m in re.finditer(r"^\| E-(\d+) \|", tp, re.M)}
assigned = set()
for t in list(briefs.values()) + [docs.get("ACCEPTANCE.md", "")]: assigned |= expand_e(t)
unassigned = sorted(def_e - assigned)
if unassigned: errs.append("E-tests not assigned to any phase/acceptance step: " + ", ".join(f"E-{n:02d}" for n in unassigned))
for pref in "FLCSPX":
    prefs = set(re.findall(rf"\b{pref}-(\d+)\b", text)); defs = set(re.findall(rf"\b{pref}-(\d+)\b", tp))
    miss = sorted(prefs - defs, key=int)
    if pref == "P": miss = [m for m in miss if m != "256"]
    if miss: errs.append(f"{pref}-xx referenced but not defined in TEST_PLAN: " + ", ".join(miss))

# 8. corpus files named in docs exist; CLAUDE.md just-targets are described in SPEC
for f in sorted(set(re.findall(r"tests/corpus/([\w.]+)", text))):
    if "*" not in f and not (root / "tests/corpus" / f).exists(): errs.append(f"corpus file missing: tests/corpus/{f}")
m = re.search(r"`just ([^`]+)`", docs.get("CLAUDE.md", ""))
spec = docs.get("SPEC.md", "")
if m:
    for tok in [t.strip() for t in m.group(1).split("|")]:
        if tok.startswith("pentest-p") or not tok: continue
        if tok not in spec: errs.append(f"just target '{tok}' (CLAUDE.md) is not described in SPEC section 10")

if errs:
    print("DOCS-CHECK FAIL"); [print(" -", e) for e in errs]; sys.exit(1)
print(f"DOCS-CHECK PASS ({len(defined)} ids defined, {len(refs)} referenced, {len(briefs)} phase briefs, toolchain {pin.group(1)})")
