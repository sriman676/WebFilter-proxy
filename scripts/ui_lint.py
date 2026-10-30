#!/usr/bin/env python3
"""Fail on dangerous patterns in the admin UI assets (`just ui-lint`). Python >= 3.10, stdlib only."""
import re, sys, pathlib
root = pathlib.Path(__file__).resolve().parent.parent / "assets" / "admin"
bad = [
    (r"\binnerHTML\b", "innerHTML"), (r"\bouterHTML\b", "outerHTML"), (r"insertAdjacentHTML", "insertAdjacentHTML"),
    (r"document\.write", "document.write"), (r"\beval\s*\(", "eval("), (r"new\s+Function", "new Function"),
    (r"set(Timeout|Interval)\s*\(\s*[\"'`]", "string setTimeout/setInterval"),
    (r"\son[a-z]+\s*=", "inline event handler attribute"), (r"javascript:", "javascript: URL"),
    (r"(src|href)\s*=\s*[\"']https?://", "external resource reference"), (r"<script(?![^>]*\bsrc=)[^>]*>", "inline <script>"),
    (r"\bstyle\s*=\s*[\"']", "inline style attribute"),
]
errs = []
if not root.exists():
    print("UI-LINT SKIP (assets/admin not created yet)"); sys.exit(0)
for f in root.rglob("*"):
    if f.suffix not in (".js", ".html", ".css"): continue
    text = f.read_text(errors="replace")
    for rx, name in bad:
        for m in re.finditer(rx, text):
            errs.append(f"{f.relative_to(root.parent.parent)}:{text[:m.start()].count(chr(10))+1}: {name}")
if errs:
    print("UI-LINT FAIL"); [print(" -", e) for e in errs]; sys.exit(1)
print("UI-LINT PASS")
