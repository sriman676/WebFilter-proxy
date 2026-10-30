# Extension Spec C: Client Enhancements (Phase 12)

Base client: SPEC.md section 5 (still authoritative for naming, exit codes, TLS, redirects). Decisions: D-60..D-62.

## C1. New options
| Option | Default | Notes |
|---|---|---|
| `--input-file <path>` (`-` = stdin) | none | one URL per line, `#` comments, UTF-8, <= 100,000 lines and 1 MiB per line cap; duplicates removed; combined with CLI URLs |
| `--retries <n>` | 2 | transient failures only (see C2); max 10 |
| `--retry-max-delay <s>` | 60 | cap for backoff and `Retry-After` |
| `--manifest <path>` | none | JSONL record of every result; enables batch resume |
| `--resume` | off | skip URLs already completed in the manifest (file must still exist with the recorded size/SHA-256) |
| `--resume-partial` | off | continue `.part` files with `Range` + `If-Range` (ETag/Last-Modified) |
| `--snapshot` | off | save page plus assets for offline viewing (C3) |
| `--snapshot-allow-scripts` | off | keep scripts (NOT recommended) |
| `--crawl-depth <n>` | 0 | 0 = off, max 5 (C4) |
| `--max-pages <n>` | 50 | max 1,000 |
| `--crawl-subdomains` | off | include subdomains of the start host |
| `--crawl-delay-ms <n>` | 250 | per-host minimum delay; floor 250 |

## C2. Retries, manifest, resume
Retry only idempotent GETs on: connect/read timeouts, connection reset, 408, 429, 502, 503, 504 (honor `Retry-After`, integer seconds or
HTTP date, capped by `--retry-max-delay`; invalid/negative values ignored). Backoff: base 500 ms x 2^n with full jitter. NEVER retry:
BLOCKED (proxy 403 with `X-WebFilter-Action: blocked`), TLS verification errors, usage errors, 4xx other than 408/429, size-limit errors.
Manifest: JSONL lines `{"url","status","bytes","sha256","saved_path","blocked","error","finished_at"}` appended atomically (single write per
line, fsync at end); a lock file `<manifest>.lock` prevents concurrent runs (stale lock detection by pid). `--resume` re-verifies each
recorded file (exists, size, SHA-256) and refetches mismatches. Paths in the manifest are never trusted: they must resolve inside the
canonical `--out-dir`. `--resume-partial` validates `206` + `Content-Range` start/total against the `.part` size; any mismatch discards
the partial file and restarts.

## C3. Snapshot
Process: fetch the page (normal rules), parse with `lol_html`, plan assets from `img[src|srcset]`, `link[rel=stylesheet|icon][href]`,
`source[src|srcset]`, `video[poster]`, `script[src]` (only with `--snapshot-allow-scripts`), CSS `url()` and `@import` (depth <= 2).
- Scope: same site only (same host and port, scheme-insensitive); `--snapshot-extra-host <h>` repeatable to allow CDNs explicitly.
- Caps: 200 assets/page, 10 MiB/asset, 100 MiB/page total; `data:` URIs left as is if <= 256 KiB else dropped.
- Allowed asset types by response media type: `image/*`, `text/css`, `font/*`, `application/font-*`; others skipped and reported. SVG is saved but
  only referenced via `<img>`/CSS; it is never inlined.
- Names: `<page-stem>_files/<hash8>_<sanitized-basename>.<ext>` with ext derived from media type (not from the server's name); same sanitizer rules
  as SPEC 5.3 steps 7-9; dedupe by URL; no overwrite.
- Sanitization (default): remove `<script>`, inline `on*` attributes, `<base>`, `<meta http-equiv=refresh>`, `<object>`, `<embed>`, `<iframe>`
  (replaced by a placeholder), `javascript:` and non-image `data:` URLs; inject a restrictive CSP meta (no scripts, no network; scheme sources `file:`/`data:` rather than `'self'`, because `'self'` is unreliable for `file://` pages; verify in Chromium and Firefox that local images/CSS still load and adjust within the same restrictions); all rewritten references are relative paths inside `_files/`.
- Failures: blocked/oversize/failed assets are omitted (attribute removed) and listed in `<page-stem>_snapshot_report.json`
  (url, reason, event_id). Everything flows through the proxy, so filters, limits and 429s apply; 429 triggers backoff.

## C4. Crawl
Start URL(s) -> BFS to `--crawl-depth`, pages <= `--max-pages`. Same host (or subdomains with the flag); redirects to another site are not followed.
- `robots.txt` is fetched per host through the proxy and ALWAYS respected (Allow/Disallow with wildcards and `$`, `Crawl-delay` as a minimum
  delay); robots fetch failure: 4xx = allow, 5xx/timeouts = disallow for that run (RFC 9309).
- Links from `a[href]` only; normalized with the SPEC 4.5 canonicalizer; fragments removed; http/https only; duplicates and already-saved
  pages skipped.
- Trap protection: <= 5 query-variants per path, path depth <= 10, frontier <= 100,000 URLs, only `text/html` saved as pages (others skipped),
  total crawl time cap `--crawl-timeout` (default 600 s).
- Output: `<out-dir>/<host>_crawl/` with each page named by SPEC 5.3 and internal links rewritten to local files; generated `index.html`
  listing pages (all text escaped). `--snapshot` composes with crawl (assets per page).
- Politeness: >= 250 ms between requests to a host regardless of `--jobs`.

## C5. Output and exit codes
Existing exit codes unchanged. Additional summary line per run (`pages`, `assets`, `blocked`, `skipped`, `retries`). `--json` gains `attempts`,
`snapshot_report`, `crawl_depth`. A crawl or batch with some failures exits 1; with only blocked items exits 3.
