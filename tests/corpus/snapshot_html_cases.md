# Snapshot sanitizer corpus (SPEC_EXT_CLIENT C3). Used by unit tests, E-80, PT-12.4, F-19/F-20. Base URL: https://site.example/dir/page.html
| ID | Input fragment | Expected output property |
|---|---|---|
| SH-01 | `<script>alert(1)</script>` | element removed |
| SH-02 | `<img src="a.png" onerror="alert(1)">` | handler removed; image kept and rewritten to a local relative path |
| SH-03 | `<base href="http://evil.example/">` | removed |
| SH-04 | `<meta http-equiv="refresh" content="0;url=http://evil.example/">` | removed |
| SH-05 | `<a href="javascript:alert(1)">x</a>` | href removed |
| SH-06 | `<iframe src="http://evil.example/"></iframe>` | replaced by a placeholder, no network reference |
| SH-07 | `<link rel="stylesheet" href="//other.example/a.css">` | cross-site asset omitted and listed in the report |
| SH-08 | `<img srcset="a.png 1x, b.png 2x">` | both candidates planned (same site), rewritten |
| SH-09 | 100,000 `<img src="/i/N.png">` elements | at most 200 assets planned; rest omitted and reported; no panic |
| SH-10 | `<img src="../../../../etc/passwd">` | resolved against the base URL as a same-site URL; local name safe; no traversal |
| SH-11 | CSS `@import url(http://evil.example/x.css);` | dropped (cross-site) |
| SH-12 | CSS `background:url(data:image/png;base64,AAAA)` (small) | kept |
| SH-13 | CSS `width:expression(alert(1))` or `behavior:url(x.htc)` | declaration removed |
| SH-14 | `<svg><script>alert(1)</script></svg>` inline | script removed |
| SH-15 | `<object data="x.swf"></object>` and `<embed src="x.swf">` | removed |
| SH-16 | `<form action="http://evil.example/post">` | action removed |
| SH-17 | unclosed and mis-nested tags | output produced, no panic |
| SH-18 | attribute value of 1 MB | attribute dropped, no panic |
| SH-19 | `<style>@import "a.css";</style>` | processed like linked CSS (depth counted) |
| SH-20 | any document | exactly one CSP meta at the start of head; no absolute external references remain |
| SH-21 | CSS import loop a.css imports b.css imports a.css | stops at depth 2, reported |
| SH-22 | asset served as `text/html` but referenced by `<img>` | skipped (media type not allowed), reported |
