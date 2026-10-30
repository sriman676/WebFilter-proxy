# Request-smuggling / framing test corpus (SPEC 4.3). Used by integration tests I-2x and pentest PT-2.x.
All cases are sent as raw bytes over a TCP socket to the PROXY on loopback; the origin is a local
recording server. For every case the origin MUST NOT receive a second (smuggled) request, and the proxy
MUST answer as listed. `\r\n` shown literally. "X" = harmless marker path `/smuggled-marker`.

| ID | Case (headers/body summary) | Expected proxy result |
|---|---|---|
| SM-01 | CL.TE: `Content-Length: 6` + `Transfer-Encoding: chunked`, body `0\r\n\r\nX` | 400 invalid_request (R1); origin sees nothing |
| SM-02 | TE.CL: `Transfer-Encoding: chunked` + `Content-Length: 4`, chunk body containing a second request | 400 (R1) |
| SM-03 | TE.TE obfuscations: `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked` (space before colon), `Transfer-Encoding:\tchunked`, `Transfer-Encoding: chunked, identity`, `Transfer-Encoding: CHUNKED` (allowed!), duplicated TE headers (one bogus) | all invalid forms 400 (R3/R4); `CHUNKED` accepted |
| SM-04 | Two `Content-Length` headers (different values) | 400 (R2) |
| SM-05 | Two identical `Content-Length` headers | 400 (R2) |
| SM-06 | `Content-Length: 5, 5` and `Content-Length: +5`, `Content-Length: 0x5`, `Content-Length: 5 ` variants | 400 (R2) |
| SM-07 | Obsolete line folding: header continued on next line starting with space | 400 (R4) |
| SM-08 | Bare LF line endings (`\n` only), bare CR inside a header value | 400 (R5) |
| SM-09 | NUL byte in header name/value | 400 (R5) |
| SM-10 | `Connection: close, Content-Length` and `Connection: transfer-encoding` | 400 (R8) |
| SM-11 | Two `Host` headers (same / different values); `Host` with trailing space before colon | 400 (R7/R4) |
| SM-12 | Absolute-form `GET http://a.test/` with `Host: b.test` | 400 (R7) |
| SM-13 | `Upgrade: h2c` with `Connection: Upgrade, HTTP2-Settings` | 400 (R10); origin sees nothing |
| SM-14 | Pipelined: two complete requests in one TCP segment, first allowed second blocked | first answered normally, second answered 403; both logged (D-10) |
| SM-15 | Keep-alive: first request to allowed host, second request (same connection) to blocked host | second 403 (D-10) |
| SM-16 | Keep-alive first-request routing: second request's `Host`/authority differs from first | each request filtered and routed by its own target |
| SM-17 | Chunk extension abuse: `5;ext=abc\r\n`, huge chunk-size hex, chunk size overflow (`FFFFFFFFFFFFFFFFF`), missing terminating chunk | extension tolerated only if engine is strict and safe; overflow/missing -> 400 or connection closed; origin never sees leftover bytes as a request |
| SM-18 | Request-line oddities: `GET  http://a.test/  HTTP/1.1` (double spaces), lowercase method, `HTTP/1.2`, `HTTP/0.9` | 400 / 505 as per R5/R6 |
| SM-19 | `Expect: 100-continue` with body sent early; `Expect` with bogus value | no desync: origin receives exactly one request |
| SM-20 | Upstream response splitting: malicious ORIGIN returns two responses in one body, header with CRLF, CL+TE, bad status line | proxy returns 502 or one clean response; client never sees a second response (R-resp rules) |
| SM-21 | Request with body on `GET`/`HEAD`, `Content-Length: 0` with `Transfer-Encoding` | handled per R1/R15; no desync |
| SM-22 | Very slow head (1 byte/s) and slow body | closed by timeouts, other clients unaffected |
| SM-23 | HTTP/1.0 request with `Connection: keep-alive` and with TE | R3 for TE; keep-alive semantics correct |
| SM-24 | Header count 101, header name > 8 KiB, URI 9 KiB, head 70 KiB | 431/414/400 as per R12 |
| SM-25 | CONNECT variants: `CONNECT evil.com:443` with a body, `CONNECT host` (no port), `CONNECT [::1]:443`, `CONNECT user@host:443` | per 4.5/4.3: 400 or policy 403; no tunnel opened on invalid forms |
Maintain this file: every new desync idea found during pentesting is appended here with an ID and
becomes a permanent regression test. Research note (RESEARCH R-01): expect novel variants; the
defense is strict parsing + fuzzing + differential tests, not an exhaustive payload list.
