//! First-party HTTP/1.1 core (D-05, SPEC 4.3, 4.4, 4.15). Pure, panic-free, fuzzed (F-04/08/09).
//!
//! Heads are parsed by our strict line parser AND by `httparse`; we accept a head only when both
//! agree (method, target, version, every header), so our accepted set is a subset of httparse's.
//! Body framing comes from one function shared by requests and responses.
#![forbid(unsafe_code)]

use crate::config::LimitsConfig;

/// Maximum hex digits in a chunk size (16 = u64 range, checked for overflow).
pub const MAX_CHUNK_SIZE_DIGITS: usize = 16;
/// Maximum chunk-size line including extensions (compat mode).
pub const MAX_CHUNK_SIZE_LINE: usize = 1024;
/// Maximum total size of chunked trailers (dropped, but validated).
pub const MAX_TRAILER_BYTES: usize = 8192;

/// HTTP version on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
}

impl HttpVersion {
    /// `1.0` / `1.1` (log `http_version`).
    pub fn as_str(self) -> &'static str {
        match self {
            HttpVersion::Http10 => "1.0",
            HttpVersion::Http11 => "1.1",
        }
    }
}

/// Header list: lowercase names, raw values with surrounding whitespace trimmed.
pub type Headers = Vec<(String, Vec<u8>)>;

/// All values of header `name` (lowercase).
pub fn values<'a>(headers: &'a Headers, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
    headers.iter().filter(move |(n, _)| n == name).map(|(_, v)| v.as_slice())
}

/// The single value of header `name`, if present exactly once.
pub fn single<'a>(headers: &'a Headers, name: &'a str) -> Option<&'a [u8]> {
    let mut it = values(headers, name);
    let first = it.next()?;
    it.next().is_none().then_some(first)
}

/// Comma-separated tokens of all `name` headers, trimmed and lowercased.
pub fn tokens(headers: &Headers, name: &str) -> Vec<String> {
    values(headers, name)
        .flat_map(|v| v.split(|b| *b == b','))
        .map(|t| String::from_utf8_lossy(t).trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// A parsed request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// Method (uppercase token).
    pub method: String,
    /// Raw request-target (canonicalized later, SPEC 4.5).
    pub target: String,
    /// Version.
    pub version: HttpVersion,
    /// Headers.
    pub headers: Headers,
}

/// A parsed response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    /// Status code.
    pub status: u16,
    /// Reason phrase (may be empty).
    pub reason: String,
    /// Version.
    pub version: HttpVersion,
    /// Headers.
    pub headers: Headers,
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body.
    None,
    /// Exactly this many bytes.
    ContentLength(u64),
    /// Chunked (decoded and re-encoded, never copied raw).
    Chunked,
    /// Until EOF (responses only); the client connection is closed afterwards (D-37).
    CloseDelimited,
}

/// Head or framing error. On the request side these map to client errors; on the response
/// side every error is a 502 `upstream_error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HeadError {
    /// More bytes are needed.
    #[error("incomplete head")]
    Incomplete,
    /// Head larger than the limit or too many headers (431).
    #[error("request head too large")]
    TooLarge,
    /// Request-target longer than the limit (414).
    #[error("request-target too long")]
    UriTooLong,
    /// Malformed or ambiguous (400).
    #[error("invalid HTTP message: {0}")]
    Invalid(&'static str),
    /// Not HTTP/1.0 or HTTP/1.1 (505).
    #[error("unsupported HTTP version")]
    Version,
    /// `TRACE` (405).
    #[error("method not allowed")]
    MethodNotAllowed,
}

impl HeadError {
    /// Status code for a request-side error.
    pub fn status(self) -> u16 {
        match self {
            HeadError::Incomplete | HeadError::Invalid(_) => 400,
            HeadError::TooLarge => 431,
            HeadError::UriTooLong => 414,
            HeadError::Version => 505,
            HeadError::MethodNotAllowed => 405,
        }
    }
}

use HeadError::Invalid;

/// Head size/count limits (SPEC 4.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Request line + headers, bytes.
    pub max_head_bytes: usize,
    /// Header count.
    pub max_headers: usize,
    /// Request-target bytes.
    pub max_uri_bytes: usize,
    /// `[http] compat` (A-25): accept lowercase methods (normalized to uppercase).
    pub compat: bool,
}

impl Limits {
    /// Limits from `[limits]`; `compat` from `[http] compat`.
    pub fn new(c: &LimitsConfig, compat: bool) -> Self {
        Self {
            max_head_bytes: c.max_head_bytes,
            max_headers: c.max_headers,
            max_uri_bytes: c.max_uri_bytes,
            compat,
        }
    }
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Field values: HTAB, SP, VCHAR, obs-text; no CTL (R5).
fn valid_value(v: &[u8]) -> bool {
    v.iter().all(|&b| b == b'\t' || (b' '..=b'~').contains(&b) || b >= 0x80)
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

/// Length of the head including the final CRLFCRLF. Rejects bare CR/LF as soon as seen (R5).
pub fn find_head_end(buf: &[u8], max_head_bytes: usize) -> Result<usize, HeadError> {
    let window = buf.get(..buf.len().min(max_head_bytes)).unwrap_or(buf);
    for (i, &b) in window.iter().enumerate() {
        match b {
            b'\n' => {
                if i == 0 || window.get(i - 1) != Some(&b'\r') {
                    return Err(Invalid("bare LF"));
                }
                if i >= 3 && window.get(i - 3..=i) == Some(b"\r\n\r\n".as_slice()) {
                    return Ok(i + 1);
                }
            }
            b'\r' if window.get(i + 1).is_some_and(|n| *n != b'\n') => {
                return Err(Invalid("bare CR"));
            }
            _ => {}
        }
    }
    if buf.len() >= max_head_bytes { Err(HeadError::TooLarge) } else { Err(HeadError::Incomplete) }
}

/// Split a complete head (ending CRLFCRLF) into its start line and header lines.
fn lines(head: &[u8]) -> (&[u8], impl Iterator<Item = &[u8]>) {
    let body = head.strip_suffix(b"\r\n\r\n").unwrap_or(head);
    let mut it = body.split(|b| *b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let first = it.next().unwrap_or(b"");
    (first, it)
}

fn parse_headers<'a>(
    lines: impl Iterator<Item = &'a [u8]>,
    max: usize,
) -> Result<Headers, HeadError> {
    let mut headers = Headers::new();
    for line in lines {
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            return Err(Invalid("obsolete line folding"));
        }
        let colon = line.iter().position(|b| *b == b':').ok_or(Invalid("header without colon"))?;
        let (name, rest) = line.split_at(colon);
        if name.is_empty() || !name.iter().all(|b| is_tchar(*b)) {
            return Err(Invalid("invalid header name")); // includes whitespace before ':' (R4)
        }
        let value = trim_ows(rest.get(1..).unwrap_or(b""));
        if !valid_value(value) {
            return Err(Invalid("control character in header value"));
        }
        if headers.len() >= max {
            return Err(HeadError::TooLarge);
        }
        headers.push((String::from_utf8_lossy(name).to_ascii_lowercase(), value.to_vec()));
    }
    Ok(headers)
}

fn parse_version(v: &[u8]) -> Result<HttpVersion, HeadError> {
    match v {
        b"HTTP/1.1" => Ok(HttpVersion::Http11),
        b"HTTP/1.0" => Ok(HttpVersion::Http10),
        [b'H', b'T', b'T', b'P', b'/', major, b'.', minor]
            if major.is_ascii_digit() && minor.is_ascii_digit() =>
        {
            Err(HeadError::Version)
        }
        _ => Err(Invalid("malformed HTTP version")),
    }
}

/// Our headers must equal httparse's exactly (names case-insensitive, values trimmed).
fn same_headers(ours: &Headers, theirs: &[httparse::Header<'_>]) -> bool {
    ours.len() == theirs.len()
        && ours
            .iter()
            .zip(theirs)
            .all(|((n, v), h)| n.eq_ignore_ascii_case(h.name) && v.as_slice() == trim_ows(h.value))
}

/// Parse a request head from the start of `buf`; returns the head and bytes consumed
/// (pipelined bytes after it are left alone).
pub fn parse_request_head(buf: &[u8], limits: &Limits) -> Result<(RequestHead, usize), HeadError> {
    let end = find_head_end(buf, limits.max_head_bytes)?;
    let head = buf.get(..end).ok_or(HeadError::Incomplete)?;
    let (line, header_lines) = lines(head);
    let mut parts = line.split(|b| *b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Invalid("malformed request line"));
    };
    if target.len() > limits.max_uri_bytes {
        return Err(HeadError::UriTooLong);
    }
    let letter = |b: &u8| b.is_ascii_uppercase() || (limits.compat && b.is_ascii_lowercase());
    if method.is_empty() || !method.iter().all(letter) {
        return Err(Invalid("invalid method")); // uppercase letters only (A-25)
    }
    if target.is_empty() || !target.iter().all(|b| (b'!'..=b'~').contains(b)) {
        return Err(Invalid("invalid request-target"));
    }
    let version = parse_version(version)?;
    let headers = parse_headers(header_lines, limits.max_headers)?;

    // Differential check against httparse (SPEC 4.15).
    let mut slots = vec![httparse::EMPTY_HEADER; limits.max_headers.max(1)];
    let mut req = httparse::Request::new(&mut slots);
    let agrees = matches!(req.parse(head), Ok(httparse::Status::Complete(n)) if n == end)
        && req.method.map(str::as_bytes) == Some(method)
        && req.path.map(str::as_bytes) == Some(target)
        && req.version == Some(u8::from(version == HttpVersion::Http11))
        && same_headers(&headers, req.headers);
    if !agrees {
        return Err(Invalid("parser differential"));
    }
    let head = RequestHead {
        method: String::from_utf8_lossy(method).to_ascii_uppercase(),
        target: String::from_utf8_lossy(target).into_owned(),
        version,
        headers,
    };
    Ok((head, end))
}

/// Parse a response head; any error means 502 `upstream_error`.
pub fn parse_response_head(
    buf: &[u8],
    limits: &Limits,
) -> Result<(ResponseHead, usize), HeadError> {
    let end = find_head_end(buf, limits.max_head_bytes)?;
    let head = buf.get(..end).ok_or(HeadError::Incomplete)?;
    let (line, header_lines) = lines(head);
    let (version, rest) = line.split_at(line.len().min(8));
    let version = parse_version(version)?;
    let (code, reason) = match rest {
        [b' ', a, b, c] => ([*a, *b, *c], &b""[..]),
        [b' ', a, b, c, b' ', reason @ ..] => ([*a, *b, *c], reason),
        _ => return Err(Invalid("malformed status line")),
    };
    if !code.iter().all(u8::is_ascii_digit) || !valid_value(reason) {
        return Err(Invalid("malformed status line"));
    }
    let status = code.iter().fold(0u16, |acc, d| acc * 10 + u16::from(d - b'0'));
    if !(100..=599).contains(&status) {
        return Err(Invalid("status code out of range"));
    }
    let headers = parse_headers(header_lines, limits.max_headers)?;

    let mut slots = vec![httparse::EMPTY_HEADER; limits.max_headers.max(1)];
    let mut resp = httparse::Response::new(&mut slots);
    let agrees = matches!(resp.parse(head), Ok(httparse::Status::Complete(n)) if n == end)
        && resp.code == Some(status)
        && resp.version == Some(u8::from(version == HttpVersion::Http11))
        && same_headers(&headers, resp.headers);
    if !agrees {
        return Err(Invalid("parser differential"));
    }
    Ok((
        ResponseHead {
            status,
            reason: String::from_utf8_lossy(reason).into_owned(),
            version,
            headers,
        },
        end,
    ))
}

fn parse_content_length(v: &[u8]) -> Result<u64, HeadError> {
    if v.is_empty() || v.len() > 19 || !v.iter().all(u8::is_ascii_digit) {
        return Err(Invalid("invalid Content-Length"));
    }
    let n = v.iter().fold(0u64, |acc, d| acc * 10 + u64::from(d - b'0'));
    if n > i64::MAX as u64 { Err(Invalid("Content-Length too large")) } else { Ok(n) }
}

/// The one framing function for both directions (SPEC 4.15 (3)); `response` is
/// `Some((status, request_method))` for responses.
fn body_framing(
    headers: &Headers,
    version: HttpVersion,
    response: Option<(u16, &str)>,
) -> Result<BodyFraming, HeadError> {
    if let Some((status, method)) = response
        && (method == "HEAD" || (100..200).contains(&status) || status == 204 || status == 304)
    {
        return Ok(BodyFraming::None);
    }
    let cls: Vec<&[u8]> = values(headers, "content-length").collect();
    let tes: Vec<&[u8]> = values(headers, "transfer-encoding").collect();
    match (cls.as_slice(), tes.as_slice()) {
        ([], []) => {
            Ok(if response.is_some() { BodyFraming::CloseDelimited } else { BodyFraming::None })
        }
        ([cl], []) => Ok(BodyFraming::ContentLength(parse_content_length(cl)?)),
        ([], [_]) if version == HttpVersion::Http10 && response.is_none() => {
            Err(Invalid("Transfer-Encoding on HTTP/1.0"))
        }
        ([], [te]) if te.eq_ignore_ascii_case(b"chunked") => Ok(BodyFraming::Chunked),
        ([], [_]) => Err(Invalid("Transfer-Encoding must be exactly chunked")),
        ([_, _, ..], _) => Err(Invalid("multiple Content-Length")),
        (_, [_, _, ..]) => Err(Invalid("multiple Transfer-Encoding")),
        ([_], [_]) => Err(Invalid("Content-Length with Transfer-Encoding")),
    }
}

/// Request body framing (R1-R3).
pub fn request_framing(h: &RequestHead) -> Result<BodyFraming, HeadError> {
    body_framing(&h.headers, h.version, None)
}

/// Response body framing; `HEAD`, 1xx, 204 and 304 never have a body.
pub fn response_framing(h: &ResponseHead, req_method: &str) -> Result<BodyFraming, HeadError> {
    body_framing(&h.headers, h.version, Some((h.status, req_method)))
}

/// Request rules beyond the head grammar: R7 (one Host), R8, R10, R14, plus framing.
pub fn validate_request(h: &RequestHead) -> Result<BodyFraming, HeadError> {
    if h.method == "TRACE" {
        return Err(HeadError::MethodNotAllowed);
    }
    if values(&h.headers, "host").count() > 1 {
        return Err(Invalid("multiple Host headers"));
    }
    let connection = tokens(&h.headers, "connection");
    if connection
        .iter()
        .any(|t| matches!(t.as_str(), "content-length" | "transfer-encoding" | "host"))
    {
        return Err(Invalid("Connection lists a framing header"));
    }
    if values(&h.headers, "upgrade").next().is_some() && !is_websocket_upgrade(h) {
        return Err(Invalid("unsupported Upgrade"));
    }
    let framing = request_framing(h)?;
    if h.method == "CONNECT"
        && !matches!(framing, BodyFraming::None | BodyFraming::ContentLength(0))
    {
        return Err(Invalid("CONNECT with a body"));
    }
    Ok(framing)
}

/// `Upgrade: websocket` with `Connection: upgrade` (R10).
pub fn is_websocket_upgrade(h: &RequestHead) -> bool {
    single(&h.headers, "upgrade").is_some_and(|u| u.eq_ignore_ascii_case(b"websocket"))
        && tokens(&h.headers, "connection").iter().any(|t| t == "upgrade")
}

/// Strip hop-by-hop and proxy headers (SPEC 4.4) and the framing headers, which are regenerated.
/// `keep_upgrade` keeps a validated websocket `Upgrade`.
pub fn forward_headers(headers: &Headers, keep_upgrade: bool) -> Headers {
    let named: Vec<String> = tokens(headers, "connection");
    headers
        .iter()
        .filter(|(n, v)| {
            let hop = matches!(
                n.as_str(),
                "connection"
                    | "keep-alive"
                    | "trailer"
                    | "transfer-encoding"
                    | "content-length"
                    | "host"
            ) || n.starts_with("proxy-")
                || n.starts_with("x-webfilter-") // only the proxy itself may set these (PF-3-01)
                || (n == "te" && !v.eq_ignore_ascii_case(b"trailers"))
                || (n == "upgrade" && !keep_upgrade)
                || (named.iter().any(|t| t == n) && !(keep_upgrade && n == "upgrade"));
            !hop
        })
        .cloned()
        .collect()
}

/// Serialize a head: start line, headers, then the framing header for `framing`.
pub fn write_head(start_line: &str, headers: &Headers, framing: BodyFraming, out: &mut Vec<u8>) {
    out.extend_from_slice(start_line.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (n, v) in headers {
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    match framing {
        BodyFraming::ContentLength(n) => {
            out.extend_from_slice(format!("content-length: {n}\r\n").as_bytes())
        }
        BodyFraming::Chunked => out.extend_from_slice(b"transfer-encoding: chunked\r\n"),
        BodyFraming::None | BodyFraming::CloseDelimited => {}
    }
    out.extend_from_slice(b"\r\n");
}

// ---------------------------------------------------------------------------------------------
// Chunked codec

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChunkState {
    Size(Vec<u8>),
    Data(u64),
    DataCr,
    DataLf,
    Trailer { line: Vec<u8>, total: usize },
    Done,
}

/// Incremental chunked-body decoder. Extensions are rejected, or validated and stripped in
/// compat mode (A-25); trailers are validated and dropped. Output is raw body bytes, to be
/// re-encoded with [`encode_chunk`] (R15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkedDecoder {
    state: ChunkState,
    compat: bool,
}

impl Default for ChunkedDecoder {
    fn default() -> Self {
        Self::new(false)
    }
}

impl ChunkedDecoder {
    /// A decoder; `compat` tolerates (and strips) chunk extensions.
    pub fn new(compat: bool) -> Self {
        Self { state: ChunkState::Size(Vec::new()), compat }
    }

    /// The terminating chunk and trailers have been read.
    pub fn is_done(&self) -> bool {
        self.state == ChunkState::Done
    }

    /// Decode as much of `input` as possible into `out`; returns bytes consumed. Bytes after the
    /// end of the body are not consumed (they belong to the next message).
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<usize, HeadError> {
        let mut i = 0;
        while i < input.len() && !self.is_done() {
            let Some(&b) = input.get(i) else { break };
            match &mut self.state {
                ChunkState::Size(buf) => {
                    i += 1;
                    match b {
                        b'\r' => {}
                        b'\n' => {
                            let digits =
                                buf.strip_suffix(b"\r").ok_or(Invalid("bare LF in chunk size"))?;
                            let size = parse_chunk_size(digits, self.compat)?;
                            self.state = if size == 0 {
                                ChunkState::Trailer { line: Vec::new(), total: 0 }
                            } else {
                                ChunkState::Data(size)
                            };
                            continue;
                        }
                        _ if buf.last() == Some(&b'\r') => {
                            return Err(Invalid("bare CR in chunk size"));
                        }
                        _ if buf.len() >= MAX_CHUNK_SIZE_LINE
                            || (!self.compat && buf.len() >= MAX_CHUNK_SIZE_DIGITS) =>
                        {
                            return Err(Invalid("chunk size line too long"));
                        }
                        _ => {}
                    }
                    buf.push(b);
                }
                ChunkState::Data(remaining) => {
                    let avail = input.len() - i;
                    let take = usize::try_from(*remaining).map_or(avail, |r| r.min(avail));
                    out.extend_from_slice(input.get(i..i + take).unwrap_or(&[]));
                    i += take;
                    *remaining -= take as u64;
                    if *remaining == 0 {
                        self.state = ChunkState::DataCr;
                    }
                }
                ChunkState::DataCr => {
                    i += 1;
                    if b != b'\r' {
                        return Err(Invalid("chunk data longer than its size"));
                    }
                    self.state = ChunkState::DataLf;
                }
                ChunkState::DataLf => {
                    i += 1;
                    if b != b'\n' {
                        return Err(Invalid("bare CR after chunk data"));
                    }
                    self.state = ChunkState::Size(Vec::new());
                }
                ChunkState::Trailer { line, total } => {
                    i += 1;
                    *total += 1;
                    if *total > MAX_TRAILER_BYTES {
                        return Err(Invalid("trailers too large"));
                    }
                    if b != b'\n' {
                        line.push(b);
                        continue;
                    }
                    let content = line.strip_suffix(b"\r").ok_or(Invalid("bare LF in trailer"))?;
                    if content.is_empty() {
                        self.state = ChunkState::Done;
                    } else {
                        // Same grammar as a header line; the trailer itself is dropped.
                        parse_headers(std::iter::once(content), 1)
                            .map_err(|_| Invalid("invalid trailer"))?;
                        line.clear();
                    }
                }
                ChunkState::Done => break,
            }
        }
        Ok(i)
    }
}

/// Hex chunk size without whitespace; overflow is an error. Extensions (`;...`) are rejected,
/// or in compat mode checked for control characters and dropped.
fn parse_chunk_size(line: &[u8], compat: bool) -> Result<u64, HeadError> {
    let (digits, ext) = match line.iter().position(|b| *b == b';') {
        Some(i) if compat => (line.get(..i).unwrap_or(b""), line.get(i..).unwrap_or(b"")),
        Some(_) => return Err(Invalid("chunk extensions are not accepted")),
        None => (line, &b""[..]),
    };
    if !ext.iter().all(|b| *b == b'\t' || (b' '..=b'~').contains(b)) {
        return Err(Invalid("control character in chunk extension"));
    }
    if digits.is_empty() || digits.len() > MAX_CHUNK_SIZE_DIGITS {
        return Err(Invalid("invalid chunk size"));
    }
    digits.iter().try_fold(0u64, |acc, &d| {
        let v = char::from(d).to_digit(16).ok_or(Invalid("invalid chunk size"))?;
        acc.checked_mul(16)
            .and_then(|a| a.checked_add(u64::from(v)))
            .ok_or(Invalid("chunk size overflow"))
    })
}

/// Append one chunk (`data` must be non-empty to avoid ending the body).
pub fn encode_chunk(data: &[u8], out: &mut Vec<u8>) {
    if data.is_empty() {
        return;
    }
    out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// The terminating chunk (no trailers).
pub const LAST_CHUNK: &[u8] = b"0\r\n\r\n";
