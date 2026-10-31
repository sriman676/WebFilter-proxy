//! Block and error responses (SPEC 4.7, 4.12): fixed safe headers, every value HTML-escaped,
//! optional operator template for the block page (A-26).
#![forbid(unsafe_code)]

use std::path::Path;

use crate::reason::Reason;

/// Maximum size of a block-page template.
pub const MAX_TEMPLATE_BYTES: u64 = 64 * 1024;
/// Host/URL shown on pages are truncated to this many characters (SPEC 4.7).
pub const MAX_SHOWN_CHARS: usize = 200;

const DEFAULT_TEMPLATE: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Blocked</title>\
<style>body{font-family:sans-serif;max-width:40em;margin:4em auto;color:#222}code{background:#eee;padding:0 .3em}</style>\
</head><body><h1>Access blocked</h1><p>The request to <code>{host}</code> was blocked by the web filter.</p>\
<p>Reason: <code>{reason}</code><br>Rule: <code>{rule_id}</code><br>Category: <code>{category}</code></p>\
<p>Event id: <code>{event_id}</code> ({timestamp})</p></body></html>";

/// HTML-escape for text and attribute contexts.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            '/' => out.push_str("&#x2F;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn shown(s: &str) -> String {
    let mut out: String = s.chars().take(MAX_SHOWN_CHARS).collect();
    if s.chars().count() > MAX_SHOWN_CHARS {
        out.push('…');
    }
    out
}

/// Values available to the block page.
#[derive(Debug, Clone, Default)]
pub struct BlockInfo<'a> {
    /// Requested URL (no query).
    pub url: &'a str,
    /// Requested host.
    pub host: &'a str,
    /// Why.
    pub reason: Reason,
    /// Matching rule.
    pub rule_id: Option<&'a str>,
    /// List category (A-27).
    pub category: Option<&'a str>,
    /// Event id (also in the log and headers).
    pub event_id: &'a str,
    /// Event timestamp.
    pub timestamp: &'a str,
}

/// The block page: built-in or an operator template with `{placeholders}`.
#[derive(Debug, Clone, Default)]
pub struct BlockPage {
    template: Option<String>,
}

impl BlockPage {
    /// Load a template (`None` = built-in page). The file must be UTF-8 and <= 64 KiB.
    pub fn load(path: Option<&Path>) -> Result<Self, String> {
        let Some(path) = path else { return Ok(Self::default()) };
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !meta.is_file() || meta.len() > MAX_TEMPLATE_BYTES {
            return Err(format!(
                "{}: must be a regular file of at most {MAX_TEMPLATE_BYTES} bytes",
                path.display()
            ));
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Self { template: Some(text) })
    }

    /// Render with every value HTML-escaped. Substitution is a single pass, so a value can never
    /// introduce another placeholder.
    pub fn render(&self, info: &BlockInfo<'_>) -> String {
        let template = self.template.as_deref().unwrap_or(DEFAULT_TEMPLATE);
        let value = |key: &str| -> Option<String> {
            Some(match key {
                "url" => shown(info.url),
                "host" => shown(info.host),
                "reason" => info.reason.as_str().to_owned(),
                "rule_id" => info.rule_id.unwrap_or("-").to_owned(),
                "category" => info.category.unwrap_or("-").to_owned(),
                "event_id" => info.event_id.to_owned(),
                "timestamp" => info.timestamp.to_owned(),
                _ => return None,
            })
        };
        let mut out = String::with_capacity(template.len() + 256);
        let mut rest = template;
        while let Some(start) = rest.find('{') {
            out.push_str(rest.get(..start).unwrap_or(""));
            let after = rest.get(start + 1..).unwrap_or("");
            match after.find('}').and_then(|end| Some((end, value(after.get(..end)?)?))) {
                Some((end, v)) => {
                    out.push_str(&html_escape(&v));
                    rest = after.get(end + 1..).unwrap_or("");
                }
                None => {
                    out.push('{');
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
    }
}

/// Standard reason phrase.
pub fn status_text(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        414 => "URI Too Long",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        508 => "Loop Detected",
        _ => "Error",
    }
}

/// A complete response with the SPEC 4.7 safety headers; always `Connection: close`.
pub fn page(
    status: u16,
    reason: Reason,
    event_id: &str,
    html: &str,
    extra_headers: &[(&str, String)],
) -> Vec<u8> {
    let action = if status == 403 { "blocked" } else { "error" };
    let mut head = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: text/html; charset=utf-8\r\nx-webfilter-action: {action}\r\n\
x-webfilter-event-id: {event_id}\r\nx-webfilter-reason: {}\r\ncache-control: no-store\r\n\
x-content-type-options: nosniff\r\ncontent-security-policy: default-src 'none'; style-src 'unsafe-inline'\r\n\
content-length: {}\r\nconnection: close\r\n",
        status_text(status),
        reason.as_str(),
        html.len()
    );
    for (name, value) in extra_headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(html.as_bytes());
    out
}

/// Generic error page (no internal details, SPEC 4.12).
pub fn error_page(
    status: u16,
    reason: Reason,
    event_id: &str,
    extra_headers: &[(&str, String)],
) -> Vec<u8> {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{status}</title></head><body><h1>{status} {}</h1>\
<p>Reason: <code>{}</code></p><p>Event id: <code>{}</code></p></body></html>",
        status_text(status),
        reason.as_str(),
        html_escape(event_id)
    );
    page(status, reason, event_id, &html, extra_headers)
}
