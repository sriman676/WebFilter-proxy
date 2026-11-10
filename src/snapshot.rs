//! Offline page snapshots (SPEC_EXT_CLIENT C3, D-61): plan same-site assets from the HTML and CSS,
//! then rewrite the page with `lol_html` so it references only local files, with scripts, inline
//! handlers, `<base>`, meta refresh, plug-ins and frames removed and a restrictive CSP meta
//! injected. Pure functions here; fetching lives in the client.
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::collections::HashMap;

use lol_html::html_content::ContentType;
use lol_html::{RewriteStrSettings, element, rewrite_str, text};
use sha2::{Digest, Sha256};
use url::Url;

/// Assets per page.
pub const MAX_ASSETS: usize = 200;
/// Bytes per asset.
pub const MAX_ASSET_BYTES: u64 = 10 * 1024 * 1024;
/// Bytes per page (all assets).
pub const MAX_PAGE_BYTES: u64 = 100 * 1024 * 1024;
/// CSS `@import` depth.
pub const MAX_CSS_DEPTH: u8 = 2;
/// Largest `data:` URI kept.
pub const MAX_DATA_URI: usize = 256 * 1024;
/// Largest attribute value processed.
pub const MAX_ATTR: usize = 64 * 1024;
/// Injected at the start of `<head>` (SH-20): no scripts, no network; local files and data only.
pub const CSP_META: &str = "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src file: data:; style-src file: 'unsafe-inline'; font-src file: data:; media-src file: data:\">";

/// Why an asset was left out (for `snapshot_report.json`).
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct Omitted {
    /// Asset URL.
    pub url: String,
    /// Reason.
    pub reason: String,
    /// Proxy event id when blocked.
    pub event_id: Option<String>,
}

/// Same site: same host and port, scheme-insensitive, or an explicitly allowed extra host.
pub fn same_site(page: &Url, asset: &Url, extra_hosts: &[String]) -> bool {
    let host = asset.host_str().map(str::to_ascii_lowercase);
    let port = |u: &Url| u.port_or_known_default().map(|p| if p == 443 || p == 80 { 0 } else { p });
    let same = host == page.host_str().map(str::to_ascii_lowercase) && port(asset) == port(page);
    same || host.is_some_and(|h| extra_hosts.iter().any(|e| e.eq_ignore_ascii_case(&h)))
}

/// `srcset` candidates.
pub fn srcset_urls(v: &str) -> Vec<String> {
    v.split(',')
        .filter_map(|c| c.split_whitespace().next().map(str::to_owned))
        .filter(|u| !u.is_empty())
        .collect()
}

fn resolve(base: &Url, r: &str) -> Option<Url> {
    let r = r.trim();
    if r.is_empty() || r.len() > MAX_ATTR || r.starts_with('#') {
        return None;
    }
    let u = base.join(r).ok()?;
    matches!(u.scheme(), "http" | "https").then_some(u)
}

/// References in CSS text: `url(...)` and `@import "..."`. Returns (is_import, raw reference).
pub fn css_refs(css: &str) -> Vec<(bool, String)> {
    let mut out = Vec::new();
    let lower = css.to_ascii_lowercase();
    let mut i = 0;
    while let Some(at) = lower.get(i..).and_then(|s| s.find("url(")) {
        let start = i + at + 4;
        let Some(end) = css.get(start..).and_then(|s| s.find(')')) else { break };
        let inner =
            css.get(start..start + end).unwrap_or("").trim().trim_matches(['"', '\'']).to_owned();
        let import = lower.get(..i + at).is_some_and(|b| b.trim_end().ends_with("@import"));
        out.push((import, inner));
        i = start + end + 1;
    }
    let mut j = 0;
    while let Some(at) = lower.get(j..).and_then(|s| s.find("@import")) {
        let rest = css.get(j + at + 7..).unwrap_or("").trim_start();
        if let Some(q) = rest.chars().next().filter(|c| *c == '"' || *c == '\'')
            && let Some(end) = rest.get(1..).and_then(|r| r.find(q))
        {
            out.push((true, rest.get(1..1 + end).unwrap_or("").to_owned()));
        }
        j += at + 7;
    }
    out
}

/// Rewrite CSS: mapped references become local paths, the rest are emptied; script-capable
/// constructs (`expression(`, `behavior:`, `-moz-binding`, `javascript:`) are neutralized (SH-13).
pub fn rewrite_css(css: &str, map: &dyn Fn(&str) -> Option<String>) -> String {
    // `<` is removed before scanning so its removal cannot assemble a reference or a neutralized
    // construct (`u<rl(`, `expressio<n(`); this also keeps `</style>` out of inline CSS.
    let stripped = css.replace('<', "");
    let css = stripped.as_str();
    // One left-to-right pass over `url(...)` and `@import "..."`: every reference is replaced in
    // place, so no rewrite can pair up with neighbouring text to form a new one.
    let mut out = String::with_capacity(css.len());
    let lower = css.to_ascii_lowercase();
    let mut i = 0;
    loop {
        let next_url = lower.get(i..).and_then(|s| s.find("url("));
        let next_import = lower.get(i..).and_then(|s| s.find("@import"));
        let (at, is_url) = match (next_url, next_import) {
            (Some(u), Some(m)) if m < u => (m, false),
            (Some(u), _) => (u, true),
            (None, Some(m)) => (m, false),
            (None, None) => break,
        };
        if is_url {
            out.push_str(css.get(i..i + at).unwrap_or(""));
            let start = i + at + 4;
            let Some(end) = css.get(start..).and_then(|s| s.find(')')) else {
                i = css.len();
                break;
            };
            let inner = css.get(start..start + end).unwrap_or("").trim().trim_matches(['"', '\'']);
            let keep_data = inner.starts_with("data:image/")
                && inner.len() <= MAX_DATA_URI
                && !inner.contains(['"', '\'', '\\', ' ', '\n', '\t', '\r']);
            match map(inner) {
                Some(local) => out.push_str(&format!("url(\"{local}\")")),
                None if keep_data => out.push_str(&format!("url(\"{inner}\")")),
                None => out.push_str("url(\"\")"),
            }
            i = start + end + 1;
        } else {
            let after = i + at + "@import".len();
            out.push_str(css.get(i..after).unwrap_or(""));
            let rest = css.get(after..).unwrap_or("");
            let ws = rest.len() - rest.trim_start().len();
            let quoted = rest.trim_start();
            let q = quoted.chars().next().filter(|c| *c == '"' || *c == '\'');
            match q.and_then(|q| quoted.get(1..).and_then(|r| r.find(q))) {
                Some(end) => {
                    let r = quoted.get(1..1 + end).unwrap_or("");
                    out.push_str(&format!(" \"{}\"", map(r).unwrap_or_default()));
                    i = after + ws + end + 2;
                }
                // An unterminated string would be closed by a quote emitted later: drop the rest.
                None if q.is_some() => {
                    i = css.len();
                    break;
                }
                None => i = after,
            }
        }
    }
    out.push_str(css.get(i..).unwrap_or(""));
    // Linear passes to a fixpoint. `x_` shares no character with any pattern except an `x` that
    // no pattern ends with, so a replacement cannot form a new match: the second pass only
    // confirms that. Each pass is O(n) (review M4: the old find/replace loop was quadratic).
    let mut clean = out;
    while let Some(next) = neutralize_pass(&clean) {
        clean = next;
    }
    clean
}

/// Patterns that make CSS executable in some engine; each is replaced by `x_`.
const CSS_BAD: [&str; 5] =
    ["expression(", "behavior:", "behaviour:", "-moz-binding", "javascript:"];

/// One left-to-right pass replacing every ASCII-case-insensitive [`CSS_BAD`] occurrence with
/// `x_`; `None` when nothing matched. Patterns are ASCII, so cuts stay on char boundaries.
fn neutralize_pass(css: &str) -> Option<String> {
    let bytes = css.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut i = 0;
    while let Some(rest) = bytes.get(i..) {
        let Some(&first) = rest.first() else { break };
        let hit = CSS_BAD.iter().find(|bad| {
            rest.get(..bad.len()).is_some_and(|w| w.eq_ignore_ascii_case(bad.as_bytes()))
        });
        if let Some(bad) = hit {
            out.extend_from_slice(b"x_");
            i += bad.len();
            changed = true;
        } else {
            out.push(first);
            i += 1;
        }
    }
    // Only whole ASCII runs were replaced, so `out` is valid UTF-8; the lossy path never runs.
    changed.then(|| {
        String::from_utf8(out)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
    })
}

/// Local name `<stem>_files/<hash8>_<basename>.<ext>`, extension from the media type (C3).
pub fn local_name(stem: &str, url: &Url, media_type: &str) -> String {
    let hash = hex::encode(Sha256::digest(url.as_str().as_bytes()));
    let base = url.path().rsplit('/').next().unwrap_or("");
    let base = base.rsplit_once('.').map_or(base, |(b, _)| b);
    let clean: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(40)
        .collect();
    let clean = if clean.is_empty() { "asset".to_owned() } else { clean };
    let ext = match media_type {
        "text/css" => "css",
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/avif" => "avif",
        "image/svg+xml" => "svg",
        "image/x-icon" | "image/vnd.microsoft.icon" => "ico",
        t if t.starts_with("font/") => t.trim_start_matches("font/"),
        "application/font-woff" => "woff",
        _ => "bin",
    };
    let ext: String = ext.chars().filter(char::is_ascii_alphanumeric).take(8).collect();
    format!("{stem}_files/{}_{clean}.{ext}", hash.get(..8).unwrap_or("00000000"))
}

/// Whether an asset response may be kept (C3 allowed media types).
pub fn allowed_media(media_type: &str) -> bool {
    media_type.starts_with("image/")
        || media_type == "text/css"
        || media_type.starts_with("font/")
        || media_type.starts_with("application/font-")
}

/// Pass 1: every asset reference in the page (resolved, deduplicated, in document order).
pub fn plan(html: &str, base: &Url, allow_scripts: bool) -> Vec<Url> {
    let found: RefCell<Vec<Url>> = RefCell::new(Vec::new());
    let push = |r: &str| {
        if let Some(u) = resolve(base, r) {
            let mut f = found.borrow_mut();
            if !f.contains(&u) {
                f.push(u);
            }
        }
    };
    let style = RefCell::new(String::new());
    let _ = rewrite_str(
        html,
        RewriteStrSettings::new()
            .append_element_content_handler(element!(
                "img[src], source[src], video[poster], link[href]",
                |el| {
                    let rel = el.get_attribute("rel").unwrap_or_default().to_ascii_lowercase();
                    let tag = el.tag_name();
                    if tag == "link" && !(rel.contains("stylesheet") || rel.contains("icon")) {
                        return Ok(());
                    }
                    for a in ["src", "poster", "href"] {
                        if let Some(v) = el.get_attribute(a) {
                            push(&v);
                        }
                    }
                    Ok(())
                }
            ))
            .append_element_content_handler(element!("img[srcset], source[srcset]", |el| {
                for u in srcset_urls(&el.get_attribute("srcset").unwrap_or_default()) {
                    push(&u);
                }
                Ok(())
            }))
            .append_element_content_handler(element!("script[src]", |el| {
                if allow_scripts && let Some(v) = el.get_attribute("src") {
                    push(&v);
                }
                Ok(())
            }))
            .append_element_content_handler(element!("[style]", |el| {
                for (_, r) in css_refs(&el.get_attribute("style").unwrap_or_default()) {
                    push(&r);
                }
                Ok(())
            }))
            .append_element_content_handler(text!("style", |t| {
                style.borrow_mut().push_str(t.as_str());
                if t.last_in_text_node() {
                    for (_, r) in css_refs(&style.borrow()) {
                        push(&r);
                    }
                    style.borrow_mut().clear();
                }
                Ok(())
            })),
    );
    let mut v = found.into_inner();
    v.retain(|u| !u.as_str().starts_with("data:"));
    v
}

/// Pass 2: sanitize and rewrite to local paths. `map` gives the local path of an absolute asset
/// URL, `None` when it was omitted (the reference is then removed).
pub fn rewrite(
    html: &str,
    base: &Url,
    map: &HashMap<String, String>,
    allow_scripts: bool,
) -> String {
    let local =
        |r: &str| -> Option<String> { resolve(base, r).and_then(|u| map.get(u.as_str()).cloned()) };
    let css_map = |r: &str| local(r);
    let style = RefCell::new(String::new());
    let head_done = RefCell::new(false);
    let result = rewrite_str(
        html,
        RewriteStrSettings::new()
            .append_element_content_handler(element!("head", |el| {
                el.prepend(CSP_META, ContentType::Html);
                *head_done.borrow_mut() = true;
                Ok(())
            }))
            .append_element_content_handler(element!("script", |el| {
                let keep =
                    allow_scripts && el.get_attribute("src").as_deref().and_then(local).is_some();
                if keep {
                    let src =
                        el.get_attribute("src").as_deref().and_then(local).unwrap_or_default();
                    el.set_attribute("src", &src)?;
                } else {
                    el.remove();
                }
                Ok(())
            }))
            .append_element_content_handler(element!(
                "base, object, embed, applet, meta[http-equiv]",
                |el| {
                    let refresh = el
                        .get_attribute("http-equiv")
                        .is_some_and(|v| v.eq_ignore_ascii_case("refresh"))
                        || el.tag_name() != "meta";
                    if refresh
                        || el
                            .get_attribute("http-equiv")
                            .is_some_and(|v| v.eq_ignore_ascii_case("content-security-policy"))
                    {
                        el.remove();
                    }
                    Ok(())
                }
            ))
            .append_element_content_handler(element!("iframe, frame, frameset", |el| {
                el.replace(
                    "<span class=\"wf-removed\">[embedded frame removed]</span>",
                    ContentType::Html,
                );
                Ok(())
            }))
            .append_element_content_handler(element!("*", |el| {
                let names: Vec<String> = el.attributes().iter().map(|a| a.name()).collect();
                for n in names {
                    let v = el.get_attribute(&n).unwrap_or_default();
                    let lower = v.trim().to_ascii_lowercase();
                    let script_url =
                        lower.starts_with("javascript:") || lower.starts_with("vbscript:");
                    let bad_data = lower.starts_with("data:")
                        && (!lower.starts_with("data:image/") || v.len() > MAX_DATA_URI);
                    if n.starts_with("on")
                        || v.len() > MAX_ATTR
                        || script_url
                        || (bad_data && n != "content")
                        || n == "formaction"
                    {
                        el.remove_attribute(&n);
                    }
                }
                if el.tag_name() == "form" {
                    el.remove_attribute("action");
                }
                if let Some(s) = el.get_attribute("style") {
                    el.set_attribute("style", &rewrite_css(&s, &css_map))?;
                }
                Ok(())
            }))
            .append_element_content_handler(element!(
                "img[src], source[src], video[poster], link[href]",
                |el| {
                    let tag = el.tag_name();
                    let rel = el.get_attribute("rel").unwrap_or_default().to_ascii_lowercase();
                    let attr = match tag.as_str() {
                        "video" => "poster",
                        "link" => "href",
                        _ => "src",
                    };
                    if tag == "link" && !(rel.contains("stylesheet") || rel.contains("icon")) {
                        el.remove(); // preload, prefetch, manifest...: no network references
                        return Ok(());
                    }
                    let v = el.get_attribute(attr).unwrap_or_default();
                    if v.trim_start().to_ascii_lowercase().starts_with("data:image/")
                        && v.len() <= MAX_DATA_URI
                    {
                        return Ok(());
                    }
                    match local(&v) {
                        Some(l) => el.set_attribute(attr, &l)?,
                        None => el.remove_attribute(attr),
                    }
                    Ok(())
                }
            ))
            .append_element_content_handler(element!("img[srcset], source[srcset]", |el| {
                let kept: Vec<String> = el
                    .get_attribute("srcset")
                    .unwrap_or_default()
                    .split(',')
                    .filter_map(|c| {
                        let mut parts = c.split_whitespace();
                        let u = parts.next()?;
                        let l = local(u)?;
                        Some(
                            std::iter::once(l)
                                .chain(parts.map(str::to_owned))
                                .collect::<Vec<_>>()
                                .join(" "),
                        )
                    })
                    .collect();
                if kept.is_empty() {
                    el.remove_attribute("srcset");
                } else {
                    el.set_attribute("srcset", &kept.join(", "))?;
                }
                Ok(())
            }))
            .append_element_content_handler(element!("a[href], area[href]", |el| {
                let v = el.get_attribute("href").unwrap_or_default();
                match resolve(base, &v) {
                    Some(u) => el.set_attribute("href", u.as_str())?, // absolute: opens online, nothing loads
                    None if v.trim_start().starts_with('#') => {}
                    None => el.remove_attribute("href"),
                }
                Ok(())
            }))
            .append_element_content_handler(text!("style", |t| {
                style.borrow_mut().push_str(t.as_str());
                if t.last_in_text_node() {
                    let css = rewrite_css(&style.borrow(), &css_map);
                    t.replace(&css, ContentType::Html); // `<` stripped by rewrite_css
                    style.borrow_mut().clear();
                } else {
                    t.remove();
                }
                Ok(())
            })),
    )
    .unwrap_or_default();
    // Unterminated tags at the end (`<script`, `<<x<script<`) are dropped, not left as raw text.
    let mut result = result;
    let after = result.rfind('>').map_or(0, |p| p + 1);
    if let Some(open) = result.get(after..).and_then(|t| t.find('<')) {
        result.truncate(after + open);
    }
    if *head_done.borrow() { result } else { format!("{CSP_META}{result}") }
}
