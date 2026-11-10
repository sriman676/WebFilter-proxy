//! Polite same-site crawling (SPEC_EXT_CLIENT C4, D-62): BFS from a start URL through the proxy,
//! robots.txt always respected (RFC 9309 failure rules), one request at a time with a per-host
//! minimum delay, trap caps, pages saved under `<out-dir>/<host>_crawl/` with internal links
//! rewritten to the local files and a generated `index.html`.
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use lol_html::{RewriteStrSettings, element, rewrite_str};
use url::Url;

use crate::client::{Client, ClientError, FetchResult, Outcome};
use crate::naming::{output_filename, sanitized_name, write_unique};
use crate::proxy::response::html_escape;
use crate::robots::Robots;
use crate::util::LockExt;

/// Deepest `--crawl-depth`.
pub const MAX_DEPTH: u8 = 5;
/// Largest `--max-pages`.
pub const MAX_PAGES: usize = 1000;
/// Minimum delay between requests to one host.
pub const MIN_DELAY: Duration = Duration::from_millis(250);
/// Query variants kept per path.
pub const MAX_QUERY_VARIANTS: usize = 5;
/// Deepest path (segments).
pub const MAX_PATH_DEPTH: usize = 10;
/// URLs ever queued.
pub const MAX_FRONTIER: usize = 100_000;

/// Crawl settings (C1 flags).
#[derive(Debug, Clone)]
pub struct CrawlOptions {
    /// Link depth from the start page (1..=5).
    pub depth: u8,
    /// Pages fetched at most.
    pub max_pages: usize,
    /// Include subdomains of the start host.
    pub subdomains: bool,
    /// Per-host minimum delay (raised to 250 ms).
    pub delay: Duration,
    /// Whole-crawl time cap.
    pub timeout: Duration,
}

/// What a crawl did.
#[derive(Debug, Default)]
pub struct CrawlReport {
    /// One result per page fetched (blocked and failed included).
    pub pages: Vec<FetchResult>,
    /// URLs not fetched, with the reason.
    pub skipped: Vec<(String, String)>,
    /// The generated index.
    pub index: Option<PathBuf>,
}

/// Whether `url` is in the crawl's site: same host, or a subdomain with `subdomains`.
pub fn in_scope(start_host: &str, url: &Url, subdomains: bool) -> bool {
    let Some(host) = url.host_str() else { return false };
    let host = host.trim_end_matches('.');
    matches!(url.scheme(), "http" | "https")
        && (host == start_host
            || (subdomains && host.strip_suffix(start_host).is_some_and(|p| p.ends_with('.'))))
}

/// `a[href]` targets of a page: resolved, fragments removed, http/https only, in order, deduplicated.
pub fn links(html: &str, base: &Url) -> Vec<Url> {
    let found: RefCell<Vec<Url>> = RefCell::new(Vec::new());
    let _ = rewrite_str(
        html,
        RewriteStrSettings::new().append_element_content_handler(element!("a[href]", |el| {
            if let Some(u) = el.get_attribute("href").and_then(|h| base.join(h.trim()).ok()) {
                let mut u = u;
                u.set_fragment(None);
                let mut f = found.borrow_mut();
                if matches!(u.scheme(), "http" | "https") && !f.contains(&u) {
                    f.push(u);
                }
            }
            Ok(())
        })),
    );
    found.into_inner()
}

/// Point `a[href]` at saved pages (`saved`: absolute URL without fragment -> local file name).
pub fn rewrite_links(html: &str, base: &Url, saved: &HashMap<String, String>) -> String {
    rewrite_str(
        html,
        RewriteStrSettings::new().append_element_content_handler(element!("a[href]", |el| {
            if let Some(mut u) = el.get_attribute("href").and_then(|h| base.join(h.trim()).ok()) {
                let fragment = u.fragment().map(|f| format!("#{f}")).unwrap_or_default();
                u.set_fragment(None);
                if let Some(local) = saved.get(u.as_str()) {
                    el.set_attribute("href", &format!("{local}{fragment}"))?;
                }
            }
            Ok(())
        })),
    )
    .unwrap_or_else(|_| html.to_owned())
}

/// Why a discovered URL is not queued (trap caps), if it is not.
fn trap(url: &Url, variants: &mut HashMap<String, usize>, queued: usize) -> Option<&'static str> {
    if queued >= MAX_FRONTIER {
        return Some("frontier limit");
    }
    if url.path_segments().is_some_and(|s| s.filter(|s| !s.is_empty()).count() > MAX_PATH_DEPTH) {
        return Some("path depth limit");
    }
    if url.query().is_some() {
        let key = format!("{}{}", url.origin().ascii_serialization(), url.path());
        let n = variants.entry(key).or_insert(0);
        if *n >= MAX_QUERY_VARIANTS {
            return Some("query variant limit");
        }
        *n += 1;
    }
    None
}

struct Polite {
    last: HashMap<String, Instant>,
    floor: Duration,
}

impl Polite {
    async fn wait(&mut self, url: &Url, robots: Option<&Robots>, agent: &str) {
        let host = url.host_str().unwrap_or("").to_owned();
        let delay = self.floor.max(robots.and_then(|r| r.delay(agent)).unwrap_or_default());
        if let Some(last) = self.last.get(&host) {
            let ready = *last + delay;
            tokio::time::sleep_until(ready.into()).await;
        }
        self.last.insert(host, Instant::now());
    }
}

fn robots_from(outcome: Result<Outcome, ClientError>) -> Robots {
    match outcome {
        Ok(Outcome::Ok { status, body, .. }) if (200..300).contains(&status) => {
            Robots::parse(&String::from_utf8_lossy(&body))
        }
        Ok(Outcome::Ok { status, .. }) if (400..500).contains(&status) => Robots::allow_all(),
        // A proxy block of robots.txt is a 403 for this purpose; the pages themselves show the block.
        Ok(Outcome::Blocked { .. }) => Robots::allow_all(),
        _ => Robots::disallow_all(), // 5xx, timeouts, network errors: unreachable
    }
}

/// The path (plus query) that robots.txt rules match against.
fn robots_path(url: &Url) -> String {
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    }
}

fn save(dir: &Path, name: &str, body: &[u8], max: u64) -> Result<PathBuf, ClientError> {
    write_unique(dir, name, body, max).map_err(|e| ClientError::Io(e.to_string()))
}

/// Crawl from `start`; pages go to `<out-dir>/<host>_crawl/`.
pub async fn crawl(
    client: &Client,
    start: &Url,
    opts: &CrawlOptions,
) -> Result<CrawlReport, ClientError> {
    let started = Instant::now();
    let copts = client.options();
    let agent = copts.user_agent.clone();
    let start_host = start
        .host_str()
        .ok_or_else(|| ClientError::Usage("URL has no host".into()))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let dir = copts
        .out_dir
        .join(sanitized_name(&format!("{start_host}_crawl")).trim_end_matches(".html"));
    std::fs::create_dir_all(&dir).map_err(|e| ClientError::Io(e.to_string()))?;
    let (depth, max_pages) = (opts.depth.min(MAX_DEPTH), opts.max_pages.clamp(1, MAX_PAGES));
    let scope = |u: &Url| in_scope(&start_host, u, opts.subdomains);

    let mut report = CrawlReport::default();
    let mut robots: HashMap<String, Robots> = HashMap::new();
    let mut polite = Polite { last: HashMap::new(), floor: opts.delay.max(MIN_DELAY) };
    let mut queue: VecDeque<(Url, u8)> = VecDeque::from([(start.clone(), 0)]);
    let mut seen: HashSet<String> = HashSet::from([start.to_string()]);
    let mut variants: HashMap<String, usize> = HashMap::new();
    let mut saved_names: HashMap<String, String> = HashMap::new();
    let mut saved_pages: Vec<(PathBuf, Url)> = Vec::new();

    while let Some((url, d)) = queue.pop_front() {
        if started.elapsed() >= opts.timeout {
            report.skipped.push((url.to_string(), "crawl timeout".into()));
            report
                .skipped
                .extend(queue.drain(..).map(|(u, _)| (u.to_string(), "crawl timeout".into())));
            break;
        }
        if report.pages.len() >= max_pages {
            report.skipped.push((url.to_string(), "max pages".into()));
            continue;
        }
        let origin = url.origin().ascii_serialization();
        if !robots.contains_key(&origin) {
            let robots_url =
                url.join("/robots.txt").map_err(|e| ClientError::Usage(e.to_string()))?;
            polite.wait(&robots_url, None, &agent).await;
            let (r, _) = client.get_within(&robots_url, &[], &scope).await;
            robots.insert(origin.clone(), robots_from(r));
        }
        let rules = robots.get(&origin);
        if rules.is_some_and(|r| !r.allowed(&agent, &robots_path(&url))) {
            report.skipped.push((url.to_string(), "robots.txt".into()));
            continue;
        }
        polite.wait(&url, rules, &agent).await;
        let t0 = Instant::now();
        // A redirect must stay in scope and must not land on a path robots.txt disallows for an
        // origin whose rules are already known (review L6).
        let robots_refused: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
        let page_scope = |u: &Url| {
            if !scope(u) {
                return false;
            }
            let disallowed = robots
                .get(&u.origin().ascii_serialization())
                .is_some_and(|r| !r.allowed(&agent, &robots_path(u)));
            if disallowed {
                *robots_refused.lock_or_recover() = Some(u.to_string());
            }
            !disallowed
        };
        let (outcome, attempts) = client.get_within(&url, &[], &page_scope).await;
        let refused = robots_refused.lock_or_recover().take();
        if let (Err(_), Some(target)) = (&outcome, refused) {
            report.skipped.push((target, "robots.txt".into()));
            continue;
        }
        let mut result = FetchResult {
            url: url.to_string(),
            final_url: url.to_string(),
            attempts,
            crawl_depth: Some(d),
            ..FetchResult::default()
        };
        match outcome {
            Err(e) => result.error = Some(e.to_string()),
            Ok(Outcome::Blocked { info, .. }) => {
                result.blocked = true;
                result.status = Some(403);
                result.event_id = info.event_id;
                result.reason = info.reason;
            }
            Ok(Outcome::Ok { final_url, status, headers, body }) => {
                result.final_url = final_url.to_string();
                result.status = Some(status);
                result.bytes = body.len() as u64;
                let media = headers
                    .get(hyper::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(|c| crate::util::media_type(c).to_ascii_lowercase());
                result.content_type.clone_from(&media);
                if !(200..300).contains(&status) {
                    result.error = Some(format!("HTTP {status}"));
                } else if media.as_deref() != Some("text/html") {
                    report.skipped.push((url.to_string(), "not text/html".into()));
                    continue;
                } else {
                    let name = output_filename(final_url.as_str());
                    let saved = save(&dir, &name, &body, copts.max_bytes)?;
                    let html = String::from_utf8_lossy(&body).into_owned();
                    if d < depth {
                        for link in links(&html, &final_url) {
                            if !scope(&link) || !seen.insert(link.to_string()) {
                                continue;
                            }
                            match trap(&link, &mut variants, seen.len()) {
                                Some(why) => report.skipped.push((link.to_string(), why.into())),
                                None => queue.push_back((link, d + 1)),
                            }
                        }
                    }
                    if let Some(snap) = &copts.snapshot {
                        match client.snapshot(&final_url, &html, &saved, snap).await {
                            Ok(r) => result.snapshot_report = Some(r),
                            Err(e) => result.warnings.push(format!("snapshot: {e}")),
                        }
                    }
                    let local = saved
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    saved_names.insert(url.to_string(), local.clone());
                    saved_names.insert(final_url.to_string(), local);
                    saved_pages.push((saved.clone(), final_url));
                    result.saved_path = Some(saved);
                }
            }
        }
        result.duration_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        report.pages.push(result);
    }

    // Internal links -> local files, then the integrity hashes of the final files.
    for (path, base) in &saved_pages {
        if let Ok(text) = std::fs::read(path) {
            let html = rewrite_links(&String::from_utf8_lossy(&text), base, &saved_names);
            crate::client::replace_file(path, html.as_bytes())
                .map_err(|e| ClientError::Io(e.to_string()))?;
        }
    }
    for r in &mut report.pages {
        r.sha256 = r.saved_path.as_deref().and_then(crate::batch::file_sha256);
    }
    let mut index = format!(
        "<!doctype html>\n<meta charset=\"utf-8\">\n{}\n<title>Crawl of {}</title>\n<h1>Crawl of {}</h1>\n<ul>\n",
        crate::snapshot::CSP_META,
        html_escape(&start_host),
        html_escape(&start_host)
    );
    for r in &report.pages {
        let status = r.status.map_or_else(|| "-".to_owned(), |s| s.to_string());
        let label = if r.blocked {
            "blocked"
        } else if r.error.is_some() {
            "error"
        } else {
            "ok"
        };
        match r.saved_path.as_deref().and_then(Path::file_name) {
            Some(f) => index.push_str(&format!(
                "<li><a href=\"{}\">{}</a> ({status}, {label})</li>\n",
                html_escape(&f.to_string_lossy()),
                html_escape(&r.url)
            )),
            None => {
                index.push_str(&format!("<li>{} ({status}, {label})</li>\n", html_escape(&r.url)))
            }
        }
    }
    index.push_str("</ul>\n");
    report.index = Some(save(&dir, "index.html", index.as_bytes(), copts.max_bytes)?);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn scope_rules() {
        assert!(in_scope("example.com", &u("https://example.com/a"), false));
        assert!(in_scope("example.com", &u("http://example.com./a"), false));
        assert!(!in_scope("example.com", &u("https://a.example.com/"), false));
        assert!(in_scope("example.com", &u("https://a.example.com/"), true));
        assert!(!in_scope("example.com", &u("https://badexample.com/"), true));
        assert!(!in_scope("example.com", &u("ftp://example.com/"), true));
    }

    #[test]
    fn links_are_resolved_and_deduplicated() {
        let html = r##"<a href="/a#x">1</a><a href="/a">2</a><a href="javascript:x()">3</a><a href=" b?q=1 ">4</a><a href="mailto:m@x">5</a>"##;
        let got: Vec<String> =
            links(html, &u("https://e.com/d/")).iter().map(Url::to_string).collect();
        assert_eq!(got, ["https://e.com/a", "https://e.com/d/b?q=1"]);
    }

    #[test]
    fn link_rewrite_keeps_fragments() {
        let saved = HashMap::from([("https://e.com/a".to_owned(), "e.com_a.html".to_owned())]);
        let out = rewrite_links(
            r#"<a href="/a#top">x</a><a href="/b">y</a>"#,
            &u("https://e.com/"),
            &saved,
        );
        assert!(out.contains(r#"href="e.com_a.html#top""#));
        assert!(out.contains(r#"href="/b""#));
    }

    #[test]
    fn traps_cap_variants_and_depth() {
        let mut v = HashMap::new();
        for i in 0..MAX_QUERY_VARIANTS {
            assert_eq!(trap(&u(&format!("https://e.com/p?i={i}")), &mut v, 1), None);
        }
        assert_eq!(trap(&u("https://e.com/p?i=99"), &mut v, 1), Some("query variant limit"));
        assert_eq!(
            trap(&u("https://e.com/1/2/3/4/5/6/7/8/9/10/11"), &mut v, 1),
            Some("path depth limit")
        );
        assert_eq!(trap(&u("https://e.com/x"), &mut v, MAX_FRONTIER), Some("frontier limit"));
    }

    #[test]
    fn robots_failure_rules() {
        let ok = |status| {
            Ok(Outcome::Ok {
                final_url: u("https://e.com/robots.txt"),
                status,
                headers: hyper::HeaderMap::new(),
                body: b"User-agent: *\nDisallow: /p".to_vec(),
            })
        };
        assert!(!robots_from(ok(200)).allowed("x", "/p"));
        assert!(robots_from(ok(404)).allowed("x", "/p"));
        assert!(!robots_from(ok(503)).allowed("x", "/"));
        assert!(!robots_from(Err(ClientError::Timeout)).allowed("x", "/"));
    }
}
