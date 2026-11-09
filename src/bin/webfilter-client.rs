//! `webfilter-client`: fetches URLs through the proxy and saves named HTML files (SPEC 5).
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use url::Url;
use webfilter::batch::{self, Manifest, Record};
use webfilter::client::{
    Client, ClientOptions, FetchResult, SnapshotOptions, exit_code, parse_input,
};
use webfilter::crawl::{self, CrawlOptions};

#[derive(Parser)]
#[command(
    name = "webfilter-client",
    version,
    about = "Fetch URLs through the WebFilter proxy and save them as HTML"
)]
struct Cli {
    /// URLs to fetch (no scheme = https://).
    #[arg(required_unless_present = "input_file")]
    urls: Vec<String>,
    /// File with one URL per line (`-` = stdin); combined with the CLI URLs.
    #[arg(long)]
    input_file: Option<PathBuf>,
    /// Retries of transient failures (max 10).
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(0..=10))]
    retries: u32,
    /// Cap in seconds for backoff and Retry-After.
    #[arg(long, default_value_t = 60)]
    retry_max_delay: u64,
    /// JSONL record of every result.
    #[arg(long)]
    manifest: Option<PathBuf>,
    /// Skip URLs completed in the manifest (file still intact).
    #[arg(long, requires = "manifest")]
    resume: bool,
    /// Continue partial downloads with Range + If-Range.
    #[arg(long)]
    resume_partial: bool,
    /// Save pages with their same-site assets for offline viewing.
    #[arg(long)]
    snapshot: bool,
    /// Keep scripts in snapshots (NOT recommended).
    #[arg(long, requires = "snapshot")]
    snapshot_allow_scripts: bool,
    /// Extra asset host (CDN) allowed in snapshots; repeatable.
    #[arg(long = "snapshot-extra-host", requires = "snapshot")]
    snapshot_extra_hosts: Vec<String>,
    /// Crawl links to this depth (0 = off, max 5).
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=5))]
    crawl_depth: u8,
    /// Most pages per crawl (max 1000).
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u64).range(1..=1000))]
    max_pages: u64,
    /// Include subdomains of the start host in a crawl.
    #[arg(long)]
    crawl_subdomains: bool,
    /// Minimum delay between requests to one host (floor 250).
    #[arg(long, default_value_t = 250)]
    crawl_delay_ms: u64,
    /// Whole-crawl time cap in seconds.
    #[arg(long, default_value_t = 600)]
    crawl_timeout: u64,
    /// Proxy URL (HTTP(S)_PROXY are ignored).
    #[arg(long, env = "WEBFILTER_PROXY", default_value = "http://127.0.0.1:8080")]
    proxy: String,
    /// Proxy user; password from WEBFILTER_PROXY_PASSWORD or --proxy-password-file.
    #[arg(long)]
    proxy_user: Option<String>,
    /// File holding the proxy password (first line).
    #[arg(long)]
    proxy_password_file: Option<PathBuf>,
    /// Output directory.
    #[arg(long, default_value = "output")]
    out_dir: PathBuf,
    /// Output file name (exactly one URL).
    #[arg(long)]
    name: Option<String>,
    /// Extra trusted root CA (PEM); repeatable. Verification is always on.
    #[arg(long = "ca-cert")]
    ca_certs: Vec<PathBuf>,
    /// Concurrent fetches.
    #[arg(long, default_value_t = 4)]
    jobs: usize,
    /// Whole-fetch timeout in seconds.
    #[arg(long, default_value_t = 30)]
    timeout: u64,
    /// Connect timeout in seconds.
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,
    /// Maximum redirects.
    #[arg(long, default_value_t = 10)]
    max_redirects: usize,
    /// Maximum body size in bytes.
    #[arg(long, default_value_t = 52_428_800)]
    max_bytes: u64,
    /// Save block pages as <name>.blocked.html.
    #[arg(long)]
    save_blocked: bool,
    /// One JSON object per URL.
    #[arg(long)]
    json: bool,
    /// Only print errors.
    #[arg(short, long)]
    quiet: bool,
    /// Print warnings and timings.
    #[arg(short, long)]
    verbose: bool,
    /// User-Agent header.
    #[arg(long, default_value = concat!("webfilter-client/", env!("CARGO_PKG_VERSION")))]
    user_agent: String,
}

/// CLI URLs plus `--input-file` (deduplicated, order kept).
fn all_urls(cli: &Cli) -> Result<Vec<String>, String> {
    let mut urls = cli.urls.clone();
    if let Some(file) = &cli.input_file {
        let text = if file.as_os_str() == "-" {
            let mut s = String::new();
            std::io::Read::read_to_string(
                &mut std::io::Read::take(std::io::stdin(), 64 * 1024 * 1024),
                &mut s,
            )
            .map_err(|e| format!("stdin: {e}"))?;
            s
        } else {
            std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?
        };
        let (more, invalid) = batch::parse_input_file(&text);
        if invalid > 0 {
            eprintln!("warning: {invalid} invalid line(s) in the input file skipped");
        }
        urls.extend(more);
    }
    let mut seen = std::collections::HashSet::new();
    urls.retain(|u| seen.insert(u.clone()));
    if urls.is_empty() {
        return Err("no URLs".into());
    }
    Ok(urls)
}

fn options(cli: &Cli, count: usize) -> Result<ClientOptions, String> {
    let proxy = Url::parse(&cli.proxy).map_err(|e| format!("--proxy: {e}"))?;
    if proxy.scheme() != "http" {
        return Err("--proxy must be http:// (D-38)".into());
    }
    let password = match (&cli.proxy_user, &cli.proxy_password_file) {
        (None, _) => None,
        (Some(_), Some(file)) => {
            let text =
                std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
            Some(text.lines().next().unwrap_or("").to_owned())
        }
        (Some(_), None) => Some(std::env::var("WEBFILTER_PROXY_PASSWORD").map_err(|_| {
            "--proxy-user needs WEBFILTER_PROXY_PASSWORD or --proxy-password-file".to_owned()
        })?),
    };
    if cli.name.is_some() && (count != 1 || cli.crawl_depth > 0) {
        return Err("--name requires exactly one URL and no crawl".into());
    }
    let name = match &cli.name {
        Some(n) if n.contains(['/', '\\']) || n.contains("..") => {
            return Err("--name must not contain separators or '..'".into());
        }
        // Same sanitizing rules as generated names (SPEC 5.1).
        Some(n) => Some(webfilter::naming::sanitized_name(n.trim_end_matches(".html"))),
        None => None,
    };
    std::fs::create_dir_all(&cli.out_dir).map_err(|e| format!("{}: {e}", cli.out_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&cli.out_dir, std::fs::Permissions::from_mode(0o750));
    }
    Ok(ClientOptions {
        proxy,
        proxy_auth: cli.proxy_user.clone().zip(password),
        out_dir: cli.out_dir.clone(),
        name,
        ca_certs: cli.ca_certs.clone(),
        jobs: cli.jobs,
        timeout: Duration::from_secs(cli.timeout),
        connect_timeout: Duration::from_secs(cli.connect_timeout),
        max_redirects: cli.max_redirects,
        max_bytes: cli.max_bytes,
        save_blocked: cli.save_blocked,
        user_agent: cli.user_agent.clone(),
        retries: cli.retries,
        retry_max_delay: Duration::from_secs(cli.retry_max_delay),
        resume_partial: cli.resume_partial,
        snapshot: cli.snapshot.then(|| SnapshotOptions {
            allow_scripts: cli.snapshot_allow_scripts,
            extra_hosts: cli
                .snapshot_extra_hosts
                .iter()
                .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
                .collect(),
        }),
    })
}

fn record(r: &FetchResult) -> Record {
    Record {
        url: r.url.clone(),
        status: r.status,
        bytes: r.bytes,
        sha256: r.sha256.clone(),
        saved_path: r.saved_path.as_ref().map(|p| p.display().to_string()),
        blocked: r.blocked,
        error: r.error.clone(),
        finished_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    }
}

/// Assets saved, from the snapshot reports.
fn assets(results: &[FetchResult]) -> u64 {
    results
        .iter()
        .filter_map(|r| r.snapshot_report.as_ref())
        .filter_map(|p| std::fs::read(p).ok())
        .filter_map(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .filter_map(|v| v.get("assets").and_then(serde_json::Value::as_u64))
        .sum()
}

async fn run(cli: &Cli, client: Arc<Client>, urls: Vec<String>) -> (Vec<FetchResult>, usize) {
    if cli.crawl_depth == 0 {
        return (client.fetch_all(urls).await, 0);
    }
    let opts = CrawlOptions {
        depth: cli.crawl_depth,
        max_pages: usize::try_from(cli.max_pages).unwrap_or(crawl::MAX_PAGES),
        subdomains: cli.crawl_subdomains,
        delay: Duration::from_millis(cli.crawl_delay_ms),
        timeout: Duration::from_secs(cli.crawl_timeout),
    };
    let (mut results, mut skipped) = (Vec::new(), 0);
    for raw in urls {
        let start = match parse_input(&raw) {
            Ok((u, _)) => u,
            Err(e) => {
                results.push(FetchResult {
                    url: raw,
                    error: Some(e.to_string()),
                    usage_error: true,
                    ..FetchResult::default()
                });
                continue;
            }
        };
        match crawl::crawl(&client, &start, &opts).await {
            Ok(report) => {
                if cli.verbose {
                    for (u, why) in &report.skipped {
                        eprintln!("skipped {u}: {why}");
                    }
                }
                if let (Some(i), false) = (&report.index, cli.quiet) {
                    eprintln!("crawl index: {}", i.display());
                }
                skipped += report.skipped.len();
                results.extend(report.pages);
            }
            Err(e) => results.push(FetchResult {
                url: start.to_string(),
                error: Some(e.to_string()),
                ..FetchResult::default()
            }),
        }
    }
    (results, skipped)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let usage = |msg: String| {
        eprintln!("error: {msg}");
        ExitCode::from(2)
    };
    let mut urls = match all_urls(&cli) {
        Ok(u) => u,
        Err(e) => return usage(e),
    };
    let client = match options(&cli, cli.urls.len() + usize::from(cli.input_file.is_some()))
        .and_then(|o| Client::new(o).map_err(|e| e.to_string()))
    {
        Ok(c) => Arc::new(c),
        Err(e) => return usage(e),
    };
    let mut manifest = match &cli.manifest {
        Some(path) => match Manifest::open(path) {
            Ok(m) => Some(m),
            Err(e) => return usage(e),
        },
        None => None,
    };
    let mut skipped = 0;
    if let (true, Some(m)) = (cli.resume, &manifest) {
        let done = batch::load(m.path());
        let before = urls.len();
        urls.retain(|raw| {
            let key = parse_input(raw).map_or_else(|_| raw.clone(), |(u, _)| u.to_string());
            !done.get(&key).is_some_and(|r| batch::completed(r, &cli.out_dir))
        });
        skipped += before - urls.len();
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => return usage(e.to_string()),
    };
    let (results, crawl_skipped) = runtime.block_on(run(&cli, client, urls));
    skipped += crawl_skipped;
    for r in &results {
        if cli.json {
            println!("{}", serde_json::to_string(r).unwrap_or_default());
        } else if !cli.quiet || r.error.is_some() {
            println!("{}", r.human_line());
        }
        if !cli.quiet {
            for w in &r.warnings {
                eprintln!("warning: {}: {w}", r.url);
            }
        }
        if cli.verbose {
            eprintln!("{} took {} ms", r.url, r.duration_ms);
        }
        if let Some(m) = manifest.as_mut()
            && let Err(e) = m.append(&record(r))
        {
            eprintln!("warning: manifest: {e}");
        }
    }
    if let Some(m) = manifest.take() {
        let _ = m.sync();
    }
    if !cli.quiet && (results.len() > 1 || skipped > 0 || cli.crawl_depth > 0 || cli.snapshot) {
        let retries: u32 = results.iter().map(|r| r.attempts.saturating_sub(1)).sum();
        eprintln!(
            "summary: pages={} assets={} blocked={} skipped={skipped} retries={retries}",
            results.iter().filter(|r| r.saved_path.is_some() && !r.blocked).count(),
            assets(&results),
            results.iter().filter(|r| r.blocked).count(),
        );
    }
    let code = if !results.is_empty() && results.iter().all(|r| r.usage_error) {
        2
    } else {
        exit_code(&results)
    };
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
