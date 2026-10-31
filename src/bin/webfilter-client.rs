//! `webfilter-client`: fetches URLs through the proxy and saves named HTML files (SPEC 5).
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use url::Url;
use webfilter::client::{Client, ClientOptions, exit_code};

#[derive(Parser)]
#[command(
    name = "webfilter-client",
    version,
    about = "Fetch URLs through the WebFilter proxy and save them as HTML"
)]
struct Cli {
    /// URLs to fetch (no scheme = https://).
    #[arg(required = true)]
    urls: Vec<String>,
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

fn options(cli: &Cli) -> Result<ClientOptions, String> {
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
    if cli.name.is_some() && cli.urls.len() != 1 {
        return Err("--name requires exactly one URL".into());
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
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let usage = |msg: String| {
        eprintln!("error: {msg}");
        ExitCode::from(2)
    };
    let client = match options(&cli).and_then(|o| Client::new(o).map_err(|e| e.to_string())) {
        Ok(c) => Arc::new(c),
        Err(e) => return usage(e),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => return usage(e.to_string()),
    };
    let results = runtime.block_on(client.fetch_all(cli.urls.clone()));
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
    }
    let code = if results.iter().all(|r| r.usage_error) { 2 } else { exit_code(&results) };
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
