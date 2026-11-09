//! `webfilter-proxy`: filtering HTTP/HTTPS forward proxy (SPEC 4.13 CLI).
#![forbid(unsafe_code)]

use std::io::BufRead;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use webfilter::blocklist::{Blocklists, ReloadOutcome};
use webfilter::config::{Config, EXIT_INVALID_CONFIG, Mode};
use webfilter::filter::{Phase, evaluate};
use webfilter::normalize::{TargetContext, canonicalize};

#[derive(Parser)]
#[command(name = "webfilter-proxy", version, about = "Filtering HTTP/HTTPS forward proxy")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, global = true, default_value = "config/config.toml")]
    config: PathBuf,
    /// Override `listen` (CLI wins over the file).
    #[arg(long, global = true)]
    listen: Option<SocketAddr>,
    /// Override `mode`.
    #[arg(long, global = true)]
    mode: Option<CliMode>,
    /// Override `logging.dir`.
    #[arg(long, global = true)]
    log_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Copy, ValueEnum)]
enum CliMode {
    Enforce,
    Monitor,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy (default).
    Run,
    /// Validate the configuration and exit (0 = valid, 2 = invalid).
    CheckConfig,
    /// Blocklist tools.
    Blocklist {
        #[command(subcommand)]
        command: BlocklistCommand,
    },
    /// Read a password from stdin and print its argon2id hash for the config.
    HashPassword,
    /// Local CA for TLS interception (SPEC 4.9).
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    /// Threat feeds (SPEC_EXT_POLICY P3).
    Feeds {
        #[command(subcommand)]
        command: FeedsCommand,
    },
}

#[derive(Subcommand)]
enum CaCommand {
    /// Create the CA in `tls.ca_dir` (never overwrites an existing one).
    Generate,
    /// Print the public CA certificate (PEM) to import into a browser (manual, D-30).
    Export,
}

#[derive(Subcommand)]
enum FeedsCommand {
    /// Active version, entries and last success of every feed.
    Status,
    /// Fetch and apply one feed (or all enabled feeds).
    Update {
        /// Feed name; all enabled feeds when omitted.
        name: Option<String>,
        /// Skip the 50-200 percent sanity guard.
        #[arg(long)]
        force: bool,
    },
    /// Restore the previous version of a feed.
    Rollback {
        /// Feed name.
        name: String,
    },
    /// Show which active feed entry (if any) a URL hits.
    Test {
        /// Absolute http(s) URL.
        url: String,
    },
}

fn feeds(cfg: &Config, command: &FeedsCommand) -> ExitCode {
    let roots: Vec<_> = Some(&cfg.tls.upstream_ca_bundle)
        .filter(|p| !p.as_os_str().is_empty())
        .cloned()
        .into_iter()
        .collect();
    let tls = match webfilter::tls::upstream_client_config(&roots) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let fetcher = webfilter::feeds::Fetcher {
        tls,
        resolver: std::sync::Arc::new(webfilter::policy::SystemResolver),
        policy: webfilter::policy::DestPolicy::new(true, Vec::new()),
    };
    let mgr = webfilter::feeds::FeedManager::new(
        cfg.feeds.clone(),
        cfg.feeds_global.dir.clone(),
        cfg.feeds_global.protected_domains.clone(),
        Some(fetcher),
        None,
    );
    let print_err = |e: &dyn std::fmt::Display| {
        eprintln!("error: {e}");
        ExitCode::FAILURE
    };
    match command {
        FeedsCommand::Status => {
            for s in mgr.status() {
                println!("{}", serde_json::to_string(&s).unwrap_or_default());
            }
            ExitCode::SUCCESS
        }
        FeedsCommand::Update { name, force } => {
            let names: Vec<String> = match name {
                Some(n) => vec![n.clone()],
                None => cfg.feeds.iter().filter(|f| f.enabled).map(|f| f.name.clone()).collect(),
            };
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => return print_err(&e),
            };
            let mut code = ExitCode::SUCCESS;
            for n in names {
                match rt.block_on(mgr.update(&n, *force)) {
                    Ok(u) => println!("{n}: {u:?}"),
                    Err(e) => {
                        eprintln!("{n}: {e}");
                        code = ExitCode::FAILURE;
                    }
                }
            }
            code
        }
        FeedsCommand::Rollback { name } => match mgr.rollback(name) {
            Ok(v) => {
                println!("{name}: active version is now {v}");
                ExitCode::SUCCESS
            }
            Err(e) => print_err(&e),
        },
        FeedsCommand::Test { url } => {
            let t = match webfilter::normalize::canonicalize(
                url,
                webfilter::normalize::TargetContext::PlainAbsolute,
            ) {
                Ok(t) => t,
                Err(e) => return print_err(&e),
            };
            let names: Vec<String> = cfg.feeds.iter().map(|f| f.name.clone()).collect();
            match mgr.check(
                &t,
                webfilter::filter::Phase::PreDns,
                &names,
                webfilter::config::Mode::Enforce,
            ) {
                Some(d) => {
                    println!("BLOCK {} ({})", d.rule_id.unwrap_or_default(), d.reason.as_str())
                }
                None => println!("no feed entry matches {}", t.url_norm),
            }
            ExitCode::SUCCESS
        }
    }
}

fn ca(cfg: &Config, command: &CaCommand) -> ExitCode {
    let dir = &cfg.tls.ca_dir;
    let result = match command {
        CaCommand::Generate => webfilter::tls::CaStore::generate(dir).map(|_| {
            eprintln!("CA created in {} (ca.key is 0600; never share or commit it)", dir.display());
        }),
        CaCommand::Export => webfilter::tls::CaStore::load(dir).map(|ca| print!("{}", ca.cert_pem)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Subcommand)]
enum BlocklistCommand {
    /// Show which rule (if any) a URL hits, without any network access.
    Test {
        /// Absolute http(s) URL.
        url: String,
    },
}

/// Load the file, apply CLI overrides, re-validate (CLI wins, SPEC 6).
fn load(cli: &Cli) -> Result<Config, ExitCode> {
    let invalid = |e: String| {
        eprintln!("error: {e}");
        ExitCode::from(EXIT_INVALID_CONFIG)
    };
    let mut cfg = Config::load(&cli.config).map_err(|e| invalid(e.to_string()))?;
    if let Some(listen) = cli.listen {
        cfg.listen = listen;
    }
    if let Some(mode) = cli.mode {
        cfg.mode = match mode {
            CliMode::Enforce => Mode::Enforce,
            CliMode::Monitor => Mode::Monitor,
        };
    }
    if let Some(dir) = &cli.log_dir {
        cfg.logging.dir = std::path::absolute(dir).map_err(|e| invalid(e.to_string()))?;
    }
    cfg.validate().map_err(|e| invalid(e.to_string()))?;
    Ok(cfg)
}

fn blocklist_test(cfg: &Config, url: &str) -> ExitCode {
    let lists = match Blocklists::load(&cfg.blocklists) {
        Ok((lists, _)) => lists,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_INVALID_CONFIG);
        }
    };
    let target = match canonicalize(url, TargetContext::PlainAbsolute) {
        Ok(t) => t,
        Err(e) => {
            println!("rejected: {} ({e})", e.reason());
            return ExitCode::SUCCESS;
        }
    };
    let mut decision = evaluate(&target, Phase::PreDns, &lists, &cfg.rules, cfg.mode);
    if let (false, Some(ip)) = (decision.is_block(), target.host.ip()) {
        decision = evaluate(&target, Phase::Resolved { ip }, &lists, &cfg.rules, cfg.mode);
    }
    println!("url:     {}", target.url_norm);
    println!("action:  {}", decision.action.as_str());
    println!("reason:  {}", decision.reason);
    println!("rule:    {}", decision.rule_id.as_deref().unwrap_or("-"));
    if target.suspicious_encoding {
        println!("note:    suspicious (double) encoding");
    }
    ExitCode::SUCCESS
}

fn hash_password() -> ExitCode {
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    let password = line.trim_end_matches(['\r', '\n']);
    if password.is_empty() {
        eprintln!("error: expected a password on stdin");
        return ExitCode::FAILURE;
    }
    match webfilter::auth::hash_password(password.as_bytes()) {
        Ok(hash) => {
            println!("{hash}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Serve until SIGINT/SIGTERM; SIGHUP reloads blocklists, SIGUSR1 reopens logs (D-31, D-67).
async fn serve(cfg: Config) -> std::io::Result<()> {
    let handle = webfilter::proxy::start(cfg, None).await?;
    eprintln!("webfilter-proxy listening on {}", handle.local_addr);
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (mut term, mut hup, mut usr1) = (
            signal(SignalKind::terminate())?,
            signal(SignalKind::hangup())?,
            signal(SignalKind::user_defined1())?,
        );
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = term.recv() => break,
                _ = hup.recv() => {
                    if let ReloadOutcome::Failed(e) = handle.deps.lists.reload() {
                        eprintln!("blocklist reload failed (previous lists kept): {e}");
                    }
                    if let Err(e) = handle.deps.reload_policies() {
                        eprintln!("policy reload failed (previous users/profiles kept): {e}");
                    }
                }
                _ = usr1.recv() => handle.deps.logger.reopen(),
            }
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    eprintln!("shutting down (draining connections)");
    handle.shutdown().await;
    Ok(())
}

fn run(cfg: Config) -> ExitCode {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.effective_worker_threads())
        .enable_all()
        .build();
    match runtime.and_then(|rt| rt.block_on(serve(cfg))) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match &cli.command {
        Some(Command::HashPassword) => hash_password(),
        Some(Command::Ca { command }) => load(&cli).map_or_else(|code| code, |c| ca(&c, command)),
        Some(Command::Feeds { command }) => {
            load(&cli).map_or_else(|code| code, |c| feeds(&c, command))
        }
        Some(Command::CheckConfig) => match load(&cli) {
            Ok(c) => {
                println!("config OK: {} (listen {})", cli.config.display(), c.listen);
                ExitCode::SUCCESS
            }
            Err(code) => code,
        },
        Some(Command::Blocklist { command: BlocklistCommand::Test { url } }) => {
            load(&cli).map_or_else(|code| code, |c| blocklist_test(&c, url))
        }
        Some(Command::Run) | None => load(&cli).map_or_else(|code| code, run),
    }
}
