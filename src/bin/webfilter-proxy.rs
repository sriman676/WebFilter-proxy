//! `webfilter-proxy`: filtering HTTP/HTTPS forward proxy (SPEC 4.13 CLI).
#![forbid(unsafe_code)]

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use webfilter::blocklist::Blocklists;
use webfilter::config::{Config, EXIT_INVALID_CONFIG};
use webfilter::filter::{Phase, evaluate};
use webfilter::normalize::{TargetContext, canonicalize};

#[derive(Parser)]
#[command(name = "webfilter-proxy", version, about = "Filtering HTTP/HTTPS forward proxy")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, global = true, default_value = "config/config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate the configuration and exit (0 = valid, 2 = invalid).
    CheckConfig,
    /// Run the proxy (implemented in Phase 2).
    Run,
    /// Blocklist tools.
    Blocklist {
        #[command(subcommand)]
        command: BlocklistCommand,
    },
    /// Read a password from stdin and print its argon2id hash for the config.
    HashPassword,
}

#[derive(Subcommand)]
enum BlocklistCommand {
    /// Show which rule (if any) a URL hits, without any network access.
    Test {
        /// Absolute http(s) URL.
        url: String,
    },
}

fn load(path: &Path) -> Result<Config, ExitCode> {
    Config::load(path).map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::from(EXIT_INVALID_CONFIG)
    })
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cfg = || load(&cli.config);
    match &cli.command {
        Command::HashPassword => hash_password(),
        Command::CheckConfig => match cfg() {
            Ok(c) => {
                println!("config OK: {} (listen {})", cli.config.display(), c.listen);
                ExitCode::SUCCESS
            }
            Err(code) => code,
        },
        Command::Blocklist { command: BlocklistCommand::Test { url } } => {
            cfg().map_or_else(|code| code, |c| blocklist_test(&c, url))
        }
        Command::Run => cfg().map_or_else(
            |code| code,
            |_| {
                eprintln!("TODO: `run` is implemented in Phase 2");
                ExitCode::FAILURE
            },
        ),
    }
}
