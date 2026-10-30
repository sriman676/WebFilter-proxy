//! `webfilter-proxy`: filtering HTTP/HTTPS forward proxy (SPEC 4.13 CLI).
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use webfilter::config::{Config, EXIT_INVALID_CONFIG};

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
    /// Run the proxy (implemented in Phase 1).
    Run,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cfg = match Config::load(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_INVALID_CONFIG);
        }
    };
    match cli.command {
        Command::CheckConfig => {
            println!("config OK: {} (listen {})", cli.config.display(), cfg.listen);
            ExitCode::SUCCESS
        }
        Command::Run => {
            eprintln!("TODO: `run` is implemented in Phase 1");
            ExitCode::FAILURE
        }
    }
}
