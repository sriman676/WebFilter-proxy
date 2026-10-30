//! `webfilter-client`: fetches URLs through the proxy and saves named HTML files (SPEC 5).
#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;

#[derive(Parser)]
#[command(name = "webfilter-client", version, about = "Fetch URLs through the WebFilter proxy")]
struct Cli {
    /// URLs to fetch.
    urls: Vec<String>,
}

fn main() -> ExitCode {
    let _cli = Cli::parse();
    eprintln!("TODO: the client is implemented in Phase 2");
    ExitCode::FAILURE
}
