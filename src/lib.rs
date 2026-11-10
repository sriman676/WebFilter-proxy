//! WebFilter: a filtering HTTP/HTTPS forward proxy and a client that fetches URLs through it.
//!
//! Behaviour is specified in `docs/SPEC.md`; module contracts in `docs/INTERFACES.md`.
#![forbid(unsafe_code)]

pub mod access;
pub mod admin;
pub mod auth;
pub mod batch;
pub mod blocklist;
pub mod client;
pub mod config;
pub mod crawl;
pub mod doctor;
pub mod feeds;
pub mod filter;
pub mod limiter;
pub mod logger;
pub mod naming;
pub mod normalize;
pub mod plugins;
pub mod policy;
pub mod profiles;
pub mod proxy;
pub mod reason;
pub mod robots;
pub mod scan;
pub mod schedule;
pub mod snapshot;
pub mod telemetry;
pub mod tls;
pub mod tui;
pub mod util;
