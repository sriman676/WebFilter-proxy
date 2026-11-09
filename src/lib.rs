//! WebFilter: a filtering HTTP/HTTPS forward proxy and a client that fetches URLs through it.
//!
//! Behaviour is specified in `docs/SPEC.md`; module contracts in `docs/INTERFACES.md`.
#![forbid(unsafe_code)]

pub mod auth;
pub mod blocklist;
pub mod client;
pub mod config;
pub mod feeds;
pub mod filter;
pub mod limiter;
pub mod logger;
pub mod naming;
pub mod normalize;
pub mod policy;
pub mod profiles;
pub mod proxy;
pub mod reason;
pub mod scan;
pub mod schedule;
pub mod tls;
