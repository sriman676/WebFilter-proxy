//! WebFilter: a filtering HTTP/HTTPS forward proxy and a client that fetches URLs through it.
//!
//! Behaviour is specified in `docs/SPEC.md`; module contracts in `docs/INTERFACES.md`.
#![forbid(unsafe_code)]

pub mod auth;
pub mod blocklist;
pub mod config;
pub mod filter;
pub mod logger;
pub mod naming;
pub mod normalize;
pub mod policy;
pub mod reason;
