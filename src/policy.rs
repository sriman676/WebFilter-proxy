//! Destination and port policy (D-11, D-12): resolve once, validate every IP, never re-resolve.
#![forbid(unsafe_code)]

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;

use crate::config::PortConfig;
use crate::normalize::{NormalizedTarget, fold_ip};
use crate::reason::Reason;

/// Maximum resolved addresses considered per name.
pub const MAX_RESOLVED: usize = 32;

/// Plain HTTP request or CONNECT tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortKind {
    /// Absolute-form HTTP request.
    Http,
    /// CONNECT.
    Connect,
}

/// Port policy (D-12).
pub fn check_port(kind: PortKind, port: u16, cfg: &PortConfig) -> Result<(), Reason> {
    let set = match kind {
        PortKind::Http => &cfg.http_allowed,
        PortKind::Connect => &cfg.connect_allowed,
    };
    if set.allows(port) { Ok(()) } else { Err(Reason::PortNotAllowed) }
}

/// IPv4 embedded in an IPv6 transition address: NAT64 `64:ff9b::/96`, IPv4-compatible
/// `::a.b.c.d`, 6to4 `2002::/16`, Teredo `2001::/32` (client address, bit-inverted). Such
/// addresses reach that IPv4, so policy checks it too (PF-1-04).
pub fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let o = v6.octets();
    let last = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    match v6.segments() {
        [0x64, 0xff9b, 0, 0, 0, 0, _, _] => Some(last),
        [0, 0, 0, 0, 0, 0, _, _] if !v6.is_loopback() && !v6.is_unspecified() => Some(last),
        [0x2002, hi, lo, ..] => Some(Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo))),
        [0x2001, 0, ..] => Some(Ipv4Addr::from(!u32::from(last))),
        _ => None,
    }
}

/// Always denied regardless of configuration: metadata endpoints (AWS/GCP/Azure link-local,
/// AWS IPv6, Oracle, Alibaba) and `0.0.0.0/8`, also when embedded in IPv6 (D-11).
pub fn is_always_denied(ip: IpAddr) -> bool {
    match fold_ip(ip) {
        IpAddr::V4(v4) => {
            v4.is_link_local()
                || v4.octets()[0] == 0
                || v4 == Ipv4Addr::new(192, 0, 0, 192)
                || v4 == Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(v6) => {
            v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)
                || embedded_ipv4(v6).is_some_and(|v4| is_always_denied(IpAddr::V4(v4)))
        }
    }
}

/// Loopback, RFC 1918, CGNAT, link-local, ULA, site-local, multicast, unspecified,
/// IETF/reserved/benchmark/documentation ranges, NAT64 local-use, and transition addresses
/// embedding any of these (D-11).
pub fn is_private(ip: IpAddr) -> bool {
    match fold_ip(ip) {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || (a == 100 && (b & 0xc0) == 64) // CGNAT 100.64/10
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || (a, b, c) == (192, 0, 0) // IETF protocol assignments 192.0.0/24
                || a >= 240 // reserved 240/4 incl. broadcast
                || (a == 198 && (b & 0xfe) == 18) // benchmarking 198.18/15
                || matches!((a, b, c), (192, 0, 2) | (198, 51, 100) | (203, 0, 113)) // TEST-NETs
        }
        IpAddr::V6(v6) => {
            let [s0, s1, s2, ..] = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s0 & 0xffc0) == 0xfe80 // link-local
                || (s0 & 0xfe00) == 0xfc00 // ULA
                || (s0 & 0xffc0) == 0xfec0 // deprecated site-local fec0::/10
                || (s0, s1) == (0x2001, 0xdb8) // documentation 2001:db8::/32
                || (s0, s1, s2) == (0x64, 0xff9b, 1) // NAT64 local-use 64:ff9b:1::/48
                || embedded_ipv4(v6).is_some_and(|v4| is_private(IpAddr::V4(v4)))
        }
    }
}

/// Destination policy for resolved addresses.
#[derive(Debug, Clone)]
pub struct DestPolicy {
    deny_private: bool,
    own: Vec<SocketAddr>,
}

impl DestPolicy {
    /// `own` = the proxy's listen addresses (loop detection).
    pub fn new(deny_private: bool, own: Vec<SocketAddr>) -> Self {
        Self { deny_private, own }
    }

    /// Check one destination address.
    pub fn check_ip(&self, ip: IpAddr, port: u16) -> Result<(), Reason> {
        let ip = fold_ip(ip);
        let is_own = |a: &SocketAddr| {
            let own_ip = fold_ip(a.ip());
            a.port() == port
                && (own_ip == ip
                    || (own_ip.is_unspecified() && (ip.is_loopback() || ip.is_unspecified())))
        };
        if self.own.iter().any(is_own) {
            return Err(Reason::LoopDetected);
        }
        if is_always_denied(ip) || (self.deny_private && is_private(ip)) {
            return Err(Reason::PrivateRange);
        }
        Ok(())
    }
}

/// Boxed future returned by [`Resolver::resolve`].
pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;

/// Name resolution, injectable for tests (TEST_PLAN `TestResolver`).
pub trait Resolver: Send + Sync {
    /// Resolve `host` once.
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a>;
}

/// The system resolver (`getaddrinfo` via tokio).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host, port)).await?.map(|a| a.ip()).collect())
        })
    }
}

/// `WEBFILTER_TEST_HOSTS="name=ip,name=ip"`: a static resolver for the netns lab (D-44). Only in
/// `insecure-test` builds; release builds always use the system resolver.
pub fn test_hosts_resolver() -> Option<std::sync::Arc<dyn Resolver>> {
    #[cfg(feature = "insecure-test")]
    if let Ok(spec) = std::env::var("WEBFILTER_TEST_HOSTS") {
        return Some(std::sync::Arc::new(StaticResolver::parse(&spec)));
    }
    None
}

/// A fixed name table (tests and the netns lab).
#[derive(Debug, Clone, Default)]
pub struct StaticResolver(pub std::collections::HashMap<String, Vec<IpAddr>>);

impl StaticResolver {
    /// Parse `name=ip,name=ip`; malformed entries are skipped.
    pub fn parse(spec: &str) -> Self {
        let mut map = std::collections::HashMap::<String, Vec<IpAddr>>::new();
        for (name, ip) in spec.split(',').filter_map(|kv| kv.split_once('=')) {
            if let Ok(ip) = ip.trim().parse() {
                map.entry(name.trim().to_ascii_lowercase()).or_default().push(ip);
            }
        }
        Self(map)
    }
}

impl Resolver for StaticResolver {
    fn resolve<'a>(&'a self, host: &'a str, _port: u16) -> ResolveFuture<'a> {
        let found = self.0.get(&host.to_ascii_lowercase()).cloned();
        Box::pin(async move { found.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound)) })
    }
}

/// Destination verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// All resolved addresses passed; connect to them in order, never re-resolve (D-11, D-38).
    Allow(Vec<IpAddr>),
    /// Denied.
    Deny(Reason),
}

/// Resolve the target once and validate ALL addresses (one bad address denies the request).
pub async fn check_destination(
    t: &NormalizedTarget,
    r: &dyn Resolver,
    p: &DestPolicy,
) -> PolicyVerdict {
    let ips = match (t.host.ip(), t.host.domain()) {
        (Some(ip), _) => vec![ip],
        (None, Some(name)) => match r.resolve(name, t.port).await {
            Ok(ips) => ips,
            Err(_) => return PolicyVerdict::Deny(Reason::UpstreamError),
        },
        (None, None) => return PolicyVerdict::Deny(Reason::InvalidRequest),
    };
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in ips.into_iter().map(fold_ip) {
        if let Err(reason) = p.check_ip(ip, t.port) {
            return PolicyVerdict::Deny(reason);
        }
        if !out.contains(&ip) && out.len() < MAX_RESOLVED {
            out.push(ip);
        }
    }
    if out.is_empty() {
        PolicyVerdict::Deny(Reason::UpstreamError)
    } else {
        PolicyVerdict::Allow(out)
    }
}
