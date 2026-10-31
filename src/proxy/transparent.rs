//! Transparent mode (SPEC 4.17, D-41..D-44; Linux lab only): connections redirected by the lab's
//! nftables rules arrive without proxy settings. The original destination comes from an
//! [`OriginalDst`]; the filter uses Host/SNI for name rules and the original IP for IP rules, and
//! the upstream connection always goes to the original IP (D-42). Connections without a valid
//! redirected destination, or aimed at the proxy itself, are closed: never an open proxy.
#![forbid(unsafe_code)]

use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::Instant;

use super::ProxyDeps;
use super::connect::{intercept, open_tunnel, read_hello};
use super::http1::{RequestHead, single};
use super::pipeline::{
    Fail, Outcome, Tunnel, Via, connect_upstream, fail, note_decision, note_fail, note_target,
    note_transparent, resolved_rule, serve_connection,
};
use crate::config::{HostVerify, OrigDstMethod, TransparentAction};
use crate::filter::{Action, Phase};
use crate::logger::{RequestEvent, SysEvent};
use crate::normalize::{NormalizedTarget, TargetContext, canonicalize, fold_ip};
use crate::policy::{PortKind, check_port};
use crate::reason::Reason;
use crate::tls::is_passthrough;

/// Largest conntrack table read (bounded memory).
const MAX_CONNTRACK_BYTES: u64 = 16 * 1024 * 1024;

/// Where a redirected connection was going before the REDIRECT rule.
pub trait OriginalDst: Send + Sync {
    /// The original destination of the accepted connection `s`.
    fn original_dst(&self, s: &TcpStream) -> io::Result<SocketAddr>;
}

/// `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST` through `nix`'s safe socket options (D-41).
#[derive(Debug, Clone, Copy, Default)]
pub struct SoOriginalDst;

impl OriginalDst for SoOriginalDst {
    #[cfg(target_os = "linux")]
    fn original_dst(&self, s: &TcpStream) -> io::Result<SocketAddr> {
        use nix::sys::socket::{getsockopt, sockopt};
        let v4 = match s.local_addr()?.ip() {
            IpAddr::V4(_) => true,
            IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some(),
        };
        if v4 {
            let a = getsockopt(s, sockopt::OriginalDst).map_err(io::Error::from)?;
            let ip = std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            Ok(SocketAddr::from((ip, u16::from_be(a.sin_port))))
        } else {
            let a = getsockopt(s, sockopt::Ip6tOriginalDst).map_err(io::Error::from)?;
            let ip = std::net::Ipv6Addr::from(a.sin6_addr.s6_addr);
            Ok(SocketAddr::from((ip, u16::from_be(a.sin6_port))))
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn original_dst(&self, _: &TcpStream) -> io::Result<SocketAddr> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Fallback: look the connection up in `/proc/net/nf_conntrack`.
#[derive(Debug, Clone)]
pub struct ConntrackOriginalDst {
    /// The conntrack table file.
    pub path: PathBuf,
}

impl Default for ConntrackOriginalDst {
    fn default() -> Self {
        Self { path: PathBuf::from("/proc/net/nf_conntrack") }
    }
}

impl OriginalDst for ConntrackOriginalDst {
    fn original_dst(&self, s: &TcpStream) -> io::Result<SocketAddr> {
        let mut table = String::new();
        std::fs::File::open(&self.path)?.take(MAX_CONNTRACK_BYTES).read_to_string(&mut table)?;
        parse_conntrack(&table, s.peer_addr()?, s.local_addr()?)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
}

/// A fixed original destination (tests, D-43; `WEBFILTER_TEST_ORIG_DST` under `insecure-test`).
#[derive(Debug, Clone, Copy)]
pub struct FixedOriginalDst(pub SocketAddr);

impl OriginalDst for FixedOriginalDst {
    fn original_dst(&self, _: &TcpStream) -> io::Result<SocketAddr> {
        Ok(self.0)
    }
}

/// Find the original destination of `peer` -> `local` in a conntrack table: the entry whose
/// original tuple starts at `peer` and whose reply tuple comes from `local`'s port.
pub fn parse_conntrack(table: &str, peer: SocketAddr, local: SocketAddr) -> Option<SocketAddr> {
    let peer_ip = fold_ip(peer.ip());
    table.lines().find_map(|line| {
        let mut tuples: [[Option<&str>; 4]; 2] = [[None; 4]; 2];
        for token in line.split_ascii_whitespace() {
            let Some((key, value)) = token.split_once('=') else { continue };
            let Some(slot) = ["src", "dst", "sport", "dport"].iter().position(|k| *k == key) else {
                continue;
            };
            // The first occurrence belongs to the original tuple, the second to the reply.
            if let Some(cell) =
                tuples.iter_mut().find_map(|t| t.get_mut(slot).filter(|c| c.is_none()))
            {
                *cell = Some(value);
            }
        }
        let [[Some(src), Some(dst), Some(sport), Some(dport)], [_, _, Some(reply_sport), _]] =
            tuples
        else {
            return None;
        };
        let src: IpAddr = src.parse().ok()?;
        let matches = fold_ip(src) == peer_ip
            && sport.parse::<u16>().ok()? == peer.port()
            && reply_sport.parse::<u16>().ok()? == local.port();
        matches.then(|| Some(SocketAddr::new(fold_ip(dst.parse().ok()?), dport.parse().ok()?)))?
    })
}

/// The configured original-destination source.
pub fn original_dst_source(method: OrigDstMethod) -> Arc<dyn OriginalDst> {
    #[cfg(feature = "insecure-test")]
    if let Some(addr) =
        std::env::var("WEBFILTER_TEST_ORIG_DST").ok().and_then(|v| v.parse::<SocketAddr>().ok())
    {
        return Arc::new(FixedOriginalDst(addr));
    }
    match method {
        OrigDstMethod::SoOriginalDst => Arc::new(SoOriginalDst),
        OrigDstMethod::Conntrack => Arc::new(ConntrackOriginalDst::default()),
    }
}

/// Serve one connection accepted on a transparent listener.
pub(crate) async fn serve(stream: TcpStream, peer: SocketAddr, deps: Arc<ProxyDeps>, tls: bool) {
    let orig = match original(&stream, &deps) {
        Ok(orig) => orig,
        Err(why) => {
            // A direct (un-redirected) connection or a loop: never proxy it (E-48, PT-7.1).
            deps.logger.system().event(
                SysEvent::OrigDstFailed,
                serde_json::json!({ "peer": peer.ip().to_string(), "error": why }),
            );
            return;
        }
    };
    if tls {
        serve_tls(stream, peer, orig, &deps).await;
    } else {
        serve_connection(stream, peer, Arc::clone(&deps), Via::Transparent(orig)).await;
    }
}

fn original(stream: &TcpStream, deps: &ProxyDeps) -> Result<SocketAddr, &'static str> {
    let orig = deps.orig_dst.original_dst(stream).map_err(|_| "no original destination")?;
    let local = stream.local_addr().map_err(|_| "no local address")?;
    let own = fold_ip(orig.ip()) == fold_ip(local.ip()) && orig.port() == local.port();
    if own || deps.policy.check_ip(orig.ip(), orig.port()) == Err(Reason::LoopDetected) {
        return Err("original destination is the proxy itself");
    }
    Ok(SocketAddr::new(fold_ip(orig.ip()), orig.port()))
}

/// Transparent HTTP target: exactly one `Host`, origin-form, port = original port (SPEC 4.17).
pub fn http_target(head: &RequestHead, orig: SocketAddr) -> Result<NormalizedTarget, Fail> {
    let invalid = |e: &'static str| fail(400, Reason::InvalidRequest, e);
    let host = single(&head.headers, "host").ok_or(invalid("transparent requests need a Host"))?;
    let host = std::str::from_utf8(host).map_err(|_| invalid("Host is not UTF-8"))?;
    let h =
        canonicalize(&format!("http://{host}/"), TargetContext::PlainAbsolute).map_err(|e| {
            fail(
                if e.reason() == Reason::UserinfoInUrl { 403 } else { 400 },
                e.reason(),
                "invalid Host",
            )
        })?;
    let explicit_port = match host.rfind(']') {
        Some(i) => host.get(i + 1..).is_some_and(|rest| rest.starts_with(':')),
        None => host.contains(':'),
    };
    if explicit_port && h.port != orig.port() {
        return Err(fail(403, Reason::HostMismatch, "Host port differs from the original port"));
    }
    let name = h.host.to_string();
    let name = name.trim_start_matches('[').trim_end_matches(']');
    canonicalize(&head.target, TargetContext::TransparentHost { host: name, port: orig.port() })
        .map_err(|e| {
            fail(
                if e.reason() == Reason::UserinfoInUrl { 403 } else { 400 },
                e.reason(),
                "invalid request target",
            )
        })
}

/// D-42: the Host/SNI name must resolve to the original IP (`strict`), or is only logged
/// (`relaxed`, `host_verified=false`).
pub(crate) async fn verify_host(
    t: &NormalizedTarget,
    orig: IpAddr,
    ev: &mut RequestEvent,
    deps: &ProxyDeps,
) -> Result<(), Fail> {
    let orig = fold_ip(orig);
    let verified = match (t.host.ip(), t.host.domain()) {
        (Some(ip), _) => fold_ip(ip) == orig,
        (None, Some(name)) => deps
            .resolver
            .resolve(name, t.port)
            .await
            .is_ok_and(|ips| ips.into_iter().any(|ip| fold_ip(ip) == orig)),
        (None, None) => false,
    };
    ev.host_verified = Some(verified);
    if !verified && deps.cfg.transparent.host_verify == HostVerify::Strict {
        return Err(fail(
            403,
            Reason::HostMismatch,
            "Host/SNI does not resolve to the original destination (D-42)",
        ));
    }
    Ok(())
}

/// Transparent TLS: one connection-level event, like a CONNECT tunnel.
async fn serve_tls(
    mut client: TcpStream,
    peer: SocketAddr,
    orig: SocketAddr,
    deps: &Arc<ProxyDeps>,
) {
    let started = Instant::now();
    let mut ev = deps.new_event(peer);
    note_transparent(&mut ev, orig);
    ev.http_method = "CONNECT".into();
    ev.url_scheme = "https".into();
    ev.dest_port = orig.port();
    let mut buf = Vec::new();
    if let Err(f) = tls_flow(&mut client, &mut buf, orig, &mut ev, deps, peer).await {
        note_fail(&mut ev, &Fail { status: None, ..f });
    }
    ev.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    deps.finish(ev);
}

async fn tls_flow(
    client: &mut TcpStream,
    buf: &mut Vec<u8>,
    orig: SocketAddr,
    ev: &mut RequestEvent,
    deps: &Arc<ProxyDeps>,
    peer: SocketAddr,
) -> Result<Outcome, Fail> {
    let cfg = &deps.cfg.transparent;
    let refuse = |reason: Reason, error: &'static str| Fail { status: None, reason, error };
    check_port(PortKind::Connect, orig.port(), &deps.cfg.ports)
        .map_err(|r| refuse(r, "port not allowed"))?;
    deps.policy
        .check_ip(orig.ip(), orig.port())
        .map_err(|r| refuse(r, "destination not allowed"))?;
    let handshake = Duration::from_secs(deps.cfg.timeouts.tls_handshake);
    let Some(hello) = read_hello(client, buf, Instant::now() + handshake).await? else {
        ev.action = Action::Block.as_str();
        return Err(refuse(Reason::NonTlsOnConnect, "non-TLS bytes on the transparent TLS port"));
    };
    ev.tls_sni.clone_from(&hello.sni);
    ev.ech_present = hello.ech_present;
    let mut act = |action: TransparentAction, reason: Reason, error: &'static str| match action {
        TransparentAction::Block => {
            ev.action = Action::Block.as_str();
            Err(refuse(reason, error))
        }
        TransparentAction::IpOnly => Ok(true),
    };
    let ip_only = if hello.ech_present {
        act(cfg.ech_action, Reason::EchBlocked, "ECH hides the server name (R-05)")?
    } else if hello.sni.is_none() {
        act(cfg.no_sni_action, Reason::NoSni, "ClientHello without SNI")?
    } else {
        false
    };
    let ip = orig.ip();
    let authority = |host: &str| {
        if host.contains(':') {
            format!("[{host}]:{}", orig.port())
        } else {
            format!("{host}:{}", orig.port())
        }
    };
    if ip_only {
        // No usable name: IP rules only, then an opaque relay to the original destination.
        let t = canonicalize(&authority(&ip.to_string()), TargetContext::ConnectAuthority)
            .map_err(|e| refuse(e.reason(), "invalid original destination"))?;
        note_target(ev, &t);
        let d = deps.evaluate(&t, Phase::Resolved { ip });
        note_decision(ev, &d);
        if d.is_block() {
            return Ok(Outcome::Done);
        }
        return passthrough(client, buf, orig, ev, deps).await;
    }
    let sni = hello.sni.as_deref().unwrap_or_default();
    let t = canonicalize(&authority(sni), TargetContext::ConnectAuthority)
        .map_err(|e| refuse(e.reason(), "invalid SNI"))?;
    note_target(ev, &t);
    ev.url_scheme = "https".into();
    let d = deps.evaluate(&t, Phase::ConnectPreDns);
    note_decision(ev, &d);
    if d.is_block() {
        return Ok(Outcome::Done); // nothing can be shown before the handshake: close
    }
    verify_host(&t, ip, ev, deps).await?;
    if let Some(d) = resolved_rule(deps, &t, &[ip]) {
        note_decision(ev, &d);
        if d.is_block() {
            return Ok(Outcome::Done);
        }
    }
    if deps.leaves.is_some()
        && !is_passthrough(&t.host.to_string(), &deps.cfg.tls.passthrough_domains)
    {
        let tunnel = Tunnel {
            host: t.host.clone(),
            port: t.port,
            ips: vec![ip],
            sni: None,
            ech: false,
            user: None,
            orig_dst: Some(orig),
            host_verified: ev.host_verified,
        };
        return intercept(client, buf, hello, tunnel, ev, deps, peer).await;
    }
    passthrough(client, buf, orig, ev, deps).await
}

/// Relay to the original destination, replaying the captured ClientHello first.
async fn passthrough(
    client: &mut TcpStream,
    buf: &mut Vec<u8>,
    orig: SocketAddr,
    ev: &mut RequestEvent,
    deps: &ProxyDeps,
) -> Result<Outcome, Fail> {
    let (mut upstream, ip) = connect_upstream(&[orig.ip()], orig.port(), deps).await?;
    ev.dest_ip = Some(ip.to_string());
    open_tunnel(client, buf, &mut upstream, b"", ev, deps).await
}
