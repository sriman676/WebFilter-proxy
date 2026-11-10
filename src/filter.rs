//! Filtering decisions (SPEC 4.6): first match wins; monitor mode never blocks (D-33).
#![forbid(unsafe_code)]

use std::net::IpAddr;

use crate::blocklist::{Blocklists, DomainSet, IpSet, PatternSet};
use crate::config::{Mode, RuleConfig};
use crate::normalize::{Host, NormalizedTarget};
use crate::reason::Reason;

/// Evaluation phase: PreDns = rules 1,2,4,5; ConnectPreDns = rules 1,2 (passthrough tunnels see
/// no URL); Resolved = rule 3; ResponseHeaders = rule 6.
#[derive(Debug, Clone, Copy)]
pub enum Phase<'a> {
    /// Before resolution.
    PreDns,
    /// Before resolution of a passthrough CONNECT.
    ConnectPreDns,
    /// For each resolved (or literal) destination IP.
    Resolved {
        /// Destination IP.
        ip: IpAddr,
    },
    /// After the upstream response head.
    ResponseHeaders {
        /// Raw `Content-Type` header value.
        content_type: Option<&'a str>,
    },
}

/// Allow or block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Forward.
    Allow,
    /// Block with 403.
    Block,
}

impl Action {
    /// `allowed` / `blocked` (log `action` field).
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allowed",
            Action::Block => "blocked",
        }
    }
}

/// A filtering decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Final action (always `Allow` in monitor mode).
    pub action: Action,
    /// Why.
    pub reason: Reason,
    /// e.g. `domain:evil.com`, `url:rx-007`, `ip:10.0.0.0/8`, `ext:.exe`, `allowlist`.
    pub rule_id: Option<String>,
    /// List file name or `config`.
    pub rule_list: Option<String>,
    /// A rule matched but monitor mode allowed the request.
    pub would_block: bool,
    /// List category of the matching rule (A-27).
    pub category: Option<String>,
}

impl Decision {
    /// Default allow (rule 7).
    pub fn allow() -> Self {
        Self {
            action: Action::Allow,
            reason: Reason::None,
            rule_id: None,
            rule_list: None,
            would_block: false,
            category: None,
        }
    }

    fn allowlisted() -> Self {
        Self {
            reason: Reason::Allowlist,
            rule_id: Some("allowlist".into()),
            rule_list: Some("config".into()),
            ..Self::allow()
        }
    }

    /// A block (or a would-block in monitor mode) by `rule_id` from `list`.
    pub fn block(mode: Mode, reason: Reason, rule_id: String, list: &str) -> Self {
        let monitor = mode == Mode::Monitor;
        Self {
            action: if monitor { Action::Allow } else { Action::Block },
            reason,
            rule_id: Some(rule_id),
            rule_list: Some(list.to_owned()),
            would_block: monitor,
            category: None,
        }
    }

    /// The request is blocked.
    pub fn is_block(&self) -> bool {
        self.action == Action::Block
    }
}

/// `allow_domains` match with the domains.txt forms: `x.com` = apex + subdomains, `*.x.com` =
/// subdomains only, `=x.com` = exact. IP hosts match only an identical entry (PF-1-09).
fn allowlisted(host: &Host, allow: &[String]) -> bool {
    let host_str = host.to_string();
    allow.iter().any(|e| {
        let e = e.trim().trim_end_matches('.').to_ascii_lowercase();
        let is_sub = |base: &str| host_str.strip_suffix(base).is_some_and(|p| p.ends_with('.'));
        match (host, e.strip_prefix("*."), e.strip_prefix('=')) {
            (Host::Domain(_), Some(base), _) => is_sub(base),
            (Host::Domain(_), _, Some(exact)) => host_str == exact,
            (Host::Domain(_), None, None) => host_str == e || is_sub(&e),
            _ => host_str == e || host.ip().is_some_and(|ip| ip.to_string() == e),
        }
    })
}

/// Final path segment (trailing dots ignored, as Windows does) ends with a blocked extension;
/// empty entries never match (PF-1-10).
fn blocked_extension<'r>(path: &str, rules: &'r RuleConfig) -> Option<&'r str> {
    let last = path.rsplit('/').next().unwrap_or("").trim_end_matches('.').to_ascii_lowercase();
    rules.blocked_extensions.iter().map(String::as_str).find(|ext| {
        let ext = ext.trim().to_ascii_lowercase();
        ext.len() > 1 && last.len() > ext.len() && last.ends_with(&ext)
    })
}

/// Evaluate the rules for one phase. The allowlist bypasses rules 2-6 only, never validation or
/// destination policy (those run outside this function).
pub fn evaluate(
    t: &NormalizedTarget,
    phase: Phase<'_>,
    lists: &Blocklists,
    rules: &RuleConfig,
    mode: Mode,
) -> Decision {
    evaluate_at(t, phase, lists, rules, mode, time::OffsetDateTime::now_utc())
}

/// [`evaluate`] at a given time (category schedules, A-27). Order: allowlist, default lists,
/// config extension/content-type rules, then each enabled category active at `now`.
pub fn evaluate_at(
    t: &NormalizedTarget,
    phase: Phase<'_>,
    lists: &Blocklists,
    rules: &RuleConfig,
    mode: Mode,
    now: time::OffsetDateTime,
) -> Decision {
    if allowlisted(&t.host, &rules.allow_domains) {
        return Decision::allowlisted();
    }
    let defaults = ["domains.txt", "url_patterns.txt", "ip_blocklist.txt"];
    if let Some(d) =
        match_lists(t, phase, (&lists.domains, &lists.patterns, &lists.ips), defaults, mode)
    {
        return d;
    }
    let block = |reason, id: String| Decision::block(mode, reason, id, "config");
    match phase {
        Phase::PreDns => {
            if let Some(ext) = blocked_extension(&t.path, rules) {
                return block(Reason::Extension, format!("ext:{}", ext.to_ascii_lowercase()));
            }
        }
        Phase::ResponseHeaders { content_type: Some(ct) } => {
            let media = crate::util::media_type(ct).to_ascii_lowercase();
            if rules.blocked_content_types.iter().any(|b| b.eq_ignore_ascii_case(&media)) {
                return block(Reason::ContentType, format!("ctype:{media}"));
            }
        }
        _ => {}
    }
    for cat in lists.categories.iter().filter(|c| c.enabled && c.schedule.is_active(now)) {
        let l = &cat.lists;
        let files = [l.files[0].as_str(), l.files[1].as_str(), l.files[2].as_str()];
        if let Some(d) = match_lists(t, phase, (&l.domains, &l.patterns, &l.ips), files, mode) {
            return Decision { category: Some(cat.name.clone()), ..d };
        }
    }
    Decision::allow()
}

/// Rules 2-4 against one list triple for the given phase.
/// [`evaluate_at`] with a profile (D-50): its effective rules and mode, then its extra lists.
/// Profiles only change list rules; safety policy is checked elsewhere and never here.
pub fn evaluate_profile(
    t: &NormalizedTarget,
    phase: Phase<'_>,
    lists: &Blocklists,
    profile: &crate::profiles::Profile,
    now: time::OffsetDateTime,
) -> Decision {
    let d = evaluate_at(t, phase, lists, &profile.rules, profile.mode, now);
    if d.reason != Reason::None {
        return d;
    }
    let Some(extra) = &profile.extra else { return d };
    let files = [extra.files[0].as_str(), extra.files[1].as_str(), extra.files[2].as_str()];
    match_lists(t, phase, (&extra.domains, &extra.patterns, &extra.ips), files, profile.mode)
        .unwrap_or(d)
}

fn match_lists(
    t: &NormalizedTarget,
    phase: Phase<'_>,
    (domains, patterns, ips): (&DomainSet, &PatternSet, &IpSet),
    files: [&str; 3],
    mode: Mode,
) -> Option<Decision> {
    let block = |reason, id: String, list| Some(Decision::block(mode, reason, id, list));
    let domain = || t.host.domain().and_then(|d| domains.matches(d));
    match phase {
        Phase::ConnectPreDns | Phase::PreDns if let Some(entry) = domain() => {
            block(Reason::DomainBlocklist, format!("domain:{entry}"), files[0])
        }
        Phase::PreDns => patterns
            .matches(&t.views)
            .and_then(|id| block(Reason::UrlPattern, format!("url:{id}"), files[1])),
        Phase::Resolved { ip } => ips
            .matches(ip)
            .and_then(|net| block(Reason::IpBlocklist, format!("ip:{net}"), files[2])),
        _ => None,
    }
}
