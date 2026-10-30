//! Filtering decisions (SPEC 4.6): first match wins; monitor mode never blocks (D-33).
#![forbid(unsafe_code)]

use std::net::IpAddr;

use crate::blocklist::Blocklists;
use crate::config::{Mode, RuleConfig};
use crate::normalize::{Host, NormalizedTarget};
use crate::reason::Reason;

/// Evaluation phase: PreDns = rules 1,2,4,5; Resolved = rule 3; ResponseHeaders = rule 6.
#[derive(Debug, Clone, Copy)]
pub enum Phase<'a> {
    /// Before resolution.
    PreDns,
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

    fn block(mode: Mode, reason: Reason, rule_id: String, list: &str) -> Self {
        let monitor = mode == Mode::Monitor;
        Self {
            action: if monitor { Action::Allow } else { Action::Block },
            reason,
            rule_id: Some(rule_id),
            rule_list: Some(list.to_owned()),
            would_block: monitor,
        }
    }

    /// The request is blocked.
    pub fn is_block(&self) -> bool {
        self.action == Action::Block
    }
}

/// `host` equals an `allow_domains` entry or is a subdomain of it.
fn allowlisted(host: &Host, allow: &[String]) -> bool {
    let host = host.to_string();
    allow.iter().any(|e| {
        let e = e.trim().trim_end_matches('.').to_ascii_lowercase();
        let e = e.strip_prefix("*.").unwrap_or(&e);
        host == e || host.strip_suffix(e).is_some_and(|p| p.ends_with('.'))
    })
}

/// Final path segment ends with a blocked extension (case-insensitive; query already separate).
fn blocked_extension<'r>(path: &str, rules: &'r RuleConfig) -> Option<&'r str> {
    let last = path.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    rules.blocked_extensions.iter().map(String::as_str).find(|ext| {
        let ext = ext.to_ascii_lowercase();
        last.len() > ext.len() && last.ends_with(&ext)
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
    if allowlisted(&t.host, &rules.allow_domains) {
        return Decision::allowlisted();
    }
    let block = |reason, id: String, list| Decision::block(mode, reason, id, list);
    match phase {
        Phase::PreDns => {
            if let Some(entry) = t.host.domain().and_then(|d| lists.domains.matches(d)) {
                return block(Reason::DomainBlocklist, format!("domain:{entry}"), "domains.txt");
            }
            if let Some(id) = lists.patterns.matches(&t.views) {
                return block(Reason::UrlPattern, format!("url:{id}"), "url_patterns.txt");
            }
            if let Some(ext) = blocked_extension(&t.path, rules) {
                return block(
                    Reason::Extension,
                    format!("ext:{}", ext.to_ascii_lowercase()),
                    "config",
                );
            }
        }
        Phase::Resolved { ip } => {
            if let Some(net) = lists.ips.matches(ip) {
                return block(Reason::IpBlocklist, format!("ip:{net}"), "ip_blocklist.txt");
            }
        }
        Phase::ResponseHeaders { content_type: Some(ct) } => {
            let media = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            if rules.blocked_content_types.iter().any(|b| b.eq_ignore_ascii_case(&media)) {
                return block(Reason::ContentType, format!("ctype:{media}"), "config");
            }
        }
        Phase::ResponseHeaders { content_type: None } => {}
    }
    Decision::allow()
}
