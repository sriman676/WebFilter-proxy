//! robots.txt (RFC 9309) for the crawler (SPEC_EXT_CLIENT C4, D-62): groups by user-agent (the
//! most specific matching group wins, else `*`), Allow/Disallow with `*` and `$`, longest match
//! wins (Allow on ties), `Crawl-delay` as a minimum delay. Only the first 512 KiB are parsed.
#![forbid(unsafe_code)]

use std::time::Duration;

/// Parsed bytes cap (RFC 9309 requires at least 500 KiB).
pub const MAX_BYTES: usize = 512 * 1024;

#[derive(Debug, Default, Clone)]
struct Group {
    agents: Vec<String>,
    rules: Vec<(bool, String)>, // (allow, pattern)
    delay: Option<f64>,
}

/// Rules for one host.
#[derive(Debug, Default, Clone)]
pub struct Robots {
    groups: Vec<Group>,
    disallow_all: bool,
}

impl Robots {
    /// Everything allowed (missing robots.txt, 4xx).
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Everything disallowed for this run (5xx, timeouts: RFC 9309 "unreachable").
    pub fn disallow_all() -> Self {
        Self { groups: Vec::new(), disallow_all: true }
    }

    /// Parse robots.txt text (BOM, CRLF, comments and invalid lines tolerated).
    pub fn parse(text: &str) -> Self {
        let mut end = text.len().min(MAX_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let text = text.get(..end).unwrap_or("");
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut groups: Vec<Group> = Vec::new();
        let mut current: Option<Group> = None;
        let mut in_agents = false;
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            let Some((key, value)) = line.split_once(':') else { continue };
            let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
            match key.as_str() {
                "user-agent" => {
                    if !in_agents && let Some(g) = current.take() {
                        groups.push(g);
                    }
                    current
                        .get_or_insert_with(Group::default)
                        .agents
                        .push(value.to_ascii_lowercase());
                    in_agents = true;
                }
                "allow" | "disallow" => {
                    in_agents = false;
                    if let Some(g) = current.as_mut()
                        && !value.is_empty()
                    {
                        g.rules.push((key == "allow", value.to_owned()));
                    }
                }
                "crawl-delay" => {
                    in_agents = false;
                    if let (Some(g), Ok(d)) = (current.as_mut(), value.parse::<f64>())
                        && d.is_finite()
                        && d >= 0.0
                    {
                        g.delay = Some(d.min(60.0));
                    }
                }
                _ => {}
            }
        }
        groups.extend(current);
        Self { groups, disallow_all: false }
    }

    fn group(&self, agent: &str) -> Option<&Group> {
        let agent = agent.to_ascii_lowercase();
        let token = agent.split('/').next().unwrap_or("");
        self.groups
            .iter()
            .filter(|g| {
                g.agents.iter().any(|a| a != "*" && !a.is_empty() && token.contains(a.as_str()))
            })
            .max_by_key(|g| g.agents.iter().map(String::len).max().unwrap_or(0))
            .or_else(|| self.groups.iter().find(|g| g.agents.iter().any(|a| a == "*")))
    }

    /// Whether `agent` may fetch `path` (path plus query, starting with `/`).
    pub fn allowed(&self, agent: &str, path: &str) -> bool {
        if self.disallow_all {
            return false;
        }
        let Some(g) = self.group(agent) else { return true };
        let best = g
            .rules
            .iter()
            .filter(|(_, p)| matches(p, path))
            .max_by(|a, b| a.1.len().cmp(&b.1.len()).then(a.0.cmp(&b.0)));
        best.is_none_or(|(allow, _)| *allow)
    }

    /// `Crawl-delay` for `agent`.
    pub fn delay(&self, agent: &str) -> Option<Duration> {
        self.group(agent).and_then(|g| g.delay).map(Duration::from_secs_f64)
    }
}

/// Pattern match with `*` (any run) and a trailing `$` (end anchor); otherwise a prefix match.
fn matches(pattern: &str, path: &str) -> bool {
    let (pattern, anchored) = match pattern.strip_suffix('$') {
        Some(p) => (p, true),
        None => (pattern, false),
    };
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        let rest = path.get(pos..).unwrap_or("");
        if i == 0 {
            if !rest.starts_with(part) {
                return false;
            }
            pos += part.len();
        } else if let Some(at) = rest.find(part) {
            pos += at + part.len();
        } else {
            return false;
        }
    }
    if !anchored {
        return true;
    }
    // Anchored: the last literal part must end the path.
    let last = parts.last().copied().unwrap_or("");
    pos == path.len() || (parts.len() > 1 && path.ends_with(last))
}
