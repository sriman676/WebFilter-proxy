//! Client identity and profiles (SPEC_EXT_POLICY P1, D-50): `client_id` per request, users,
//! CIDR clients (longest prefix wins) and profiles that add lists, allowlists and limits but never
//! weaken safety policy. Built from the config and swapped atomically on reload.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use crate::blocklist::{ListSet, parse_domains, parse_ips, parse_patterns};
use crate::config::{Config, Mode, RateConfig, RuleConfig};
use crate::normalize::fold_ip;

/// Name of the profile that always exists.
pub const DEFAULT_PROFILE: &str = "default";

/// The client network a source address belongs to: IPv4 (IPv4-mapped IPv6 folded) or the IPv6
/// /64. Lockouts, limits and the per-IP connection cap all key by it (PF-1-05, D-50, RV3-L3).
pub fn client_net(peer: IpAddr) -> IpAddr {
    match fold_ip(peer) {
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
        v4 => v4,
    }
}

/// `user:<name>` or `ip:<addr>` (IPv4-mapped folded; other IPv6 as its /64), never from headers.
pub fn client_id(peer: IpAddr, user: Option<&str>) -> String {
    match (user, client_net(peer)) {
        (Some(u), _) => format!("user:{u}"),
        (None, IpAddr::V6(net)) => format!("ip:{net}/64"),
        (None, v4) => format!("ip:{v4}"),
    }
}

/// Dashboard settings (A-30): stored in `state/settings.json` with versions; applied on top of
/// the config file. Only mode, extra allowlist entries and category on/off/schedule; TLS,
/// destination policy, ports and auth stay file-only.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    /// Global content-rule mode.
    pub mode: Option<Mode>,
    /// Added to `rules.allow_domains`.
    pub allow_domains: Vec<String>,
    /// Category overrides.
    pub categories: std::collections::BTreeMap<String, crate::blocklist::CategoryOverride>,
}

impl Settings {
    /// `cfg` with these settings applied (profiles and mode).
    pub fn apply(&self, cfg: &Config) -> Config {
        let mut c = cfg.clone();
        if let Some(m) = self.mode {
            c.mode = m;
        }
        c.rules.allow_domains.extend(self.allow_domains.iter().cloned());
        c
    }
}

/// A compiled profile.
#[derive(Debug)]
pub struct Profile {
    /// Name.
    pub name: String,
    /// Content-rule mode.
    pub mode: Mode,
    /// Effective rules: global rules plus the profile's allowlist and overrides.
    pub rules: RuleConfig,
    /// Extra blocked domains and URL patterns.
    pub extra: Option<ListSet>,
    /// Limits; `None` = unlimited.
    pub rate: Option<RateConfig>,
    /// Feeds applied to this profile (Phase 10).
    pub feeds: Vec<String>,
    /// Download scanning override (Phase 10).
    pub scan_downloads: Option<bool>,
    /// Access requests override (Phase 11).
    pub access_requests: Option<bool>,
}

impl Profile {
    /// The implicit profile when nothing is configured: global rules, no limits.
    pub fn from_global(cfg: &Config) -> Self {
        Self {
            name: DEFAULT_PROFILE.to_owned(),
            mode: cfg.mode,
            rules: cfg.rules.clone(),
            extra: None,
            rate: None,
            feeds: Vec::new(),
            scan_downloads: None,
            access_requests: None,
        }
    }
}

/// A user's credentials and profile.
#[derive(Debug, Clone)]
pub struct User {
    /// argon2id PHC hash.
    pub phc: String,
    /// Profile.
    pub profile: Arc<Profile>,
}

/// Users, clients and profiles (INTERFACES `PolicySet`).
#[derive(Debug)]
pub struct PolicySet {
    profiles: HashMap<String, Arc<Profile>>,
    default: Arc<Profile>,
    users: HashMap<String, User>,
    /// Longest prefix first: (prefix length, network address -> profile) per family.
    v4: Vec<(u8, HashMap<u32, Arc<Profile>>)>,
    v6: Vec<(u8, HashMap<u128, Arc<Profile>>)>,
}

/// Prefix lengths, longest first.
fn longest_first<T>(m: HashMap<u8, T>) -> Vec<(u8, T)> {
    let mut v: Vec<_> = m.into_iter().collect();
    v.sort_by_key(|e| std::cmp::Reverse(e.0));
    v
}

fn mask4(a: u32, len: u8) -> u32 {
    a & u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0)
}

fn mask6(a: u128, len: u8) -> u128 {
    a & u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0)
}

impl PolicySet {
    /// Compile the config; any unknown profile, bad CIDR or bad list entry is an error.
    pub fn build(cfg: &Config) -> Result<Self, String> {
        let mut profiles = HashMap::new();
        for p in &cfg.profiles {
            let name_ok = crate::util::valid_name(&p.name);
            if !name_ok {
                return Err(format!("profile name {:?}: use [a-z0-9_-], 1-32 chars", p.name));
            }
            let mut rules = cfg.rules.clone();
            rules.allow_domains.extend(p.allow_domains.iter().cloned());
            if let Some(e) = &p.blocked_extensions {
                rules.blocked_extensions.clone_from(e);
            }
            if let Some(c) = &p.blocked_content_types {
                rules.blocked_content_types.clone_from(c);
            }
            let extra = if p.extra_blocked_domains.is_empty() && p.extra_url_patterns.is_empty() {
                None
            } else {
                let err = |e: crate::blocklist::ListError| format!("profile {}: {e}", p.name);
                Some(ListSet {
                    domains: parse_domains(&p.extra_blocked_domains.join("\n")).map_err(err)?.list,
                    patterns: parse_patterns(&p.extra_url_patterns.join("\n")).map_err(err)?.list,
                    ips: parse_ips("").map_err(err)?.list,
                    files: [
                        format!("profile:{}", p.name),
                        format!("profile:{}", p.name),
                        String::new(),
                    ],
                })
            };
            let profile = Profile {
                name: p.name.clone(),
                mode: p.mode.unwrap_or(cfg.mode),
                rules,
                extra,
                rate: p.rate,
                feeds: p.feeds.clone(),
                scan_downloads: p.scan_downloads,
                access_requests: p.access_requests,
            };
            if profiles.insert(p.name.clone(), Arc::new(profile)).is_some() {
                return Err(format!("duplicate profile {:?}", p.name));
            }
        }
        let default = Arc::clone(
            profiles
                .entry(DEFAULT_PROFILE.to_owned())
                .or_insert_with(|| Arc::new(Profile::from_global(cfg))),
        );
        let lookup = |name: &str| {
            profiles.get(name).cloned().ok_or_else(|| format!("unknown profile {name:?}"))
        };
        let mut users = HashMap::new();
        let legacy =
            cfg.proxy_auth.iter().map(|a| (&a.username, &a.password_hash.0, DEFAULT_PROFILE));
        let listed =
            cfg.users.iter().map(|u| (&u.username, &u.password_hash.0, u.profile.as_str()));
        for (name, phc, profile) in legacy.chain(listed) {
            let user = User { phc: phc.clone(), profile: lookup(profile)? };
            if users.insert(name.clone(), user).is_some() {
                return Err(format!("duplicate user {name:?}"));
            }
        }
        let mut v4: HashMap<u8, HashMap<u32, Arc<Profile>>> = HashMap::new();
        let mut v6: HashMap<u8, HashMap<u128, Arc<Profile>>> = HashMap::new();
        for c in &cfg.clients {
            let net: IpNet =
                c.cidr.trim().parse().map_err(|_| format!("invalid cidr {:?}", c.cidr))?;
            let profile = lookup(&c.profile)?;
            let dup = match net.trunc() {
                IpNet::V4(n) => {
                    v4.entry(n.prefix_len()).or_default().insert(u32::from(n.network()), profile)
                }
                IpNet::V6(n) => {
                    v6.entry(n.prefix_len()).or_default().insert(u128::from(n.network()), profile)
                }
            };
            if dup.is_some() {
                return Err(format!("duplicate cidr {:?}", c.cidr));
            }
        }
        Ok(Self { profiles, default, users, v4: longest_first(v4), v6: longest_first(v6) })
    }

    /// Whether any user exists (then proxy authentication is required).
    pub fn has_users(&self) -> bool {
        !self.users.is_empty()
    }

    /// A user by name.
    pub fn user(&self, name: &str) -> Option<&User> {
        self.users.get(name)
    }

    /// A profile by name.
    pub fn profile(&self, name: &str) -> Option<&Arc<Profile>> {
        self.profiles.get(name)
    }

    /// Number of profiles (bounded label set for stats/metrics).
    pub fn profile_names(&self) -> impl Iterator<Item = &str> {
        self.profiles.keys().map(String::as_str)
    }

    /// Profile for a source address: longest-prefix CIDR match, else `default`.
    pub fn profile_for_ip(&self, peer: IpAddr) -> &Arc<Profile> {
        let found = match fold_ip(peer) {
            IpAddr::V4(a) => self.v4.iter().find_map(|(len, m)| m.get(&mask4(u32::from(a), *len))),
            IpAddr::V6(a) => self.v6.iter().find_map(|(len, m)| m.get(&mask6(u128::from(a), *len))),
        };
        found.unwrap_or(&self.default)
    }

    /// `client_id` and profile: user profile > longest-prefix CIDR > `default` (D-50).
    pub fn resolve(&self, peer: IpAddr, user: Option<&str>) -> (String, Arc<Profile>) {
        let profile = user
            .and_then(|u| self.users.get(u))
            .map_or_else(|| self.profile_for_ip(peer), |u| &u.profile);
        (client_id(peer, user), Arc::clone(profile))
    }
}
