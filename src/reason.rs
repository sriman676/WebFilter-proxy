//! The `reason` enum shared by decisions, block pages and the `reason` log field (INTERFACES.md).
#![forbid(unsafe_code)]

use serde::Serialize;

macro_rules! reasons {
    ($($variant:ident => $name:literal),* $(,)?) => {
        /// Why a request was allowed, blocked or rejected. Serialized in snake_case.
        #[allow(missing_docs)] // variants are documented in INTERFACES.md "Reason enum"
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum Reason {
            $($variant,)*
            #[default]
            None,
        }

        impl Reason {
            /// Every variant, for exhaustive tests.
            pub const ALL: &[Reason] = &[$(Reason::$variant,)* Reason::None];

            /// The snake_case name used in logs and block pages.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Reason::$variant => $name,)*
                    Reason::None => "none",
                }
            }
        }
    };
}

reasons! {
    Allowlist => "allowlist",
    DomainBlocklist => "domain_blocklist",
    IpBlocklist => "ip_blocklist",
    UrlPattern => "url_pattern",
    Extension => "extension",
    ContentType => "content_type",
    HostMismatch => "host_mismatch",
    SniMismatch => "sni_mismatch",
    ParserDifferential => "parser_differential",
    InvalidRequest => "invalid_request",
    UserinfoInUrl => "userinfo_in_url",
    PortNotAllowed => "port_not_allowed",
    PrivateRange => "private_range",
    LoopDetected => "loop_detected",
    AuthRequired => "auth_required",
    AuthFailed => "auth_failed",
    RateLimited => "rate_limited",
    UpstreamCertInvalid => "upstream_cert_invalid",
    UpstreamError => "upstream_error",
    Timeout => "timeout",
    TooManyConnections => "too_many_connections",
    NonTlsOnConnect => "non_tls_on_connect",
    MethodNotAllowed => "method_not_allowed",
    H2ProtocolError => "h2_protocol_error",
    H2Flood => "h2_flood",
    OrigDstFailed => "orig_dst_failed",
    NoSni => "no_sni",
    EchBlocked => "ech_blocked",
    QuotaExceeded => "quota_exceeded",
    FeedDomain => "feed_domain",
    FeedUrl => "feed_url",
    FeedIp => "feed_ip",
    HashBlocklist => "hash_blocklist",
    MalwareDetected => "malware_detected",
    Unscannable => "unscannable",
    ScannerUnavailable => "scanner_unavailable",
    InternalError => "internal_error",
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
