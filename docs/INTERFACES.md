# Module Contracts (Rust sketches; names are normative, bodies are yours)

Keep modules decoupled: `normalize`, `blocklist`, `policy`, `filter`, `logger`, `naming` are PURE or
side-effect-isolated and unit-testable without sockets.

```rust
// ---------- normalize ----------
pub struct NormalizedTarget {
    pub scheme: Scheme,            // Http | Https
    pub host: Host,                // Domain(String ascii lowercase) | Ipv4 | Ipv6
    pub port: u16,
    pub path: String,              // normalized, starts with '/'
    pub query: Option<String>,     // raw query (never logged by value)
    pub url_norm: String,
    pub views: [String; 3],        // normalized, decoded-once, decoded-twice (regex views)
    pub suspicious_encoding: bool,
}
pub enum TargetError { Invalid(&'static str), ParserDifferential, UserInfo }
pub fn canonicalize(raw_target: &str, ctx: TargetContext) -> Result<NormalizedTarget, TargetError>;
// TargetContext: PlainAbsolute | ConnectAuthority | InterceptedOrigin{ connect_host: String, port: u16 }

// ---------- blocklist ----------
pub struct Blocklists { /* domains: HashMap<String, DomainRule>, regexes: RegexSet + ids, ips: IpNet table */ }
pub struct BlocklistHandle(/* ArcSwap<Blocklists> */);
impl BlocklistHandle {
    pub fn load(cfg: &BlocklistConfig) -> Result<(Self, LoadReport), LoadError>;
    pub fn snapshot(&self) -> Arc<Blocklists>;                  // lock-free read
    pub fn reload(&self) -> ReloadOutcome;                      // keeps old list on failure
    pub fn spawn_watcher(self: &Arc<Self>, interval: Duration, sys: SystemLog) -> JoinHandle<()>;
}
pub struct LoadReport { pub domains: usize, pub regexes: usize, pub ips: usize, pub warnings: Vec<String>, pub duplicates: usize }

// ---------- policy (destination & ports) ----------
pub struct DestPolicy { /* deny_private, always_deny nets, own_addrs */ }
pub trait Resolver: Send + Sync { async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>>; } // injectable for tests
pub enum PolicyVerdict { Allow(IpAddr), Deny(Reason) }
pub fn check_port(scheme_or_connect: PortKind, port: u16, cfg: &PortConfig) -> Result<(), Reason>;
pub async fn check_destination(t: &NormalizedTarget, r: &dyn Resolver, p: &DestPolicy) -> PolicyVerdict;

// ---------- filter ----------
pub enum Phase { PreDns, Resolved { ip: IpAddr }, ResponseHeaders { content_type: Option<String> } } // CONNECT passthrough uses PreDns then Resolved
pub struct Decision { pub action: Action /*Allow|Block*/, pub reason: Reason, pub rule_id: Option<String>, pub rule_list: Option<String>, pub would_block: bool }
pub fn evaluate(t: &NormalizedTarget, phase: Phase, lists: &Blocklists, rules: &RuleConfig, mode: Mode) -> Decision;

// ---------- logger ----------
#[derive(Serialize)] pub struct RequestEvent { /* exactly the fields of LOG_SCHEMA.md; all keys always serialized */ }
pub struct EventLogger { /* bounded channel + writer thread */ }
impl EventLogger {
    pub fn start(cfg: &LoggingConfig) -> io::Result<Self>;
    pub fn log(&self, e: RequestEvent);       // never blocks, never panics; drops + counts when full
    pub fn dropped(&self) -> u64;
    pub fn shutdown(self, deadline: Duration); // flush
}
pub struct SystemLog; impl SystemLog { pub fn event(&self, kind: SysEvent, detail: serde_json::Value); }

// ---------- tls ----------
pub struct CaStore { /* loads/generates ca.pem + ca.key; enforces 0600; zeroize on drop */ }
pub struct LeafCache { /* moka cache host -> Arc<ServerConfig>, TTL 12h, max 10_000 */ }
impl LeafCache { pub fn server_config_for(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, TlsError>; }
pub fn upstream_client_config(extra_roots: &[PathBuf]) -> Result<Arc<rustls::ClientConfig>, TlsError>; // verification ALWAYS on

// ---------- proxy ----------
// proxy::http1 (D-05) - pure where possible, fuzzable
pub struct RequestHead { pub method: String, pub target: String, pub version: HttpVersion, pub headers: Vec<(String, Vec<u8>)> }
pub enum BodyFraming { None, ContentLength(u64), Chunked, CloseDelimited }
pub enum HeadError { Incomplete, TooLarge, Invalid(&'static str), Version }
pub fn parse_request_head(buf: &[u8], limits: &Limits) -> Result<(RequestHead, usize /*consumed*/), HeadError>;
pub fn parse_response_head(buf: &[u8], limits: &Limits, req_method: &str) -> Result<(ResponseHead, usize), HeadError>;
pub fn request_framing(h: &RequestHead) -> Result<BodyFraming, HeadError>;            // one function...
pub fn response_framing(h: &ResponseHead, req_method: &str) -> Result<BodyFraming, HeadError>; // ...shared rules
pub struct ChunkedDecoder; impl ChunkedDecoder { pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<usize, HeadError>; }
pub fn encode_chunk(data: &[u8], out: &mut Vec<u8>);
pub async fn serve_connection(stream: TcpStream, peer: SocketAddr, deps: Arc<ProxyDeps>) ; // per-request pipeline loop
pub struct ProxyDeps { pub cfg: Arc<Config>, pub lists: Arc<BlocklistHandle>, pub logger: Arc<EventLogger>,
    pub resolver: Arc<dyn Resolver>, pub tls: Option<Arc<LeafCache>>, pub stats: Arc<Stats> }
pub struct ProxyHandle { pub local_addr: SocketAddr, /* shutdown(), join() */ }
pub async fn start(cfg: Config, resolver: Option<Arc<dyn Resolver>>) -> Result<ProxyHandle>; // used by integration tests (port 0)

// ---------- client ----------
pub struct FetchResult { pub url: String, pub final_url: String, pub status: Option<u16>, pub bytes: u64,
    pub content_type: Option<String>, pub saved_path: Option<PathBuf>, pub blocked: Option<BlockInfo>, pub error: Option<ClientError>, pub duration_ms: u64 }
pub struct BlockInfo { pub event_id: Option<String>, pub reason: Option<String> }
pub async fn fetch_all(urls: Vec<String>, opts: ClientOptions) -> Vec<FetchResult>;
pub fn exit_code(results: &[FetchResult]) -> i32;

// ---------- naming ----------
pub fn output_filename(original_url: &Url) -> String;              // SPEC 5.3 steps 1-10, pure
pub fn write_unique(out_dir: &Path, stem_name: &str, data: impl Read, max: u64) -> io::Result<PathBuf>; // step 11
```

// ---------- http2 (Phase 6) ----------
pub struct H2Limits { pub max_concurrent_streams: u32, pub max_header_list_size: u32, pub max_frame_size: u32,
    pub initial_stream_window: u32, pub initial_conn_window: u32, pub max_continuation_frames: u32,
    pub reset_limit: (u32, Duration), pub control_frame_limit: (u32, Duration), pub max_streams_per_conn: u32, pub stall_timeout: Duration }
pub enum Alpn { Http11, H2 }
pub struct ClientHelloInfo { pub sni: Option<String>, pub alpn: Vec<Vec<u8>>, pub ech_present: bool, pub raw: Bytes }
pub async fn read_client_hello(stream: &mut TcpStream, timeout: Duration) -> Result<ClientHelloInfo>;   // bytes retained for replay
pub async fn connect_upstream_mirroring(hello: &ClientHelloInfo, target: &UpstreamTarget, cfg: &Arc<rustls::ClientConfig>)
    -> Result<(UpstreamTls, Alpn)>;                                                                   // D-40
pub fn validate_h2_request(parts: &H2RequestParts, connect_host: &str) -> Result<NormalizedTarget, H2Reject>; // H1-H9
pub struct FloodGuard; impl FloodGuard {
    pub fn on_rst(&mut self, now: Instant, caused_by_us: bool) -> Verdict;
    pub fn on_control_frame(&mut self, kind: FrameKind, now: Instant) -> Verdict;
    pub fn on_continuation(&mut self, header_bytes: usize) -> Verdict; }                              // Verdict::{Ok, GoAway}

// ---------- transparent (Phase 7, Linux) ----------
pub trait OriginalDst: Send + Sync { fn get(&self, stream: &TcpStream) -> io::Result<SocketAddr>; }
pub struct SoOriginalDst; pub struct ConntrackOriginalDst; pub struct FixedOriginalDst(pub SocketAddr); // Fixed = tests only
pub enum HostVerify { Strict, Relaxed }
pub async fn verify_host_vs_dst(host: &str, dst: IpAddr, r: &dyn Resolver, mode: HostVerify) -> Result<bool, TargetError>;
pub async fn serve_transparent_http(stream: TcpStream, deps: Arc<ProxyDeps>, od: Arc<dyn OriginalDst>);
pub async fn serve_transparent_tls(stream: TcpStream, deps: Arc<ProxyDeps>, od: Arc<dyn OriginalDst>);


// ---------- v1.1: identity, limits (Phase 9) ----------
pub struct ClientId(String);                       // "user:<name>" | "ip:<addr or /64>"
pub struct PolicySet { /* users, clients(CIDR trie), profiles; ArcSwap-able */ }
pub fn resolve_identity(peer: IpAddr, user: Option<&str>, ps: &PolicySet) -> (ClientId, Arc<Profile>);
pub struct Limiter;   // bounded LRU of buckets, monotonic clock injected for tests
impl Limiter {
    pub fn check_request(&self, id: &ClientId, rate: &RateConfig) -> Result<(), LimitReject>;   // 429
    pub fn acquire_connection(&self, id: &ClientId, rate: &RateConfig) -> Result<ConnGuard, LimitReject>; // 503
    pub fn add_quota(&self, id: &ClientId, rate: &RateConfig, bytes: u64) -> Result<(), LimitReject>;
    pub fn bandwidth(&self, id: &ClientId, rate: &RateConfig, dir: Direction) -> Shaper;       // AsyncRead/Write adapters
}
// ---------- v1.1: feeds, scanning (Phase 10) ----------
pub struct FeedManager; impl FeedManager { pub async fn update(&self, name: &str, force: bool) -> Result<FeedUpdate>;
    pub fn rollback(&self, name: &str) -> Result<()>; pub fn status(&self) -> Vec<FeedStatus>; pub fn active(&self) -> Arc<FeedSet>; }
pub struct FeedSet { /* domains, url_digests: HashSet<[u8;16]>, ips */ }
pub trait Scanner: Send + Sync { fn name(&self) -> &'static str; async fn scan(&self, src: &mut dyn ScanSource) -> Result<ScanVerdict, ScanError>; }
pub enum ScanVerdict { Clean, Infected { signature: String }, Blocklisted }
pub struct ScanPipeline;  // eligibility (extension/type/magic), modes detect|block, temp files, unscannable handling
pub struct ClamdScanner; pub struct HashBlocklistScanner; // YaraScanner behind cargo feature "yara"
// ---------- v1.1: admin and access requests (Phase 11) ----------
pub struct AdminServer; pub fn render_metrics(stats: &Stats, lists: &ListCounts) -> String;   // text exposition, bounded labels
pub struct AccessRequests; impl AccessRequests { pub fn csrf_token(&self, event_id: &str, client: &ClientId) -> String;
    pub fn submit(&self, form: &RequestForm, client: &ClientId) -> Result<RequestId, AccessError>;
    pub fn decide(&self, id: RequestId, d: Decision) -> Result<Option<TempAllow>, AccessError>; }
pub struct TempAllows; impl TempAllows { pub fn matches(&self, client: &ClientId, profile: &str, t: &NormalizedTarget, now: SystemTime) -> Option<&TempAllow>; }
// ---------- v1.1: client (Phase 12) ----------
pub struct Manifest; pub fn rewrite_html(input: &[u8], base: &Url, policy: &SnapshotPolicy, plan: &mut AssetPlan) -> Result<Vec<u8>>;
pub fn rewrite_css(input: &[u8], base: &Url, plan: &mut AssetPlan) -> Result<Vec<u8>>;
pub struct Robots; pub fn parse_robots(body: &[u8], agent: &str) -> Robots; pub struct Crawler;


## Reason enum (serialized snake_case; also the `reason` log field)
allowlist, domain_blocklist, ip_blocklist, url_pattern, extension, content_type, host_mismatch,
sni_mismatch, parser_differential, invalid_request, userinfo_in_url, port_not_allowed, private_range,
loop_detected, auth_required, auth_failed, rate_limited, upstream_cert_invalid, upstream_error, timeout,
too_many_connections, non_tls_on_connect, method_not_allowed, h2_protocol_error, h2_flood, orig_dst_failed,
no_sni, ech_blocked, quota_exceeded, feed_domain, feed_url, feed_ip, hash_blocklist, malware_detected,
unscannable, scanner_unavailable, internal_error, none.

## Error handling conventions
`thiserror` enums per module, `anyhow` only in binaries. No panics on external input. Every fallible
network step has a timeout (SPEC 4.11). Public functions have doc comments with an example or invariants.
