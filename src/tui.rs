//! Terminal dashboard (SPEC_EXT_OPS O5, D-58): `webfilter-proxy tui` reads the admin API only.
//! Every string from the API is stripped of control characters and escape sequences before it is
//! drawn; the terminal is restored on exit and on panic (ratatui's init hook); an unreachable admin
//! listener shows a status line instead of crashing.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Panels (O5).
pub const TABS: [&str; 6] =
    ["Overview", "Events", "Top blocked", "Clients", "Feeds", "Access requests"];

/// Remove control characters, escape sequences and bidi overrides (D-58), cap the length.
pub fn safe(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Skip a CSI/OSC sequence: ESC [ ... final byte, or ESC ] ... BEL/ST.
            match chars.peek() {
                Some('[') => {
                    chars.next();
                    for d in chars.by_ref() {
                        if ('@'..='~').contains(&d) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    for d in chars.by_ref() {
                        if d == '\u{7}' || d == '\\' {
                            break;
                        }
                    }
                }
                _ => {}
            }
            continue;
        }
        if c.is_control()
            || ('\u{202a}'..='\u{202e}').contains(&c)
            || ('\u{2066}'..='\u{2069}').contains(&c)
        {
            continue;
        }
        out.push(c);
        if out.chars().count() >= max {
            break;
        }
    }
    out
}

/// What the dashboard shows.
#[derive(Debug, Default, Clone)]
pub struct State {
    /// Selected tab.
    pub tab: usize,
    /// Event filter (substring).
    pub filter: String,
    /// Typing the filter.
    pub editing: bool,
    /// Selected access request row.
    pub selected: usize,
    /// Approve TTL in hours.
    pub ttl_hours: u64,
    /// Status line.
    pub status: String,
    /// `stats`.
    pub stats: Value,
    /// `events/recent`.
    pub events: Value,
    /// `top/blocked`.
    pub top: Value,
    /// `clients`.
    pub clients: Value,
    /// `feeds`.
    pub feeds: Value,
    /// `access-requests?status=pending`.
    pub requests: Value,
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => safe(x, 120),
        Some(Value::Null) | None => String::new(),
        Some(other) => safe(&other.to_string(), 120),
    }
}

fn rows(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

fn table<'a>(
    title: String,
    header: &[&'a str],
    body: Vec<Vec<String>>,
    widths: &[u16],
    selected: Option<usize>,
) -> Table<'a> {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let rows: Vec<Row> = body
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let row = Row::new(r.into_iter().map(Cell::from));
            if Some(i) == selected {
                row.style(Style::default().add_modifier(Modifier::REVERSED))
            } else {
                row
            }
        })
        .collect();
    Table::new(rows, widths.iter().map(|w| Constraint::Percentage(*w)))
        .header(Row::new(header.iter().copied()).style(bold))
        .block(Block::default().borders(Borders::ALL).title(title))
}

/// Draw one frame (pure; tested with ratatui's TestBackend).
pub fn draw(f: &mut Frame, st: &State) {
    let [tabs_area, body, status_area] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(5), Constraint::Length(1)])
            .areas(f.area());
    let tabs = Tabs::new(TABS)
        .select(st.tab)
        .block(Block::default().borders(Borders::ALL).title("WebFilter"));
    f.render_widget(tabs, tabs_area);
    match st.tab {
        0 => {
            let x = &st.stats;
            let text = format!(
                "mode: {}\nrequests: {}   blocked: {}   active connections: {}\nlists: {} domains, {} url patterns, {} ip ranges\ninterception: {}   scanning: {}   access requests: {}",
                s(x, "mode"),
                s(x, "requests"),
                s(x, "blocked"),
                s(x, "active_connections"),
                s(&x["lists"], "domains"),
                s(&x["lists"], "url_patterns"),
                s(&x["lists"], "ip_blocklist"),
                s(x, "intercept"),
                s(x, "scan"),
                s(x, "access_requests"),
            );
            f.render_widget(
                Paragraph::new(text)
                    .block(Block::default().borders(Borders::ALL).title("Overview")),
                body,
            );
        }
        1 => {
            let filter = st.filter.to_lowercase();
            let body_rows = rows(&st.events)
                .iter()
                .filter(|e| {
                    filter.is_empty()
                        || ["dest_host", "uri_path", "client_id", "reason"]
                            .iter()
                            .any(|k| s(e, k).to_lowercase().contains(&filter))
                })
                .take(200)
                .map(|e| {
                    vec![
                        s(e, "timestamp"),
                        s(e, "client_id"),
                        s(e, "http_method"),
                        s(e, "url"),
                        s(e, "action"),
                        s(e, "reason"),
                    ]
                })
                .collect();
            let title = if st.editing {
                "Events (filter: typing, Enter to finish)"
            } else {
                "Events (/ to filter)"
            };
            f.render_widget(
                table(
                    title.to_owned(),
                    &["time", "client", "method", "url", "action", "reason"],
                    body_rows,
                    &[18, 14, 6, 40, 8, 14],
                    None,
                ),
                body,
            );
        }
        2 => {
            let body_rows =
                rows(&st.top).iter().map(|t| vec![s(t, "host"), s(t, "count")]).collect();
            f.render_widget(
                table("Top blocked".into(), &["host", "blocks"], body_rows, &[80, 20], None),
                body,
            );
        }
        3 => {
            let body_rows = rows(&st.clients)
                .iter()
                .map(|c| {
                    vec![s(c, "client_id"), s(c, "requests"), s(c, "blocked"), s(c, "last_seen")]
                })
                .collect();
            f.render_widget(
                table(
                    "Clients".into(),
                    &["client", "requests", "blocked", "last seen"],
                    body_rows,
                    &[40, 15, 15, 30],
                    None,
                ),
                body,
            );
        }
        4 => {
            let body_rows = rows(&st.feeds)
                .iter()
                .map(|x| vec![s(x, "name"), s(x, "enabled"), s(x, "entries"), s(x, "active")])
                .collect();
            f.render_widget(
                table(
                    "Feeds".into(),
                    &["feed", "enabled", "entries", "active version"],
                    body_rows,
                    &[30, 15, 15, 40],
                    None,
                ),
                body,
            );
        }
        _ => {
            let body_rows = rows(&st.requests)
                .iter()
                .map(|r| {
                    vec![
                        s(r, "client_id"),
                        s(r, "host"),
                        s(r, "reason"),
                        s(r, "justification"),
                        s(r, "status"),
                    ]
                })
                .collect();
            let title = format!("Access requests (a approve, d deny, t TTL {} h)", st.ttl_hours);
            f.render_widget(
                table(
                    title,
                    &["client", "host", "reason", "justification", "status"],
                    body_rows,
                    &[20, 25, 15, 30, 10],
                    Some(st.selected),
                ),
                body,
            );
        }
    }
    let line = format!("q quit  Tab next  r refresh  | {}", safe(&st.status, 200));
    f.render_widget(Paragraph::new(line), status_area);
}

/// Minimal client for the loopback admin API (Bearer token from a file or env; never argv).
pub struct AdminClient {
    addr: String,
    host: String,
    token: String,
}

impl AdminClient {
    /// `admin` is `http://host:port`.
    pub fn new(admin: &str, token: String) -> Result<Self, String> {
        let hp = admin
            .strip_prefix("http://")
            .ok_or("--admin must be http://127.0.0.1:port")?
            .trim_end_matches('/');
        Ok(Self { addr: hp.to_owned(), host: hp.to_owned(), token })
    }

    async fn call(&self, method: &str, path: &str, body: Option<&str>) -> Result<Value, String> {
        let mut s = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect(&self.addr),
        )
        .await
        .map_err(|_| "admin unreachable (timeout)".to_owned())?
        .map_err(|e| format!("admin unreachable: {e}"))?;
        let body = body.unwrap_or("");
        let ct = if method == "GET" { "" } else { "Content-Type: application/json\r\n" };
        let req = format!(
            "{method} /api/v1/{path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n{ct}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.host,
            self.token,
            body.len()
        );
        s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            s.take(16 * 1024 * 1024).read_to_end(&mut out),
        )
        .await
        .map_err(|_| "admin timeout".to_owned())?
        .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&out);
        let (head, payload) = text.split_once("\r\n\r\n").ok_or("bad admin response")?;
        let status = head.split(' ').nth(1).unwrap_or("");
        if !status.starts_with('2') {
            return Err(format!("admin answered {}", safe(status, 8)));
        }
        serde_json::from_str(payload).map_err(|e| e.to_string())
    }

    /// Refresh every panel.
    pub async fn refresh(&self, st: &mut State) {
        let r = async {
            st.stats = self.call("GET", "stats", None).await?;
            st.events = self.call("GET", "events/recent?limit=300", None).await?;
            st.top = self.call("GET", "top/blocked?n=50", None).await?;
            st.clients = self.call("GET", "clients", None).await?;
            st.feeds = self.call("GET", "feeds", None).await?;
            st.requests = self.call("GET", "access-requests?status=pending", None).await?;
            Ok::<(), String>(())
        }
        .await;
        st.status = match r {
            Ok(()) => "connected".into(),
            Err(e) => e,
        };
    }

    async fn decide(&self, st: &mut State, approve: bool) {
        let Some(id) =
            rows(&st.requests).get(st.selected).and_then(|r| r.get("id")).and_then(Value::as_str)
        else {
            return;
        };
        let body = serde_json::json!({ "decision": if approve { "approve" } else { "deny" }, "ttl_secs": st.ttl_hours * 3600 }).to_string();
        let path = format!(
            "access-requests/{}/decide",
            url::form_urlencoded::byte_serialize(id.as_bytes()).collect::<String>()
        );
        st.status = match self.call("POST", &path, Some(&body)).await {
            Ok(_) => {
                format!("request {} {}", safe(id, 32), if approve { "approved" } else { "denied" })
            }
            Err(e) => e,
        };
    }
}

/// Run the TUI until `q`. The terminal is restored on every exit path and on panic.
pub async fn run(client: AdminClient) -> std::io::Result<()> {
    let mut terminal = ratatui::try_init()?;
    let mut st = State { ttl_hours: 4, ..State::default() };
    client.refresh(&mut st).await;
    let mut last = Instant::now();
    let result = loop {
        if let Err(e) = terminal.draw(|f| draw(f, &st)) {
            break Err(e);
        }
        if event::poll(Duration::from_millis(250))?
            && let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
        {
            if st.editing {
                match k.code {
                    KeyCode::Enter | KeyCode::Esc => st.editing = false,
                    KeyCode::Backspace => {
                        st.filter.pop();
                    }
                    KeyCode::Char(c) if st.filter.len() < 64 && !c.is_control() => {
                        st.filter.push(c)
                    }
                    _ => {}
                }
                continue;
            }
            match k.code {
                KeyCode::Char('q') => break Ok(()),
                KeyCode::Tab => st.tab = (st.tab + 1) % TABS.len(),
                KeyCode::BackTab => st.tab = (st.tab + TABS.len() - 1) % TABS.len(),
                KeyCode::Char('/') => st.editing = true,
                KeyCode::Char('r') => client.refresh(&mut st).await,
                KeyCode::Down => {
                    st.selected = (st.selected + 1).min(rows(&st.requests).len().saturating_sub(1))
                }
                KeyCode::Up => st.selected = st.selected.saturating_sub(1),
                KeyCode::Char('t') => {
                    st.ttl_hours = if st.ttl_hours >= 24 { 1 } else { st.ttl_hours * 2 }.min(24)
                }
                KeyCode::Char('a') if st.tab == 5 => client.decide(&mut st, true).await,
                KeyCode::Char('d') if st.tab == 5 => client.decide(&mut st, false).await,
                _ => {}
            }
        }
        if last.elapsed() >= Duration::from_secs(5) {
            client.refresh(&mut st).await;
            last = Instant::now();
        }
    };
    ratatui::try_restore()?;
    result
}
