//! HTTP/2 flood guard (SPEC 4.16, D-45): a frame-header scanner under the `h2` crate that counts
//! what `h2` does not expose (RST_STREAM rate and ratio, control-frame floods, CONTINUATION chains,
//! streams per connection) and trips the connection into GOAWAY(ENHANCE_YOUR_CALM). Pure and
//! panic-free on any input (fuzz target `h2_frames`).
#![forbid(unsafe_code)]

use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::config::Http2Config;
use crate::util::LockExt;

/// The client connection preface (RFC 9113 3.4).
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER: usize = 9;
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const PRIORITY: u8 = 0x2;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
/// Reset-ratio rule: more than half of at least this many opened streams were reset.
const RATIO_MIN_STREAMS: u32 = 50;

/// Why a connection was cut (the `h2_flood` event's `violation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// Too many RST_STREAM (received or caused by the peer's errors) per window.
    RapidReset,
    /// More than half of the opened streams were reset.
    ResetRatio,
    /// SETTINGS/PING/PRIORITY/empty DATA/WINDOW_UPDATE(0) flood.
    ControlFlood,
    /// A header block spread over too many CONTINUATION frames.
    ContinuationFlood,
    /// A stream made no flow-control progress for `stall_timeout_secs`.
    Stall,
    /// One of the `h2` crate's own limits (pending-accept resets, CONTINUATION, header size).
    Library,
}

impl Violation {
    /// Log name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RapidReset => "rapid_reset",
            Self::ResetRatio => "reset_ratio",
            Self::ControlFlood => "control_flood",
            Self::ContinuationFlood => "continuation_flood",
            Self::Stall => "flow_control_stall",
            Self::Library => "h2_limit",
        }
    }
}

/// Which side the scanned bytes come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// A client: starts with the preface; odd-numbered HEADERS open streams.
    Client,
    /// An origin: no preface; streams are ours, only flood rules apply.
    Origin,
}

/// Counters for one scanning window.
#[derive(Debug, Default, Clone, Copy)]
struct Window {
    resets: u32,
    control: u32,
    opened: u32,
}

/// Incremental frame-header scanner.
#[derive(Debug)]
pub struct FrameScanner {
    limits: Limits,
    peer: Peer,
    preface_left: usize,
    header: [u8; FRAME_HEADER],
    header_len: usize,
    kind: u8,
    flags: u8,
    payload_left: usize,
    window_update: [u8; 4],
    window_update_len: usize,
    continuations: Option<u32>,
    last_stream: u32,
    total_streams: u64,
    window: Window,
    window_start: Instant,
}

/// The `[http2]` numbers the scanner enforces.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Max CONTINUATION frames per header block.
    pub max_continuation_frames: u32,
    /// RST_STREAM per window.
    pub reset_limit: u32,
    /// Control frames per window.
    pub control_frame_limit: u32,
    /// Window length.
    pub window: Duration,
}

impl From<&Http2Config> for Limits {
    fn from(c: &Http2Config) -> Self {
        Self {
            max_continuation_frames: c.max_continuation_frames,
            reset_limit: c.reset_limit,
            control_frame_limit: c.control_frame_limit,
            window: Duration::from_secs(c.limit_window_secs),
        }
    }
}

impl FrameScanner {
    /// A scanner for bytes coming from `peer`.
    pub fn new(limits: Limits, peer: Peer, now: Instant) -> Self {
        Self {
            limits,
            peer,
            preface_left: if peer == Peer::Client { PREFACE.len() } else { 0 },
            header: [0; FRAME_HEADER],
            header_len: 0,
            kind: 0,
            flags: 0,
            payload_left: 0,
            window_update: [0; 4],
            window_update_len: 0,
            continuations: None,
            last_stream: 0,
            total_streams: 0,
            window: Window::default(),
            window_start: now,
        }
    }

    /// Streams the client opened so far.
    pub fn total_streams(&self) -> u64 {
        self.total_streams
    }

    /// Count `n` resets this side caused through stream errors (MadeYouReset).
    pub fn local_resets(&mut self, n: u32, now: Instant) -> Option<Violation> {
        self.roll(now);
        self.window.resets = self.window.resets.saturating_add(n);
        self.check_resets()
    }

    /// Scan more bytes; the first violation found is returned.
    pub fn feed(&mut self, mut data: &[u8], now: Instant) -> Option<Violation> {
        self.roll(now);
        if self.preface_left > 0 {
            let n = self.preface_left.min(data.len());
            self.preface_left -= n;
            data = data.get(n..).unwrap_or(&[]);
        }
        while !data.is_empty() {
            if self.payload_left > 0 {
                let n = self.payload_left.min(data.len());
                if self.kind == WINDOW_UPDATE {
                    for &b in data.get(..n).unwrap_or(&[]) {
                        if let Some(slot) = self.window_update.get_mut(self.window_update_len) {
                            *slot = b;
                            self.window_update_len += 1;
                        }
                    }
                }
                self.payload_left -= n;
                data = data.get(n..).unwrap_or(&[]);
                if self.payload_left == 0
                    && let Some(v) = self.frame_done()
                {
                    return Some(v);
                }
                continue;
            }
            let need = FRAME_HEADER - self.header_len;
            let n = need.min(data.len());
            if let (Some(dst), Some(src)) =
                (self.header.get_mut(self.header_len..self.header_len + n), data.get(..n))
            {
                dst.copy_from_slice(src);
            }
            self.header_len += n;
            data = data.get(n..).unwrap_or(&[]);
            if self.header_len == FRAME_HEADER {
                self.header_len = 0;
                if let Some(v) = self.frame_start() {
                    return Some(v);
                }
            }
        }
        None
    }

    fn roll(&mut self, now: Instant) {
        if now.saturating_duration_since(self.window_start) >= self.limits.window {
            self.window = Window::default();
            self.window_start = now;
        }
    }

    fn check_resets(&self) -> Option<Violation> {
        let w = self.window;
        if w.resets > self.limits.reset_limit {
            Some(Violation::RapidReset)
        } else if w.opened >= RATIO_MIN_STREAMS && u64::from(w.resets) * 2 > u64::from(w.opened) {
            Some(Violation::ResetRatio)
        } else {
            None
        }
    }

    fn control(&mut self) -> Option<Violation> {
        self.window.control = self.window.control.saturating_add(1);
        (self.window.control > self.limits.control_frame_limit).then_some(Violation::ControlFlood)
    }

    /// A frame header is complete.
    fn frame_start(&mut self) -> Option<Violation> {
        let h = self.header;
        let len = usize::from(h[0]) << 16 | usize::from(h[1]) << 8 | usize::from(h[2]);
        let stream = u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]);
        self.kind = h[3];
        self.flags = h[4];
        self.payload_left = len;
        self.window_update_len = 0;
        let verdict = match self.kind {
            HEADERS => {
                if self.peer == Peer::Client && stream % 2 == 1 && stream > self.last_stream {
                    self.last_stream = stream;
                    self.total_streams += 1;
                    self.window.opened = self.window.opened.saturating_add(1);
                }
                self.continuations = (self.flags & END_HEADERS == 0).then_some(0);
                None
            }
            CONTINUATION => {
                let n = self.continuations.unwrap_or(0).saturating_add(1);
                self.continuations = (self.flags & END_HEADERS == 0).then_some(n);
                (n > self.limits.max_continuation_frames).then_some(Violation::ContinuationFlood)
            }
            RST_STREAM => {
                self.window.resets = self.window.resets.saturating_add(1);
                self.check_resets()
            }
            SETTINGS | PING | PRIORITY => self.control(),
            DATA if len == 0 && self.flags & END_STREAM == 0 => self.control(),
            _ => None,
        };
        if verdict.is_some() {
            return verdict;
        }
        if len == 0 { self.frame_done() } else { None }
    }

    /// A frame's payload is complete.
    fn frame_done(&mut self) -> Option<Violation> {
        if self.kind == WINDOW_UPDATE && self.window_update_len == 4 {
            let w = self.window_update;
            if u32::from_be_bytes([w[0] & 0x7f, w[1], w[2], w[3]]) == 0 {
                return self.control();
            }
        }
        None
    }
}

/// Shared between a guarded stream, the connection driver and the stream tasks.
#[derive(Debug)]
pub struct GuardState {
    epoch: Instant,
    tripped: Mutex<Option<Violation>>,
    notify: Notify,
    local_resets: AtomicU32,
    last_frame_ms: AtomicU64,
    /// Streams opened by the client (for the event detail).
    pub streams: AtomicU64,
}

impl Default for GuardState {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            tripped: Mutex::new(None),
            notify: Notify::new(),
            local_resets: AtomicU32::new(0),
            last_frame_ms: AtomicU64::new(0),
            streams: AtomicU64::new(0),
        }
    }
}

impl GuardState {
    /// Record a violation (first one wins) and wake the connection driver.
    pub fn trip(&self, v: Violation) {
        let mut t = self.tripped.lock_or_recover();
        if t.is_none() {
            *t = Some(v);
        }
        drop(t);
        self.notify.notify_one();
    }

    /// The violation, if any.
    pub fn violation(&self) -> Option<Violation> {
        *self.tripped.lock_or_recover()
    }

    /// Wait until the guard trips.
    pub async fn tripped(&self) -> Violation {
        loop {
            let notified = self.notify.notified();
            if let Some(v) = self.violation() {
                return v;
            }
            notified.await;
        }
    }

    /// A stream error we sent because of the client's request (MadeYouReset accounting).
    pub fn local_reset(&self) {
        self.local_resets.fetch_add(1, Ordering::Relaxed);
    }

    fn mark_input(&self, now: Instant) {
        let ms = u64::try_from(now.saturating_duration_since(self.epoch).as_millis()).unwrap_or(0);
        self.last_frame_ms.store(ms, Ordering::Relaxed);
    }

    /// Time since the peer last sent any bytes.
    pub fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_frame_ms.load(Ordering::Relaxed));
        self.epoch.elapsed().saturating_sub(last)
    }
}

/// A byte stream whose reads are scanned; after a violation, further input is dropped so the
/// connection can only send its GOAWAY and close.
pub struct Guarded<S> {
    inner: S,
    scanner: FrameScanner,
    state: Arc<GuardState>,
}

impl<S> Guarded<S> {
    /// Guard `inner` (bytes from `peer`).
    pub fn new(inner: S, cfg: &Http2Config, peer: Peer, state: Arc<GuardState>) -> Self {
        Self { inner, scanner: FrameScanner::new(cfg.into(), peer, Instant::now()), state }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Guarded<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.state.violation().is_some() {
            return Poll::Pending; // the driver is closing the connection
        }
        let before = buf.filled().len();
        let me = &mut *self;
        let res = Pin::new(&mut me.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            let now = Instant::now();
            let fresh = buf.filled().get(before..).unwrap_or(&[]);
            if !fresh.is_empty() {
                me.state.mark_input(now);
            }
            let local = me.state.local_resets.swap(0, Ordering::Relaxed);
            let verdict =
                me.scanner.local_resets(local, now).or_else(|| me.scanner.feed(fresh, now));
            me.state.streams.store(me.scanner.total_streams(), Ordering::Relaxed);
            if let Some(v) = verdict {
                // Withhold the offending bytes: the driver answers with our GOAWAY.
                buf.set_filled(before);
                me.state.trip(v);
                return Poll::Pending;
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Guarded<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
