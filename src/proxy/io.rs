//! Async I/O for the HTTP/1 core: bounded, deadline-driven head reading that keeps pipelined
//! bytes, and body copying per framing (chunked is decoded and re-encoded, R15). Every await is
//! wrapped in a timeout (SPEC 4.15 (8)).
#![forbid(unsafe_code)]

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout};

use super::http1::{BodyFraming, ChunkedDecoder, HeadError, LAST_CHUNK, encode_chunk};

/// Read size per syscall.
pub const READ_CHUNK: usize = 16 * 1024;

/// I/O failure classes, mapped to statuses by the pipeline.
#[derive(Debug, thiserror::Error)]
pub enum IoError {
    /// Deadline or idle timeout.
    #[error("timeout")]
    Timeout,
    /// Peer closed early.
    #[error("connection closed")]
    Closed,
    /// Framing error in a head or body.
    #[error("{0}")]
    Framing(#[from] HeadError),
    /// Socket error.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Read more bytes into `buf`; `Ok(0)` is EOF.
pub async fn fill<R: AsyncRead + Unpin>(
    src: &mut R,
    buf: &mut Vec<u8>,
    deadline: Instant,
) -> Result<usize, IoError> {
    let mut chunk = [0u8; READ_CHUNK];
    let n = tokio::time::timeout_at(deadline, src.read(&mut chunk))
        .await
        .map_err(|_| IoError::Timeout)??;
    buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
    Ok(n)
}

/// Parse a head out of `buf`, reading more until `parse` stops returning `Incomplete`.
/// Returns `Ok(None)` on a clean EOF before any byte. On success the head bytes are drained
/// from `buf`; pipelined bytes after it stay.
pub async fn read_head<R, T>(
    src: &mut R,
    buf: &mut Vec<u8>,
    deadline: Instant,
    parse: impl Fn(&[u8]) -> Result<(T, usize), HeadError>,
) -> Result<Option<T>, IoError>
where
    R: AsyncRead + Unpin,
{
    loop {
        if !buf.is_empty() {
            match parse(buf) {
                Ok((head, used)) => {
                    buf.drain(..used.min(buf.len()));
                    return Ok(Some(head));
                }
                Err(HeadError::Incomplete) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if fill(src, buf, deadline).await? == 0 {
            return if buf.is_empty() { Ok(None) } else { Err(IoError::Closed) };
        }
    }
}

/// `write_all` bounded by an idle timeout.
pub async fn write_all<W: AsyncWrite + Unpin>(
    dst: &mut W,
    data: &[u8],
    idle: Duration,
) -> Result<(), IoError> {
    timeout(idle, dst.write_all(data)).await.map_err(|_| IoError::Timeout)?.map_err(IoError::Io)
}

/// Copy one message body from `src` (starting with already-buffered `buf`) to `dst`, re-framing
/// chunked bodies. Bytes after the body stay in `buf`. Returns body bytes copied. `idle` bounds
/// every read and write.
pub async fn copy_body<R, W>(
    src: &mut R,
    buf: &mut Vec<u8>,
    dst: &mut W,
    framing: BodyFraming,
    compat: bool,
    idle: Duration,
) -> Result<u64, IoError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    copy_body_tap(src, buf, dst, framing, compat, idle, true, &mut |_| true).await
}

/// Where a body copy stands, so a copy stopped by its tap can resume on another sink without
/// restarting Content-Length counting or chunked decoding (download scanning, review L2).
#[derive(Debug)]
pub enum BodyState {
    /// Content-Length bytes still to copy.
    Remaining(u64),
    /// Chunked decoding in progress.
    Chunked(ChunkedDecoder),
    /// Until EOF.
    Close,
}

impl BodyState {
    /// The start state for `framing`.
    pub fn new(framing: BodyFraming, compat: bool) -> Self {
        match framing {
            BodyFraming::None => Self::Remaining(0),
            BodyFraming::ContentLength(n) => Self::Remaining(n),
            BodyFraming::Chunked => Self::Chunked(ChunkedDecoder::new(compat)),
            BodyFraming::CloseDelimited => Self::Close,
        }
    }
}

/// [`copy_body`] that also hands every decoded payload chunk to `tap` (download scanning, D-53).
/// `reframe = false` writes the decoded payload only (close-delimited delivery). When `tap`
/// returns false the copy stops early with `IoError::Closed` left to the caller to interpret.
#[allow(clippy::too_many_arguments)]
pub async fn copy_body_tap<R, W>(
    src: &mut R,
    buf: &mut Vec<u8>,
    dst: &mut W,
    framing: BodyFraming,
    compat: bool,
    idle: Duration,
    reframe: bool,
    tap: &mut (dyn FnMut(&[u8]) -> bool + Send),
) -> Result<u64, IoError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut state = BodyState::new(framing, compat);
    copy_body_resume(src, buf, dst, &mut state, idle, reframe, tap).await
}

/// [`copy_body_tap`] from (and updating) `state`. Bytes handed to a `tap` that returned false
/// count as consumed, so a later call continues right after them. Cancel-safe at its awaits
/// when `dst` never pends (a sink).
#[allow(clippy::too_many_arguments)]
pub async fn copy_body_resume<R, W>(
    src: &mut R,
    buf: &mut Vec<u8>,
    dst: &mut W,
    state: &mut BodyState,
    idle: Duration,
    reframe: bool,
    tap: &mut (dyn FnMut(&[u8]) -> bool + Send),
) -> Result<u64, IoError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    match state {
        BodyState::Remaining(remaining) => {
            while *remaining > 0 {
                if buf.is_empty() && fill(src, buf, Instant::now() + idle).await? == 0 {
                    return Err(IoError::Closed);
                }
                let take = usize::try_from(*remaining).map_or(buf.len(), |r| r.min(buf.len()));
                let data: Vec<u8> = buf.drain(..take).collect();
                *remaining -= take as u64;
                if !tap(&data) {
                    return Err(IoError::Closed);
                }
                write_all(dst, &data, idle).await?;
                total += take as u64;
            }
        }
        BodyState::Chunked(decoder) => loop {
            let mut decoded = Vec::new();
            let used = decoder.feed(buf, &mut decoded)?;
            buf.drain(..used.min(buf.len()));
            if !decoded.is_empty() {
                total += decoded.len() as u64;
                if !tap(&decoded) {
                    return Err(IoError::Closed);
                }
                if reframe {
                    let mut framed = Vec::with_capacity(decoded.len() + 16);
                    encode_chunk(&decoded, &mut framed);
                    write_all(dst, &framed, idle).await?;
                } else {
                    write_all(dst, &decoded, idle).await?;
                }
            }
            if decoder.is_done() {
                if reframe {
                    write_all(dst, LAST_CHUNK, idle).await?;
                }
                break;
            }
            if fill(src, buf, Instant::now() + idle).await? == 0 {
                return Err(IoError::Closed);
            }
        },
        BodyState::Close => loop {
            if !buf.is_empty() {
                total += buf.len() as u64;
                let data = std::mem::take(buf);
                if !tap(&data) {
                    return Err(IoError::Closed);
                }
                write_all(dst, &data, idle).await?;
            }
            if fill(src, buf, Instant::now() + idle).await? == 0 {
                break;
            }
        },
    }
    timeout(idle, dst.flush()).await.map_err(|_| IoError::Timeout)??;
    Ok(total)
}
