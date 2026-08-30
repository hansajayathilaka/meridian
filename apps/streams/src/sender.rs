//! Sender engine (T09, task 10.7): drives the actual outbound `mrd.file/1` transfer once a stream
//! is open and its manifest sent (task 10.6, `FileStream::build_open_params` +
//! `P2pSession::open_stream`) — splitting the file into [`crate::merkle::CHUNK_SIZE`] chunks,
//! sealing each under the per-file key `k_f` (task 10.5's [`crate::chunk::seal_chunk`]), wrapping
//! it in the wire [`crate::chunk::ChunkFrame`] envelope, and pushing it out via
//! [`meridian_core::session::P2pSession::send_stream_frame`] (task 10.4), throttled by a
//! low-watermark backpressure policy over
//! [`meridian_core::session::P2pSession::stream_buffered_amount`] (task 10.2), while emitting
//! progress events and sequencing multi-file batches.
//!
//! Manifest generation/sealing and the OPEN/ACCEPT round trip are **out of scope** here (task
//! 10.6's job, already done by the time this module's functions are called) — every function in
//! this module assumes `sid` is already an open, accepted `mrd.file/1` data channel.
//!
//! ## Backpressure thresholds — `TODO: confirm` (this task's own recorded risk: no design doc pins
//! concrete numbers; task 10.14's soak test is the intended validator against real throughput)
//! [`SenderConfig::default`] picks:
//! - **High watermark: 4 MiB** (`64` chunks' worth). Large enough to smooth over ordinary
//!   network/RTT jitter without ever needing a per-chunk acknowledgment (this substrate has none —
//!   `buffered_amount` is the only backpressure signal, per `Transport::buffered_amount`'s own doc),
//!   but small enough to cap how much unacknowledged ciphertext a single stalled transfer can pile
//!   up in the transport's send queue (and, by extension, across several concurrent transfers) if
//!   the receiving peer or its network briefly stalls.
//! - **Low watermark: 1 MiB** (a quarter of the high watermark, `16` chunks' worth). Deliberately
//!   *not* equal to the high watermark: a single-threshold watermark would pause and immediately
//!   resume every time `buffered_amount` drifted a few bytes either side of one line (a real
//!   transport's queue depth is not perfectly monotonic under concurrent drains), thrashing the
//!   send loop. Resuming only once the backlog has drained to a quarter of where it triggered the
//!   pause gives a meaningful hysteresis gap while still resuming promptly (not waiting for the
//!   queue to go fully empty, which would idle the link).
//! - **Poll interval while paused: 5 ms.** Frequent enough that resuming feels instantaneous to a
//!   human once capacity frees up, without busy-spinning the executor between polls.
//!
//! ## Batch sequencing
//! [`send_files`] sends a batch of files **sequentially**: file `N+1`'s first chunk is only handed
//! to `send_stream_frame` after file `N`'s last chunk has been (not necessarily peer-*acknowledged*
//! — this substrate has no application-level ack; "sent" here means "handed to the transport").
//! Chosen over interleaving multiple files' chunks on the wire because interleaving would need its
//! own per-file backpressure/priority/fairness policy (which file gets the next slot when the
//! watermark allows one more send?) — a second, unscoped design question this task's own risk note
//! doesn't ask for. Sequential sending needs none of that: one [`SenderConfig`]/watermark loop,
//! reused per file, in file order.
//!
//! ## Wire encoding
//! Every chunk sent goes out as a [`crate::chunk::ChunkFrame`] (`{i: uint, data: bstr}`,
//! `docs/api/wire-protocol.md` §6), CBOR-encoded via [`crate::chunk::ChunkFrame::encode`] — the
//! exact `bytes` handed to `send_stream_frame`. [`crate::chunk::ChunkFrame`] is the single
//! canonical type for this shape, shared with the receiver engine (task 10.8,
//! [`crate::receiver`]), so the two sides can never independently drift on the wire shape.
//!
//! ## Reordering: chunk `i` carries its own position, deliberately never inferred from call order
//! The channel is reliable + unordered ([`crate::file::FileStream::channel_cfg`]): the transport
//! may deliver frames out of the order they were sent. This module's own send loop happens to send
//! chunks `0, 1, 2, …` in order (the common case), but nothing in [`send_chunk_frame`] — the one
//! primitive that actually builds and sends a wire frame — assumes or depends on that: it takes an
//! explicit `i` and bakes it into the frame it sends, so calling it for chunk 5 before chunk 2
//! produces exactly the same two frames (order-independent) as calling it the other way around.
//! [`send_chunk_frame`] is `pub` specifically so this property is unit-testable in isolation (see
//! this module's tests) and so a future resume engine (task 10.9) — which will need to (re)send an
//! arbitrary, non-contiguous subset of chunk indices — has a ready-made per-chunk primitive rather
//! than needing to re-derive one from [`send_files`]'s whole-file loop.

use std::future::Future;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use meridian_core::chat::ChatState;
use meridian_core::session::{P2pSession, SessionError};
use meridian_core::streams::StreamId;
use meridian_core::transport::Transport;
use meridian_proto::CodecError;

use crate::chunk::{seal_chunk, ChunkFrame};
use crate::merkle::CHUNK_SIZE;

/// Errors from the sender engine. Both variants pass through an underlying error verbatim; neither
/// ever carries `k_f` or plaintext chunk bytes.
#[derive(Debug, thiserror::Error)]
pub enum SenderError {
    /// The session substrate rejected the send (e.g. `sid` is not (or no longer) an open stream on
    /// this session — see [`SessionError::UnknownStream`]) or the query for `stream_buffered_amount`
    /// failed the same way.
    #[error("session error while sending a chunk: {0}")]
    Session(#[from] SessionError),
    /// CBOR-encoding the `{i, data}` chunk frame failed. Never happens for well-formed inputs (a
    /// `u64` index and a `Vec<u8>` always encode); kept as a real error rather than an `unwrap`
    /// purely so this module never panics on a codec-layer regression.
    #[error("failed to encode a chunk frame: {0}")]
    Encode(#[from] CodecError),
}

/// Low-watermark backpressure policy + poll cadence — see the module doc for the concrete defaults
/// and their rationale. Every field is a plain, cheaply-`Copy`able number; construct a
/// non-default value directly (`SenderConfig { high_watermark: ..., ..Default::default() }`) to
/// tune it, e.g. for task 10.14's soak test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SenderConfig {
    /// Pause sending once `stream_buffered_amount(sid)` exceeds this many bytes.
    pub high_watermark: u64,
    /// Once paused, resume only after `stream_buffered_amount(sid)` has drained to at or below this
    /// many bytes. Must be `<= high_watermark` for the hysteresis to ever engage; nothing in this
    /// module enforces that (a caller who sets `low_watermark > high_watermark` simply never pauses
    /// long, since the first poll after crossing `high_watermark` would already be `<=
    /// low_watermark` too) — see [`SenderConfig::default`] for a config that does engage it.
    pub low_watermark: u64,
    /// How long to sleep between polls of `stream_buffered_amount` while paused.
    pub poll_interval: Duration,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            high_watermark: 4 * 1024 * 1024,
            low_watermark: 1024 * 1024,
            poll_interval: Duration::from_millis(5),
        }
    }
}

/// One already-open file transfer to send — everything [`send_file`]/[`send_files`] need about a
/// single transfer besides the session/chat/config they're already given. `sid` must already be an
/// open, accepted `mrd.file/1` data channel (task 10.6's `open_stream`/`on_open` round trip); `k_f`
/// must be the exact per-file key sealed into that transfer's manifest
/// (`FileStream::build_open_params`'s own returned key).
pub struct FileSend<'a> {
    pub sid: StreamId,
    pub k_f: &'a [u8; 32],
    /// Display name only (echoes the manifest's own `name` field into progress events) — never used
    /// as a path or otherwise interpreted.
    pub name: String,
    pub data: &'a [u8],
}

impl std::fmt::Debug for FileSend<'_> {
    /// Deliberately omits `k_f` (key material) and `data` (up to gigabytes of file content) — only
    /// `sid`/`name`/`data`'s length are ever safe to print, matching this crate's convention
    /// (`crate::chunk::ChunkFrame`, `crate::receiver::FileReceiver`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSend")
            .field("sid", &self.sid)
            .field("name", &self.name)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// A progress update for one file in a (possibly multi-file) batch. Carries no key material or
/// plaintext chunk bytes — safe to log/print/render directly.
#[derive(Clone, Debug, PartialEq)]
pub struct SendProgress {
    /// This file's position in the batch (`0`-based). Always `0` for a single-file [`send_file`]
    /// call.
    pub file_index: usize,
    /// Total number of files in the batch (`1` for a single-file [`send_file`] call).
    pub file_count: usize,
    /// The file's display name, echoed from [`FileSend::name`].
    pub name: String,
    /// Bytes of this file handed to `send_stream_frame` so far (plaintext count, i.e. the file's
    /// own size — not the larger sealed/ratchet-framed wire size).
    pub bytes_sent: u64,
    /// This file's total size in bytes.
    pub total_bytes: u64,
    /// Average throughput so far for this file: `bytes_sent / (elapsed time since this file's first
    /// chunk)`, in bytes/second. `0.0` for the very first event of a file (no elapsed time yet) and
    /// for a zero-byte file's only event.
    pub bytes_per_sec: f64,
}

/// A subscriber for [`SendProgress`] updates — the same `tokio::sync::mpsc` channel idiom
/// `meridian-core`'s own `P2pSession`/`SessionEvent` plumbing already uses
/// (`apps/core/src/session.rs`), not a new async idiom introduced by this crate. The CLI/TUI
/// surfaces that render a progress bar (tasks 10.10/10.11) hold the paired
/// [`mpsc::UnboundedReceiver<SendProgress>`] and `.recv().await` it concurrently with the send.
pub type ProgressSender = mpsc::UnboundedSender<SendProgress>;

/// Sends one already-open file transfer end to end: chunk, seal, frame, and push every chunk of
/// `file.data` over `file.sid`, throttled by `cfg`'s watermarks, emitting a [`SendProgress`] after
/// every chunk (and once, with `bytes_sent = total_bytes = 0`, for a zero-byte file) if `progress`
/// is supplied.
pub async fn send_file<T: Transport>(
    session: &mut P2pSession<T>,
    chat: &mut ChatState,
    file: FileSend<'_>,
    cfg: &SenderConfig,
    progress: Option<&ProgressSender>,
) -> Result<(), SenderError> {
    send_one(session, chat, &file, 0, 1, cfg, progress).await
}

/// Sends a batch of already-open file transfers **sequentially** — see the module doc's "Batch
/// sequencing" section for why sequential was chosen over interleaving. `files[i].file_index` in
/// every emitted [`SendProgress`] is `i`; `file_count` is `files.len()` throughout.
pub async fn send_files<T: Transport>(
    session: &mut P2pSession<T>,
    chat: &mut ChatState,
    files: &[FileSend<'_>],
    cfg: &SenderConfig,
    progress: Option<&ProgressSender>,
) -> Result<(), SenderError> {
    let file_count = files.len();
    for (file_index, file) in files.iter().enumerate() {
        send_one(session, chat, file, file_index, file_count, cfg, progress).await?;
    }
    Ok(())
}

/// Shared per-file send loop behind both [`send_file`] and [`send_files`].
async fn send_one<T: Transport>(
    session: &mut P2pSession<T>,
    chat: &mut ChatState,
    file: &FileSend<'_>,
    file_index: usize,
    file_count: usize,
    cfg: &SenderConfig,
    progress: Option<&ProgressSender>,
) -> Result<(), SenderError> {
    let total = file.data.len() as u64;
    let start = Instant::now();
    let mut sent: u64 = 0;

    let mut chunks = file.data.chunks(CHUNK_SIZE).enumerate().peekable();
    if chunks.peek().is_none() {
        // A zero-byte file has no chunks to send at all (unlike `crate::merkle`'s tree, which
        // still builds one virtual leaf) — still surface exactly one terminal progress event so a
        // batch UI always sees a completion update per file, never silence for an empty file.
        emit_progress(progress, file_index, file_count, &file.name, 0, 0, 0.0);
    }
    for (i, chunk) in chunks {
        wait_for_capacity(|| session.stream_buffered_amount(file.sid), cfg).await?;
        send_chunk_frame(session, chat, file.sid, file.k_f, i as u64, chunk).await?;
        sent += chunk.len() as u64;
        let elapsed = start.elapsed().as_secs_f64();
        let bytes_per_sec = if elapsed > 0.0 {
            sent as f64 / elapsed
        } else {
            0.0
        };
        emit_progress(
            progress,
            file_index,
            file_count,
            &file.name,
            sent,
            total,
            bytes_per_sec,
        );
    }
    Ok(())
}

fn emit_progress(
    progress: Option<&ProgressSender>,
    file_index: usize,
    file_count: usize,
    name: &str,
    bytes_sent: u64,
    total_bytes: u64,
    bytes_per_sec: f64,
) {
    if let Some(tx) = progress {
        // A dropped receiver (UI gone away) is not this engine's problem — the transfer itself
        // must keep going; silently ignore the send failure rather than erroring the whole
        // transfer over a UI-side disconnect.
        let _ = tx.send(SendProgress {
            file_index,
            file_count,
            name: name.to_string(),
            bytes_sent,
            total_bytes,
            bytes_per_sec,
        });
    }
}

/// Seals one chunk (task 10.5's [`seal_chunk`]) and sends it as a `{i, data}` [`ChunkFrame`] over
/// `sid` via `send_stream_frame`. Public (see the module doc's "Reordering" section): callers may
/// invoke this directly, for any `i`, in any order — nothing here depends on having sent `i - 1`
/// first, or on this call's return happening before/after a sibling call's.
pub async fn send_chunk_frame<T: Transport>(
    session: &mut P2pSession<T>,
    chat: &mut ChatState,
    sid: StreamId,
    k_f: &[u8; 32],
    i: u64,
    chunk: &[u8],
) -> Result<(), SenderError> {
    let sealed = seal_chunk(k_f, i, chunk);
    let bytes = ChunkFrame { i, data: sealed }.encode()?;
    session.send_stream_frame(chat, sid, &bytes).await?;
    Ok(())
}

/// The low-watermark backpressure hysteresis (module doc): if `buffered_amount()` is already at or
/// below `cfg.high_watermark`, returns immediately. Otherwise polls every `cfg.poll_interval` until
/// it drops to at or below `cfg.low_watermark`. Generic over how "buffered amount" is queried
/// (rather than taking a `&P2pSession<T>` directly) so this hysteresis logic is unit-testable in
/// isolation, without a live P2P session/transport (see this module's tests).
async fn wait_for_capacity<F, Fut>(
    mut buffered_amount: F,
    cfg: &SenderConfig,
) -> Result<(), SessionError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<u64, SessionError>>,
{
    if buffered_amount().await? <= cfg.high_watermark {
        return Ok(());
    }
    loop {
        tokio::time::sleep(cfg.poll_interval).await;
        if buffered_amount().await? <= cfg.low_watermark {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    fn cfg(high: u64, low: u64) -> SenderConfig {
        SenderConfig {
            high_watermark: high,
            low_watermark: low,
            poll_interval: Duration::from_millis(1),
        }
    }

    #[tokio::test]
    async fn wait_for_capacity_returns_immediately_when_already_under_the_high_watermark() {
        let calls = Arc::new(AtomicU64::new(0));
        let calls2 = calls.clone();
        wait_for_capacity(
            move || {
                calls2.fetch_add(1, Ordering::SeqCst);
                async { Ok(5u64) }
            },
            &cfg(100, 20),
        )
        .await
        .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "must not poll again once already under the high watermark"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_capacity_pauses_above_high_and_resumes_only_at_or_below_low() {
        // Simulated buffered-amount readings over successive polls: starts well above the high
        // watermark (100), drains gradually, and must not be treated as "resumed" until it reaches
        // the low watermark (20) — not merely back under the high one (a value of 50 here would
        // wrongly resume a single-threshold policy).
        let sequence = [150u64, 150, 90, 50, 15];
        let idx = Arc::new(AtomicUsize::new(0));
        let idx2 = idx.clone();
        let result = wait_for_capacity(
            move || {
                let i = idx2.fetch_add(1, Ordering::SeqCst).min(sequence.len() - 1);
                async move { Ok(sequence[i]) }
            },
            &cfg(100, 20),
        )
        .await;
        assert!(result.is_ok());
        // Every reading was consulted (the last one, 15, is what finally satisfied the low
        // watermark) — proves the loop kept polling through the whole drain, not just the first
        // sub-100 reading (90), which is above the low watermark and must not have resumed early.
        assert_eq!(idx.load(Ordering::SeqCst), sequence.len());
    }

    #[tokio::test]
    async fn wait_for_capacity_propagates_the_underlying_session_error() {
        let err = wait_for_capacity(
            || async { Err(SessionError::UnknownStream(42)) },
            &cfg(100, 20),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SessionError::UnknownStream(42)));
    }
}
