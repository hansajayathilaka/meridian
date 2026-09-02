//! `mrd.file/1` — the [`StreamType`] implementation for P2P file transfer (T09, task 10.6). The
//! literal acceptance bar this module exists to meet
//! (`docs/architecture/features/09-file-transfer.md`): "implemented purely as a stream type against
//! the T04 registry — no changes to core session code allowed." Nothing in `meridian-core`,
//! `meridian-crypto`, or `meridian-transport` changes for this file type to exist; this crate only
//! *depends on* `meridian-core`'s public surface (the registry, the ratchet-sealing primitive) the
//! same way any third-party implementer would (`docs/api/stream-types-v1.md`).
//!
//! Scope (task 10.6, per its own task file): the `StreamType` shell (name/version/channel
//! config/direction/mandatory), the recipient accept/reject policy hook (`on_open`), a minimal
//! per-transfer state container fed by `on_frame`, and building + ratchet-sealing the manifest sent
//! on `mrd.ctrl/1`'s `Open.params` (`docs/architecture/system-design.md` §7.2). The sender loop that
//! actually streams chunks (10.7), the receiver loop that verifies/writes them (10.8), resume
//! (10.9), and the CLI/TUI surfaces (10.10/10.11) are separate, independently-testable tasks built
//! on top of the shell defined here.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use zeroize::Zeroizing;

use meridian_core::chat::{ChatError, ChatState};
use meridian_core::envelope::Direction;
use meridian_core::store::{KeyHandle, SecretStore};
use meridian_core::streams::{OpenDecision, PolicyCtx, StreamId, StreamType};
use meridian_core::transport::ChannelCfg;
use meridian_proto::CodecError;

use crate::chunk::ChunkFrame;
use crate::manifest::FileManifest;
use crate::merkle::CHUNK_SIZE;
use crate::resume::{ResumeRequest, FRAME_TAG_CHUNK, FRAME_TAG_RESUME};

/// Registry name for this stream type, including its version suffix — see
/// [`StreamType::name`]/[`StreamType::version`].
pub const NAME: &str = "mrd.file/1";

/// The numeric version matching [`NAME`]'s `/1` suffix.
pub const VERSION: u16 = 1;

/// Synchronous "ask a human" hook signature — see [`FileStream::with_ask_user`].
type AskUserFn = dyn Fn(&PolicyCtx, &FileManifest) -> bool + Send + Sync;

/// The file metadata half of a `mrd.file/1` manifest — everything [`FileStream::build_open_params`]
/// needs about the file itself, as opposed to the two parties' identities. Grouped into its own type
/// only to keep `build_open_params`'s argument count sane; carries no behavior of its own.
pub struct FileMeta {
    pub name: String,
    pub size: u64,
    pub root: [u8; 32],
}

/// `TODO: confirm` — `docs/architecture/features/09-file-transfer.md` specifies "auto-accept images
/// < N MB configurable" but pins no default `N`. 5 MiB is this crate's own starting default; it is a
/// UX knob, never a wire-relevant constant (nothing about the threshold value is on the wire — only
/// the sender's `size` field is), so a future spec decision can freely change it without a
/// conformance-vector break. Callers needing a different default should call
/// [`FileStream::new`]/[`FileStream::with_ask_user`] directly rather than relying on this constant.
pub const DEFAULT_AUTO_ACCEPT_IMAGE_MAX_BYTES: u64 = 5 * 1024 * 1024;

/// Errors from this module's own helpers (manifest build + seal). Never surfaces from the
/// [`StreamType`] trait methods themselves — those have no `Result` to return, so a malformed or
/// adversarial `on_open` input becomes [`OpenDecision::Reject`], never a panic or a propagated error.
#[derive(Debug, thiserror::Error)]
pub enum FileStreamError {
    /// Sealing `k_f` under the ratchet failed (e.g. no established session with the peer yet —
    /// [`ChatError::NoSession`]). [`FileStream::build_open_params`] never falls back to sending
    /// `k_f` unsealed; it errors instead.
    #[error("failed to seal k_f under the ratchet: {0}")]
    Seal(#[from] ChatError),
    /// CBOR-encoding the manifest failed.
    #[error("failed to encode manifest: {0}")]
    Encode(#[from] CodecError),
    /// The CSPRNG failed to fill `k_f`'s bytes.
    #[error("failed to generate a fresh per-file key: {0}")]
    Rng(String),
}

/// The three-way verdict [`decide_file_offer`] computes from policy alone — richer than the
/// `StreamType` trait's own [`OpenDecision`] (`Accept`/`Reject` only), so the pure policy logic
/// stays independently testable apart from the synchronous "ask a human" step
/// [`FileStream::on_open`] performs to collapse `AskUser` into whichever of the two the wire
/// actually carries. Mirrors `docs/api/stream-types-v1.md`'s framing of `on_open`: "prompt or
/// consult a policy engine here" — `AskUser` is the seam where that happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileOfferVerdict {
    /// Auto-accept without consulting anyone: an image under the configured size threshold, and
    /// the peer is already an established contact.
    AutoAccept,
    /// Neither auto-acceptable nor a stranger: consult the caller's policy/prompt hook.
    AskUser,
    /// Reject outright, with the `code`/`reason` [`OpenDecision::Reject`] carries on the wire.
    Reject { code: String, reason: String },
}

/// Pure policy decision for an inbound `mrd.file/1` OPEN, given its manifest and the live
/// first-contact signal from [`PolicyCtx`].
///
/// **First-contact takes precedence over everything else**: a stranger is never auto-accepted
/// regardless of file type or size, checked *before* the size/type threshold so nothing below it can
/// ever override this. This mirrors chat's own message-request gate one layer up
/// (`PolicyCtx::first_contact`'s doc: "the message-request gate, §7.1") and the
/// `anonymity-model`/`stream-type-authoring` skills' guidance that file transfer sits between chat's
/// auto-accept and tunnel's always-prompt: the size-threshold auto-accept for images is the spec's
/// own compromise for an *established* contact, never a bypass of the contact relationship itself.
pub fn decide_file_offer(
    manifest: &FileManifest,
    policy: &PolicyCtx,
    auto_accept_image_max_bytes: u64,
) -> FileOfferVerdict {
    if policy.first_contact {
        return FileOfferVerdict::Reject {
            code: "first-contact".to_string(),
            reason: "file transfers require an established contact".to_string(),
        };
    }
    if is_probably_image(&manifest.name) && manifest.size <= auto_accept_image_max_bytes {
        FileOfferVerdict::AutoAccept
    } else {
        FileOfferVerdict::AskUser
    }
}

/// Sender-supplied file name → "probably an image" heuristic used only for the auto-accept
/// convenience threshold above, never as a security boundary.
///
/// `TODO: confirm` — the `mrd.file/1` manifest (task 10.3's [`FileManifest`]) carries no dedicated
/// content-type field, so extension-sniffing the sender-controlled `name` is the only signal
/// available today. A hostile (but already-contacted — first-contact is rejected above regardless)
/// sender can trivially name a non-image file `photo.jpg` to *reach* this branch, but cannot use it
/// to exceed `auto_accept_image_max_bytes`, and the bytes still must pass merkle verification (task
/// 10.8) before anything is ever written to disk. If the spec later adds a real content-type field,
/// prefer it over extension sniffing.
fn is_probably_image(name: &str) -> bool {
    const IMAGE_EXTENSIONS: &[&str] = &[
        "jpg", "jpeg", "png", "gif", "webp", "bmp", "heic", "heif", "avif", "tiff", "tif",
    ];
    let lower = name.to_ascii_lowercase();
    IMAGE_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(&format!(".{ext}")))
}

/// Per-transfer state captured from the moment a `mrd.file/1` OPEN is accepted on this side.
/// Deliberately minimal: task 10.8 (the receiver engine) owns turning `pending_chunks` into
/// verified, on-disk bytes (decoding each `{i, data}` chunk body, per-chunk AEAD open via
/// [`crate::chunk::open_chunk`], incremental merkle verification against `manifest.root`, offset
/// writes, resume). This struct only defines the shape that engine will consume.
#[derive(Debug, Clone, Default)]
pub struct TransferState {
    /// The manifest captured at accept time. Always `Some` for an entry this module itself created
    /// (`FileStream::accept`, the only writer) — `on_frame` never creates an entry, only inserts into
    /// one that already exists.
    pub manifest: Option<FileManifest>,
    /// Raw inbound chunk frames, keyed by each frame's own claimed chunk index `i` (decoded from its
    /// `{i, data}` CBOR body) — **not** arrival order, since `channel_cfg` is reliable + unordered.
    /// Mirrors `crate::receiver::FileReceiver`'s own `chunks: BTreeMap<u64, Vec<u8>>` convention for
    /// the identical reason: a duplicate/retransmitted delivery of an index already buffered must
    /// not grow this structure (review finding F3/N1 — an unbounded `Vec` here let a flooding or
    /// retransmitting peer grow memory without bound, and forced an O(n) rescan just to find which
    /// indices had arrived). [`FileStream::on_frame`] is the only writer, and this is always a keyed
    /// **insert** (last-arrival-wins), never a keyed *ignore*: a duplicate index for a chunk already
    /// buffered replaces the existing entry rather than appending a second one — bounding this
    /// structure to at most one entry per index either way, but only "replace" also lets task
    /// 10.9/10.16's real resume protocol supersede a previously-buffered *corrupted* delivery with a
    /// later, genuine resend for the same index (`corrupted_chunk_adversarial.rs`'s own acceptance
    /// test exercises exactly this and would silently break under a first-wins/ignore policy, since
    /// nothing else ever removes or replaces a buffered entry before this restructuring existed).
    ///
    /// **Resolved `TODO: confirm` (task 11.3's own open question):** once a transfer is accepted,
    /// its manifest's `size` is already known, so `on_frame` also rejects an index that is obviously
    /// out of range for that size (via [`leaf_count_for_size`]) *before* ever inserting it — not just
    /// relying on the fact that a validated in-range index is inherently bounded by the leaf count.
    /// This closes F3's DoS concern directly at the point of insertion (mirroring
    /// `FileReceiver::receive_frame`'s own `OutOfRange` check, which today only ever runs later, at
    /// `finalize_transfer`/reassembly time) rather than leaving a window where an arbitrary `u64`
    /// index can still be buffered until that later check runs. This is a small, natural guard added
    /// as part of this restructuring — not a new validation subsystem — and it does not change what a
    /// *legitimate* transfer needs: every real index is always `< leaf_count`.
    pub pending_chunks: BTreeMap<u64, Vec<u8>>,
}

/// Number of [`CHUNK_SIZE`] leaves a file of `size` bytes was split into, matching
/// [`crate::merkle::MerkleTree`]'s own empty-file convention (a zero-byte file is exactly one
/// virtual leaf, never zero leaves). Mirrors `crate::receiver`'s own private helper of the same name
/// and shape exactly — kept as its own copy here (rather than exported and shared) since this module
/// must not depend on `receiver.rs`'s internals, and the computation is a one-line mirror of the
/// manifest's own `size` field, not receiver-engine logic.
fn leaf_count_for_size(size: u64) -> usize {
    if size == 0 {
        1
    } else {
        size.div_ceil(CHUNK_SIZE as u64) as usize
    }
}

/// The `mrd.file/1` [`StreamType`]: registry name/version, channel config, and the recipient policy
/// hook (task 10.6). Register with [`meridian_core::streams::register_stream_type`] like any other
/// additive type — zero core-crate edits.
pub struct FileStream {
    auto_accept_image_max_bytes: u64,
    /// Synchronous "ask a human" hook, consulted only when [`decide_file_offer`] returns
    /// `AskUser`. Defaults to always declining (`|_, _| false`) — the safe default until a UI layer
    /// (10.10/10.11) wires a real prompt. `on_open` is a synchronous trait method with no async
    /// escape hatch, so `docs/api/stream-types-v1.md`'s "prompt or consult a policy engine here"
    /// must itself be synchronous — this closure *is* that seam.
    ask_user: Arc<AskUserFn>,
    transfers: Mutex<HashMap<StreamId, TransferState>>,
    /// (task 10.9) Sender-side watchers for an inbound in-stream resume message, keyed by `sid`.
    /// Populated only by [`FileStream::watch_resume`], which the caller that *sent* (opened) a
    /// `mrd.file/1` transfer registers right after opening it, so that when the peer later sends a
    /// [`crate::resume::FRAME_TAG_RESUME`] frame back on that same stream, `on_frame` has somewhere
    /// to deliver it (an mpsc channel, not a return value — `on_frame` is a synchronous trait method
    /// with no way to itself call the async `send_stream_frame`/`send_missing_chunks`, so the actual
    /// resend is driven by whatever async caller is watching this channel). A receiver-side
    /// `FileStream` (one that instead accepted this `sid` via `on_open`) never registers a watcher
    /// here, so a resume frame arriving at the receiver — which the protocol never sends in that
    /// direction — is simply dropped, matching `on_frame`'s existing "ignore what nobody is tracking"
    /// default for chunk frames on an unaccepted stream.
    resume_watchers: Mutex<HashMap<StreamId, mpsc::UnboundedSender<ResumeRequest>>>,
}

impl Default for FileStream {
    fn default() -> Self {
        Self::new(DEFAULT_AUTO_ACCEPT_IMAGE_MAX_BYTES)
    }
}

impl FileStream {
    /// A `FileStream` that auto-accepts images under `auto_accept_image_max_bytes` bytes (from an
    /// already-established contact) and never accepts anything else without an explicit
    /// [`with_ask_user`](Self::with_ask_user) hook — i.e. every non-auto-accept OPEN is declined
    /// until a caller opts in to a real prompt.
    pub fn new(auto_accept_image_max_bytes: u64) -> Self {
        Self::with_ask_user(auto_accept_image_max_bytes, |_policy, _manifest| false)
    }

    /// Like [`new`](Self::new), but with a caller-supplied synchronous policy hook for the
    /// `AskUser` verdict — the seam a CLI/TUI layer (10.10/10.11) wires to an actual accept/reject
    /// prompt. Never consulted for a first-contact OPEN (`decide_file_offer` rejects those before
    /// this hook is even reachable) or an auto-acceptable one.
    pub fn with_ask_user(
        auto_accept_image_max_bytes: u64,
        ask_user: impl Fn(&PolicyCtx, &FileManifest) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            auto_accept_image_max_bytes,
            ask_user: Arc::new(ask_user),
            transfers: Mutex::new(HashMap::new()),
            resume_watchers: Mutex::new(HashMap::new()),
        }
    }

    /// A snapshot of the per-transfer state for `sid`, if this side has accepted (and is therefore
    /// tracking) that stream. For the receiver engine (10.8) and tests.
    pub fn transfer(&self, sid: StreamId) -> Option<TransferState> {
        self.transfers.lock().ok()?.get(&sid).cloned()
    }

    /// (task 10.9) Registers this `sid` as a sender-side transfer to watch for an inbound in-stream
    /// resume message, returning the receiving half of the channel `on_frame` delivers one to. The
    /// caller (the sender engine, or whoever is orchestrating a redial-triggered resume — see
    /// `crate::resume`'s module doc for the redial-trigger gap this crate cannot itself close) is
    /// expected to call this once, right after opening the transfer via
    /// `P2pSession::open_stream`/`FileStream::build_open_params`, then `.recv().await` this channel
    /// concurrently with the rest of its send loop.
    pub fn watch_resume(&self, sid: StreamId) -> mpsc::UnboundedReceiver<ResumeRequest> {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Ok(mut watchers) = self.resume_watchers.lock() {
            watchers.insert(sid, tx);
        }
        rx
    }

    /// Records the accepted transfer's manifest and returns the `Accept` decision. The only writer
    /// of a new `transfers` entry.
    fn accept(&self, sid: StreamId, manifest: FileManifest) -> OpenDecision {
        if let Ok(mut transfers) = self.transfers.lock() {
            transfers.insert(
                sid,
                TransferState {
                    manifest: Some(manifest),
                    pending_chunks: BTreeMap::new(),
                },
            );
        }
        OpenDecision::Accept
    }

    /// Generates a fresh, CSPRNG-random per-file key `k_f` (task 10.5's own recorded should-fix:
    /// never reused across files, and now backed by `getrandom` rather than any deterministic
    /// source), seals it under the ratchet on the session with `peer_ik` via
    /// [`ChatState::seal_bytes`] — the *existing* chat/session encryption path every other
    /// content-shaped payload in this codebase already goes through, not a new mechanism — and
    /// builds the `mrd.file/1` manifest CBOR body (`docs/architecture/system-design.md` §7.2:
    /// `{name, size, root, enc(k_f under ratchet)}`) ready to hand to
    /// `P2pSession::open_stream`'s `params` argument.
    ///
    /// Returns `(params, k_f)`: `params` is the encoded manifest to send on `Open`; `k_f` is the
    /// raw key the caller (the sender engine, task 10.7) keeps to seal this file's chunks via
    /// [`crate::chunk::seal_chunk`]. Only the *sealed* form of `k_f` (ciphertext) ever goes into the
    /// manifest's own `key` field. `k_f` is returned `Zeroizing`-wrapped (security-reviewer finding
    /// on task 10.6) — it derefs to `&[u8; 32]` so callers pass it to `seal_chunk` unchanged, but is
    /// cleared automatically when the caller (10.7's sender, once the transfer ends) drops it,
    /// matching this codebase's convention for any symmetric/derived key material that must outlive
    /// a single call (`apps/crypto/src/x3dh.rs`, `apps/crypto/src/ratchet.rs`).
    pub fn build_open_params(
        chat: &mut ChatState,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        peer_ik: &[u8; 32],
        meta: FileMeta,
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), FileStreamError> {
        let k_f = fresh_k_f()?;
        let sealed_key = chat.seal_bytes(store, handle, our_ik, peer_ik, &k_f[..])?;
        let manifest = FileManifest {
            name: meta.name,
            size: meta.size,
            root: meta.root,
            key: sealed_key,
        };
        let params = manifest.encode()?;
        Ok((params, k_f))
    }
}

/// Generates a fresh, independently random 32-byte per-file key via the OS CSPRNG. Split out of
/// [`FileStream::build_open_params`] so its freshness (task 10.5's recorded should-fix) is directly
/// unit-testable without needing a live ratchet session.
fn fresh_k_f() -> Result<Zeroizing<[u8; 32]>, FileStreamError> {
    let mut k_f = [0u8; 32];
    getrandom::fill(&mut k_f).map_err(|e| FileStreamError::Rng(e.to_string()))?;
    Ok(Zeroizing::new(k_f))
}

impl StreamType for FileStream {
    fn name(&self) -> &'static str {
        NAME
    }

    fn version(&self) -> u16 {
        VERSION
    }

    fn channel_cfg(&self) -> ChannelCfg {
        // Reliable + unordered (`docs/api/stream-types-v1.md`'s built-in table: "manifest on ctrl;
        // 64 KiB chunks; merkle resume"): chunks must all eventually arrive, but not in any
        // particular order (offset carries position; backpressure/resume live in later tasks).
        ChannelCfg {
            label: NAME.to_string(),
            reliable: true,
            ordered: false,
            max_retransmits: None,
        }
    }

    fn direction(&self) -> Direction {
        Direction::Bidir
    }

    // `mandatory()` is left at the trait's default (`false`): an unsupported peer simply can't
    // receive files — opening it against such a peer yields `Reject{code:"unsupported"}` at
    // capability exchange, never a session error (mirrors `OptionalExotic` in
    // `apps/core/src/streams.rs`'s own test module, the only other optional-type example on hand).

    /// The recipient accept/reject policy hook (task 10.6). Decodes the manifest carried in
    /// `params`, runs [`decide_file_offer`], and — only for the `AskUser` verdict — consults the
    /// injected [`ask_user`](Self) hook. A malformed manifest is rejected outright, never decoded
    /// partially or panicked on (every byte off the wire is hostile).
    fn on_open(&self, sid: StreamId, params: &[u8], policy: &PolicyCtx) -> OpenDecision {
        let manifest = match FileManifest::decode(params) {
            Ok(m) => m,
            Err(_) => {
                return OpenDecision::Reject {
                    code: "invalid".to_string(),
                    reason: "malformed mrd.file/1 manifest".to_string(),
                }
            }
        };
        match decide_file_offer(&manifest, policy, self.auto_accept_image_max_bytes) {
            FileOfferVerdict::AutoAccept => self.accept(sid, manifest),
            FileOfferVerdict::AskUser => {
                if (self.ask_user)(policy, &manifest) {
                    self.accept(sid, manifest)
                } else {
                    OpenDecision::Reject {
                        code: "policy".to_string(),
                        reason: "file transfer declined".to_string(),
                    }
                }
            }
            FileOfferVerdict::Reject { code, reason } => OpenDecision::Reject { code, reason },
        }
    }

    /// Inbound frame dispatch into the per-transfer state (task 10.6's own scope: buffering only —
    /// decode/verify/write is task 10.8's receiver engine) plus, as of task 10.9, the resume-frame
    /// dispatch. Every inbound `mrd.file/1` in-stream frame now carries a one-byte discriminator
    /// (`crate::resume`'s module doc, "Wire framing") ahead of its actual body:
    /// - [`FRAME_TAG_CHUNK`]: the body (with the tag byte stripped) is decoded as a [`ChunkFrame`]
    ///   only far enough to read its own claimed index `i` — the *value* inserted into
    ///   `pending_chunks` is still the bare, untouched `ChunkFrame`-encoded body bytes, byte-for-byte
    ///   identical to what task 10.7/10.8 already produce/consume. Buffered only for a stream this
    ///   side accepted (e.g. the sender's own side, which never calls `on_open` for a stream it
    ///   itself opened, is silently dropped, matching the trait's documented default rather than
    ///   growing unbounded state for a transfer with no captured manifest); a body that fails to
    ///   decode as a `ChunkFrame`, or whose claimed index `i` is out of range for the accepted
    ///   manifest's own size (task 11.3, review finding F3), is likewise dropped without buffering
    ///   anything. `pending_chunks` is keyed by `i` and bounded to one entry per index (task 11.3,
    ///   review finding N1) — a duplicate/retransmitted index for a chunk already buffered *replaces*
    ///   the existing entry rather than appending a second one: see
    ///   [`TransferState::pending_chunks`]'s own doc for why replace, not ignore.
    /// - [`FRAME_TAG_RESUME`]: decoded as a [`ResumeRequest`] and forwarded to whichever
    ///   [`watch_resume`](Self::watch_resume) caller registered a watcher for this `sid` (the
    ///   sender's own side); dropped silently if nobody is watching (e.g. it arrived at the
    ///   receiver's own side, where the protocol never sends one) or if it fails to decode (every
    ///   byte off the wire is hostile — never panics).
    /// - anything else (an unrecognized tag byte, or an empty frame with no tag at all) is dropped
    ///   without touching any state, exactly like a malformed manifest at `on_open`.
    fn on_frame(&self, sid: StreamId, frame: &[u8]) {
        let Some((&tag, body)) = frame.split_first() else {
            return;
        };
        match tag {
            FRAME_TAG_CHUNK => {
                if let Ok(mut transfers) = self.transfers.lock() {
                    if let Some(state) = transfers.get_mut(&sid) {
                        if let Some(manifest) = state.manifest.as_ref() {
                            if let Ok(chunk) = ChunkFrame::decode(body) {
                                let leaf_count = leaf_count_for_size(manifest.size);
                                if (chunk.i as usize) < leaf_count {
                                    // Keyed insert, last-arrival-wins (a plain `BTreeMap::insert`,
                                    // not `entry().or_insert()`) — see `TransferState::pending_chunks`'
                                    // own doc for why: a duplicate index can legitimately arrive
                                    // because task 10.9/10.16's resume protocol resends exactly this
                                    // index after a previous delivery for it failed downstream
                                    // verification (e.g. a corrupted chunk), and that later, genuine
                                    // resend must be able to supersede the earlier bad bytes. Either
                                    // policy (overwrite or first-wins/ignore) equally satisfies F3's
                                    // memory bound — this buffer never exceeds one entry per index
                                    // either way — so there is no bounding reason to prefer
                                    // first-wins, and only overwrite keeps resume's own
                                    // corrupted-chunk-recovery acceptance test
                                    // (`corrupted_chunk_adversarial.rs`, task 10.16) working.
                                    state.pending_chunks.insert(chunk.i, body.to_vec());
                                }
                            }
                        }
                    }
                }
            }
            FRAME_TAG_RESUME => {
                if let Ok(resume) = ResumeRequest::decode(body) {
                    if let Ok(watchers) = self.resume_watchers.lock() {
                        if let Some(tx) = watchers.get(&sid) {
                            // A dropped/gone-away watcher is not this dispatch's problem — the
                            // frame is simply not actionable by anyone anymore; ignore the send
                            // failure rather than treat it as an error (mirrors `sender.rs`'s own
                            // `emit_progress` convention for a disconnected receiver).
                            let _ = tx.send(resume);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    use meridian_core::streams::{register_stream_type, StreamRegistry};

    fn manifest(name: &str, size: u64) -> FileManifest {
        FileManifest {
            name: name.to_string(),
            size,
            root: [0x42; 32],
            key: vec![0xAA; 48],
        }
    }

    fn ctx(first_contact: bool) -> PolicyCtx {
        PolicyCtx {
            peer_ik: [0x11; 32],
            first_contact,
        }
    }

    const MAX: u64 = 1_000_000;

    #[test]
    fn auto_accepts_a_small_image_from_an_established_contact() {
        let verdict = decide_file_offer(&manifest("cat.png", MAX - 1), &ctx(false), MAX);
        assert_eq!(verdict, FileOfferVerdict::AutoAccept);
    }

    #[test]
    fn image_exactly_at_the_threshold_is_still_auto_accepted() {
        // Inclusive boundary: `size <= max`, not `<`.
        let verdict = decide_file_offer(&manifest("cat.png", MAX), &ctx(false), MAX);
        assert_eq!(verdict, FileOfferVerdict::AutoAccept);
    }

    #[test]
    fn oversized_image_from_an_established_contact_prompts_rather_than_auto_accepting() {
        let verdict = decide_file_offer(&manifest("cat.png", MAX + 1), &ctx(false), MAX);
        assert_eq!(verdict, FileOfferVerdict::AskUser);
    }

    #[test]
    fn non_image_from_an_established_contact_prompts_regardless_of_size() {
        let verdict = decide_file_offer(&manifest("resume.pdf", 10), &ctx(false), MAX);
        assert_eq!(verdict, FileOfferVerdict::AskUser);
    }

    #[test]
    fn a_stranger_is_never_auto_accepted_regardless_of_file_type_or_size() {
        // The exact combination that *would* auto-accept from an established contact...
        let tiny_image = manifest("cat.png", 1);
        assert_eq!(
            decide_file_offer(&tiny_image, &ctx(false), MAX),
            FileOfferVerdict::AutoAccept,
            "sanity: this combination auto-accepts once first_contact is false"
        );
        // ...must instead be rejected outright the moment `first_contact` is true, taking
        // precedence over the size/type threshold entirely (never `AskUser`, never `AutoAccept`).
        assert_eq!(
            decide_file_offer(&tiny_image, &ctx(true), MAX),
            FileOfferVerdict::Reject {
                code: "first-contact".to_string(),
                reason: "file transfers require an established contact".to_string(),
            }
        );
    }

    #[test]
    fn a_stranger_sending_a_large_non_image_is_also_rejected_not_merely_asked() {
        let verdict = decide_file_offer(&manifest("payload.exe", MAX * 10), &ctx(true), MAX);
        assert!(matches!(verdict, FileOfferVerdict::Reject { .. }));
    }

    #[test]
    fn extension_matching_is_case_insensitive() {
        let verdict = decide_file_offer(&manifest("CAT.PNG", 1), &ctx(false), MAX);
        assert_eq!(verdict, FileOfferVerdict::AutoAccept);
    }

    #[test]
    fn non_image_extension_never_auto_accepts_even_at_zero_bytes() {
        let verdict = decide_file_offer(&manifest("a", 0), &ctx(false), MAX);
        assert_eq!(verdict, FileOfferVerdict::AskUser);
    }

    #[test]
    fn fresh_k_f_is_independently_random_every_call() {
        // Task 10.5's own recorded should-fix: k_f generation must be CSPRNG-backed, not
        // deterministic — a freshness test proving two consecutive calls never collide (and aren't
        // trivially related, e.g. all-zero or sequential).
        let a = fresh_k_f().unwrap();
        let b = fresh_k_f().unwrap();
        assert_ne!(*a, *b, "two consecutive k_f draws must never collide");
        assert_ne!(*a, [0u8; 32], "k_f must never be the all-zero key");
        assert_ne!(*b, [0u8; 32], "k_f must never be the all-zero key");
    }

    #[test]
    fn on_open_with_default_ask_user_declines_anything_not_auto_acceptable() {
        let fs = FileStream::new(MAX);
        let decision = fs.on_open(
            1,
            &manifest("resume.pdf", 10).encode().unwrap(),
            &ctx(false),
        );
        assert!(matches!(decision, OpenDecision::Reject { .. }));
        assert!(
            fs.transfer(1).is_none(),
            "a declined OPEN must not be tracked"
        );
    }

    #[test]
    fn on_open_auto_accepts_a_small_image_and_records_transfer_state() {
        let fs = FileStream::new(MAX);
        let m = manifest("cat.png", 10);
        let decision = fs.on_open(7, &m.encode().unwrap(), &ctx(false));
        assert_eq!(decision, OpenDecision::Accept);
        let recorded = fs.transfer(7).expect("accepted transfer must be tracked");
        assert_eq!(recorded.manifest, Some(m));
        assert!(recorded.pending_chunks.is_empty());
    }

    #[test]
    fn on_open_rejects_a_first_contact_stranger_even_with_a_permissive_ask_user_hook() {
        // A permissive `ask_user` (always says yes) must still never fire for a stranger — the
        // `Reject{first-contact}` verdict short-circuits before the hook is ever consulted.
        let fs = FileStream::with_ask_user(MAX, |_policy, _manifest| true);
        let decision = fs.on_open(3, &manifest("cat.png", 1).encode().unwrap(), &ctx(true));
        assert!(
            matches!(decision, OpenDecision::Reject { ref code, .. } if code == "first-contact")
        );
        assert!(fs.transfer(3).is_none());
    }

    #[test]
    fn on_open_ask_user_hook_can_accept_a_non_auto_acceptable_offer() {
        let asked = Arc::new(AtomicBool::new(false));
        let asked_clone = asked.clone();
        let fs = FileStream::with_ask_user(MAX, move |_policy, _manifest| {
            asked_clone.store(true, Ordering::SeqCst);
            true
        });
        let m = manifest("resume.pdf", 10);
        let decision = fs.on_open(9, &m.encode().unwrap(), &ctx(false));
        assert_eq!(decision, OpenDecision::Accept);
        assert!(
            asked.load(Ordering::SeqCst),
            "the ask_user hook must have been consulted"
        );
        assert_eq!(fs.transfer(9).unwrap().manifest, Some(m));
    }

    #[test]
    fn on_open_rejects_a_malformed_manifest_without_panicking() {
        let fs = FileStream::new(MAX);
        let decision = fs.on_open(1, b"not a valid cbor manifest", &ctx(false));
        assert!(matches!(decision, OpenDecision::Reject { ref code, .. } if code == "invalid"));
    }

    /// (task 10.9) Prepends the chunk-frame discriminator byte — every real in-stream `mrd.file/1`
    /// frame now carries one (`crate::resume`'s module doc, "Wire framing").
    fn tagged_chunk(body: &[u8]) -> Vec<u8> {
        crate::resume::tag_frame(FRAME_TAG_CHUNK, body.to_vec())
    }

    /// (task 11.3) Builds a real, decodable `ChunkFrame`-encoded body for index `i` — as of task
    /// 11.3, `on_frame` decodes each chunk frame's own `i` (to key `pending_chunks` and to check it
    /// against the accepted manifest's leaf count), so tests can no longer feed arbitrary
    /// placeholder bytes the way the pre-11.3 arrival-order `Vec` allowed.
    fn chunk_frame_bytes(i: u64, data: &[u8]) -> Vec<u8> {
        crate::chunk::ChunkFrame {
            i,
            data: data.to_vec(),
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn on_frame_buffers_only_for_a_stream_this_side_accepted() {
        let fs = FileStream::new(MAX);
        // No prior `on_open`/accept for sid 5: frames must be dropped, not buffered anywhere.
        fs.on_frame(
            5,
            &tagged_chunk(&chunk_frame_bytes(0, b"stray chunk frame")),
        );
        assert!(fs.transfer(5).is_none());

        // Large enough that indices 0 and 1 are both in range.
        let m = manifest("cat.png", CHUNK_SIZE as u64 * 2);
        assert_eq!(
            fs.on_open(5, &m.encode().unwrap(), &ctx(false)),
            OpenDecision::Accept
        );
        let frame_a = chunk_frame_bytes(0, b"chunk-a");
        let frame_b = chunk_frame_bytes(1, b"chunk-b");
        fs.on_frame(5, &tagged_chunk(&frame_a));
        fs.on_frame(5, &tagged_chunk(&frame_b));
        let recorded = fs.transfer(5).unwrap();
        let expected: BTreeMap<u64, Vec<u8>> = BTreeMap::from([(0, frame_a), (1, frame_b)]);
        assert_eq!(recorded.pending_chunks, expected);
    }

    #[test]
    fn on_frame_strips_the_tag_byte_leaving_pending_chunks_byte_for_byte_identical() {
        // Regression pin for the wire-framing change itself: `pending_chunks` must hold exactly the
        // pre-10.9 `ChunkFrame`-encoded bytes (task 10.7/10.8's own shape), never the tag byte —
        // keyed (task 11.3) by the frame's own index rather than arrival position.
        let fs = FileStream::new(MAX);
        // Large enough that index 3 is in range (4 leaves).
        let m = manifest("cat.png", CHUNK_SIZE as u64 * 4);
        fs.on_open(1, &m.encode().unwrap(), &ctx(false));
        let real_chunk_frame = crate::chunk::ChunkFrame {
            i: 3,
            data: vec![0xEE; 12],
        }
        .encode()
        .unwrap();
        fs.on_frame(1, &tagged_chunk(&real_chunk_frame));
        let recorded = fs.transfer(1).unwrap();
        assert_eq!(recorded.pending_chunks.len(), 1);
        assert_eq!(recorded.pending_chunks.get(&3), Some(&real_chunk_frame));
        // And it must still decode as a normal `ChunkFrame`, exactly as `sender_engine.rs`'s tests
        // rely on.
        let decoded = crate::chunk::ChunkFrame::decode(&recorded.pending_chunks[&3]).unwrap();
        assert_eq!(decoded.i, 3);
    }

    /// (task 11.3, review finding N1) A duplicate/retransmitted chunk frame for an index already
    /// buffered must never grow `pending_chunks` past one entry per index — bounding growth is F3's
    /// own concern, and it holds regardless of *which* copy the single remaining entry ends up
    /// holding. See `TransferState::pending_chunks`'s own doc for why the copy that wins is
    /// specifically the *latest* arrival (not the first): a legitimate resume resend for a
    /// previously-corrupted index must be able to supersede the earlier bad bytes
    /// (`corrupted_chunk_adversarial.rs`, task 10.16).
    #[test]
    fn on_frame_ignores_a_duplicate_chunk_index_rather_than_growing_the_buffer() {
        let fs = FileStream::new(MAX);
        let m = manifest("cat.png", CHUNK_SIZE as u64 * 2);
        fs.on_open(4, &m.encode().unwrap(), &ctx(false));

        let first = chunk_frame_bytes(0, &[0x01; 8]);
        let retransmit = chunk_frame_bytes(0, &[0x02; 8]); // same index, different payload
        fs.on_frame(4, &tagged_chunk(&first));
        fs.on_frame(4, &tagged_chunk(&retransmit));
        // A third, fourth, ... duplicate must not grow it either.
        fs.on_frame(4, &tagged_chunk(&retransmit));

        let recorded = fs.transfer(4).unwrap();
        assert_eq!(
            recorded.pending_chunks.len(),
            1,
            "a duplicate/retransmitted index must never grow the buffer"
        );
        assert_eq!(
            recorded.pending_chunks.get(&0),
            Some(&retransmit),
            "the latest arrival for an index must win, so a genuine resume resend can supersede a \
             previously-buffered corrupted delivery for the same index"
        );
    }

    /// (task 11.3's own resolved `TODO: confirm`) An obviously out-of-range chunk index — beyond the
    /// accepted manifest's own leaf count — must be rejected at `on_frame` time, not merely left for
    /// a later `finalize_transfer`-style check, closing F3's DoS concern directly rather than
    /// allowing unbounded-index insertion until then.
    #[test]
    fn on_frame_drops_an_out_of_range_chunk_index_without_buffering_it() {
        let fs = FileStream::new(MAX);
        // A single-leaf file (tiny size): only index 0 is in range.
        let m = manifest("cat.png", 10);
        fs.on_open(6, &m.encode().unwrap(), &ctx(false));

        let hostile = chunk_frame_bytes(999, b"out of range");
        fs.on_frame(6, &tagged_chunk(&hostile));
        assert!(
            fs.transfer(6).unwrap().pending_chunks.is_empty(),
            "an out-of-range index must never be buffered"
        );

        // The real, in-range index still buffers normally afterward.
        let real = chunk_frame_bytes(0, b"real chunk");
        fs.on_frame(6, &tagged_chunk(&real));
        assert_eq!(fs.transfer(6).unwrap().pending_chunks.len(), 1);
    }

    #[test]
    fn on_frame_routes_a_resume_frame_to_its_registered_watcher() {
        let fs = FileStream::new(MAX);
        let mut rx = fs.watch_resume(9);
        let resume = ResumeRequest {
            bitmap: vec![0b0000_0110],
        };
        let tagged = crate::resume::tag_frame(FRAME_TAG_RESUME, resume.encode().unwrap());
        fs.on_frame(9, &tagged);
        let received = rx.try_recv().expect("resume must be delivered");
        assert_eq!(received, resume);
    }

    #[test]
    fn on_frame_drops_a_resume_frame_with_no_registered_watcher_without_panicking() {
        let fs = FileStream::new(MAX);
        let resume = ResumeRequest { bitmap: vec![0xFF] };
        let tagged = crate::resume::tag_frame(FRAME_TAG_RESUME, resume.encode().unwrap());
        // No `watch_resume` call for sid 42 at all — must not panic, must not affect `transfers`.
        fs.on_frame(42, &tagged);
        assert!(fs.transfer(42).is_none());
    }

    #[test]
    fn on_frame_drops_an_unknown_tag_and_an_empty_frame_without_panicking() {
        let fs = FileStream::new(MAX);
        let m = manifest("cat.png", 1);
        fs.on_open(2, &m.encode().unwrap(), &ctx(false));
        fs.on_frame(2, &[0xFFu8, 1, 2, 3]); // unrecognized tag
        fs.on_frame(2, &[]); // empty: no tag byte at all
        assert!(fs.transfer(2).unwrap().pending_chunks.is_empty());
    }

    #[test]
    fn on_frame_drops_a_malformed_resume_body_without_panicking() {
        let fs = FileStream::new(MAX);
        let _rx = fs.watch_resume(7);
        let garbage = crate::resume::tag_frame(FRAME_TAG_RESUME, b"not valid cbor".to_vec());
        fs.on_frame(7, &garbage); // must not panic
    }

    #[test]
    fn registers_into_the_stream_registry_as_optional_bidir() {
        let mut registry = StreamRegistry::with_builtins();
        register_stream_type(&mut registry, Arc::new(FileStream::default()));
        assert!(registry.supports(NAME));
        let advert = registry
            .advertise()
            .into_iter()
            .find(|a| a.name == NAME)
            .expect("mrd.file/1 must be advertised once registered");
        assert_eq!(advert.ver, VERSION);
        assert_eq!(advert.dir, Direction::Bidir);
        assert!(
            !advert.mandatory,
            "an unsupported peer must simply lack file transfer, never fail the session"
        );
    }

    #[test]
    fn channel_cfg_is_reliable_and_unordered() {
        let fs = FileStream::default();
        let cfg = fs.channel_cfg();
        assert!(cfg.reliable);
        assert!(!cfg.ordered);
        assert_eq!(cfg.max_retransmits, None);
        assert_eq!(cfg.label, NAME);
    }
}
