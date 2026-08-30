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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use meridian_core::chat::{ChatError, ChatState};
use meridian_core::envelope::Direction;
use meridian_core::store::{KeyHandle, SecretStore};
use meridian_core::streams::{OpenDecision, PolicyCtx, StreamId, StreamType};
use meridian_core::transport::ChannelCfg;
use meridian_proto::CodecError;

use crate::manifest::FileManifest;

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
    /// (`FileStream::accept`, the only writer) — `on_frame` never creates an entry, only appends to
    /// one that already exists.
    pub manifest: Option<FileManifest>,
    /// Raw inbound stream frames, in arrival order — **not** file order, since `channel_cfg` is
    /// reliable + unordered; each frame's own `i` (decoded from its `{i, data}` CBOR body, task
    /// 10.8) is what determines its place in the file.
    pub pending_chunks: Vec<Vec<u8>>,
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
        }
    }

    /// A snapshot of the per-transfer state for `sid`, if this side has accepted (and is therefore
    /// tracking) that stream. For the receiver engine (10.8) and tests.
    pub fn transfer(&self, sid: StreamId) -> Option<TransferState> {
        self.transfers.lock().ok()?.get(&sid).cloned()
    }

    /// Records the accepted transfer's manifest and returns the `Accept` decision. The only writer
    /// of a new `transfers` entry.
    fn accept(&self, sid: StreamId, manifest: FileManifest) -> OpenDecision {
        if let Ok(mut transfers) = self.transfers.lock() {
            transfers.insert(
                sid,
                TransferState {
                    manifest: Some(manifest),
                    pending_chunks: Vec::new(),
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
    /// decode/verify/write is task 10.8's receiver engine). Frames for a stream this side never
    /// accepted (e.g. this is the sender's own side, which never calls `on_open` for a stream it
    /// itself opened) are silently dropped, matching the trait's documented default ("ignores")
    /// rather than growing unbounded state for a transfer with no captured manifest.
    fn on_frame(&self, sid: StreamId, frame: &[u8]) {
        if let Ok(mut transfers) = self.transfers.lock() {
            if let Some(state) = transfers.get_mut(&sid) {
                state.pending_chunks.push(frame.to_vec());
            }
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

    #[test]
    fn on_frame_buffers_only_for_a_stream_this_side_accepted() {
        let fs = FileStream::new(MAX);
        // No prior `on_open`/accept for sid 5: frames must be dropped, not buffered anywhere.
        fs.on_frame(5, b"stray chunk frame");
        assert!(fs.transfer(5).is_none());

        let m = manifest("cat.png", 1);
        assert_eq!(
            fs.on_open(5, &m.encode().unwrap(), &ctx(false)),
            OpenDecision::Accept
        );
        fs.on_frame(5, b"chunk-a");
        fs.on_frame(5, b"chunk-b");
        let recorded = fs.transfer(5).unwrap();
        assert_eq!(
            recorded.pending_chunks,
            vec![b"chunk-a".to_vec(), b"chunk-b".to_vec()]
        );
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
