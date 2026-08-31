//! In-stream resume protocol for `mrd.file/1` (T09, task 10.9): lets a receiver tell the sender
//! which chunks are still missing after a session drop + redial (ICE restart —
//! `meridian_core::session::P2pSession::ice_restart`, `docs/architecture/system-design.md`
//! invariant 5: "ratchets and now stream-level state outlive the transport"), so the sender resumes
//! instead of re-sending the whole file.
//!
//! ## Design decision: in-stream, not a new `CtrlFrame` variant — `TODO: confirm` (architect to
//! ratify at this task's own review; see `docs/tasks/phase-10/10.9-resume-protocol.md`'s own risk
//! note)
//! `docs/api/wire-protocol.md` §5 documents `Resume = {sid, bitmap: bstr}` as a `mrd.ctrl/1` ctrl
//! frame. This module deliberately does **not** implement that: `apps/envelope/src/ctrl.rs`'s
//! `CtrlFrame` enum has no `Resume` variant today, and adding one would force that enum *and*
//! `apps/core/src/session.rs::handle_ctrl`'s exhaustive match to grow a file-transfer-specific arm —
//! exactly the core-crate leakage task 10.4's "additive stream type, zero core-crate edits" review
//! gate exists to reject (`apps/CLAUDE.md`, root `CLAUDE.md`). Instead, the resume message rides
//! **in-stream**, over `mrd.file/1`'s own already-open per-transfer data channel, via task 10.4's
//! [`meridian_core::session::P2pSession::send_stream_frame`] — handled inside
//! [`crate::file::FileStream::on_frame`] itself, exactly like a chunk frame. Task 10.12 is expected
//! to correct `wire-protocol.md` §5 to match. If the architect disagrees at review, this module's
//! shape needs revisiting before that correction lands.
//!
//! ## Wire framing — one leading discriminator byte before every in-stream `mrd.file/1` frame
//! (task 10.9's own pin; byte-for-byte, task 10.12 copies this verbatim into the wire doc)
//! Before this task, `mrd.file/1`'s data channel only ever carried [`crate::chunk::ChunkFrame`]s
//! (task 10.7/10.8), so [`crate::file::FileStream::on_frame`] never needed to distinguish anything.
//! Now that a resume message can arrive on the very same channel, every frame
//! `send_stream_frame` carries for a `mrd.file/1` transfer is:
//!
//! ```text
//! tag: u8 ‖ body: bytes
//! ```
//!
//! where `tag` is one of:
//! - [`FRAME_TAG_CHUNK`] (`0x00`) — `body` is a [`crate::chunk::ChunkFrame`] CBOR encoding (`{i,
//!   data}`), byte-for-byte unchanged from task 10.7/10.8's own pinned shape — only the *outer*
//!   framing gained a byte, never `ChunkFrame`'s own CBOR body.
//! - [`FRAME_TAG_RESUME`] (`0x01`) — `body` is a [`ResumeRequest`] CBOR encoding (`{bitmap}`).
//!
//! Any other leading byte value, or an empty frame, is not a valid `mrd.file/1` in-stream frame and
//! is silently dropped by `on_frame` (every byte off the wire is hostile; this crate's existing
//! convention — see `crate::file`'s module doc — is to fail closed, never panic, on a malformed
//! frame from an already-accepted stream).
//!
//! ## Missing-range bitmap encoding (task 10.9's own pin, byte-for-byte)
//! [`ResumeRequest::bitmap`] is exactly `ceil(leaf_count / 8)` bytes — `leaf_count` being the
//! file's total chunk count, [`crate::receiver::FileReceiver::leaf_count`] — one bit per chunk
//! index, **LSB-first within each byte**: bit `(i % 8)` of byte `(i / 8)` is `1` if chunk `i` is
//! still missing (not yet received *and verified* by the receiver — matching
//! [`crate::receiver::FileReceiver::received_offsets`]'s own "both AEAD-open and merkle-verify
//! passed" definition of "received") and `0` if chunk `i` has already been received and verified.
//! Any bits at or beyond `leaf_count` in the final byte are `0` and MUST be ignored by the reader
//! (a sender that receives a bitmap with garbage trailing bits treats them as "not missing", never
//! as an instruction to send a chunk index that doesn't exist in this file) — see
//! [`ResumeRequest::missing_indices`], which never returns an index `>= leaf_count` regardless of
//! what the trailing bits of a hostile/malformed bitmap contain.
//!
//! ## Redial trigger — what signal actually exists today (architect-review flag)
//! `TODO: confirm` — no automatic hook exists. [`meridian_core::session::P2pSession::ice_restart`]
//! is a plain `async fn` a caller invokes explicitly on a network-change signal (see
//! `apps/core/tests/p2p_session.rs::ice_restart_preserves_session_and_ratchet` for the exact call
//! shape: `session.ice_restart().await?`); it renegotiates ICE candidate pairs only; it neither
//! emits a [`meridian_core::session::SessionEvent`] variant nor calls back into
//! [`meridian_core::streams::StreamType`] in any way, and that trait itself has no
//! `on_reconnect`/`on_resume` hook (`apps/core/src/streams.rs`: only `on_open`/`on_frame` exist).
//! Because ICE restart renegotiates only candidate pairs — the underlying data channels (including
//! `mrd.file/1`'s) are left open the whole time — "once the stream is live again" is, in practice,
//! "immediately after `ice_restart()` returns `Ok(())`". This module therefore does not (and, per
//! this task's own scope, must not — no core-crate edits) wire itself to an automatic callback: the
//! **caller** of `ice_restart()` (a session-lifecycle/network-monitor layer outside
//! `meridian-streams`, not yet designed as of this task) is expected to invoke
//! [`crate::sender::send_resume_bitmap`] itself, once per in-flight receiver-side transfer, right
//! after its own `ice_restart()` call returns. This is a real scope gap this task's own review
//! should weigh in on: either a future task adds a `StreamType::on_reconnect`/a `SessionEvent`
//! variant to `meridian-core` (a core-crate change, therefore out of *this* task's own no-core-edits
//! scope), or redial-triggered resume permanently stays an explicit call site the application layer
//! must remember to make.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use meridian_proto::{decode, encode, CodecError};

/// Discriminator byte marking an in-stream `mrd.file/1` frame as a bulk [`crate::chunk::ChunkFrame`]
/// — see the module doc's "Wire framing" section.
pub const FRAME_TAG_CHUNK: u8 = 0x00;

/// Discriminator byte marking an in-stream `mrd.file/1` frame as a [`ResumeRequest`] — see the
/// module doc's "Wire framing" section.
pub const FRAME_TAG_RESUME: u8 = 0x01;

/// The `mrd.file/1` in-stream resume message (task 10.9): `{bitmap}` — see the module doc for the
/// exact, pinned bitmap encoding. Carries no `sid` of its own (unlike `wire-protocol.md` §5's
/// ctrl-frame-shaped `Resume = {sid, bitmap}`): since this rides in-stream over the specific
/// transfer's own data channel, the receiving side already knows `sid` from which channel the frame
/// arrived on (`FileStream::on_frame`'s own `sid` parameter) — carrying it again on the wire would
/// be redundant, unverifiable-against-anything, and purely decorative.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeRequest {
    /// One bit per chunk index — `1` = still missing, `0` = already received and verified. See the
    /// module doc's "Missing-range bitmap encoding" section for the exact, pinned layout.
    #[serde(with = "meridian_proto::bytes::bytes_vec")]
    pub bitmap: Vec<u8>,
}

impl ResumeRequest {
    /// Deterministic-CBOR encode — the exact bytes carried as `body` in a [`FRAME_TAG_RESUME`]
    /// in-stream frame (see [`crate::sender::send_resume_bitmap`]).
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        encode(self)
    }

    /// Decode a resume message from previously-decrypted plaintext bytes (this type never touches
    /// ciphertext). Every byte off the wire is hostile; this never panics on malformed input, only
    /// returns [`CodecError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        decode(bytes)
    }

    /// Builds the current missing-range bitmap from a receiver's own bookkeeping —
    /// [`crate::receiver::FileReceiver::received_offsets`] and
    /// [`crate::receiver::FileReceiver::leaf_count`] — per the module doc's pinned encoding.
    pub fn from_received(received: &BTreeSet<u64>, leaf_count: usize) -> Self {
        let mut bitmap = vec![0u8; leaf_count.div_ceil(8)];
        for i in 0..leaf_count as u64 {
            if !received.contains(&i) {
                bitmap[(i / 8) as usize] |= 1 << (i % 8);
            }
        }
        Self { bitmap }
    }

    /// Whether chunk index `i` is marked missing by this bitmap. `false` for any `i` past the end
    /// of the bitmap's own bytes (a short/truncated bitmap is read as "nothing further is missing",
    /// never as "everything past this point is missing") — paired with
    /// [`missing_indices`](Self::missing_indices)'s own `leaf_count` bound, this means a hostile or
    /// truncated bitmap can only ever under-report what's missing, never make the sender address a
    /// chunk index that doesn't exist in the file.
    pub fn is_missing(&self, i: u64) -> bool {
        match self.bitmap.get((i / 8) as usize) {
            Some(byte) => byte & (1 << (i % 8)) != 0,
            None => false,
        }
    }

    /// The chunk indices (always `< leaf_count`, regardless of how many bytes this bitmap actually
    /// carries — see [`is_missing`](Self::is_missing)) this bitmap marks missing, in ascending
    /// order. `leaf_count` is supplied by the caller (the sender's own authoritative chunk count for
    /// this file — [`crate::sender::send_missing_chunks`]'s doc), never trusted from the bitmap's
    /// own length, so a bitmap shorter *or* longer than the sender's real `leaf_count` can never
    /// cause an out-of-range chunk index to be produced.
    pub fn missing_indices(&self, leaf_count: usize) -> Vec<u64> {
        (0..leaf_count as u64)
            .filter(|&i| self.is_missing(i))
            .collect()
    }
}

/// Prepends the one-byte discriminator ([`FRAME_TAG_CHUNK`]/[`FRAME_TAG_RESUME`]) to an
/// already-encoded frame body — the exact bytes [`meridian_core::session::P2pSession::send_stream_frame`]
/// carries for a `mrd.file/1` transfer's data channel (module doc's "Wire framing" section).
pub fn tag_frame(tag: u8, mut body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(tag);
    out.append(&mut body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_request_round_trips() {
        let r = ResumeRequest {
            bitmap: vec![0b0000_0101, 0b1111_1111],
        };
        let bytes = r.encode().unwrap();
        assert_eq!(ResumeRequest::decode(&bytes).unwrap(), r);
    }

    #[test]
    fn bitmap_is_a_cbor_byte_string_not_an_int_array() {
        let r = ResumeRequest {
            bitmap: vec![0xAB, 0xCD],
        };
        let bytes = r.encode().unwrap();
        let value: ciborium::value::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(entries) = value else {
            panic!("resume request must encode as a CBOR map");
        };
        for (key, val) in entries {
            if let ciborium::value::Value::Text(field) = key {
                if field == "bitmap" {
                    assert!(matches!(val, ciborium::value::Value::Bytes(_)));
                }
            }
        }
    }

    #[test]
    fn from_received_marks_exactly_the_unreceived_indices_missing() {
        let received: BTreeSet<u64> = [0u64, 1, 3].into_iter().collect();
        let r = ResumeRequest::from_received(&received, 5);
        // leaf_count 5 -> ceil(5/8) = 1 byte.
        assert_eq!(r.bitmap.len(), 1);
        assert!(!r.is_missing(0));
        assert!(!r.is_missing(1));
        assert!(r.is_missing(2));
        assert!(!r.is_missing(3));
        assert!(r.is_missing(4));
        assert_eq!(r.missing_indices(5), vec![2, 4]);
    }

    #[test]
    fn all_received_produces_an_all_zero_bitmap_and_no_missing_indices() {
        let received: BTreeSet<u64> = (0..16).collect();
        let r = ResumeRequest::from_received(&received, 16);
        assert!(r.bitmap.iter().all(|&b| b == 0));
        assert!(r.missing_indices(16).is_empty());
    }

    #[test]
    fn nothing_received_marks_every_index_missing_across_a_byte_boundary() {
        let received: BTreeSet<u64> = BTreeSet::new();
        // 9 leaves -> ceil(9/8) = 2 bytes, exercising the byte-boundary crossing.
        let r = ResumeRequest::from_received(&received, 9);
        assert_eq!(r.bitmap.len(), 2);
        assert_eq!(r.missing_indices(9), (0..9).collect::<Vec<_>>());
    }

    #[test]
    fn trailing_bits_past_leaf_count_are_never_reported_as_missing() {
        // A hostile/garbled bitmap with every bit set, including padding bits past leaf_count (5
        // leaves needs only 1 byte / 8 bits, so bits 5..8 are padding).
        let r = ResumeRequest { bitmap: vec![0xFF] };
        assert_eq!(r.missing_indices(5), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn a_truncated_bitmap_under_reports_rather_than_over_reports() {
        // Caller's authoritative leaf_count (9) exceeds what this (adversarial/corrupt) bitmap can
        // even address (1 byte = 8 bits) — indices 8 must read as "not missing", never fabricated
        // out of thin air, and never panic on the out-of-bounds byte index.
        let r = ResumeRequest { bitmap: vec![0xFF] };
        assert!(!r.is_missing(8));
        assert_eq!(r.missing_indices(9), (0..8).collect::<Vec<_>>());
    }

    #[test]
    fn tag_frame_prepends_exactly_one_discriminator_byte() {
        let body = vec![1u8, 2, 3];
        let tagged = tag_frame(FRAME_TAG_CHUNK, body.clone());
        assert_eq!(tagged[0], FRAME_TAG_CHUNK);
        assert_eq!(&tagged[1..], &body[..]);

        let tagged_resume = tag_frame(FRAME_TAG_RESUME, body.clone());
        assert_eq!(tagged_resume[0], FRAME_TAG_RESUME);
        assert_eq!(&tagged_resume[1..], &body[..]);
    }
}
