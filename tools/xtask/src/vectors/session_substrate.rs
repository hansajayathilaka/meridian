//! Session-substrate conformance fixtures (`test-vectors/session-substrate-v1.json`, task 11.7,
//! review finding F7): the per-stream HKDF-export `info` byte layout
//! ([`meridian_core::test_support::stream_export_info`], task 10.4) and
//! `SignalContent::IceRestartOffer`/`IceRestartAnswer`'s CBOR encoding (task 10.22, ADR 0025).
//! Architect-ratified as its own file, separate from `file-transfer-v1.json`: these are
//! core/envelope session-lifecycle plumbing, not `meridian-streams` file-transfer shapes — see
//! `docs/tasks/phase-11/11.7-file-transfer-conformance-vectors.md`'s Risks/notes.
//!
//! `stream_export_info` is the one surface of the five this task vectors that also gets a
//! dedicated re-derivation test (`apps/core/tests/stream_export_info_conformance.rs`) rather than
//! relying on `xtask regenerate-and-diff` self-consistency alone — same bug class as
//! `apps/crypto/src/x3dh.rs`'s `divergent_kdf_label_does_not_match_committed_vector`: a
//! spec-divergent domain tag would still self-consistently round-trip through a generator that
//! (bug included) matches its own committed vector, so a dedicated test that calls the crate's
//! *real* function against pinned inputs and diffs the byte output is what actually gates CI. The
//! other four surfaces (`FileManifest`, `ChunkFrame`/merkle, resume bitmap, `IceRestartOffer`/
//! `Answer`) are ordinary public serde/CBOR shapes already exercised by real round-trip/shape
//! unit tests in-crate — `xtask regenerate-and-diff` alone is sufficient for them, matching the
//! accepted `federation-v1.json` precedent.

use meridian_core::streams::StreamId;
use meridian_core::test_support::stream_export_info;
use meridian_envelope::SignalContent;
use serde::Serialize;

#[derive(Serialize)]
struct Fixtures {
    version: u32,
    note: String,
    stream_export_info: Vec<StreamExportInfoVector>,
    signal_content: Vec<SignalContentVector>,
}

#[derive(Serialize)]
struct StreamExportInfoVector {
    name: String,
    ty: String,
    sid: StreamId,
    /// `stream_export_info(ty, sid)` — `"mrd/stream/" ‖ ty ‖ sid:u64-be` (apps/core/src/session.rs).
    info_hex: String,
}

fn build_stream_export_info(name: &str, ty: &str, sid: StreamId) -> StreamExportInfoVector {
    StreamExportInfoVector {
        name: name.to_string(),
        ty: ty.to_string(),
        sid,
        info_hex: hex::encode(stream_export_info(ty, sid)),
    }
}

#[derive(Serialize)]
struct SignalContentVector {
    name: String,
    variant: String,
    fields: serde_json::Value,
    /// `SignalContent::encode()` — the exact ratchet-plaintext bytes for this signaling payload.
    encoded_hex: String,
}

fn build_signal_content(
    name: &str,
    variant: &str,
    content: SignalContent,
) -> Result<SignalContentVector, String> {
    let bytes = content.encode().map_err(|e| e.to_string())?;
    let back = SignalContent::decode(&bytes).map_err(|e| e.to_string())?;
    if back != content {
        return Err(format!(
            "session-substrate vector '{name}': decode(encode(_)) did not round-trip"
        ));
    }
    let fields = match &content {
        SignalContent::IceRestartOffer { sdp, dtls_fp, ice }
        | SignalContent::IceRestartAnswer { sdp, dtls_fp, ice } => serde_json::json!({
            "sdp_hex": hex::encode(sdp),
            "dtls_fp": dtls_fp,
            "ice": ice,
        }),
        _ => {
            return Err(format!(
                "session-substrate vector '{name}': unexpected variant"
            ))
        }
    };
    Ok(SignalContentVector {
        name: name.to_string(),
        variant: variant.to_string(),
        fields,
        encoded_hex: hex::encode(&bytes),
    })
}

pub fn generate_session_substrate() -> Result<(), String> {
    let mut vectors = Vec::new();

    // --- stream_export_info (task 10.4) ---------------------------------------------------------
    // Canonical case, plus the architect-ratified sid=0 / sid=u64::MAX boundary pair pinning the
    // 8-byte big-endian encoding at both ends of its range.
    let stream_export_info_vectors = vec![
        build_stream_export_info("canonical", "mrd.file/1", 7),
        build_stream_export_info("sid-zero", "mrd.file/1", 0),
        build_stream_export_info("sid-max", "mrd.file/1", u64::MAX),
    ];

    // --- SignalContent::IceRestartOffer / IceRestartAnswer (task 10.22, ADR 0025) ---------------
    // One canonical vector each, plus one with an empty `ice` candidate list (architect-ratified).
    vectors.push(build_signal_content(
        "ice-restart-offer-canonical",
        "IceRestartOffer",
        SignalContent::IceRestartOffer {
            sdp: b"v=0\r\no=- 46 2 IN IP4 127.0.0.1\r\n...".to_vec(),
            dtls_fp: "sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99".to_string(),
            ice: vec![
                "candidate:1 1 UDP 2130706431 203.0.113.10 54400 typ host".to_string(),
                "candidate:2 1 UDP 1694498815 203.0.113.10 54401 typ srflx raddr 10.0.0.5 rport 54401"
                    .to_string(),
            ],
        },
    )?);
    vectors.push(build_signal_content(
        "ice-restart-offer-empty-ice",
        "IceRestartOffer",
        SignalContent::IceRestartOffer {
            sdp: b"v=0\r\no=- 47 2 IN IP4 127.0.0.1\r\n...".to_vec(),
            dtls_fp: "sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99".to_string(),
            ice: vec![],
        },
    )?);
    vectors.push(build_signal_content(
        "ice-restart-answer-canonical",
        "IceRestartAnswer",
        SignalContent::IceRestartAnswer {
            sdp: b"v=0\r\no=- 46 3 IN IP4 127.0.0.1\r\n...".to_vec(),
            dtls_fp: "sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99".to_string(),
            ice: vec!["candidate:1 1 UDP 2130706431 203.0.113.20 54500 typ host".to_string()],
        },
    )?);
    vectors.push(build_signal_content(
        "ice-restart-answer-empty-ice",
        "IceRestartAnswer",
        SignalContent::IceRestartAnswer {
            sdp: b"v=0\r\no=- 47 3 IN IP4 127.0.0.1\r\n...".to_vec(),
            dtls_fp: "sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99".to_string(),
            ice: vec![],
        },
    )?);

    let fixtures = Fixtures {
        version: 1,
        note: "Session-substrate conformance vectors (task 11.7, review finding F7): the \
               per-stream HKDF-export `info` byte layout (stream_export_info, task 10.4) and \
               SignalContent::IceRestartOffer/IceRestartAnswer CBOR encoding (task 10.22, \
               ADR 0025). Deterministic (fixed byte patterns, no RNG/wall-clock). Regenerate with \
               `cargo run -p xtask -- vectors`. `stream_export_info` additionally gets a dedicated \
               re-derivation test (apps/core/tests/stream_export_info_conformance.rs), not just \
               this generator's own self-consistency — see this module's doc comment. Spec: \
               docs/api/stream-types-v1.md, docs/adr/0025-ice-restart-renegotiation.md, \
               apps/core/src/session.rs, apps/envelope/src/signal.rs."
            .into(),
        stream_export_info: stream_export_info_vectors,
        signal_content: vectors,
    };

    super::write_json(&super::vector_path("session-substrate-v1.json"), &fixtures)
}
