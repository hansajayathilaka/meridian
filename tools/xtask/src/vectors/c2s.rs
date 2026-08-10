//! Generate c2s conformance fixtures for the federation-hint extension (`test-vectors/c2s-v1.json`,
//! review finding F20).
//!
//! `Fetch{hint}` / `RouteBody{to_hint}` (task 2.3/2.7/2.8) had hand-written round-trip assertions in
//! `apps/proto/tests/roundtrip.rs` — real, but Rust-only, so a WASM/mobile implementation had no
//! committed byte-fixed target to reproduce. The federation error codes added to
//! [`meridian_proto::error_codes`] (task 2.9) had no wire-encoding test at all, Rust or otherwise.
//! This module closes both gaps the same way `federation.rs` already does for the s2s side: every
//! vector's `frame_hex` is produced by the real `Frame::new`/`to_bytes` encode path (deterministic
//! CBOR, fixed byte patterns, no RNG/wall-clock), and `apps/proto/tests/conformance.rs` independently
//! reconstructs each vector from its committed hex fields and re-derives `frame_hex` to close the loop.
//!
//! Scope (task 3.14): the hint fields and the *new* federation error codes only — not the whole
//! historic c2s frame set, which `roundtrip.rs` already covers and which is a pre-existing gap this
//! task does not widen into.
//! Spec: docs/api/wire-protocol.md, docs/api/federation-protocol-v1.md, apps/proto/src/msg.rs.

use meridian_proto::{error_codes, ErrBody, Fetch, Frame, Op, OpaqueBlob, RouteBody};
use serde::Serialize;

#[derive(Serialize)]
struct Fixtures {
    version: u32,
    note: String,
    vectors: Vec<Vector>,
}

#[derive(Serialize)]
struct Vector {
    name: String,
    op: String,
    id: u64,
    /// Hex/plain field values of the body, for eyeballing without decoding CBOR.
    fields: serde_json::Value,
    /// `Frame::to_bytes()` — the exact bytes a conforming implementation must reproduce.
    frame_hex: String,
}

fn build_vector<B: serde::Serialize>(
    name: &str,
    op: Op,
    id: u64,
    body: &B,
    fields: serde_json::Value,
) -> Result<Vector, String> {
    let frame = Frame::new(op, id, body).map_err(|e| e.to_string())?;
    let bytes = frame.to_bytes().map_err(|e| e.to_string())?;
    let back = Frame::from_bytes(&bytes).map_err(|e| e.to_string())?;
    if back != frame {
        return Err(format!(
            "c2s vector '{name}': from_bytes(to_bytes(_)) did not round-trip"
        ));
    }
    Ok(Vector {
        name: name.to_string(),
        op: format!("{op:?}"),
        id,
        fields,
        frame_hex: hex::encode(&bytes),
    })
}

pub fn generate_c2s() -> Result<(), String> {
    let mut vectors = Vec::new();

    // Fetch — hint absent (same-server; the pre-2.3 shape) and present (federated).
    let fetch_no_hint = Fetch {
        target: [0x11u8; 32],
        hint: None,
        tamper: false,
    };
    vectors.push(build_vector(
        "fetch-no-hint",
        Op::Fetch,
        1,
        &fetch_no_hint,
        serde_json::json!({
            "target_hex": hex::encode(fetch_no_hint.target),
            "hint": null,
            "tamper": fetch_no_hint.tamper,
        }),
    )?);

    let fetch_with_hint = Fetch {
        target: [0x22u8; 32],
        hint: Some("org-b.example".into()),
        tamper: false,
    };
    vectors.push(build_vector(
        "fetch-with-hint",
        Op::Fetch,
        2,
        &fetch_with_hint,
        serde_json::json!({
            "target_hex": hex::encode(fetch_with_hint.target),
            "hint": fetch_with_hint.hint,
            "tamper": fetch_with_hint.tamper,
        }),
    )?);

    // RouteBody — to_hint absent (same-server) and present (federated).
    let route_no_hint = RouteBody {
        to: [0x33u8; 32],
        to_hint: None,
        blob: OpaqueBlob::new(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };
    vectors.push(build_vector(
        "route-no-hint",
        Op::Route,
        3,
        &route_no_hint,
        serde_json::json!({
            "to_hex": hex::encode(route_no_hint.to),
            "to_hint": null,
            "blob_hex": hex::encode(route_no_hint.blob.as_bytes()),
        }),
    )?);

    let route_with_hint = RouteBody {
        to: [0x44u8; 32],
        to_hint: Some("org-b.example".into()),
        blob: OpaqueBlob::new(vec![0xCA, 0xFE, 0xBA, 0xBE]),
    };
    vectors.push(build_vector(
        "route-with-hint",
        Op::Route,
        4,
        &route_with_hint,
        serde_json::json!({
            "to_hex": hex::encode(route_with_hint.to),
            "to_hint": route_with_hint.to_hint,
            "blob_hex": hex::encode(route_with_hint.blob.as_bytes()),
        }),
    )?);

    // The federation error codes added by task 2.9 (client-side error taxonomy) — the specific
    // "new federation error codes" this task's scope names.
    for (name, code, msg) in [
        (
            "err-fed-denied",
            error_codes::FED_DENIED,
            "org-b.example is not accepting this request",
        ),
        (
            "err-fed-unreachable",
            error_codes::FED_UNREACHABLE,
            "org-b.example unreachable",
        ),
        (
            "err-not-found-at-hint",
            error_codes::NOT_FOUND_AT_HINT,
            "no such account at org-b.example",
        ),
    ] {
        let err = ErrBody {
            code: code.into(),
            msg: msg.into(),
        };
        vectors.push(build_vector(
            name,
            Op::Err,
            5,
            &err,
            serde_json::json!({ "code": err.code, "msg": err.msg }),
        )?);
    }

    let fixtures = Fixtures {
        version: 1,
        note: "c2s wire-encoding conformance vectors for the federation-hint extension (F20): \
               Fetch.hint, RouteBody.to_hint, and the new federation error codes — deterministic \
               CBOR (fixed byte patterns, no RNG/wall-clock). Regenerate with `cargo run -p xtask \
               -- vectors`. Spec: docs/api/wire-protocol.md, docs/api/federation-protocol-v1.md, \
               apps/proto/src/msg.rs. The full historic c2s frame set (Challenge/Auth/Publish/\
               Bundle/Deliver/TurnReq/TurnGrant) is proven only by apps/proto/tests/roundtrip.rs's \
               hand-written round trips, a pre-existing gap this task does not widen into (see \
               docs/tasks/phase-3/3.14-c2s-hint-conformance-vectors.md Scope)."
            .into(),
        vectors,
    };

    super::write_json(&super::vector_path("c2s-v1.json"), &fixtures)
}
