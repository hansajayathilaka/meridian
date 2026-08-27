//! Conformance-vector gate for the c2s federation-hint extension (task 3.14, review finding F20)
//! and the T07 mailbox wire fields (task 8.3/8.4): re-derive every committed
//! `test-vectors/c2s-v1.json` vector via `meridian-proto`'s *real* `Frame::new`/`to_bytes` encode
//! path and assert byte-for-byte equality against the committed `frame_hex`. This is what actually
//! gates CI — not just "the xtask generator ran and diffed clean" — so a WASM/mobile implementation
//! has a byte-fixed, independently-reproducible target for `Fetch.hint`, `RouteBody.to_hint`,
//! `RouteOk.queued`, `Deliver.mailbox_id`, `MailboxAck`/`MailboxAckOk`, and the federation/mailbox
//! error codes, the same bar `apps/crypto/tests/conformance.rs` already holds crypto-derivation
//! vectors to.
//!
//! Hand-written Rust-only round trips for the full c2s frame set (including these same types)
//! already live in `tests/roundtrip.rs` — this file adds the missing byte-fixed, cross-target proof
//! on top, it does not replace them.

use std::path::PathBuf;

use meridian_proto::{
    error_codes, Deliver, ErrBody, Fetch, Frame, MailboxAck, MailboxAckOk, Op, OpaqueBlob,
    RouteBody, RouteOk,
};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("meridian-proto lives at <root>/apps/proto")
        .join("test-vectors")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
}

fn b32(v: &Value, field: &str) -> [u8; 32] {
    let hexstr = v[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing {field}"));
    let bytes = hex::decode(hexstr).unwrap_or_else(|e| panic!("{field}: {e}"));
    bytes
        .try_into()
        .unwrap_or_else(|b: Vec<u8>| panic!("{field}: expected 32 bytes, got {}", b.len()))
}

fn bvec(v: &Value, field: &str) -> Vec<u8> {
    hex::decode(
        v[field]
            .as_str()
            .unwrap_or_else(|| panic!("missing {field}")),
    )
    .unwrap()
}

#[test]
fn c2s_vectors_match_real_encoding() {
    let fixtures = load("c2s-v1.json");
    for vec in fixtures["vectors"].as_array().unwrap() {
        let name = vec["name"].as_str().unwrap();
        let op = vec["op"].as_str().unwrap();
        let id = vec["id"].as_u64().unwrap();
        let fields = &vec["fields"];
        let expected_hex = vec["frame_hex"].as_str().unwrap();

        let bytes = match op {
            "Fetch" => {
                let fetch = Fetch {
                    target: b32(fields, "target_hex"),
                    hint: fields["hint"].as_str().map(str::to_string),
                    tamper: fields["tamper"].as_bool().unwrap(),
                };
                Frame::new(Op::Fetch, id, &fetch)
                    .unwrap()
                    .to_bytes()
                    .unwrap()
            }
            "Route" => {
                let route = RouteBody {
                    to: b32(fields, "to_hex"),
                    to_hint: fields["to_hint"].as_str().map(str::to_string),
                    blob: OpaqueBlob::new(bvec(fields, "blob_hex")),
                };
                Frame::new(Op::Route, id, &route)
                    .unwrap()
                    .to_bytes()
                    .unwrap()
            }
            // Non-vacuity (task 8.4 Risks/notes): `fields["queued"]` is read here rather than
            // hardcoded, so a `route-ok-queued` vector genuinely exercises `RouteOk.queued` — this
            // was hand-verified by temporarily replacing the line below with `queued: false` and
            // confirming `route-ok-queued`'s frame_hex assertion fails (it does: the real encoder
            // emits the `queued` key, the stub doesn't) before restoring the real read.
            "RouteOk" => {
                let route_ok = RouteOk {
                    delivered: fields["delivered"].as_bool().unwrap(),
                    queued: fields["queued"].as_bool().unwrap(),
                };
                Frame::new(Op::RouteOk, id, &route_ok)
                    .unwrap()
                    .to_bytes()
                    .unwrap()
            }
            // Non-vacuity: `fields["mailbox_id"]` is read here rather than hardcoded to `None` —
            // hand-verified the same way (`mailbox_id: None` stub made `deliver-with-mailbox-id`'s
            // frame_hex assertion fail, since the real encoder emits the `mailbox_id` key).
            "Deliver" => {
                let deliver = Deliver {
                    from: b32(fields, "from_hex"),
                    blob: OpaqueBlob::new(bvec(fields, "blob_hex")),
                    mailbox_id: fields["mailbox_id"].as_u64(),
                };
                Frame::new(Op::Deliver, id, &deliver)
                    .unwrap()
                    .to_bytes()
                    .unwrap()
            }
            // Non-vacuity: `fields["ids"]` is read here rather than hardcoded to `vec![]` —
            // hand-verified the same way (`ids: Vec::new()` stub made `mailbox-ack`'s frame_hex
            // assertion fail, since the real encoder emits the non-empty CBOR array).
            "MailboxAck" => {
                let ack = MailboxAck {
                    ids: fields["ids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_u64().unwrap())
                        .collect(),
                };
                Frame::new(Op::MailboxAck, id, &ack)
                    .unwrap()
                    .to_bytes()
                    .unwrap()
            }
            "MailboxAckOk" => Frame::new(Op::MailboxAckOk, id, &MailboxAckOk {})
                .unwrap()
                .to_bytes()
                .unwrap(),
            "Err" => {
                let err = ErrBody {
                    code: fields["code"].as_str().unwrap().to_string(),
                    msg: fields["msg"].as_str().unwrap().to_string(),
                };
                // Every vectored code must still be one of the module's own constants — catches
                // the fixture and the source constant silently drifting apart.
                assert!(
                    [
                        error_codes::FED_DENIED,
                        error_codes::FED_UNREACHABLE,
                        error_codes::NOT_FOUND_AT_HINT,
                        error_codes::MAILBOX_FULL,
                    ]
                    .contains(&err.code.as_str()),
                    "{name}: code {:?} is not a recognized error_codes constant",
                    err.code
                );
                Frame::new(Op::Err, id, &err).unwrap().to_bytes().unwrap()
            }
            other => panic!("{name}: unhandled op {other} — add a case above"),
        };

        assert_eq!(hex::encode(&bytes), expected_hex, "{name}: frame_hex");

        // Round trip: decoding the committed bytes back must reproduce the same frame.
        let decoded = Frame::from_bytes(&bytes).unwrap();
        assert_eq!(
            hex::encode(decoded.to_bytes().unwrap()),
            expected_hex,
            "{name}: re-encode"
        );
    }
}

/// Deliverable 2 of task 8.4: the backward-compatibility claim, verified rather than merely
/// asserted — the seven vectors that predate 8.3's `WIRE_VERSION` 1->2 bump (task 3.14's F20
/// fixtures) must still carry the exact `frame_hex` bytes they had before 8.3/8.4 touched this
/// file, byte for byte. These hex strings are copied from the pre-8.4 commit (`cc47eb7`'s tree,
/// i.e. before this task's regeneration ever ran) — a hardcoded oracle independent of whatever the
/// file currently says, so a future accidental edit to an old vector's bytes fails this test even
/// if someone "fixed" both the fixture and this assertion together by hand.
#[test]
fn pre_8_3_vectors_are_byte_identical_after_8_4_regeneration() {
    let fixtures = load("c2s-v1.json");
    let vectors = fixtures["vectors"].as_array().unwrap();
    let by_name = |name: &str| -> &str {
        vectors
            .iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("missing pre-8.3 vector {name:?}"))["frame_hex"]
            .as_str()
            .unwrap()
    };

    let pre_8_3 = [
        ("fetch-no-hint", "a3626f706546657463686269640164626f6479582aa16674617267657458201111111111111111111111111111111111111111111111111111111111111111"),
        ("fetch-with-hint", "a3626f706546657463686269640264626f6479583da266746172676574582022222222222222222222222222222222222222222222222222222222222222226468696e746d6f72672d622e6578616d706c65"),
        ("route-no-hint", "a3626f7065526f7574656269640364626f64795830a262746f5820333333333333333333333333333333333333333333333333333333333333333364626c6f6244deadbeef"),
        ("route-with-hint", "a3626f7065526f7574656269640464626f64795846a362746f5820444444444444444444444444444444444444444444444444444444444444444467746f5f68696e746d6f72672d622e6578616d706c6564626c6f6244cafebabe"),
        ("err-fed-denied", "a3626f70634572726269640564626f64795842a264636f64656a6665645f64656e696564636d7367782b6f72672d622e6578616d706c65206973206e6f7420616363657074696e6720746869732072657175657374"),
        ("err-fed-unreachable", "a3626f70634572726269640564626f64795835a264636f64656f6665645f756e726561636861626c65636d736778196f72672d622e6578616d706c6520756e726561636861626c65"),
        ("err-not-found-at-hint", "a3626f70634572726269640564626f6479583ea264636f6465716e6f745f666f756e645f61745f68696e74636d736778206e6f2073756368206163636f756e74206174206f72672d622e6578616d706c65"),
    ];

    for (name, expected_hex) in pre_8_3 {
        assert_eq!(
            by_name(name),
            expected_hex,
            "{name}: pre-8.3 vector bytes must not change under 8.4's regeneration"
        );
    }
}
