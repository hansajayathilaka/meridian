//! Conformance-vector gate for the c2s federation-hint extension (task 3.14, review finding F20):
//! re-derive every committed `test-vectors/c2s-v1.json` vector via `meridian-proto`'s *real*
//! `Frame::new`/`to_bytes` encode path and assert byte-for-byte equality against the committed
//! `frame_hex`. This is what actually gates CI — not just "the xtask generator ran and diffed
//! clean" — so a WASM/mobile implementation has a byte-fixed, independently-reproducible target for
//! `Fetch.hint`, `RouteBody.to_hint`, and the new federation error codes, the same bar
//! `apps/crypto/tests/conformance.rs` already holds crypto-derivation vectors to.
//!
//! Hand-written Rust-only round trips for the full c2s frame set (including these same types)
//! already live in `tests/roundtrip.rs` — this file adds the missing byte-fixed, cross-target proof
//! on top, it does not replace them.

use std::path::PathBuf;

use meridian_proto::{error_codes, ErrBody, Fetch, Frame, Op, OpaqueBlob, RouteBody};
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
