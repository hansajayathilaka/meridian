//! Generate the T06 federation (s2s) conformance fixtures (`test-vectors/federation-v1.json`).
//!
//! Every `FedFrame` body type gets at least one deterministic fixture (fixed byte patterns, no
//! RNG/wall-clock), covering the exact CBOR bytes any conforming s2s implementation must
//! reproduce. Spec: docs/api/federation-protocol-v1.md, apps/proto/src/fed.rs.

use meridian_proto::{
    FedBundle, FedErr, FedFetchBundle, FedFrame, FedHello, FedOp, FedReachability, FedReachable,
    FedRoute, OpaqueBlob, PrekeyBundle, BUNDLE_VERSION,
};
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
    /// Hex-encoded field values of the body, for eyeballing without decoding CBOR.
    fields: serde_json::Value,
    /// `FedFrame::to_bytes()` — the exact bytes a conforming implementation must reproduce.
    frame_hex: String,
}

fn build_vector<B: serde::Serialize>(
    name: &str,
    op: FedOp,
    id: u64,
    body: &B,
    fields: serde_json::Value,
) -> Result<Vector, String> {
    let frame = FedFrame::new(op, id, body).map_err(|e| e.to_string())?;
    let bytes = frame.to_bytes().map_err(|e| e.to_string())?;
    let back = FedFrame::from_bytes(&bytes).map_err(|e| e.to_string())?;
    if back != frame {
        return Err(format!(
            "federation vector '{name}': from_bytes(to_bytes(_)) did not round-trip"
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

fn sample_bundle() -> PrekeyBundle {
    PrekeyBundle {
        v: BUNDLE_VERSION,
        account_pub: [0x11u8; 32],
        spk: [0x22u8; 32],
        spk_sig: [0x33u8; 64],
        otks: vec![[0x44u8; 32]],
        otk_sigs: vec![[0x55u8; 64]],
        device_record: None,
    }
}

pub fn generate_federation() -> Result<(), String> {
    let mut vectors = Vec::new();

    let hello = FedHello {
        v: 1,
        domain: "org-a.example".into(),
    };
    vectors.push(build_vector(
        "hello",
        FedOp::Hello,
        0,
        &hello,
        serde_json::json!({ "v": hello.v, "domain": hello.domain }),
    )?);

    let fetch_bundle = FedFetchBundle {
        target: [0x66u8; 32],
        requesting_server: "org-a.example".into(),
    };
    vectors.push(build_vector(
        "fetch-bundle",
        FedOp::FetchBundle,
        1,
        &fetch_bundle,
        serde_json::json!({
            "target_hex": hex::encode(fetch_bundle.target),
            "requesting_server": fetch_bundle.requesting_server,
        }),
    )?);

    let bundle_body = FedBundle {
        bundle: sample_bundle(),
    };
    vectors.push(build_vector(
        "bundle",
        FedOp::Bundle,
        1,
        &bundle_body,
        serde_json::json!({
            "account_pub_hex": hex::encode(bundle_body.bundle.account_pub),
            "spk_hex": hex::encode(bundle_body.bundle.spk),
        }),
    )?);

    let route = FedRoute {
        to: [0x77u8; 32],
        from: [0x88u8; 32],
        envelope: OpaqueBlob::new(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };
    vectors.push(build_vector(
        "route",
        FedOp::Route,
        2,
        &route,
        serde_json::json!({
            "to_hex": hex::encode(route.to),
            "from_hex": hex::encode(route.from),
            "envelope_hex": hex::encode(route.envelope.as_bytes()),
        }),
    )?);

    let reachability = FedReachability {
        target: [0x99u8; 32],
    };
    vectors.push(build_vector(
        "reachability",
        FedOp::Reachability,
        3,
        &reachability,
        serde_json::json!({ "target_hex": hex::encode(reachability.target) }),
    )?);

    let reachable = FedReachable { connected: true };
    vectors.push(build_vector(
        "reachable",
        FedOp::Reachable,
        3,
        &reachable,
        serde_json::json!({ "connected": reachable.connected }),
    )?);

    let err = FedErr {
        code: meridian_proto::fed_error_codes::NOT_FOUND.into(),
        msg: "unknown target".into(),
    };
    vectors.push(build_vector(
        "err",
        FedOp::Err,
        2,
        &err,
        serde_json::json!({ "code": err.code, "msg": err.msg }),
    )?);

    let fixtures = Fixtures {
        version: 1,
        note: "T06 federation (s2s) wire-encoding conformance vectors — deterministic CBOR \
               (fixed byte patterns, no RNG/wall-clock). Regenerate with `cargo run -p xtask -- \
               vectors`. Spec: docs/api/federation-protocol-v1.md, apps/proto/src/fed.rs."
            .into(),
        vectors,
    };

    super::write_json(&super::vector_path("federation-v1.json"), &fixtures)
}
