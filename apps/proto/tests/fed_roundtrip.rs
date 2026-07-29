//! s2s federation wire round-trip: every FedFrame body survives CBOR encode/decode, and the
//! 32-byte key fields land as compact CBOR byte strings (mirrors tests/roundtrip.rs's structure).

use meridian_proto::{
    FedBundle, FedErr, FedFetchBundle, FedFrame, FedHello, FedOp, FedReachability, FedReachable,
    FedRoute, OpaqueBlob, PrekeyBundle, BUNDLE_VERSION,
};

fn sample_bundle() -> PrekeyBundle {
    PrekeyBundle {
        v: BUNDLE_VERSION,
        account_pub: [7u8; 32],
        spk: [9u8; 32],
        spk_sig: [1u8; 64],
        otks: vec![[2u8; 32], [3u8; 32]],
        otk_sigs: vec![[4u8; 64], [5u8; 64]],
        device_record: None,
    }
}

#[test]
fn fed_frame_and_bodies_roundtrip() {
    let hello = FedHello {
        v: 1,
        domain: "org-a.example".into(),
    };
    let frame = FedFrame::new(FedOp::Hello, 0, &hello).unwrap();
    let bytes = frame.to_bytes().unwrap();
    let back = FedFrame::from_bytes(&bytes).unwrap();
    assert_eq!(back.op, FedOp::Hello);
    assert_eq!(back.id, 0);
    assert_eq!(back.decode::<FedHello>().unwrap(), hello);

    let fetch_bundle = FedFetchBundle {
        target: [5u8; 32],
        requesting_server: "org-a.example".into(),
    };
    let f = FedFrame::new(FedOp::FetchBundle, 1, &fetch_bundle).unwrap();
    assert_eq!(
        FedFrame::from_bytes(&f.to_bytes().unwrap())
            .unwrap()
            .decode::<FedFetchBundle>()
            .unwrap(),
        fetch_bundle
    );

    let bundle = FedBundle {
        bundle: sample_bundle(),
    };
    let f = FedFrame::new(FedOp::Bundle, 1, &bundle).unwrap();
    assert_eq!(f.decode::<FedBundle>().unwrap(), bundle);

    let route = FedRoute {
        to: [1u8; 32],
        from: [2u8; 32],
        envelope: OpaqueBlob::new(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };
    let f = FedFrame::new(FedOp::Route, 2, &route).unwrap();
    assert_eq!(f.decode::<FedRoute>().unwrap(), route);

    let reachability = FedReachability { target: [3u8; 32] };
    let f = FedFrame::new(FedOp::Reachability, 3, &reachability).unwrap();
    assert_eq!(f.decode::<FedReachability>().unwrap(), reachability);

    let reachable = FedReachable { connected: true };
    let f = FedFrame::new(FedOp::Reachable, 3, &reachable).unwrap();
    assert_eq!(f.decode::<FedReachable>().unwrap(), reachable);

    let err = FedErr {
        code: "not_found".into(),
        msg: "unknown target".into(),
    };
    let f = FedFrame::new(FedOp::Err, 3, &err).unwrap();
    assert_eq!(f.decode::<FedErr>().unwrap(), err);
}

#[test]
fn fed_route_b32_fields_roundtrip_exactly() {
    // FedRoute's `to`/`from` are b32 fixed-length keys, distinct from each other and from the
    // opaque envelope; a round trip through FedFrame must preserve every field exactly.
    let route = FedRoute {
        to: [0xAAu8; 32],
        from: [0xBBu8; 32],
        envelope: OpaqueBlob::new(vec![1, 2, 3, 4, 5]),
    };
    let f = FedFrame::new(FedOp::Route, 42, &route).unwrap();
    let decoded = FedFrame::from_bytes(&f.to_bytes().unwrap())
        .unwrap()
        .decode::<FedRoute>()
        .unwrap();
    assert_eq!(decoded.to, route.to);
    assert_eq!(decoded.from, route.from);
    assert_eq!(decoded.envelope, route.envelope);
}
