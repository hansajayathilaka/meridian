//! Wire round-trip: every frame body and the bundle survive CBOR encode/decode, and byte-array
//! fields land as compact CBOR byte strings (not integer arrays).

use meridian_proto::{
    Auth, Bundle, Challenge, Deliver, Fetch, Frame, Op, OpaqueBlob, PrekeyBundle, Publish,
    RouteBody, BUNDLE_VERSION,
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
fn frame_and_bodies_roundtrip() {
    let challenge = Challenge {
        nonce: [42u8; 32],
        server_time: 1_700_000_000,
        server_domain: "chat.example".into(),
    };
    let frame = Frame::new(Op::Challenge, 1, &challenge).unwrap();
    let bytes = frame.to_bytes().unwrap();
    let back = Frame::from_bytes(&bytes).unwrap();
    assert_eq!(back.op, Op::Challenge);
    assert_eq!(back.id, 1);
    assert_eq!(back.decode::<Challenge>().unwrap(), challenge);

    let auth = Auth {
        account_pub: [8u8; 32],
        sig: [6u8; 64],
        invite: Some("token".into()),
        max_bundle_v: 1,
    };
    let f = Frame::new(Op::Auth, 2, &auth).unwrap();
    assert_eq!(
        Frame::from_bytes(&f.to_bytes().unwrap())
            .unwrap()
            .decode::<Auth>()
            .unwrap(),
        auth
    );

    let publish = Publish {
        bundle: sample_bundle(),
    };
    let f = Frame::new(Op::Publish, 3, &publish).unwrap();
    assert_eq!(f.decode::<Publish>().unwrap(), publish);

    let fetch = Fetch {
        target: [5u8; 32],
        tamper: false,
    };
    let f = Frame::new(Op::Fetch, 4, &fetch).unwrap();
    assert_eq!(f.decode::<Fetch>().unwrap(), fetch);

    let route = RouteBody {
        to: [1u8; 32],
        blob: OpaqueBlob::new(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };
    let f = Frame::new(Op::Route, 5, &route).unwrap();
    assert_eq!(f.decode::<RouteBody>().unwrap(), route);

    let deliver = Deliver {
        from: [1u8; 32],
        blob: OpaqueBlob::new(vec![1, 2, 3]),
    };
    let f = Frame::new(Op::Deliver, 6, &deliver).unwrap();
    assert_eq!(f.decode::<Deliver>().unwrap(), deliver);

    let bundle = Bundle {
        bundle: sample_bundle(),
    };
    let f = Frame::new(Op::Bundle, 7, &bundle).unwrap();
    assert_eq!(f.decode::<Bundle>().unwrap(), bundle);
}

#[test]
fn opaque_blob_encodes_as_cbor_byte_string() {
    // A 4-byte blob must encode as a CBOR byte string: 0x44 (major 2, len 4) followed by 4 bytes —
    // NOT as an array of integers (which would start with 0x84).
    let blob = OpaqueBlob::new(vec![0xAA, 0xBB, 0xCC, 0xDD]);
    let bytes = meridian_proto::encode(&blob).unwrap();
    assert_eq!(bytes, vec![0x44, 0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn bundle_structural_validation() {
    let mut b = sample_bundle();
    assert!(b.structurally_valid());
    b.otk_sigs.pop(); // mismatched counts
    assert!(!b.structurally_valid());
}
