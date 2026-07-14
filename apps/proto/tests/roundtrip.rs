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

#[test]
fn chat_content_roundtrips() {
    use meridian_proto::ChatContent;
    let text = ChatContent::Text {
        id: [7u8; 16],
        body: "hello, world".into(),
    };
    assert_eq!(ChatContent::decode(&text.encode().unwrap()).unwrap(), text);

    let receipt = ChatContent::Receipt { ack: [7u8; 16] };
    assert_eq!(
        ChatContent::decode(&receipt.encode().unwrap()).unwrap(),
        receipt
    );
}

#[test]
fn message_envelope_roundtrips_and_binds_signing_input() {
    use meridian_proto::{MessageEnvelope, Prekey};
    let prekey = Prekey {
        ek_pub: [1u8; 32],
        used_spk: [2u8; 32],
        used_opk: Some([3u8; 32]),
    };
    let env = MessageEnvelope {
        sender_pub: [9u8; 32],
        prekey: Some(prekey),
        ct: vec![0xDE, 0xAD, 0xBE, 0xEF],
        sig: [0u8; 64],
    };
    // Wraps and unwraps through the opaque-blob byte form unchanged.
    let decoded = MessageEnvelope::from_blob(&env.to_blob().unwrap()).unwrap();
    assert_eq!(decoded, env);

    // The signing input binds sender/prekey/ct: mutating the ciphertext changes it.
    let base = env.signing_bytes();
    let mut tampered = env.clone();
    tampered.ct = vec![0x00];
    assert_ne!(base, tampered.signing_bytes());

    // An envelope with no prekey (steady-state message) also round-trips.
    let steady = MessageEnvelope {
        prekey: None,
        ..env
    };
    assert_eq!(
        MessageEnvelope::from_blob(&steady.to_blob().unwrap()).unwrap(),
        steady
    );
}

#[test]
fn ctrl_frames_roundtrip() {
    use meridian_proto::ctrl::{ChanCfgWire, Direction, Limits, StreamAdvert};
    use meridian_proto::{CtrlFrame, CTRL_VERSION};

    let hello = CtrlFrame::Hello {
        v: CTRL_VERSION,
        streams: vec![
            StreamAdvert {
                name: "mrd.ctrl/1".into(),
                ver: 1,
                dir: Direction::Bidir,
                mandatory: true,
            },
            StreamAdvert {
                name: "mrd.chat/1".into(),
                ver: 1,
                dir: Direction::Bidir,
                mandatory: true,
            },
        ],
        transports: vec!["webrtc".into()],
        limits: Limits { max_frame: 65536 },
    };
    for frame in [
        hello,
        CtrlFrame::Open {
            sid: 7,
            ty: "mrd.chat/1".into(),
            params: vec![1, 2, 3],
            chan: ChanCfgWire {
                reliable: true,
                ordered: true,
                max_rtx: None,
                rtp: false,
            },
        },
        CtrlFrame::Accept { sid: 7 },
        CtrlFrame::Reject {
            sid: 9,
            code: "unsupported".into(),
            reason: "unknown type".into(),
        },
        CtrlFrame::Close {
            sid: 7,
            status: "done".into(),
        },
        CtrlFrame::Keepalive { t: 42 },
    ] {
        let bytes = frame.encode().unwrap();
        assert_eq!(CtrlFrame::decode(&bytes).unwrap(), frame);
    }
}

#[test]
fn signal_content_roundtrips() {
    use meridian_proto::SignalContent;

    for content in [
        SignalContent::SdpOffer {
            sdp: b"v=loopback\ntoken=1\n".to_vec(),
            dtls_fp: "sha-256 AB:CD".into(),
            ice: vec!["candidate:host 1".into()],
        },
        SignalContent::SdpAnswer {
            sdp: b"v=loopback\ntoken=2\n".to_vec(),
            dtls_fp: "sha-256 EF:01".into(),
            ice: vec![],
        },
        SignalContent::IceTrickle {
            candidates: vec!["candidate:srflx 2".into()],
        },
        SignalContent::Ctrl {
            frame: vec![9, 9, 9],
        },
    ] {
        let bytes = content.encode().unwrap();
        assert_eq!(SignalContent::decode(&bytes).unwrap(), content);
    }
}
