//! Wire round-trip for content-shaped types: chat content, the message envelope, `mrd.ctrl/1`
//! frames, and P2P signal content all survive CBOR encode/decode. These types deliberately live
//! in `meridian-envelope`, not `meridian-proto` (F15) — see apps/envelope/src/lib.rs.

#[test]
fn chat_content_roundtrips() {
    use meridian_envelope::ChatContent;
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
    use meridian_envelope::{MessageEnvelope, Prekey};
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
    use meridian_envelope::ctrl::{ChanCfgWire, Direction, Limits, StreamAdvert};
    use meridian_envelope::{CtrlFrame, CTRL_VERSION};

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
    use meridian_envelope::SignalContent;

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
