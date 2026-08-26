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
fn message_envelope_roundtrips_and_binds_the_preamble_aad_encoding() {
    use meridian_envelope::{preamble_aad_bytes, MessageEnvelope, Prekey, ENVELOPE_VERSION};
    let prekey = Prekey {
        ek_pub: [1u8; 32],
        used_spk: [2u8; 32],
        used_opk: Some([3u8; 32]),
    };
    let env = MessageEnvelope {
        v: ENVELOPE_VERSION,
        sender_pub: [9u8; 32],
        eid: [6u8; 16],
        prekey: Some(prekey),
        ct: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    // Wraps and unwraps through the opaque-blob byte form unchanged.
    let decoded = MessageEnvelope::from_blob(&env.to_blob().unwrap()).unwrap();
    assert_eq!(decoded, env);

    // v2 (ADR 0016 C3): the envelope no longer signs anything — authentication is the ratchet
    // AEAD's job. What this crate still owns is the canonical preamble encoding fed into that
    // AEAD's AAD: distinct prekey preambles must encode to distinct bytes (the "splice-ambiguity"
    // property `preamble_aad_bytes`'s own doc comment explains the explicit presence flags exist
    // for), and a `None` preamble must encode differently from a present one.
    let base = preamble_aad_bytes(&env.prekey);
    let mut tampered = env.clone();
    tampered.prekey.as_mut().unwrap().used_opk = None;
    assert_ne!(base, preamble_aad_bytes(&tampered.prekey));
    assert_ne!(base, preamble_aad_bytes(&None));

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

/// ADR 0016 C5/R5: a `v` mismatch is a hard, local, unilateral reject — never a downgrade or a
/// negotiated fallback. This falls out of ordinary strict CBOR struct decoding as long as `v` is
/// genuinely mandatory (never `Option`/defaulted) — this test pins that a non-`ENVELOPE_VERSION`
/// value still decodes structurally (so the *caller*, `ChatState::open_bytes`, is what enforces the
/// hard reject — see `MessageEnvelope::from_blob`'s own doc comment for why that split is
/// deliberate), and that a `v`-less legacy (v1-shaped) blob fails to decode at all, since `v` is not
/// `#[serde(default)]`.
#[test]
fn envelope_version_is_mandatory_and_never_defaulted() {
    use meridian_envelope::{MessageEnvelope, ENVELOPE_VERSION};

    let env = MessageEnvelope {
        v: 999, // deliberately not ENVELOPE_VERSION
        sender_pub: [9u8; 32],
        eid: [1u8; 16],
        prekey: None,
        ct: vec![0x01],
    };
    let decoded = MessageEnvelope::from_blob(&env.to_blob().unwrap())
        .expect("a non-canonical v still decodes structurally — enforcement is the caller's job");
    assert_eq!(decoded.v, 999);
    assert_ne!(decoded.v, ENVELOPE_VERSION);

    // A v1-shaped CBOR map (no `v` field at all, plus the old `sig` field) must NOT decode as a v2
    // envelope — `v` has no `#[serde(default)]`, so its absence is a hard decode error, not a
    // silently-defaulted 0/None. This is what makes the flag day (R5) a clean decode failure rather
    // than an ambiguous, silently-accepted mismatch.
    use ciborium::value::Value;
    let v1_shaped = Value::Map(vec![
        (
            Value::Text("sender_pub".into()),
            Value::Bytes(vec![9u8; 32]),
        ),
        (Value::Text("ct".into()), Value::Bytes(vec![0x01])),
        (Value::Text("sig".into()), Value::Bytes(vec![0u8; 64])),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&v1_shaped, &mut bytes).unwrap();
    assert!(
        MessageEnvelope::from_blob(&bytes).is_err(),
        "a v1-shaped blob with no `v` field must fail to decode as a v2 envelope, never silently \
         default"
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
