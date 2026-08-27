//! Wire round-trip: every frame body and the bundle survive CBOR encode/decode, and byte-array
//! fields land as compact CBOR byte strings (not integer arrays).

use meridian_proto::{
    error_codes, Auth, Bundle, Challenge, Deliver, Fetch, Frame, MailboxAck, MailboxAckOk, Op,
    OpaqueBlob, PrekeyBundle, Publish, RouteBody, RouteOk, BUNDLE_VERSION,
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
        hint: None,
        tamper: false,
    };
    let f = Frame::new(Op::Fetch, 4, &fetch).unwrap();
    assert_eq!(f.decode::<Fetch>().unwrap(), fetch);

    let route = RouteBody {
        to: [1u8; 32],
        to_hint: None,
        blob: OpaqueBlob::new(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };
    let f = Frame::new(Op::Route, 5, &route).unwrap();
    assert_eq!(f.decode::<RouteBody>().unwrap(), route);

    let deliver = Deliver {
        from: [1u8; 32],
        blob: OpaqueBlob::new(vec![1, 2, 3]),
        mailbox_id: None,
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
fn fetch_hint_absent_is_byte_identical_to_pre_2_3_shape() {
    // A hint-less Fetch (existing clients) must encode identically whether or not the `hint`
    // field exists in the struct at all — `skip_serializing_if` must actually omit the map key,
    // not merely encode a CBOR null.
    let with_field_absent = Fetch {
        target: [9u8; 32],
        hint: None,
        tamper: true,
    };
    let bytes = meridian_proto::encode(&with_field_absent).unwrap();
    // { target: bstr[32], tamper: true } — exactly two map entries, no "hint" key anywhere.
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("hint"));
    assert_eq!(
        meridian_proto::decode::<Fetch>(&bytes).unwrap(),
        with_field_absent
    );
}

#[test]
fn fetch_hint_present_empty_and_over_length_roundtrip() {
    for hint in [
        "org-b.test".to_string(),
        String::new(),
        "x".repeat(400), // over the 253-byte DNS-name ceiling identity-format.md documents;
                         // the wire type itself places no length limit — enforcement, if any,
                         // is server behaviour deferred to 2.7.
    ] {
        let fetch = Fetch {
            target: [3u8; 32],
            hint: Some(hint.clone()),
            tamper: false,
        };
        let f = Frame::new(Op::Fetch, 10, &fetch).unwrap();
        assert_eq!(f.decode::<Fetch>().unwrap(), fetch);
        assert_eq!(f.decode::<Fetch>().unwrap().hint, Some(hint));
    }
}

#[test]
fn route_to_hint_present_and_absent_roundtrip() {
    let absent = RouteBody {
        to: [4u8; 32],
        to_hint: None,
        blob: OpaqueBlob::new(vec![1, 2, 3]),
    };
    let bytes = meridian_proto::encode(&absent).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("to_hint"));
    assert_eq!(meridian_proto::decode::<RouteBody>(&bytes).unwrap(), absent);

    let present = RouteBody {
        to: [4u8; 32],
        to_hint: Some("org-b.test".to_string()),
        blob: OpaqueBlob::new(vec![1, 2, 3]),
    };
    let f = Frame::new(Op::Route, 11, &present).unwrap();
    assert_eq!(f.decode::<RouteBody>().unwrap(), present);
}

#[test]
fn bundle_structural_validation() {
    let mut b = sample_bundle();
    assert!(b.structurally_valid());
    b.otk_sigs.pop(); // mismatched counts
    assert!(!b.structurally_valid());
}

// --- 8.3: T07 mailbox wire vocabulary --------------------------------------------------------

#[test]
fn route_ok_delivered_true_no_queued_is_byte_identical_to_pre_8_3_shape() {
    // The backward-compatibility claim, tested: a `RouteOk{delivered:true}` reply (the shape every
    // existing client already speaks) must encode with no `queued` key at all — `queued: false`'s
    // `skip_serializing_if` must actually omit the map key, not merely encode `false`.
    let ok = RouteOk {
        delivered: true,
        queued: false,
    };
    let bytes = meridian_proto::encode(&ok).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("queued"));
    assert_eq!(meridian_proto::decode::<RouteOk>(&bytes).unwrap(), ok);
}

#[test]
fn route_ok_queued_true_roundtrips_and_is_present_on_the_wire() {
    let ok = RouteOk {
        delivered: false,
        queued: true,
    };
    let bytes = meridian_proto::encode(&ok).unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("queued"));
    let f = Frame::new(Op::RouteOk, 20, &ok).unwrap();
    assert_eq!(f.decode::<RouteOk>().unwrap(), ok);
}

#[test]
fn deliver_no_mailbox_id_is_byte_identical_to_pre_8_3_shape() {
    // The backward-compatibility claim, tested: a live-route `Deliver{from, blob}` (no
    // `mailbox_id`) must encode with no `mailbox_id` key at all.
    let deliver = Deliver {
        from: [1u8; 32],
        blob: OpaqueBlob::new(vec![1, 2, 3]),
        mailbox_id: None,
    };
    let bytes = meridian_proto::encode(&deliver).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("mailbox_id"));
    assert_eq!(meridian_proto::decode::<Deliver>(&bytes).unwrap(), deliver);
}

#[test]
fn deliver_mailbox_id_present_roundtrips() {
    let deliver = Deliver {
        from: [1u8; 32],
        blob: OpaqueBlob::new(vec![1, 2, 3]),
        mailbox_id: Some(42),
    };
    let bytes = meridian_proto::encode(&deliver).unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("mailbox_id"));
    let f = Frame::new(Op::Deliver, 21, &deliver).unwrap();
    let decoded = f.decode::<Deliver>().unwrap();
    assert_eq!(decoded, deliver);
    assert_eq!(decoded.mailbox_id, Some(42));
}

#[test]
fn mailbox_ack_and_ack_ok_roundtrip() {
    let ack = MailboxAck { ids: vec![1, 2, 3] };
    let f = Frame::new(Op::MailboxAck, 22, &ack).unwrap();
    assert_eq!(f.decode::<MailboxAck>().unwrap(), ack);

    let empty = MailboxAck { ids: vec![] };
    let f = Frame::new(Op::MailboxAck, 23, &empty).unwrap();
    assert_eq!(f.decode::<MailboxAck>().unwrap(), empty);

    let ack_ok = MailboxAckOk {};
    let f = Frame::new(Op::MailboxAckOk, 24, &ack_ok).unwrap();
    assert_eq!(f.decode::<MailboxAckOk>().unwrap(), ack_ok);
}

#[test]
fn mailbox_full_error_codes_are_the_expected_strings() {
    assert_eq!(error_codes::MAILBOX_FULL, "mailbox_full");
    assert_eq!(
        meridian_proto::fed_error_codes::MAILBOX_FULL,
        "mailbox_full"
    );
}

// Content-shaped type round-trips (chat, message envelope, ctrl frames, signal content) live in
// apps/envelope/tests/roundtrip.rs — those types are NOT part of meridian-proto (F15; see
// apps/envelope/src/lib.rs and apps/proto/src/lib.rs).
