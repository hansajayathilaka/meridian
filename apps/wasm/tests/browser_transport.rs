//! Same-process SDP offer/answer loopback for `BrowserTransport` (task 12.11 deliverable 2).
//!
//! Exercises the negotiation subset `core-api-contracts.md` freezes — `new_session`/
//! `add_data_channel`/`local_description`/`set_remote_description`/`add_ice_candidate`/the
//! fingerprint accessors, plus the `set_remote_offer_and_answer`/`ice_restart` additions (task
//! 10.22/ADR 0025) — between two [`BrowserTransport`] instances, each backed by its own real
//! `RTCPeerConnection`, in one headless-browser tab. This is a same-tab loopback, not a live
//! two-machine network test (explicitly deferred to the interop-matrix task, 12.17, per this task's
//! own Risks/notes) — it proves the negotiation plumbing is wired correctly against the browser's
//! real WebRTC objects and that the DTLS-fingerprint-binding property
//! (`system-design.md` §7.1 step 13) holds, not that a data channel opens across a real network path.
//!
//! Needs real `RTCPeerConnection`/`RTCDataChannel` objects, unavailable in Node — run with
//! `wasm-pack test --chrome --headless` (or `--firefox`), never `--node` (see `apps/wasm/src/lib.rs`'s
//! own module doc for why its *unit* tests stay Node-only and this lives in a separate integration
//! test binary instead, with its own `wasm_bindgen_test_configure!(run_in_browser)`).

use meridian_core::transport::{ChannelCfg, IceConfig, Transport};
use meridian_wasm::transport::BrowserTransport;
use wasm_bindgen_test::wasm_bindgen_test;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn two_browser_transports_negotiate_and_agree_on_fingerprints() {
    let a = BrowserTransport::new();
    let b = BrowserTransport::new();

    let sa = a
        .new_session(IceConfig::default())
        .await
        .expect("a.new_session");
    let sb = b
        .new_session(IceConfig::default())
        .await
        .expect("b.new_session");

    a.add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.ctrl/1"))
        .await
        .expect("a.add_data_channel");
    b.add_data_channel(&sb, ChannelCfg::reliable_ordered("mrd.ctrl/1"))
        .await
        .expect("b.add_data_channel");

    // A is the dialer: `local_description` reads its cached, not-yet-committed offer directly.
    let offer = a
        .local_description(&sa)
        .expect("a.local_description (offer)");
    let offer_text = std::str::from_utf8(offer.as_bytes()).expect("offer is UTF-8 SDP text");
    assert!(
        offer_text.starts_with("v=0"),
        "a genuine SDP offer starts with the v=0 line, got: {offer_text}"
    );
    assert!(
        offer_text.contains("a=fingerprint:"),
        "a real RTCPeerConnection offer always asserts a DTLS fingerprint"
    );

    // B answers.
    b.set_remote_description(&sb, offer.clone())
        .await
        .expect("b.set_remote_description(offer)");
    let answer = b
        .local_description(&sb)
        .expect("b.local_description (answer)");

    // A applies B's answer, lazily committing its own cached offer as a side effect (mirrors
    // `WebRtcTransport`'s "offer/answer without a role hint" bookkeeping).
    a.set_remote_description(&sa, answer.clone())
        .await
        .expect("a.set_remote_description(answer)");

    // The DTLS-fingerprint-binding property (`system-design.md` §7.1 step 13): each side's
    // *negotiated remote* fingerprint must equal the other side's *asserted local* fingerprint —
    // the value the substrate later cross-checks against the identity-signed envelope (§4.6).
    let a_local_fp = a.local_fingerprint(&sa).expect("a.local_fingerprint");
    let b_local_fp = b.local_fingerprint(&sb).expect("b.local_fingerprint");
    let a_remote_fp = a.dtls_fingerprint(&sa).expect("a.dtls_fingerprint");
    let b_remote_fp = b.dtls_fingerprint(&sb).expect("b.dtls_fingerprint");
    assert_eq!(
        a_remote_fp, b_local_fp,
        "a's negotiated remote fingerprint must equal b's asserted local fingerprint"
    );
    assert_eq!(
        b_remote_fp, a_local_fp,
        "b's negotiated remote fingerprint must equal a's asserted local fingerprint"
    );
    assert_ne!(
        a_local_fp, b_local_fp,
        "two distinct RTCPeerConnections must not share a DTLS certificate"
    );

    // Trickle each side's own gathered candidates to the other — exercises `local_candidates`/
    // `add_ice_candidate` against real WebRTC objects. Not asserting connectivity/`selected_path`
    // here: a same-tab loopback proves the negotiation plumbing, not a live network path (deferred
    // to task 12.17 per this task's own Risks/notes).
    let a_candidates = a.local_candidates(&sa).await.expect("a.local_candidates");
    let b_candidates = b.local_candidates(&sb).await.expect("b.local_candidates");
    assert!(
        !a_candidates.is_empty(),
        "a headless-Chrome host candidate should always gather"
    );
    assert!(
        !b_candidates.is_empty(),
        "a headless-Chrome host candidate should always gather"
    );
    for c in a_candidates {
        b.add_ice_candidate(&sb, c)
            .await
            .expect("b.add_ice_candidate");
    }
    for c in b_candidates {
        a.add_ice_candidate(&sa, c)
            .await
            .expect("a.add_ice_candidate");
    }

    a.close(&sa).await.expect("a.close");
    b.close(&sb).await.expect("b.close");
}

#[wasm_bindgen_test]
async fn set_remote_offer_and_answer_handles_a_fresh_offer_after_the_original_handshake() {
    // Exercises the ADR 0025 / task 10.22 addition: after a full initial handshake, `a`'s own
    // bookkeeping still has `committed_local_sdp = Some(its original offer)` (never cleared once
    // the handshake completes) — so a *second*, later, genuine offer from `b` (an ICE restart)
    // would be misread by `set_remote_description`'s flag-based "already committed ⇒ must be an
    // answer" heuristic as the answer to `a`'s own stale offer. `set_remote_offer_and_answer`
    // exists precisely so a caller that already knows (from its own protocol-level role decision)
    // that this is a genuine offer can bypass that misclassification.
    let a = BrowserTransport::new();
    let b = BrowserTransport::new();

    let sa = a.new_session(IceConfig::default()).await.unwrap();
    let sb = b.new_session(IceConfig::default()).await.unwrap();
    a.add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.ctrl/1"))
        .await
        .unwrap();
    b.add_data_channel(&sb, ChannelCfg::reliable_ordered("mrd.ctrl/1"))
        .await
        .unwrap();

    // Original handshake: a dials, b answers.
    let first_offer = a.local_description(&sa).unwrap();
    b.set_remote_description(&sb, first_offer.clone())
        .await
        .unwrap();
    let first_answer = b.local_description(&sb).unwrap();
    a.set_remote_description(&sa, first_answer).await.unwrap();

    // b restarts ICE (a real, local ufrag/pwd rotation — task 10.19/ADR 0025's local primitive)
    // and produces a fresh, genuine offer.
    b.ice_restart(&sb).await.expect("b.ice_restart");
    let second_offer = b
        .local_description(&sb)
        .expect("b.local_description after restart is a fresh offer");
    assert_ne!(
        second_offer, first_offer,
        "an ICE restart must produce a genuinely different offer"
    );

    a.set_remote_offer_and_answer(&sa, second_offer)
        .await
        .expect("set_remote_offer_and_answer must produce a real answer to b's second offer");

    let second_answer = a
        .local_description(&sa)
        .expect("a.local_description is now a's answer to b's second offer");
    assert_ne!(
        second_answer, first_offer,
        "local_description must now be a's answer, not a's stale original offer"
    );

    // b's DTLS certificate must be untouched by its own ICE restart (task 10.19's own invariant,
    // mirrored here for the browser backend) — a's negotiated remote fingerprint after this second
    // round trip must still equal b's local fingerprint.
    let b_local_fp = b.local_fingerprint(&sb).expect("b.local_fingerprint");
    let a_remote_fp = a.dtls_fingerprint(&sa).expect("a.dtls_fingerprint");
    assert_eq!(
        a_remote_fp, b_local_fp,
        "fingerprint binding must still hold after the ICE-restart offer/answer round trip"
    );

    a.close(&sa).await.unwrap();
    b.close(&sb).await.unwrap();
}

#[wasm_bindgen_test]
async fn unknown_session_handle_is_a_clean_error_not_a_panic() {
    use meridian_core::transport::{SessionHandle, TransportError};

    let a = BrowserTransport::new();
    let bogus = SessionHandle(u64::MAX);
    assert!(matches!(
        a.new_session(IceConfig::default()).await.map(|_| ()).and(
            a.add_ice_candidate(
                &bogus,
                meridian_core::transport::IceCandidate(String::new())
            )
            .await
        ),
        Err(TransportError::UnknownSession)
    ));
    assert!(matches!(
        a.local_description(&bogus),
        Err(TransportError::UnknownSession)
    ));
}
