//! Gated integration coverage for [`WebRtcTransport`] — real ICE/SCTP/DTLS between two peers on
//! localhost, mirroring `loopback.rs`'s unit tests but over the production backend (1.15, F10
//! backend). `cargo nextest run -p meridian-transport --features webrtc`.

#![cfg(feature = "webrtc")]

use std::sync::Arc;
use std::time::Duration;

use meridian_transport::{
    ChannelCfg, IceConfig, IcePolicy, IceServer, SessionHandle, Transport, WebRtcTransport,
};

async fn connect_pair() -> (
    Arc<WebRtcTransport>,
    SessionHandle,
    Arc<WebRtcTransport>,
    SessionHandle,
) {
    let ta = Arc::new(WebRtcTransport::new());
    let tb = Arc::new(WebRtcTransport::new());

    let sa = ta.new_session(IceConfig::default()).await.unwrap();
    let sb = tb.new_session(IceConfig::default()).await.unwrap();

    ta.add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.ctrl/1"))
        .await
        .unwrap();
    tb.add_data_channel(&sb, ChannelCfg::reliable_ordered("mrd.ctrl/1"))
        .await
        .unwrap();

    let offer = ta.local_description(&sa).unwrap();
    tb.set_remote_description(&sb, offer).await.unwrap();
    for c in ta.local_candidates(&sa).await.unwrap() {
        tb.add_ice_candidate(&sb, c).await.unwrap();
    }

    let answer = tb.local_description(&sb).unwrap();
    ta.set_remote_description(&sa, answer).await.unwrap();
    for c in tb.local_candidates(&sb).await.unwrap() {
        ta.add_ice_candidate(&sa, c).await.unwrap();
    }

    (ta, sa, tb, sb)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_peers_exchange_bytes_over_real_ice_sctp_dtls() {
    let (ta, sa, tb, sb) = connect_pair().await;

    let ca = ta
        .add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.chat/1"))
        .await
        .unwrap();
    let cb = tb
        .add_data_channel(&sb, ChannelCfg::reliable_ordered("mrd.chat/1"))
        .await
        .unwrap();

    ta.send(&sa, &ca, b"hello over real webrtc").await.unwrap();
    let (_cid, data) = tb.recv(&sb).await.unwrap().unwrap();
    assert_eq!(data, b"hello over real webrtc");

    tb.send(&sb, &cb, b"hi back").await.unwrap();
    let (_cid, data) = ta.recv(&sa).await.unwrap().unwrap();
    assert_eq!(data, b"hi back");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negotiated_fingerprints_agree_and_bind_to_the_real_dtls_cert() {
    let (ta, sa, tb, sb) = connect_pair().await;

    let a_local = ta.local_fingerprint(&sa).unwrap();
    let b_local = tb.local_fingerprint(&sb).unwrap();
    let a_remote = ta.dtls_fingerprint(&sa).unwrap();
    let b_remote = tb.dtls_fingerprint(&sb).unwrap();

    // Each side's negotiated remote value is exactly the other's asserted local value — the
    // property `apps/core`'s §4.6 cross-check relies on.
    assert_eq!(a_local, b_remote);
    assert_eq!(b_local, a_remote);
    // And it's a real SHA-256 DTLS fingerprint, not a loopback placeholder.
    assert!(a_local.0.starts_with("sha-256 "));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_path_is_direct_on_localhost() {
    let (ta, sa, tb, sb) = connect_pair().await;
    let ca = ta
        .add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.chat/1"))
        .await
        .unwrap();
    tb.add_data_channel(&sb, ChannelCfg::reliable_ordered("mrd.chat/1"))
        .await
        .unwrap();
    // Drive one message so we know the channel — and therefore the underlying ICE/DTLS/SCTP
    // stack — actually finished connecting before asking for the selected path.
    ta.send(&sa, &ca, b"warm up").await.unwrap();
    tb.recv(&sb).await.unwrap().unwrap();

    let path = tokio::time::timeout(Duration::from_secs(15), ta.selected_path(&sa))
        .await
        .expect("selected_path timed out")
        .unwrap();
    assert_eq!(path, meridian_transport::Path::Direct);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_remote_fingerprint_never_connects() {
    // Corrupt the last hex digit of the offer's declared DTLS fingerprint before the answerer
    // applies it — modelling a peer (or a compromised sender) whose SDP disagrees with the
    // certificate it will actually present. Real WebRTC enforces certificate-matches-SDP binding
    // inside the DTLS handshake itself: the handshake must never complete, so the module docs'
    // central safety claim ("WebRTC's own DTLS stack refuses to complete a handshake whose peer
    // certificate does not match the SDP-declared fingerprint") is exercised here, not just
    // asserted in a comment.
    let ta = Arc::new(WebRtcTransport::new());
    let tb = Arc::new(WebRtcTransport::new());

    let sa = ta.new_session(IceConfig::default()).await.unwrap();
    let sb = tb.new_session(IceConfig::default()).await.unwrap();
    ta.add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.ctrl/1"))
        .await
        .unwrap();
    tb.add_data_channel(&sb, ChannelCfg::reliable_ordered("mrd.ctrl/1"))
        .await
        .unwrap();

    let offer = ta.local_description(&sa).unwrap();
    let mut sdp_bytes = offer.0;
    let marker = b"a=fingerprint:";
    let start = sdp_bytes
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("offer carries a fingerprint line");
    let line_end = sdp_bytes[start..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| start + p)
        .unwrap_or(sdp_bytes.len());
    let last = if sdp_bytes[line_end - 1] == b'\r' {
        line_end - 2
    } else {
        line_end - 1
    };
    sdp_bytes[last] = if sdp_bytes[last] == b'0' { b'1' } else { b'0' };

    tb.set_remote_description(&sb, meridian_transport::Sdp(sdp_bytes))
        .await
        .unwrap();
    for c in ta.local_candidates(&sa).await.unwrap() {
        tb.add_ice_candidate(&sb, c).await.unwrap();
    }
    let answer = tb.local_description(&sb).unwrap();
    ta.set_remote_description(&sa, answer).await.unwrap();
    for c in tb.local_candidates(&sb).await.unwrap() {
        ta.add_ice_candidate(&sa, c).await.unwrap();
    }

    // `tb` is the one who received the tampered claim about `ta`'s certificate — its DTLS
    // transport is the one that must refuse the handshake (validating "does the peer's real cert
    // match what they declared in their SDP" is inherently a property the *receiver* of that SDP
    // checks, not the declarer). Connectivity must never converge on tb's side: either the
    // transport's own bounded wait reports `NoPath`, or the outer timeout fires first.
    if let Ok(Ok(path)) = tokio::time::timeout(Duration::from_secs(20), tb.selected_path(&sb)).await
    {
        panic!("connected over a tampered fingerprint! path={path:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_immediately_before_close_is_still_delivered() {
    // Regression test for the race `close()` used to have: `send()` only guarantees the bytes
    // were handed to the SCTP association's outgoing buffer, not that they left the process —
    // closing the peer connection right after a send, with no flush, could silently drop it
    // (found via `apps/cli`'s `session connect`, where the responder's final reply raced its own
    // `close()`). `close()` now drains each channel's `buffered_amount()` before tearing down.
    let (ta, sa, tb, sb) = connect_pair().await;
    let ca = ta
        .add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.chat/1"))
        .await
        .unwrap();
    tb.add_data_channel(&sb, ChannelCfg::reliable_ordered("mrd.chat/1"))
        .await
        .unwrap();

    ta.send(&sa, &ca, b"final message before close")
        .await
        .unwrap();
    ta.close(&sa).await.unwrap();

    let (_cid, data) = tokio::time::timeout(Duration::from_secs(5), tb.recv(&sb))
        .await
        .expect("recv timed out — the pre-close send was dropped")
        .unwrap()
        .expect("channel closed with no message delivered");
    assert_eq!(data, b"final message before close");
}

/// Pull an `a=ice-ufrag:`/`a=ice-pwd:` value out of raw SDP text — mirrors
/// `webrtc_backend::parse_fingerprint`'s own style for reading a single attribute line, but that
/// helper is private to the crate, so the test re-implements the same trivial line scan rather than
/// reaching into crate internals.
fn sdp_attr<'a>(sdp: &'a str, prefix: &str) -> &'a str {
    sdp.lines()
        .find_map(|l| l.trim_end_matches('\r').strip_prefix(prefix))
        .unwrap_or_else(|| panic!("SDP carried no {prefix} line:\n{sdp}"))
}

/// Regression test for task 10.19 (`docs/tasks/phase-10/10.19-real-transport-ice-restart.md`) / ADR
/// 0025: `WebRtcTransport::ice_restart` now invokes webrtc-rs's real ICE-agent restart instead of
/// only resetting local candidate-gathering bookkeeping.
///
/// **What this test does and does not prove.** It proves the *local* half of a restart is real and
/// well-behaved: (a) the restarted `local_description()` carries a genuinely different ICE
/// ufrag/pwd than before (not a relabeled no-op), (b) calling `ice_restart()` alone — with no peer
/// coordination — does not corrupt this side's own already-open data channel bookkeeping, and (c)
/// the DTLS fingerprint is byte-identical before and after (the cert must never rotate across a
/// restart). It deliberately does **not** call the real primitive on an already-connected pair and
/// then assert the channel keeps flowing end to end: per ADR 0025 and this crate's own module docs,
/// a real ICE restart with no peer-side signaling unilaterally deletes the local ICE agent's
/// selected candidate pair, so a peer that never receives the restarted offer has no way to bring
/// up a replacement — the full resumability promise needs the signaling round trip landing in
/// 10.21/10.22, not this task alone. A reader should not mistake this test for proof that gap is
/// closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ice_restart_produces_a_genuinely_new_local_offer_without_disturbing_channels_or_fingerprint(
) {
    let (ta, sa, tb, sb) = connect_pair().await;
    let ca = ta
        .add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.chat/1"))
        .await
        .unwrap();
    tb.add_data_channel(&sb, ChannelCfg::reliable_ordered("mrd.chat/1"))
        .await
        .unwrap();

    // Warm the channel up so we know the connection genuinely completed before restarting it.
    ta.send(&sa, &ca, b"before restart").await.unwrap();
    assert_eq!(tb.recv(&sb).await.unwrap().unwrap().1, b"before restart");

    let sdp_before = ta.local_description(&sa).unwrap();
    let sdp_before = std::str::from_utf8(&sdp_before.0).unwrap();
    let ufrag_before = sdp_attr(sdp_before, "a=ice-ufrag:").to_string();
    let pwd_before = sdp_attr(sdp_before, "a=ice-pwd:").to_string();
    let fp_before = ta.local_fingerprint(&sa).unwrap();

    ta.ice_restart(&sa).await.unwrap();

    // (a) The restarted local description carries genuinely different ICE credentials — proof
    // this is a real restart, not the old no-op relabeled.
    let sdp_after = ta.local_description(&sa).unwrap();
    let sdp_after = std::str::from_utf8(&sdp_after.0).unwrap();
    let ufrag_after = sdp_attr(sdp_after, "a=ice-ufrag:").to_string();
    let pwd_after = sdp_attr(sdp_after, "a=ice-pwd:").to_string();
    assert_ne!(
        ufrag_before, ufrag_after,
        "ice_restart() did not rotate the local ICE ufrag"
    );
    assert_ne!(
        pwd_before, pwd_after,
        "ice_restart() did not rotate the local ICE pwd"
    );

    // (c) The DTLS fingerprint must never rotate across a restart — no `RTCPeerConnection` is ever
    // recreated, only the ICE agent's own credentials/candidates. A later task's layered
    // fingerprint cross-check (ADR 0025) depends on this holding at the transport level.
    let fp_after = ta.local_fingerprint(&sa).unwrap();
    assert_eq!(
        fp_before, fp_after,
        "DTLS fingerprint changed across an ICE restart — the cert must be stable"
    );

    // (b) The already-open data channel's local API surface is untouched by calling the local-only
    // restart primitive by itself: `send()` still accepts bytes into the SCTP outbound queue and
    // `buffered_amount()` still reads back a value, without erroring or panicking. This does *not*
    // assert `tb` ever receives this message — with no peer coordination (out of this task's
    // scope), the underlying candidate pair `ta` just abandoned is exactly what `tb` still has
    // selected, so delivery is not expected to succeed until the signaling round trip lands.
    ta.send(&sa, &ca, b"after local-only restart, no peer coordination")
        .await
        .unwrap();
    ta.buffered_amount(&sa, &ca)
        .await
        .expect("buffered_amount must still be a valid, readable local channel property");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn buffered_amount_rises_under_backpressure_and_drains_as_peer_receives() {
    // (10.2) Send faster than the peer drains — the peer never calls `recv()` during the send
    // burst — and prove `buffered_amount` is a real, changing value: non-zero while the sender's
    // own SCTP outbound queue backs up, then back down to zero once the peer actually consumes it.
    let (ta, sa, tb, sb) = connect_pair().await;
    let ca = ta
        .add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.chat/1"))
        .await
        .unwrap();
    tb.add_data_channel(&sb, ChannelCfg::reliable_ordered("mrd.chat/1"))
        .await
        .unwrap();

    assert_eq!(
        ta.buffered_amount(&sa, &ca).await.unwrap(),
        0,
        "nothing queued before any send"
    );

    // Each chunk sits comfortably under the SCTP default max-message-size (64 KiB); the total
    // volume (3 MiB) comfortably exceeds the default 1 MiB receive window, so with nobody
    // draining on the other end the sender's own outbound queue cannot fully flush.
    let chunk = vec![0xABu8; 32 * 1024];
    let chunk_count: usize = 96;
    for _ in 0..chunk_count {
        ta.send(&sa, &ca, &chunk).await.unwrap();
    }

    let buffered = ta.buffered_amount(&sa, &ca).await.unwrap();
    assert!(
        buffered > 0,
        "expected a non-zero buffered amount after sending {} bytes with no drain on the peer",
        chunk_count * chunk.len()
    );

    // Now let tb actually drain it, and confirm ta's buffered_amount falls back to zero.
    let total = chunk_count * chunk.len();
    let mut received = 0usize;
    let drain = async {
        while received < total {
            let (_cid, data) = tb.recv(&sb).await.unwrap().unwrap();
            received += data.len();
        }
    };
    tokio::time::timeout(Duration::from_secs(20), drain)
        .await
        .expect("drain timed out");

    // Poll until the sender's own queue reports empty — bounded, since a real (if local) network
    // still needs a moment for the last SACKs to land after the last byte is read.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let now = ta.buffered_amount(&sa, &ca).await.unwrap();
        if now == 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "buffered_amount never drained back to 0 (stuck at {now})"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Regression test for 10.18 (`docs/tasks/phase-10/10.18-sctp-max-message-size-fix.md`): before this
/// fix, a real `WebRtcTransport` could not send a single full 64 KiB `mrd.file/1` chunk — every
/// multi-chunk file transfer failed deterministically on its first full chunk with `webrtc-sctp`'s
/// own "outbound packet larger than maximum message size" error, over plain loopback, with no
/// network impairment involved (`docs/testing/soak-file-transfer-throughput.md`). This drives two
/// real `WebRtcTransport` instances through a byte-identical multi-chunk transfer at
/// `FULL_CHUNK_ON_WIRE_SIZE` — the measured on-the-wire size of one of the first 24 full
/// `mrd.file/1` chunks once per-chunk AEAD, CBOR framing, the frame-kind discriminator, and the
/// outer ratchet seal are all accounted for (see `apps/transport/src/webrtc_backend.rs`'s module
/// doc, "SCTP max-message-size" section, for the byte-by-byte accounting and why a chunk later in a
/// very large file lands a few bytes higher) — in **both** directions, over one
/// connected pair, so the fix is proven symmetric regardless of which side dialed and which
/// answered, not just proven for whichever side happens to send first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_chunk_file_transfer_completes_over_real_sctp() {
    // The measured size of one of the first 24 full, on-the-wire `mrd.file/1` chunks (65536-byte
    // plaintext + 16-byte chunk AEAD tag + 14 bytes of CBOR `ChunkFrame{i, data}` framing + 1-byte
    // resume-vs-chunk discriminator + 2-byte ratchet header-length prefix + 80-byte encrypted
    // ratchet header + 16-byte ratchet AEAD tag = 65665 — CBOR's variable-length chunk-index
    // encoding adds a few more bytes for a chunk index at 24+/256+/65536+, still comfortably under
    // the 256 KiB ceiling), reproduced here at the transport layer without depending on
    // `meridian-streams`/`meridian-core` (this crate sits below both) — this is the message size
    // that failed deterministically against the pre-fix 65536-byte SCTP default.
    const FULL_CHUNK_ON_WIRE_SIZE: usize = 65665;
    // Three chunks (~192 KiB) — comfortably more than the "at least 2-3 chunks" this regression
    // needs to prove the fix holds across a real multi-chunk transfer, not just one lucky message.
    const CHUNK_COUNT: usize = 3;

    let (ta, sa, tb, sb) = connect_pair().await;
    let ca = ta
        .add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.file/1"))
        .await
        .unwrap();
    let cb = tb
        .add_data_channel(&sb, ChannelCfg::reliable_ordered("mrd.file/1"))
        .await
        .unwrap();

    // Build deterministic, distinguishable "chunks" — each seeded by its own index so a mangled or
    // reordered chunk would be caught by the byte-identical comparison below, not just a length
    // check.
    let chunks: Vec<Vec<u8>> = (0..CHUNK_COUNT)
        .map(|i| {
            let mut v = vec![0u8; FULL_CHUNK_ON_WIRE_SIZE];
            v[0] = i as u8;
            v[FULL_CHUNK_ON_WIRE_SIZE - 1] = 0xFF ^ (i as u8);
            v
        })
        .collect();

    // Alice -> Bob: every chunk arrives, in order, byte-identical. Before this fix, the very first
    // `ta.send` here failed with `TransportError::Backend("... outbound packet larger than maximum
    // message size")`.
    for chunk in &chunks {
        ta.send(&sa, &ca, chunk).await.unwrap();
    }
    for expected in &chunks {
        let (_cid, data) = tokio::time::timeout(Duration::from_secs(15), tb.recv(&sb))
            .await
            .expect("recv timed out waiting for a full-size chunk")
            .unwrap()
            .unwrap();
        assert_eq!(&data, expected, "chunk arrived corrupted or reordered");
    }

    // Bob -> Alice, the same size, over the same connected pair: proves the fix is symmetric — the
    // answerer's outbound ceiling is exactly as raised as the dialer's, not just one side of it.
    for chunk in &chunks {
        tb.send(&sb, &cb, chunk).await.unwrap();
    }
    for expected in &chunks {
        let (_cid, data) = tokio::time::timeout(Duration::from_secs(15), ta.recv(&sa))
            .await
            .expect("recv timed out waiting for a full-size chunk")
            .unwrap()
            .unwrap();
        assert_eq!(&data, expected, "chunk arrived corrupted or reordered");
    }
}

/// Regression test for 1.30 (`docs/tasks/phase-1/1.30-turn-tcp-dependency-gap.md`): under
/// `IcePolicy::RelayOnly` against a TURN server whose UDP path never answers — exactly what a
/// UDP-blocked NAT/firewall looks like from the ICE agent's perspective, and (per the pinned
/// `webrtc-ice` 0.17.1's total lack of client-side TURN-over-TCP support) the only relay transport
/// this backend can actually attempt today even when a `transport=tcp` URL is also offered —
/// `local_candidates` used to be able to stall well past its own bounded waits (empirically, past a
/// 90s outer script timeout on the real netns/coturn rig). It must now fail loud, quickly, and with
/// a clear error instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_only_gathering_fails_fast_against_a_silent_turn_server() {
    // A real UDP socket that accepts packets but never replies — indistinguishable, from the ICE
    // agent's side, from a firewall that silently drops UDP to the TURN server.
    let silent_turn = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind silent TURN stand-in");
    let addr = silent_turn.local_addr().unwrap();

    let ta = Arc::new(WebRtcTransport::new());
    let cfg = IceConfig {
        stun_servers: Vec::new(),
        ice_servers: vec![IceServer {
            urls: vec![format!("turn:{addr}?transport=udp")],
            username: Some("regression-test-user".into()),
            credential: Some("regression-test-pass".into()),
        }],
        policy: IcePolicy::RelayOnly,
    };
    let sa = ta.new_session(cfg).await.unwrap();
    ta.add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.ctrl/1"))
        .await
        .unwrap();

    let started = std::time::Instant::now();
    // Generous outer guard so a genuine regression (an unbounded hang) fails this test loudly
    // instead of hanging the whole suite — this is not the bound under test, just a backstop.
    let outcome = tokio::time::timeout(Duration::from_secs(40), ta.local_candidates(&sa)).await;
    let elapsed = started.elapsed();

    assert!(
        outcome.is_ok(),
        "local_candidates hung past the outer 40s test guard after {elapsed:?} — the \
         gather-and-connect flow is no longer bounded"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "local_candidates took {elapsed:?} to return — expected it to fail fast (bounded by \
         GATHER_TIMEOUT), not creep toward the outer test guard"
    );
    // Whether it errors outright or returns with no usable candidates, it must not silently
    // report success with a relay candidate that was never actually reachable.
    if let Ok(Ok(candidates)) = outcome {
        assert!(
            candidates.is_empty(),
            "gathered a candidate from a TURN server that never answered: {candidates:?}"
        );
    }

    drop(silent_turn);
}
