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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ice_restart_keeps_the_live_channel_flowing() {
    let (ta, sa, tb, sb) = connect_pair().await;
    let ca = ta
        .add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.chat/1"))
        .await
        .unwrap();
    let cb = tb
        .add_data_channel(&sb, ChannelCfg::reliable_ordered("mrd.chat/1"))
        .await
        .unwrap();

    ta.send(&sa, &ca, b"before restart").await.unwrap();
    assert_eq!(tb.recv(&sb).await.unwrap().unwrap().1, b"before restart");

    // A real local ICE-transport restart on both sides (see webrtc_backend module docs for why
    // this is local-only) must not tear down the live data channel.
    ta.ice_restart(&sa).await.unwrap();
    tb.ice_restart(&sb).await.unwrap();

    tb.send(&sb, &cb, b"after restart").await.unwrap();
    assert_eq!(ta.recv(&sa).await.unwrap().unwrap().1, b"after restart");
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
