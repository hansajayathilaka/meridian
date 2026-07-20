//! Gated integration coverage for [`WebRtcTransport`] — real ICE/SCTP/DTLS between two peers on
//! localhost, mirroring `loopback.rs`'s unit tests but over the production backend (1.15, F10
//! backend). `cargo nextest run -p meridian-transport --features webrtc`.

#![cfg(feature = "webrtc")]

use std::sync::Arc;
use std::time::Duration;

use meridian_transport::{ChannelCfg, IceConfig, SessionHandle, Transport, WebRtcTransport};

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
