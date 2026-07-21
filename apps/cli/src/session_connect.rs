//! `meridian session connect <peer-id>` (1.24) — establish a **real** P2P session between two
//! separate OS processes over the real rendezvous, the cross-process counterpart to `session
//! demo`'s single-process simulation (`LoopbackTransport`'s fabric is in-process only, so it can
//! never prove two real processes — let alone two network namespaces, 1.26 — can actually connect).
//!
//! Mirrors `chat.rs`'s connect/publish-bundle/fetch-peer-bundle/role-by-key-order setup, but calls
//! `dial_with_config`/`answer_with_config` (T04's session substrate) instead of relaying chat
//! envelopes. The signaling connection is dropped once the P2P session is up — T04's "servers out
//! of the data path" property, now proven over a real socket rather than in-process channels.
//!
//! `--transport loopback` is rejected outright: there is no cross-process loopback mode.

use meridian_core::identity::{KeyHandle, SecretStore};

use crate::TransportArg;

/// Everything `cmd_session_connect` gathers before entering the async connect flow. Every field
/// besides `transport` is only read by [`run_webrtc`] (behind the `webrtc` feature); without that
/// feature `run` rejects the command before touching them.
#[cfg_attr(not(feature = "webrtc"), allow(dead_code))]
pub struct ConnectArgs<'a> {
    pub server: String,
    pub store: &'a dyn SecretStore,
    pub handle: &'a KeyHandle,
    pub account_pub: [u8; 32],
    pub peer_ik: [u8; 32],
    pub peer_label: String,
    pub transport: TransportArg,
    pub json: bool,
}

pub async fn run(args: ConnectArgs<'_>) -> Result<(), String> {
    if args.transport == TransportArg::Loopback {
        return Err(
            "session connect requires a real transport; --transport loopback cannot rendezvous \
             across two processes (LoopbackTransport's fabric is in-process only) — use \
             --transport webrtc"
                .to_string(),
        );
    }

    #[cfg(feature = "webrtc")]
    {
        run_webrtc(args).await
    }
    #[cfg(not(feature = "webrtc"))]
    {
        let _ = args;
        Err(
            "meridian-cli was built without the `webrtc` feature; rebuild with `--features \
             webrtc` to use `session connect`"
                .to_string(),
        )
    }
}

#[cfg(feature = "webrtc")]
async fn run_webrtc(args: ConnectArgs<'_>) -> Result<(), String> {
    use std::sync::Arc;

    use meridian_core::chat::ChatState;
    use meridian_core::envelope::ChatContent;
    use meridian_core::relay;
    use meridian_core::session::{answer_with_config, dial_with_config, SessionEvent};
    use meridian_core::signal_relay::RendezvousRelay;
    use meridian_core::signaling::{SignalingClient, DEFAULT_OTK_COUNT};
    use meridian_core::streams::StreamRegistry;
    use meridian_core::transport::{IcePolicy, WebRtcTransport};

    let ConnectArgs {
        server,
        store,
        handle,
        account_pub,
        peer_ik,
        peer_label,
        transport: _,
        json,
    } = args;

    let mut chat = ChatState::default();

    let mut client = SignalingClient::connect(&server, store, handle, account_pub, None, 1)
        .await
        .map_err(|e| format!("connecting to {server}: {e}"))?;

    // Publish a fresh bundle so the peer can reach us (needed regardless of role: the initiator
    // fetches it to X3DH against; the responder needs its own spk/otk secrets in the vault so the
    // offer's prekey message can establish the responder ratchet session).
    let generated = client
        .publish_bundle(store, handle, DEFAULT_OTK_COUNT)
        .await
        .map_err(|e| format!("publishing bundle: {e}"))?;
    let otks: Vec<([u8; 32], [u8; 32])> = generated
        .bundle
        .otks
        .iter()
        .zip(generated.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    chat.vault
        .set_bundle(generated.bundle.spk, *generated.spk_secret, otks);

    // Roles are decided by key order so two peers both running `session connect` settle on exactly
    // one dialer without racing (mirrors chat.rs).
    let initiator = account_pub.as_slice() <= peer_ik.as_slice();
    if initiator {
        let peer_bundle = fetch_with_retry(&mut client, peer_ik, &peer_label).await?;
        chat.start_initiator_session(
            store,
            handle,
            &account_pub,
            &peer_ik,
            &peer_bundle.spk,
            peer_bundle.otks.first().copied(),
        )
        .map_err(|e| format!("establishing session: {e}"))?;
    }

    let transport = Arc::new(WebRtcTransport::new());
    let registry = Arc::new(StreamRegistry::with_builtins());
    // Localhost, direct policy: real ICE/STUN discovers the host pair without any TURN relay.
    let cfg = relay::ice_config(IcePolicy::Direct, Vec::new(), Vec::new());

    let mut session = {
        let mut adapter = RendezvousRelay::new(&mut client);
        if initiator {
            dial_with_config(
                transport, store, handle, account_pub, peer_ik, &mut chat, &mut adapter, registry,
                cfg,
            )
            .await
            .map_err(|e| format!("dial: {e}"))?
        } else {
            answer_with_config(
                transport, store, handle, account_pub, peer_ik, &mut chat, &mut adapter, registry,
                cfg,
            )
            .await
            .map_err(|e| format!("answer: {e}"))?
        }
    };

    // T04's "servers out of the data path" property — now proven over a real socket: the
    // rendezvous connection is no longer needed once the P2P session is up.
    let _ = client.close().await;

    let role_label = if initiator { "initiator" } else { "responder" };
    let mut lines = Vec::new();
    let info = session.info().await;
    lines.push(format!(
        "[session] path={} — P2P established, DTLS fp verified \u{2714}",
        info.path
    ));

    // One chat message each way over the re-homed data channel, mirroring `session demo`'s
    // headline: the initiator sends first, the responder receives then replies, so both processes
    // have something concrete printed to assert on.
    if initiator {
        session
            .send_chat(store, handle, &mut chat, "hello over p2p")
            .await
            .map_err(|e| e.to_string())?;
        lines.push("[chat] sent: hello over p2p".to_string());
        if let Some(SessionEvent::Chat(ChatContent::Text { body, .. })) = session
            .pump(store, handle, &mut chat)
            .await
            .map_err(|e| e.to_string())?
        {
            lines.push(format!("[chat] recv: {body}"));
        }
    } else {
        if let Some(SessionEvent::Chat(ChatContent::Text { body, .. })) = session
            .pump(store, handle, &mut chat)
            .await
            .map_err(|e| e.to_string())?
        {
            lines.push(format!("[chat] recv: {body}"));
        }
        session
            .send_chat(store, handle, &mut chat, "hi back — no server in the path")
            .await
            .map_err(|e| e.to_string())?;
        lines.push("[chat] sent: hi back — no server in the path".to_string());
    }

    let info = session.info().await;
    lines.push(info.to_string());

    if json {
        println!(
            "{{\"event\":\"p2p_connect\",\"role\":\"{role_label}\",\"peer\":{},\"established\":true,\"transport\":\"{}\",\"path\":\"{}\"}}",
            json_string(&peer_label),
            info.transport,
            info.path,
        );
    } else {
        println!("— P2P session with {peer_label} ({role_label}) —");
        for l in &lines {
            println!("{l}");
        }
    }

    let _ = session.close().await;
    Ok(())
}

/// Fetch + verify the peer's bundle, retrying while the peer has not published yet (`not_found`).
/// A signature mismatch is still a hard, immediate failure (never a downgrade) — mirrors
/// `chat.rs::fetch_with_retry`.
#[cfg(feature = "webrtc")]
async fn fetch_with_retry(
    client: &mut meridian_core::signaling::SignalingClient,
    peer_ik: [u8; 32],
    peer_label: &str,
) -> Result<meridian_core::proto::PrekeyBundle, String> {
    use meridian_core::signaling::SignalError;
    for attempt in 0..40u32 {
        match client.fetch_bundle(peer_ik, false).await {
            Ok(bundle) => return Ok(bundle),
            Err(SignalError::Server(e)) if e.code == "not_found" => {
                if attempt == 0 {
                    eprintln!("waiting for {peer_label} to come online…");
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(e) => return Err(format!("fetching {peer_label}: {e}")),
        }
    }
    Err(format!("{peer_label} did not publish a bundle in time"))
}

/// Minimal JSON string escaping (bodies/labels can contain quotes/backslashes) — mirrors
/// `chat.rs::json_string`.
#[cfg(feature = "webrtc")]
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
