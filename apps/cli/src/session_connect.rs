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
//!
//! Real TURN is wired for real (task 1.25's coturn + `meridian-rendezvous` ephemeral-credential
//! minting): before dialing, this always asks the still-open signaling connection for a fresh
//! [`meridian_core::proto::TurnGrant`] via `request_turn_credentials`. A successful grant feeds a
//! real `IceServer` into the ICE config under the peer's *resolved* policy
//! (`direct`/`prefer-relay`/`relay-only` all actually work now); a `turn_unavailable` mint failure
//! only degrades to a host/srflx-only attempt under `direct` — `prefer-relay`/`relay-only` still
//! fail closed rather than silently connecting without relay, which would hand host/srflx
//! candidates to the peer despite the user having asked for those to stay hidden (defeating the
//! whole point of `config set policy relay-only`).

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
    use meridian_core::proto::error_codes;
    use meridian_core::relay;
    use meridian_core::session::{answer_with_config, dial_with_config, SessionEvent};
    use meridian_core::signal_relay::RendezvousRelay;
    use meridian_core::signaling::{SignalError, SignalingClient, DEFAULT_OTK_COUNT};
    use meridian_core::streams::StreamRegistry;
    use meridian_core::transport::{IcePolicy, IceServer, WebRtcTransport};

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

    // Resolve the configured relay policy for this peer up front — it decides both what a TURN
    // mint failure means below and what policy the ICE config ultimately gathers under.
    let resolved_policy = crate::policy::load()?.resolve(&peer_ik);

    let mut chat = ChatState::default();

    let mut client = SignalingClient::connect(&server, store, handle, account_pub, None, 1)
        .await
        .map_err(|e| format!("connecting to {server}: {e}"))?;

    // Always attempt to mint a real ephemeral TURN credential while the signaling connection is
    // still open (T05, §5.4) — this is the real bug fix over 1.24: that version hardcoded an empty
    // `ice_servers` list regardless of policy, so any cell that genuinely needs relay (symmetric
    // NAT, UDP-blocked egress) could never connect even under the default `direct` policy, which
    // gathers host+srflx+relay and prefers whichever is fastest.
    let ice_servers: Vec<IceServer> = match client.request_turn_credentials().await {
        Ok(grant) => vec![IceServer {
            urls: grant.urls,
            username: Some(grant.username),
            credential: Some(grant.credential),
        }],
        // No relay is configured on this org's rendezvous (dev/air-gapped). `direct` degrades to a
        // host/srflx-only attempt, same as before any relay existed. `prefer-relay`/`relay-only`
        // still fail closed — the whole point of those policies is relay availability, so silently
        // proceeding without one would expose host/srflx candidates the user explicitly asked to
        // keep hidden.
        Err(SignalError::Server(e)) if e.code == error_codes::TURN_UNAVAILABLE => {
            if resolved_policy != IcePolicy::Direct {
                return Err(format!(
                    "no TURN relay is configured on {server} (turn_unavailable), but the \
                     configured policy for {peer_label} is {} — refusing to silently connect \
                     without relay, which would expose host/srflx candidates to the peer",
                    meridian_core::relay::policy_str(resolved_policy)
                ));
            }
            Vec::new()
        }
        // Any other failure while requesting TURN credentials (auth, transport, codec, …) is
        // unexpected — fail loud rather than silently proceeding without relay under any policy.
        Err(e) => {
            return Err(format!("requesting TURN credentials from {server}: {e}"));
        }
    };

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
    // The resolved policy plus whatever TURN servers were minted above — `dial_with_config`/
    // `answer_with_config`/`WebRtcTransport` already handle gathering and relay fallback for
    // whichever candidate classes this allows (T05's ladder), nothing else changes here.
    let cfg = relay::ice_config(resolved_policy, ice_servers, Vec::new());

    let mut session = {
        let mut adapter = RendezvousRelay::new(&mut client);
        if initiator {
            dial_with_config(
                transport,
                store,
                handle,
                account_pub,
                peer_ik,
                &mut chat,
                &mut adapter,
                registry,
                cfg,
            )
            .await
            .map_err(|e| format!("dial: {e}"))?
        } else {
            answer_with_config(
                transport,
                store,
                handle,
                account_pub,
                peer_ik,
                &mut chat,
                &mut adapter,
                registry,
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
