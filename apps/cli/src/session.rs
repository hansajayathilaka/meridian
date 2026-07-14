//! `meridian session demo` — the T04 acceptance demo, runnable from the terminal
//! (docs/architecture/features/04-p2p-session-substrate.md "Working output").
//!
//! The headline is "servers out of the data path": this drives two in-process peers over the
//! deterministic `LoopbackTransport`, establishes a direct session with DTLS-fingerprint binding,
//! then **drops the signaling relay** ("kill the server mid-conversation") and shows chat continuing
//! over the data channel — printing the same `session info` line the spec's demo script does.
//!
//! Cross-process P2P over real NATs is the webrtc-rs backend (feature-gated in `meridian-transport`)
//! and is exercised by `tools/netns-two-lans.sh`; this in-process demo proves the substrate logic
//! deterministically without a network.

use std::sync::Arc;

use meridian_core::chat::ChatState;
use meridian_core::identity::{generate_account, AccountId, KeyHandle, MemorySecretStore};
use meridian_core::proto::ChatContent;
use meridian_core::session::{answer, dial, MemRelay, SessionEvent};
use meridian_core::signaling::generate_bundle;
use meridian_core::streams::StreamRegistry;
use meridian_core::transport::{LoopbackFabric, LoopbackTransport};

struct DemoPeer {
    store: MemorySecretStore,
    account: AccountId,
    chat: ChatState,
}

impl DemoPeer {
    fn new(hint: &str) -> Self {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, hint).expect("account");
        Self {
            store,
            account,
            chat: ChatState::default(),
        }
    }
    fn ik(&self) -> [u8; 32] {
        *self.account.public_key().as_bytes()
    }
    fn handle(&self) -> KeyHandle {
        self.account.handle().clone()
    }
}

/// Run the in-process P2P demo, returning the printed lines (also returned so the acceptance test
/// can assert on them).
pub async fn run_demo(json: bool) -> Result<Vec<String>, String> {
    let mut alice = DemoPeer::new("chat.a");
    let mut bob = DemoPeer::new("chat.b");
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    // T03 ratchet: Bob publishes a bundle, Alice starts an initiator session against it.
    let bundle =
        generate_bundle(&bob.store, &bob.handle(), bob_ik, 5).map_err(|e| e.to_string())?;
    let otks: Vec<([u8; 32], [u8; 32])> = bundle
        .bundle
        .otks
        .iter()
        .zip(bundle.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    bob.chat
        .vault
        .set_bundle(bundle.bundle.spk, *bundle.spk_secret, otks);
    alice
        .chat
        .start_initiator_session(
            &alice.store,
            &alice.handle(),
            &alice_ik,
            &bob_ik,
            &bundle.bundle.spk,
            bundle.bundle.otks.first().copied(),
        )
        .map_err(|e| e.to_string())?;

    // One fabric = one LAN; a MemRelay = the rendezvous, which we drop after connecting.
    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));
    let (mut relay_a, mut relay_b) = MemRelay::pair(alice_ik, bob_ik);

    let (astore, ahandle) = (&alice.store, alice.handle());
    let (bstore, bhandle) = (&bob.store, bob.handle());

    let (ra, rb) = {
        let achat = &mut alice.chat;
        let bchat = &mut bob.chat;
        tokio::join!(
            dial(
                ta.clone(),
                astore,
                &ahandle,
                alice_ik,
                bob_ik,
                achat,
                &mut relay_a,
                Arc::new(StreamRegistry::with_builtins()),
            ),
            answer(
                tb.clone(),
                bstore,
                &bhandle,
                bob_ik,
                alice_ik,
                bchat,
                &mut relay_b,
                Arc::new(StreamRegistry::with_builtins()),
            ),
        )
    };
    let mut asess = ra.map_err(|e| format!("dial: {e}"))?;
    let mut bsess = rb.map_err(|e| format!("answer: {e}"))?;

    // Kill the server: drop the signaling relay. Everything below is peer-to-peer.
    drop(relay_a);
    drop(relay_b);

    let mut lines = Vec::new();
    let path = asess.info().await.path;
    let candidate_class = if path == meridian_core::transport::Path::Relay {
        "relay"
    } else {
        "host"
    };
    lines.push(format!(
        "[session] ICE: {path} ({candidate_class}) — P2P established, DTLS fp verified \u{2714}"
    ));
    lines.push("[session] rendezvous stopped — chat continues over the data channel:".to_string());

    // Alice → Bob, then Bob → Alice, entirely over the data channel.
    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "hello over p2p")
        .await
        .map_err(|e| e.to_string())?;
    if let Some(SessionEvent::Chat(ChatContent::Text { body, .. })) = bsess
        .pump(&bob.store, &bhandle, &mut bob.chat)
        .await
        .map_err(|e| e.to_string())?
    {
        lines.push(format!("  [alice \u{2192} bob] {body}"));
    }
    bsess
        .send_chat(
            &bob.store,
            &bhandle,
            &mut bob.chat,
            "hi back — no server in the path",
        )
        .await
        .map_err(|e| e.to_string())?;
    if let Some(SessionEvent::Chat(ChatContent::Text { body, .. })) = asess
        .pump(&alice.store, &ahandle, &mut alice.chat)
        .await
        .map_err(|e| e.to_string())?
    {
        lines.push(format!("  [bob \u{2192} alice] {body}"));
    }

    // Measure a keepalive RTT over ctrl (both sides pumping), then print the `session info` line.
    let (ping, _) = {
        let a = asess.ping(&alice.store, &ahandle, &mut alice.chat);
        let b = bsess.pump(&bob.store, &bhandle, &mut bob.chat);
        tokio::join!(a, b)
    };
    let _ = ping.map_err(|e| e.to_string())?;

    lines.push(asess.info().await.to_string());

    if json {
        println!("{{\"event\":\"p2p_demo\",\"established\":true,\"server_dropped\":true}}");
    } else {
        for l in &lines {
            println!("{l}");
        }
    }
    Ok(lines)
}
