//! `meridian session demo` — the T04/T05 acceptance demo, runnable from the terminal
//! (docs/architecture/features/04-p2p-session-substrate.md and
//! docs/architecture/features/05-nat-traversal-relay-policy.md "Working output").
//!
//! The T04 headline is "servers out of the data path": two in-process peers over the deterministic
//! `LoopbackTransport` establish a session with DTLS-fingerprint binding, then the signaling relay
//! is **dropped** and chat continues over the data channel.
//!
//! T05 layers the **relay policy** and **NAT ladder** on top: `--nat` picks a simulated NAT/egress
//! cell (full-cone, port-restricted, symmetric:symmetric, udp-blocked) and `--policy` picks the
//! `direct | prefer-relay | relay-only` knob, so the same demo prints the spec's path lines —
//! `path=relay (turn-a, udp)` on symmetric NAT, `path=relay (turn-a, tls-443)` when UDP is dropped,
//! and, under `relay-only`, proof that host/srflx candidates were never offered.
//!
//! Cross-process P2P over real NATs is the webrtc-rs backend (feature-gated in `meridian-transport`)
//! and is exercised by `tools/netns-nat-matrix.sh`; this in-process demo proves the substrate logic
//! deterministically without a network.

use std::sync::Arc;

use meridian_core::chat::ChatState;
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{generate_account, AccountId, KeyHandle, MemorySecretStore};
use meridian_core::relay;
use meridian_core::session::{
    answer_with_config, dial_with_config, MemRelay, P2pSession, SessionEvent,
};
use meridian_core::signaling::generate_bundle;
use meridian_core::streams::StreamRegistry;
use meridian_core::transport::{
    IcePolicy, IceServer, LoopbackFabric, LoopbackTransport, NatScenario, Transport,
};
#[cfg(feature = "webrtc")]
use meridian_core::transport::WebRtcTransport;

use crate::TransportArg;

pub(crate) struct DemoPeer {
    pub store: MemorySecretStore,
    account: AccountId,
    pub chat: ChatState,
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
    pub fn handle(&self) -> KeyHandle {
        self.account.handle().clone()
    }
}

/// The illustrative ephemeral TURN grant a `meridian chat` session would receive from the rendezvous
/// (`request_turn_credentials`). The demo fabricates it so the substrate logic is exercised without
/// a live server; server-side minting is covered by the rendezvous integration tests. `turn-a` is
/// the label `session info` prints for the relay.
pub(crate) fn demo_ice_servers() -> Vec<IceServer> {
    vec![IceServer {
        urls: vec![
            "turn:turn-a:3478?transport=udp".into(),
            "turn:turn-a:3478?transport=tcp".into(),
            "turns:turn-a:443?transport=tcp".into(),
        ],
        username: Some("1700000000:demo".into()),
        credential: Some("demo-hmac".into()),
    }]
}

/// Establish a live P2P session between two fresh peers over an already-built transport pair, under
/// `policy`, with the given TURN servers. Returns both live sessions plus the peers (whose
/// stores/handles the caller needs to pump chat). Does everything `connect`/`connect_webrtc` need
/// *except* building the transports themselves — the X3DH/bundle setup and dial/answer plumbing is
/// identical regardless of which `Transport` backend is in play.
async fn establish<T: Transport>(
    ta: Arc<T>,
    tb: Arc<T>,
    policy: IcePolicy,
    ice_servers: Vec<IceServer>,
) -> Result<(P2pSession<T>, P2pSession<T>, DemoPeer, DemoPeer), String> {
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

    let (mut relay_a, mut relay_b) = MemRelay::pair(alice_ik, bob_ik);

    let cfg_a = relay::ice_config(policy, ice_servers.clone(), Vec::new());
    let cfg_b = relay::ice_config(policy, ice_servers, Vec::new());

    let (ahandle, bhandle) = (alice.handle(), bob.handle());
    let (ra, rb) = {
        let achat = &mut alice.chat;
        let bchat = &mut bob.chat;
        tokio::join!(
            dial_with_config(
                ta,
                &alice.store,
                &ahandle,
                alice_ik,
                bob_ik,
                achat,
                &mut relay_a,
                Arc::new(StreamRegistry::with_builtins()),
                cfg_a,
            ),
            answer_with_config(
                tb,
                &bob.store,
                &bhandle,
                bob_ik,
                alice_ik,
                bchat,
                &mut relay_b,
                Arc::new(StreamRegistry::with_builtins()),
                cfg_b,
            ),
        )
    };
    let asess = ra.map_err(|e| format!("dial: {e}"))?;
    let bsess = rb.map_err(|e| format!("answer: {e}"))?;
    // Signaling relay dropped here: the session is now server-independent.
    Ok((asess, bsess, alice, bob))
}

/// Establish a live P2P session between two fresh peers over `scenario`, under `policy`, with the
/// given TURN servers, using the deterministic `LoopbackTransport`. Shared by the demo and
/// `meridian doctor`.
pub(crate) async fn connect(
    scenario: NatScenario,
    policy: IcePolicy,
    ice_servers: Vec<IceServer>,
) -> Result<
    (
        P2pSession<LoopbackTransport>,
        P2pSession<LoopbackTransport>,
        DemoPeer,
        DemoPeer,
    ),
    String,
> {
    // Both peers live on the same simulated network (`scenario`); each gathers under `policy`.
    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::with_scenario(fabric.clone(), scenario));
    let tb = Arc::new(LoopbackTransport::with_scenario(fabric.clone(), scenario));
    establish(ta, tb, policy, ice_servers).await
}

/// Establish a live P2P session between two fresh peers over the real `WebRtcTransport` backend
/// (real ICE/SCTP/DTLS on localhost, 1.15). There is no NAT simulation for a real transport — callers
/// must not pass a non-default `scenario`; `run_demo` enforces this before calling in.
#[cfg(feature = "webrtc")]
pub(crate) async fn connect_webrtc(
    policy: IcePolicy,
    ice_servers: Vec<IceServer>,
) -> Result<
    (
        P2pSession<WebRtcTransport>,
        P2pSession<WebRtcTransport>,
        DemoPeer,
        DemoPeer,
    ),
    String,
> {
    let ta = Arc::new(WebRtcTransport::new());
    let tb = Arc::new(WebRtcTransport::new());
    establish(ta, tb, policy, ice_servers).await
}

/// Options for the relay-policy demo.
pub(crate) struct DemoOpts {
    pub json: bool,
    pub policy: IcePolicy,
    pub scenario: NatScenario,
    pub transport: TransportArg,
}

/// Run the in-process P2P demo, returning the printed lines (also returned so the acceptance test
/// can assert on them). Dispatches on `opts.transport`: `Loopback` uses the deterministic simulation
/// (and honors `--nat`/`--policy`); `Webrtc` uses the real backend behind the `webrtc` cargo feature,
/// and — because there is no NAT simulation for a real transport and the demo's fabricated TURN
/// servers only mean anything to `LoopbackTransport`'s simulation — rejects a non-default `--nat` or a
/// non-`direct` `--policy` up front rather than silently ignoring them or hanging trying to reach a
/// fake TURN host.
pub async fn run_demo(opts: DemoOpts) -> Result<Vec<String>, String> {
    match opts.transport {
        TransportArg::Loopback => {
            let (asess, bsess, alice, bob) =
                connect(opts.scenario, opts.policy, demo_ice_servers()).await?;
            run_demo_generic(asess, bsess, alice, bob, &opts).await
        }
        TransportArg::Webrtc => {
            if opts.scenario != NatScenario::default() {
                return Err(format!(
                    "--transport webrtc has no NAT simulation (--nat {} is meaningless for a real \
                     transport); drop --nat or use --transport loopback",
                    opts.scenario.label()
                ));
            }
            if opts.policy != IcePolicy::Direct {
                return Err(
                    "--transport webrtc only supports --policy direct today: the demo's TURN \
                     servers are fabricated for LoopbackTransport's simulation and a real \
                     WebRtcTransport would try to actually reach them; real TURN support lands in \
                     1.23"
                        .to_string(),
                );
            }
            #[cfg(feature = "webrtc")]
            {
                let (asess, bsess, alice, bob) =
                    connect_webrtc(opts.policy, demo_ice_servers()).await?;
                run_demo_generic(asess, bsess, alice, bob, &opts).await
            }
            #[cfg(not(feature = "webrtc"))]
            {
                Err("meridian-cli was built without the `webrtc` feature; rebuild with \
                     `--features webrtc` to use `--transport webrtc`"
                    .to_string())
            }
        }
    }
}

/// The printed-output logic shared by every `Transport` backend: identical for `LoopbackTransport`
/// and `WebRtcTransport`, including the `transport=...` line (via `SessionInfo`'s `Display`), so the
/// same acceptance assertions hold regardless of which backend produced the session.
async fn run_demo_generic<T: Transport>(
    mut asess: P2pSession<T>,
    mut bsess: P2pSession<T>,
    alice: DemoPeer,
    bob: DemoPeer,
    opts: &DemoOpts,
) -> Result<Vec<String>, String> {
    let (ahandle, bhandle) = (alice.handle(), bob.handle());
    let mut alice = alice;
    let mut bob = bob;

    let mut lines = Vec::new();
    let info = asess.info().await;
    lines.push(format!(
        "[session] path={} — P2P established, DTLS fp verified \u{2714}",
        info_path(&info)
    ));
    lines.push(format!(
        "[session] nat={} policy={} — rendezvous stopped, chat continues over the data channel:",
        opts.scenario.label(),
        relay::policy_str(opts.policy),
    ));

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

    let info = asess.info().await;
    // Under relay-only, print the privacy claim the demo must *show*: the peer never saw our IPs.
    if opts.policy == IcePolicy::RelayOnly {
        lines.push(format!("[session] {}", info.candidates_offered_line()));
    }
    lines.push(info.to_string());

    if opts.json {
        println!(
            "{{\"event\":\"p2p_demo\",\"established\":true,\"server_dropped\":true,\"path\":\"{}\",\"policy\":\"{}\",\"nat\":\"{}\"}}",
            info.path,
            relay::policy_str(opts.policy),
            opts.scenario.label(),
        );
    } else {
        for l in &lines {
            println!("{l}");
        }
    }
    Ok(lines)
}

/// Render the path with relay detail for the headline line, e.g. `relay (turn-a, tls-443)`.
fn info_path(info: &meridian_core::session::SessionInfo) -> String {
    match (&info.relay_server, info.relay_transport) {
        (Some(srv), Some(xport)) => format!("{} ({srv}, {xport})", info.path),
        _ => info.path.to_string(),
    }
}
