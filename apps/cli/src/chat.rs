//! `meridian chat <id>` — a 1:1 E2EE chat relayed through the rendezvous (T03).
//!
//! This is the client event loop: it publishes a fresh prekey bundle (so the peer can reach us),
//! fetches+verifies the peer's bundle, establishes/loads the ratchet session, and then relays
//! signed, ratchet-encrypted [`mrd.chat/1`](meridian_core::envelope::ChatContent) envelopes as opaque
//! blobs. All the crypto lives in `meridian-core`; this file is orchestration + terminal I/O.
//!
//! Roles are decided deterministically (the lexicographically-smaller identity key initiates) so
//! that two peers both typing `meridian chat <other>` establish exactly one X3DH session rather
//! than racing two. The non-initiator buffers typed lines until the opening message arrives.
//!
//! Session state (ratchet + prekey vault) is sealed at rest under a keystore-derived key and
//! reloaded on restart, so a killed client resumes mid-ratchet with no re-handshake.

use meridian_core::chat::ChatState;
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{KeyHandle, SecretStore};
use meridian_core::signaling::{SignalingClient, DEFAULT_OTK_COUNT};
use tokio::sync::mpsc;

use crate::account;

/// Everything `cmd_chat` gathers before entering the async loop.
pub struct ChatArgs<'a> {
    pub server: String,
    pub store: &'a dyn SecretStore,
    pub handle: &'a KeyHandle,
    pub account_pub: [u8; 32],
    pub peer_ik: [u8; 32],
    pub peer_label: String,
    pub json: bool,
}

pub async fn run(args: ChatArgs<'_>) -> Result<(), String> {
    let ChatArgs {
        server,
        store,
        handle,
        account_pub,
        peer_ik,
        peer_label,
        json,
    } = args;

    let mut state = load_state(store, handle)?;

    let mut client = SignalingClient::connect(&server, store, handle, account_pub, None, 1)
        .await
        .map_err(|e| format!("connecting to {server}: {e}"))?;

    // Publish a fresh bundle so the peer can reach us, and record the matching prekey secrets.
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
    state
        .vault
        .set_bundle(generated.bundle.spk, *generated.spk_secret, otks);

    // Roles are decided by key order so two peers both running `chat` establish exactly one X3DH.
    // Only the initiator needs the peer's bundle; the responder derives everything from the
    // opening prekey message, so it just waits (avoiding a mutual fetch deadlock at startup).
    let initiator = account_pub.as_slice() <= peer_ik.as_slice();
    if initiator && !state.has_session(&peer_ik) {
        let peer_bundle = fetch_with_retry(&mut client, peer_ik, &peer_label).await?;
        state
            .start_initiator_session(
                store,
                handle,
                &account_pub,
                &peer_ik,
                &peer_bundle.spk,
                peer_bundle.otks.first().copied(),
            )
            .map_err(|e| format!("establishing session: {e}"))?;
    }
    save_state(&state, store, handle)?;

    banner(&peer_label, &state, &account_pub, &peer_ik, initiator, json);

    // Read stdin lines on a blocking thread, forwarding them into the async loop.
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut pending: Vec<String> = Vec::new();

    loop {
        tokio::select! {
            maybe_line = rx.recv() => {
                match maybe_line {
                    Some(text) if text.trim().is_empty() => {}
                    Some(text) => {
                        if state.has_session(&peer_ik) {
                            send_text(&mut client, &mut state, store, handle, &account_pub, &peer_ik, &text, json).await?;
                        } else {
                            pending.push(text);
                            if !json {
                                println!("(waiting for {peer_label} to open the session…)");
                            }
                        }
                    }
                    None => break, // stdin closed
                }
            }
            delivered = client.next_deliver() => {
                let deliver = delivered.map_err(|e| format!("receiving: {e}"))?;
                handle_inbound(&mut client, &mut state, store, handle, &account_pub, &deliver, &peer_label, json, &mut pending).await?;
            }
        }
        save_state(&state, store, handle)?;
    }

    save_state(&state, store, handle)?;
    let _ = client.close().await;
    Ok(())
}

/// Fetch + verify the peer's bundle, retrying while the peer has not published yet (`not_found`).
/// A signature mismatch is still a hard, immediate failure (never a downgrade).
async fn fetch_with_retry(
    client: &mut SignalingClient,
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

/// Route a blob, treating a `not_connected` server reply as "not delivered" rather than a fatal
/// error: a momentarily-offline peer must not tear down the chat session (offline delivery is the
/// T07 mailbox). Other transport/server errors still propagate.
async fn route_tolerant(
    client: &mut SignalingClient,
    to: [u8; 32],
    blob: Vec<u8>,
) -> Result<bool, String> {
    use meridian_core::proto::error_codes::NOT_CONNECTED;
    use meridian_core::signaling::SignalError;
    match client.route(to, blob).await {
        Ok(delivered) => Ok(delivered),
        Err(SignalError::Server(e)) if e.code == NOT_CONNECTED => Ok(false),
        Err(e) => Err(format!("routing message: {e}")),
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_text(
    client: &mut SignalingClient,
    state: &mut ChatState,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    account_pub: &[u8; 32],
    peer_ik: &[u8; 32],
    text: &str,
    json: bool,
) -> Result<(), String> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|e| e.to_string())?;
    let blob = state
        .seal_outbound(
            store,
            handle,
            account_pub,
            peer_ik,
            &ChatContent::Text {
                id,
                body: text.to_string(),
            },
        )
        .map_err(|e| format!("sealing message: {e}"))?;
    let delivered = route_tolerant(client, *peer_ik, blob).await?;
    if json {
        println!(
            "{{\"event\":\"sent\",\"id\":\"{}\",\"delivered\":{}}}",
            hex::encode(id),
            delivered
        );
    } else if delivered {
        println!("[you] {text}");
    } else {
        println!("[you] {text}  (peer offline — not delivered; mailbox is T07)");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_inbound(
    client: &mut SignalingClient,
    state: &mut ChatState,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    account_pub: &[u8; 32],
    deliver: &meridian_core::proto::Deliver,
    peer_label: &str,
    json: bool,
    pending: &mut Vec<String>,
) -> Result<(), String> {
    let content = match state.open_inbound(
        store,
        handle,
        account_pub,
        &deliver.from,
        deliver.blob.as_bytes(),
    ) {
        Ok(c) => c,
        Err(e) => {
            // A bad/forged envelope is dropped, loudly, never trusted.
            if json {
                println!("{{\"event\":\"rejected\",\"reason\":\"{e}\"}}");
            } else {
                eprintln!("! rejected an envelope from {peer_label}: {e}");
            }
            return Ok(());
        }
    };

    match content {
        ChatContent::Text { id, body } => {
            if json {
                println!(
                    "{{\"event\":\"recv\",\"id\":\"{}\",\"body\":{}}}",
                    hex::encode(id),
                    json_string(&body)
                );
            } else {
                println!("[{peer_label}] {body}");
            }
            // Auto-acknowledge with a delivery receipt.
            let receipt = state
                .seal_outbound(
                    store,
                    handle,
                    account_pub,
                    &deliver.from,
                    &ChatContent::Receipt { ack: id },
                )
                .map_err(|e| format!("sealing receipt: {e}"))?;
            let _ = route_tolerant(client, deliver.from, receipt).await?;

            // Session is now live for a former non-initiator — flush anything they typed early.
            let queued = std::mem::take(pending);
            for text in queued {
                send_text(
                    client,
                    state,
                    store,
                    handle,
                    account_pub,
                    &deliver.from,
                    &text,
                    json,
                )
                .await?;
            }
        }
        ChatContent::Receipt { ack } => {
            if json {
                println!("{{\"event\":\"receipt\",\"ack\":\"{}\"}}", hex::encode(ack));
            } else {
                println!("  ✓ delivered {}", &hex::encode(ack)[..8]);
            }
        }
    }
    Ok(())
}

fn banner(
    peer_label: &str,
    state: &ChatState,
    account_pub: &[u8; 32],
    peer_ik: &[u8; 32],
    initiator: bool,
    json: bool,
) {
    if json {
        return;
    }
    println!("— E2EE chat with {peer_label} —");
    if let Some(sn) = state.safety_number(account_pub, peer_ik) {
        println!(
            "  safety number: {}",
            meridian_core::crypto::display_groups(&sn)
        );
    }
    if initiator {
        println!("  (type a message and press enter; Ctrl-D to quit)");
    } else {
        println!("  (waiting for the first message; you can start typing — it will send once the session opens)");
    }
}

fn load_state(store: &dyn SecretStore, handle: &KeyHandle) -> Result<ChatState, String> {
    let path = account::sessions_path()?;
    match std::fs::read(&path) {
        Ok(sealed) => ChatState::open_at_rest(store, handle, &sealed)
            .map_err(|e| format!("opening session store {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ChatState::default()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

fn save_state(
    state: &ChatState,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), String> {
    let path = account::sessions_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let sealed = state
        .seal_at_rest(store, handle)
        .map_err(|e| format!("sealing session store: {e}"))?;
    std::fs::write(&path, sealed).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Minimal JSON string escaping for `--json` output (bodies can contain quotes/backslashes).
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
