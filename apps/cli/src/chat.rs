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
//!
//! A first envelope from a peer this `ChatState` has never seen before is gated into a
//! segregated message-request state rather than delivered (task 2.10, system-design.md §3.5): see
//! `handle_inbound`'s `ChatError::MessageRequest` arm for the prompt and `answer_request` for the
//! accept/reject handling.
//!
//! (task 4.4) Every outbound `mrd.chat/1` text send also consults `meridian_core::trust`'s
//! un-softenable [`SendGate`]: a verified contact's key change hard-blocks sends (no bypass, only
//! re-verification clears it) and a pinned (TOFU) contact's blocks until the user explicitly
//! acknowledges the canonical warning — see `send_gated`. This CLI is the scriptable reference/demo
//! surface (`apps/cli/CLAUDE.md`), so it enforces the same invariant the TUI's modal (task 4.22)
//! will later present more richly, rather than only ever displaying it once that lands.

use meridian_core::chat::{ChatError, ChatState};
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{KeyHandle, SecretStore};
use meridian_core::signaling::{SignalingClient, DEFAULT_OTK_COUNT};
use meridian_core::trust::{SendGate, TrustStore};
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
    /// The peer id's `@domain` hint (task 2.7 wire plumbing): passed through to `fetch_bundle` so
    /// a cross-org peer's bundle is fetched via this server's federated path
    /// (system-design.md §3.3) rather than only ever looked up locally. This client still only
    /// ever dials `server` above — never `peer_hint` directly (the routing invariant).
    pub peer_hint: String,
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
        peer_hint,
        json,
    } = args;

    let mut state = load_state(store, handle)?;
    let mut trust = load_trust(store, handle)?;
    // TOFU-record (or just refresh) this contact so `can_send` below has something to consult.
    // Never itself a key-change signal — see `TrustStore::observe`'s doc for why a same-invocation
    // `peer_ik` can't organically surface one; that correlation has to come from a caller that
    // actually knows two keys are the same contact (`TrustStore::observe_key_change`), which this
    // single fixed-peer relay chat has no basis to invent on its own.
    trust.observe(peer_ik, &peer_hint, crate::now_unix());
    save_trust(&trust, store, handle)?;

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
    state.vault.set_bundle(
        generated.bundle.spk,
        *generated.spk_secret,
        otks,
        crate::now_unix(),
    );

    // Roles are decided by key order so two peers both running `chat` establish exactly one X3DH.
    // Only the initiator needs the peer's bundle; the responder derives everything from the
    // opening prekey message, so it just waits (avoiding a mutual fetch deadlock at startup).
    let initiator = account_pub.as_slice() <= peer_ik.as_slice();
    if initiator && !state.has_session(&peer_ik) {
        let peer_bundle = fetch_with_retry(&mut client, peer_ik, &peer_hint, &peer_label).await?;
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
    // Set while a message request from `peer_ik` is awaiting the user's accept/reject decision
    // (task 2.10, §3.5): the next typed line is read as the answer instead of chat text to send.
    let mut awaiting_request = false;
    // (task 4.4) Text held behind a live `SendGate::Warn` — the peer's key changed while pinned
    // (not yet verified) — plus whether the next typed line should be read as that warning's
    // acknowledge/decline answer instead of ordinary chat text. Mirrors `pending`/`awaiting_request`
    // above exactly, one gate lower in the same escalation.
    let mut pending_key_change_ack: Vec<String> = Vec::new();
    let mut awaiting_key_change_ack = false;

    loop {
        tokio::select! {
            maybe_line = rx.recv() => {
                match maybe_line {
                    Some(text) if text.trim().is_empty() => {}
                    Some(text) if awaiting_request => {
                        answer_request(&mut client, &mut state, &trust, store, handle, &account_pub, &peer_ik, &peer_hint, &peer_label, &text, json, &mut pending, &mut pending_key_change_ack, &mut awaiting_key_change_ack).await?;
                        awaiting_request = false;
                    }
                    Some(text) if awaiting_key_change_ack => {
                        answer_key_change_warning(&mut client, &mut state, &mut trust, store, handle, &account_pub, &peer_ik, &peer_hint, &peer_label, &text, json, &mut pending_key_change_ack, &mut awaiting_key_change_ack).await?;
                    }
                    Some(text) => {
                        if state.has_session(&peer_ik) {
                            send_gated(&mut client, &mut state, &trust, store, handle, &account_pub, &peer_ik, &peer_hint, &peer_label, vec![text], json, &mut pending_key_change_ack, &mut awaiting_key_change_ack).await?;
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
                handle_inbound(&mut client, &mut state, &trust, store, handle, &account_pub, &deliver, &peer_hint, &peer_label, json, &mut pending, &mut awaiting_request, &mut pending_key_change_ack, &mut awaiting_key_change_ack).await?;
            }
        }
        save_state(&state, store, handle)?;
        save_trust(&trust, store, handle)?;
    }

    save_state(&state, store, handle)?;
    save_trust(&trust, store, handle)?;
    let _ = client.close().await;
    Ok(())
}

/// Fetch + verify the peer's bundle, retrying while the peer has not published yet (`not_found`,
/// or the federated `not_found_at_hint` — task 2.7/2.9). A signature mismatch, a policy denial, or
/// an unreachable hint is still a hard, immediate failure (never a downgrade, never retried).
async fn fetch_with_retry(
    client: &mut SignalingClient,
    peer_ik: [u8; 32],
    peer_hint: &str,
    peer_label: &str,
) -> Result<meridian_core::proto::PrekeyBundle, String> {
    use meridian_core::signaling::SignalError;
    // Set once a `not_found_at_hint` (task 2.9) is observed, so the final message — if every
    // attempt exhausts — can name the reachability-specific outcome instead of the generic
    // "did not publish" text used for a purely local `not_found`.
    let mut stale_hint = false;
    for attempt in 0..40u32 {
        match client
            .fetch_bundle(peer_ik, Some(peer_hint.to_string()), false)
            .await
        {
            Ok(bundle) => return Ok(bundle),
            // "not_found" (local): no bundle here yet — retry, the peer may publish soon.
            Err(SignalError::Server(e)) if e.code == "not_found" => {
                stale_hint = false;
                if attempt == 0 {
                    eprintln!("waiting for {peer_label} to come online…");
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            // `not_found_at_hint` (task 2.7/2.9): the hinted org doesn't hold this account. From a
            // single response this is indistinguishable from "hasn't published there yet" and
            // "the hint is permanently stale" (e.g. the peer re-registered at a different org) —
            // retry the same bounded number of times as the local case, but if every attempt
            // exhausts this way, report the distinct "unreachable at hint" outcome below (never a
            // security warning: ADR 0001, docs/security/verification-ux.md).
            Err(SignalError::NotFoundAtHint { .. }) => {
                stale_hint = true;
                if attempt == 0 {
                    eprintln!("waiting for {peer_label} to come online at {peer_hint}…");
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            // `fed_denied`/`fed_unreachable` (and anything else): definitive policy/connectivity
            // outcomes, never retried — see `federation_error_line` for the distinct copy.
            Err(e) => return Err(federation_error_line(&e, peer_label, "fetching")),
        }
    }
    if stale_hint {
        Err(format!(
            "{peer_label} unreachable at hint {peer_hint}: no account found there after \
             retrying — the hint may be stale (the peer may have re-registered elsewhere); this \
             is a reachability issue, never a security warning"
        ))
    } else {
        Err(format!("{peer_label} did not publish a bundle in time"))
    }
}

/// Render a definitive (non-retried) fetch/route failure as one diagnosable line, keeping the
/// reachability-vs-policy-vs-security distinction visible in the copy itself (task 2.9, extended
/// to the routing path by task 2.15). `BundleVerification` falls through to the generic arm below,
/// which prefixes context but never rewords its canonical, un-softenable wording
/// (docs/security/verification-ux.md) — only `FedDenied`/`FedUnreachable` get bespoke,
/// reachability/policy-flavored copy here. `action` names the operation in the generic arm's
/// prefix (`"fetching"` for the bundle path, `"routing message to"` for the ongoing-chat path) so
/// one shared match doesn't misdescribe which call failed.
fn federation_error_line(
    e: &meridian_core::signaling::SignalError,
    peer_label: &str,
    action: &str,
) -> String {
    use meridian_core::signaling::SignalError;
    match e {
        SignalError::FedDenied { hint, detail } => format!(
            "federation denied: {hint} is not accepting requests for {peer_label} ({detail}) — \
             a policy outcome, not a security warning"
        ),
        SignalError::FedUnreachable { hint, detail } => format!(
            "{peer_label} unreachable at hint {hint}: could not reach that server ({detail})"
        ),
        other => format!("{action} {peer_label}: {other}"),
    }
}

/// Route a blob, treating a `not_connected` server reply as "not delivered" rather than a fatal
/// error: a momentarily-offline peer must not tear down the chat session (offline delivery is the
/// T07 mailbox). Other transport/server errors still propagate.
///
/// `hint` (task 2.15) is the peer's `@domain` routing hint — the same value already threaded into
/// `fetch_with_retry` — passed on every routed call (not just the initial bundle fetch) so an
/// ongoing chat with a cross-org peer actually reaches the federation path instead of the server
/// treating an absent hint as local-only (system-design.md §3.3 step 2, §3.4). A definitive
/// `FedDenied`/`FedUnreachable` surfaces through the same non-security-flavored copy the fetch path
/// already gets (`federation_error_line`), rather than collapsing into a generic string.
async fn route_tolerant(
    client: &mut SignalingClient,
    to: [u8; 32],
    hint: &str,
    blob: Vec<u8>,
    peer_label: &str,
) -> Result<bool, String> {
    use meridian_core::proto::error_codes::NOT_CONNECTED;
    use meridian_core::signaling::SignalError;
    match client
        .route_with_hint(to, Some(hint.to_string()), blob)
        .await
    {
        Ok(delivered) => Ok(delivered),
        Err(SignalError::Server(e)) if e.code == NOT_CONNECTED => Ok(false),
        Err(e) => Err(federation_error_line(&e, peer_label, "routing message to")),
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
    peer_hint: &str,
    peer_label: &str,
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
    let delivered = route_tolerant(client, *peer_ik, peer_hint, blob, peer_label).await?;
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

/// (task 4.4) Every outbound `mrd.chat/1` **text** send funnels through here — never straight to
/// [`send_text`] — so `meridian_core::trust`'s un-softenable [`SendGate`] is consulted before
/// anything is sealed/routed, no matter which call site (typed input, the post-accept/post-deliver
/// flush queue) is sending. Delivery receipts are not routed through this gate: they only ever
/// acknowledge content the user already decrypted and saw, so withholding them protects nothing an
/// attacker doesn't already have and would just break the protocol's own liveness.
///
/// - [`SendGate::Ok`]: sends every one of `texts`, in order, exactly as [`send_text`] always did.
/// - [`SendGate::Blocked`]: refuses **all** of `texts` — prints the canonical wording (never a
///   silent drop) and sends nothing. No path here — or anywhere in this file — can send past a
///   `Blocked` gate; the only way out is a genuine re-verification
///   (`meridian_core::trust::TrustStore::mark_verified`), which this CLI does not yet expose a
///   command for (out of scope here — the safety-number/QR verify flow is a separate task), so a
///   `Blocked` contact simply cannot be messaged by this binary until that lands.
/// - [`SendGate::Warn`]: prints the canonical wording and holds `texts` in `held` pending the next
///   typed line's accept/decline (see `answer_key_change_warning`) — "blocking-until-acknowledged"
///   per verification-ux.md, not a full interactive Verify flow (4.22's TUI modal owns that), but
///   never a silent pass-through either.
#[allow(clippy::too_many_arguments)]
async fn send_gated(
    client: &mut SignalingClient,
    state: &mut ChatState,
    trust: &TrustStore,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    account_pub: &[u8; 32],
    peer_ik: &[u8; 32],
    peer_hint: &str,
    peer_label: &str,
    texts: Vec<String>,
    json: bool,
    held: &mut Vec<String>,
    awaiting_ack: &mut bool,
) -> Result<(), String> {
    if texts.is_empty() {
        return Ok(());
    }
    match trust.can_send(peer_ik) {
        SendGate::Ok => {
            for text in texts {
                send_text(
                    client,
                    state,
                    store,
                    handle,
                    account_pub,
                    peer_ik,
                    peer_hint,
                    peer_label,
                    &text,
                    json,
                )
                .await?;
            }
            Ok(())
        }
        SendGate::Blocked(reason) => {
            print_gate_line("blocked", &reason, texts.len(), peer_label, json);
            // `texts` is intentionally dropped here, not queued: verification-ux.md is explicit
            // this is a hard stop, and re-queuing would just be a slower-motion bypass (send it
            // later, once nobody's looking) of the same invariant.
            Ok(())
        }
        SendGate::Warn(reason) => {
            // Print once per new hold, not once per already-held message piling up behind it.
            if !*awaiting_ack {
                print_gate_line("warning", &reason, texts.len(), peer_label, json);
            }
            held.extend(texts);
            *awaiting_ack = true;
            Ok(())
        }
    }
}

/// Shared `Blocked`/`Warn` line(s), in both `--json` and plain modes — factored out (and kept pure,
/// unlike most of this file) so the CLI can never present one without the other (both call sites in
/// [`send_gated`] must go through this) and so the "the canonical `reason` text always ends up
/// somewhere the user sees it, never swallowed" property is unit-testable without a live network
/// (see the `tests` module below).
fn gate_lines(
    kind: &str,
    reason: &str,
    held_count: usize,
    peer_label: &str,
    json: bool,
) -> Vec<String> {
    if json {
        vec![format!(
            "{{\"event\":\"key_change_{kind}\",\"from\":{},\"reason\":{},\"held\":{held_count}}}",
            json_string(peer_label),
            json_string(reason)
        )]
    } else {
        let mut lines = vec![format!("! {reason}")];
        if kind == "warning" {
            lines.push(format!(
                "  type 'y' to acknowledge and send ({held_count} message(s) held), anything else cancels them:"
            ));
        }
        lines
    }
}

fn print_gate_line(kind: &str, reason: &str, held_count: usize, peer_label: &str, json: bool) {
    for line in gate_lines(kind, reason, held_count, peer_label, json) {
        println!("{line}");
    }
}

/// (task 4.4) Handle the user's typed answer to a live `SendGate::Warn` prompt (mirrors
/// `answer_request`'s accept/reject pattern exactly, one gate lower): `y`/`yes` (case-insensitive)
/// acknowledges via [`TrustStore::acknowledge_key_change`] — which re-pins the contact's new key
/// **without** a safety-number compare, exactly as verification-ux.md specifies for the pinned
/// case — and then flushes every held message through [`send_gated`] again (now reading `Ok`).
/// Anything else declines: the held messages are discarded, and the contact stays gated (the next
/// send attempt re-prompts).
///
/// `held`/`awaiting_ack` are the **same** state the caller's main loop reads (never fresh, throwaway
/// locals for the post-ack flush): [`send_gated`]'s re-check after acknowledging is expected to
/// read `Ok` (nothing else mutates `trust` between the `acknowledge_key_change` call just above it
/// and that re-check, both on this single-threaded event loop), but if it somehow didn't — a future
/// change, a race this code doesn't anticipate — a message must re-arm the *real* prompt state
/// rather than being silently captured in a local that is dropped when this function returns. This
/// function therefore fully owns `*awaiting_ack` (the caller no longer resets it unconditionally).
#[allow(clippy::too_many_arguments)]
async fn answer_key_change_warning(
    client: &mut SignalingClient,
    state: &mut ChatState,
    trust: &mut TrustStore,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    account_pub: &[u8; 32],
    peer_ik: &[u8; 32],
    peer_hint: &str,
    peer_label: &str,
    answer: &str,
    json: bool,
    held: &mut Vec<String>,
    awaiting_ack: &mut bool,
) -> Result<(), String> {
    let ack = matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    let queued = std::mem::take(held);
    *awaiting_ack = false;
    if ack {
        // `TrustError::NotAcknowledgeable` here would mean the gate is no longer `PinnedKeyChanged`
        // (e.g. it escalated to `Blocked` under our feet, or was already acknowledged) — surface it
        // rather than silently dropping the held messages either way.
        trust
            .acknowledge_key_change(peer_ik)
            .map_err(|e| format!("acknowledging key change for {peer_label}: {e}"))?;
        if json {
            println!(
                "{{\"event\":\"key_change_acknowledged\",\"from\":{}}}",
                json_string(peer_label)
            );
        } else {
            println!(
                "(acknowledged — {peer_label}'s new key is re-pinned; re-verify when you can)"
            );
        }
        // Re-check through the real `held`/`awaiting_ack` state, not a throwaway local: `can_send`
        // is expected to read `Ok` now, but if it somehow doesn't, the held text must land back in
        // the state the main loop actually reads next, not be silently dropped.
        send_gated(
            client,
            state,
            trust,
            store,
            handle,
            account_pub,
            peer_ik,
            peer_hint,
            peer_label,
            queued,
            json,
            held,
            awaiting_ack,
        )
        .await?;
    } else {
        if json {
            println!(
                "{{\"event\":\"key_change_declined\",\"from\":{},\"discarded\":{}}}",
                json_string(peer_label),
                queued.len()
            );
        } else {
            println!(
                "(not sent — key-change warning for {peer_label} was not acknowledged; {} \
                 message(s) discarded)",
                queued.len()
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_inbound(
    client: &mut SignalingClient,
    state: &mut ChatState,
    trust: &TrustStore,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    account_pub: &[u8; 32],
    deliver: &meridian_core::proto::Deliver,
    peer_hint: &str,
    peer_label: &str,
    json: bool,
    pending: &mut Vec<String>,
    awaiting_request: &mut bool,
    pending_key_change_ack: &mut Vec<String>,
    awaiting_key_change_ack: &mut bool,
) -> Result<(), String> {
    // Retire a superseded prekey generation whose grace window has passed *before* consulting the
    // vault, so 1.31's reconnect-race allowance stays time-bounded in a long-running process rather
    // than lasting until the next republish. Expiry is enforced here, at the point of use, because
    // `meridian-core` is clock-free (wasm32) — see `crate::now_unix`.
    state.vault.expire_previous_generation(crate::now_unix());

    match state.open_inbound(
        store,
        handle,
        account_pub,
        &deliver.from,
        deliver.blob.as_bytes(),
    ) {
        Ok(content) => {
            deliver_content(
                client,
                state,
                trust,
                store,
                handle,
                account_pub,
                &deliver.from,
                peer_hint,
                peer_label,
                json,
                pending,
                pending_key_change_ack,
                awaiting_key_change_ack,
                content,
            )
            .await
        }
        // First contact from `peer_label` (task 2.10, §3.5): landed in the segregated
        // message-request state instead of being delivered — see `ChatState::open_inbound`'s gate.
        // The demo script's prompt (docs/architecture/features/06-cross-org-federation.md):
        // "message request from mrd1:<alice>… — accept? y".
        Err(ChatError::MessageRequest) => {
            let req = state
                .pending_request(&deliver.from)
                .expect("open_inbound just inserted this request");
            if json {
                println!(
                    "{{\"event\":\"message_request\",\"from\":{},\"safety_number\":{}}}",
                    json_string(peer_label),
                    json_string(&req.safety_number)
                );
            } else {
                println!("message request from {peer_label} — accept? y/n");
                println!(
                    "  safety number: {}",
                    meridian_core::crypto::display_groups(&req.safety_number)
                );
            }
            *awaiting_request = true;
            Ok(())
        }
        // Already gated: refused, never merged into the pending request (task 2.10 deliverable).
        Err(ChatError::RequestPending) => {
            if json {
                println!("{{\"event\":\"rejected\",\"reason\":\"pending message request\"}}");
            }
            Ok(())
        }
        Err(e) => {
            // A bad/forged envelope is dropped, loudly, never trusted.
            if json {
                println!("{{\"event\":\"rejected\",\"reason\":\"{e}\"}}");
            } else {
                eprintln!("! rejected an envelope from {peer_label}: {e}");
            }
            Ok(())
        }
    }
}

/// Present a decoded [`ChatContent`] exactly the same way whether it arrived as an ordinary
/// delivery or as the `intro` of a just-accepted [`meridian_core::chat::MessageRequest`] (task
/// 2.10) — factored out so both paths share one behavior (receipt + flushing buffered outgoing
/// text) rather than drifting apart.
#[allow(clippy::too_many_arguments)]
async fn deliver_content(
    client: &mut SignalingClient,
    state: &mut ChatState,
    trust: &TrustStore,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    account_pub: &[u8; 32],
    from: &[u8; 32],
    peer_hint: &str,
    peer_label: &str,
    json: bool,
    pending: &mut Vec<String>,
    pending_key_change_ack: &mut Vec<String>,
    awaiting_key_change_ack: &mut bool,
    content: ChatContent,
) -> Result<(), String> {
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
            // Auto-acknowledge with a delivery receipt. Never gated by `SendGate` (task 4.4's
            // `send_gated` doc comment): a receipt only acknowledges content the user already
            // decrypted and saw, so withholding it protects nothing.
            let receipt = state
                .seal_outbound(
                    store,
                    handle,
                    account_pub,
                    from,
                    &ChatContent::Receipt { ack: id },
                )
                .map_err(|e| format!("sealing receipt: {e}"))?;
            let _ = route_tolerant(client, *from, peer_hint, receipt, peer_label).await?;

            // Session is now live (or newly accepted) — flush anything typed early, gated exactly
            // like ordinary typed input (task 4.4): `send_gated` decides Ok/Warn/Blocked itself.
            let queued = std::mem::take(pending);
            send_gated(
                client,
                state,
                trust,
                store,
                handle,
                account_pub,
                from,
                peer_hint,
                peer_label,
                queued,
                json,
                pending_key_change_ack,
                awaiting_key_change_ack,
            )
            .await?;
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

/// Handle the user's typed answer to a pending message-request prompt (task 2.10): `y`/`yes`
/// (case-insensitive) accepts, anything else rejects. Accepting delivers the held intro exactly
/// like an ordinary message; rejecting is silent (see [`ChatState::reject_request`]'s doc comment
/// on why nothing is sent back to the sender).
#[allow(clippy::too_many_arguments)]
async fn answer_request(
    client: &mut SignalingClient,
    state: &mut ChatState,
    trust: &TrustStore,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    account_pub: &[u8; 32],
    peer_ik: &[u8; 32],
    peer_hint: &str,
    peer_label: &str,
    answer: &str,
    json: bool,
    pending: &mut Vec<String>,
    pending_key_change_ack: &mut Vec<String>,
    awaiting_key_change_ack: &mut bool,
) -> Result<(), String> {
    let accept = matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    if accept {
        if let Some(req) = state.accept_request(peer_ik) {
            if json {
                println!(
                    "{{\"event\":\"request_accepted\",\"from\":{}}}",
                    json_string(peer_label)
                );
            } else {
                println!("(accepted — now chatting with {peer_label})");
            }
            deliver_content(
                client,
                state,
                trust,
                store,
                handle,
                account_pub,
                peer_ik,
                peer_hint,
                peer_label,
                json,
                pending,
                pending_key_change_ack,
                awaiting_key_change_ack,
                req.intro,
            )
            .await?;
        }
    } else {
        state.reject_request(peer_ik);
        if json {
            println!(
                "{{\"event\":\"request_rejected\",\"from\":{}}}",
                json_string(peer_label)
            );
        } else {
            println!("(rejected — {peer_label} will need to be accepted again to reach you)");
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

/// (task 4.4) Load the sealed [`TrustStore`] alongside `load_state`'s `ChatState` — same
/// missing-file-means-fresh-store / any-other-error-is-fatal shape, same fail-closed-on-tamper
/// behavior (`TrustStore::open_at_rest`'s doc: ADR 0021 condition 5b — a corrupt/wrong-key blob
/// must never be silently reinitialized, since that would erase key-change/pinned-key history).
fn load_trust(store: &dyn SecretStore, handle: &KeyHandle) -> Result<TrustStore, String> {
    let path = account::trust_path()?;
    match std::fs::read(&path) {
        Ok(sealed) => TrustStore::open_at_rest(store, handle, &sealed)
            .map_err(|e| format!("opening trust store {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TrustStore::default()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

/// Mirrors `save_state` exactly.
fn save_trust(
    trust: &TrustStore,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), String> {
    let path = account::trust_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let sealed = trust
        .seal_at_rest(store, handle)
        .map_err(|e| format!("sealing trust store: {e}"))?;
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

#[cfg(test)]
mod tests {
    //! (task 4.4) Unit coverage for `gate_lines` — the pure core of the CLI's key-change gate
    //! surfacing. `send_gated`/`answer_key_change_warning` themselves need a live
    //! `SignalingClient`/network to exercise end to end (covered instead by `meridian-core`'s
    //! `key_change_gate` integration tests, which drive the same `SendGate`/`TrustStore` this file
    //! merely consults); what belongs here is the CLI-specific property that the canonical `reason`
    //! text always ends up in what gets printed, in both output modes, and is never dropped.
    use super::*;

    const REASON: &str = "The safety number for bob@org-b.test has changed. \
        This can happen if they reinstalled or switched devices — but it can also mean someone is \
        intercepting your messages. Sends to bob@org-b.test are blocked until you verify the new \
        safety number with them through a channel you trust.";

    #[test]
    fn blocked_plain_mode_surfaces_the_full_canonical_reason_and_no_ack_prompt() {
        let lines = gate_lines("blocked", REASON, 2, "bob@org-b.test", false);
        assert_eq!(lines.len(), 1, "Blocked never offers an acknowledge prompt");
        assert!(
            lines[0].contains(REASON),
            "the canonical reason must be surfaced verbatim, never summarized/softened: {lines:?}"
        );
    }

    #[test]
    fn blocked_json_mode_carries_the_full_reason_and_event_name() {
        let lines = gate_lines("blocked", REASON, 3, "bob@org-b.test", true);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"event\":\"key_change_blocked\""));
        assert!(lines[0].contains("\"held\":3"));
        assert!(lines[0].contains(&json_string(REASON)));
    }

    #[test]
    fn warn_plain_mode_surfaces_the_reason_and_an_explicit_acknowledge_prompt() {
        let lines = gate_lines("warning", REASON, 1, "bob@org-b.test", false);
        assert_eq!(
            lines.len(),
            2,
            "Warn must show the reason AND an explicit prompt — never a silent hold"
        );
        assert!(lines[0].contains(REASON));
        assert!(
            lines[1].to_lowercase().contains("acknowledge"),
            "must make the pending decision explicit: {lines:?}"
        );
    }

    #[test]
    fn warn_json_mode_carries_the_full_reason_and_event_name() {
        let lines = gate_lines("warning", REASON, 1, "bob@org-b.test", true);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"event\":\"key_change_warning\""));
        assert!(lines[0].contains(&json_string(REASON)));
    }

    #[test]
    fn neither_mode_ever_drops_the_reason_text() {
        for json in [false, true] {
            for kind in ["blocked", "warning"] {
                let lines = gate_lines(kind, REASON, 0, "bob@org-b.test", json);
                let joined = lines.join("\n");
                assert!(
                    joined.contains(REASON) || joined.contains(&json_string(REASON)),
                    "kind={kind} json={json} dropped the canonical reason: {lines:?}"
                );
            }
        }
    }
}
