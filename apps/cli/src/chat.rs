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
//! accept/reject handling. (task 4.7) Accepting is also where this gate meets `meridian-core`'s
//! trust module: `answer_request` TOFU-pins the sender as a real `Contact` and offers an inline
//! petname, while rejecting touches `trust` not at all — see `run`'s deferred-pin comment for why
//! the ordinary early-`observe` call below does not itself pin an as-yet-undecided first contact.
//!
//! (task 4.4) Every outbound `mrd.chat/1` text send also consults `meridian_core::trust`'s
//! un-softenable [`SendGate`]: a verified contact's key change hard-blocks sends (no bypass, only
//! re-verification clears it) and a pinned (TOFU) contact's blocks until the user explicitly
//! acknowledges the canonical warning — see `send_gated`. This CLI is the scriptable reference/demo
//! surface (`apps/cli/CLAUDE.md`), so it enforces the same invariant the TUI's modal (task 4.22)
//! will later present more richly, rather than only ever displaying it once that lands.
//!
//! (task 4.9) On *repeated* `ChatError::Desync` from a peer, `handle_inbound` may hand off to
//! `maybe_attempt_recovery`: gated first by `trust`'s `can_send` (never automatically re-handshaking
//! a peer with an unresolved key change), it then re-fetches that peer's bundle and forces a fresh
//! session via `meridian_core::chat::ChatState::replace_session_as_initiator` /
//! `meridian_core::desync::attempt_recovery` — the receiver-side half task 1.18 deferred to this
//! feature. See `docs/api/messaging-envelope-v1.md` §3 "Desync recovery" for the full guarded design.

use meridian_core::chat::{ChatError, ChatState, SPK_ROTATION_INTERVAL_SECS};
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{KeyHandle, SecretStore};
use meridian_core::signaling::{SignalingClient, DEFAULT_OTK_COUNT};
use meridian_core::trust::{SendGate, TrustStore};
use tokio::sync::mpsc;

use crate::account;

/// How often `run`'s main loop checks whether the current SPK generation needs rotating (task 6.2,
/// ADR 0016 C1/R1). Mirrors `apps/tui/src/worker.rs::SPK_ROTATION_CHECK_INTERVAL_SECS` exactly —
/// same reasoning (`SPK_ROTATION_INTERVAL_SECS` is week-scale, so hourly polling is generous
/// headroom without checking on every typed line or inbound envelope) — but implemented separately
/// per this task's own scope: `meridian-cli` and `meridian-tui` are separate crates with no shared
/// "long-running client loop" module to hang one common implementation off, so this is genuinely new
/// work in both, not a shared change.
const SPK_ROTATION_CHECK_INTERVAL_SECS: u64 = 3600;

/// Mirrors `apps/tui/src/worker.rs::SPK_ROTATION_WARN_GRACE_MULTIPLE` exactly — see that constant's
/// own doc comment for the reasoning.
const SPK_ROTATION_WARN_GRACE_MULTIPLE: u64 = 2;

/// Outcome of one [`rotate_spk_if_due`] call — exists so tests can assert exactly what happened,
/// mirroring `apps/tui/src/worker.rs::SpkRotationOutcome` (kept as a separate type per this file's
/// own scope, not shared — see [`SPK_ROTATION_CHECK_INTERVAL_SECS`]'s doc comment).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SpkRotationOutcome {
    /// The generation was not yet due for rotation at the checked `now_unix` — no republish
    /// attempted.
    NotDue,
    /// The generation was due and the republish succeeded — `state.vault` now carries a fresh
    /// publish timestamp; `run`'s own post-select `save_state` call persists it exactly like any
    /// other in-loop mutation of `state`.
    Rotated,
    /// The generation was due but the republish itself failed (e.g. an unreachable server). Per
    /// this task's fail-open decision (see `docs/tasks/phase-6/6.2-spk-rotation-enforcement.md`'s
    /// Outcome section), `state.vault` is left exactly as it was and the stale generation is kept in
    /// service — logged, never propagated as a hard error that would tear the chat session down.
    RotationFailed(String),
}

/// The enforcement step `run`'s periodic tick calls (task 6.2): checks
/// `state.vault.rotation_due` against `now_unix` and, if due, republishes a fresh bundle.
///
/// **Deliberately opens its own short-lived connection to `server`** rather than reusing `run`'s
/// own persistent `client` — mirrors `apps/tui/src/worker.rs::republish_bundle`'s identical choice.
/// A second, independent connection alongside the primary one is not a new risk: the rendezvous
/// server already supports multiple simultaneous connections per account (`apps/rendezvous/src/
/// state.rs`'s own multi-device connection list, "a routed envelope is pushed to all of them") — a
/// fresh connection here costs one extra handshake roughly once a week (whenever the generation is
/// actually due), which is negligible, and keeps this function testable the same proven way
/// `republish_bundle`'s own unreachable-server test already is, without needing to force a failure
/// on `run`'s live, already-open connection mid-loop (that connection's `close()` takes `self` by
/// value, so it cannot be "broken and later reused" from inside a running loop anyway).
///
/// **Never calls `SystemTime::now()` itself** — `now_unix` is an explicit argument, mirroring
/// `PrekeyVault::rotation_due`/`generation_age_secs`'s own deliberately clock-free, caller-supplies-
/// time design (`apps/core/src/chat.rs`, task 6.1) — so tests drive this with a fake clock, no real
/// waiting involved.
pub(crate) async fn rotate_spk_if_due(
    server: &str,
    state: &mut ChatState,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    account_pub: [u8; 32],
    now_unix: u64,
) -> SpkRotationOutcome {
    if !state.vault.rotation_due(now_unix) {
        return SpkRotationOutcome::NotDue;
    }

    warn_if_spk_overdue(state.vault.generation_age_secs(now_unix));

    let mut client =
        match SignalingClient::connect(server, store, handle, account_pub, None, 1).await {
            Ok(client) => client,
            Err(e) => {
                let message = format!("connecting to {server}: {e}");
                eprintln!(
                    "meridian chat: SPK rotation republish failed, continuing with the stale \
                 generation (fail-open — see task 6.2's Outcome section): {message}"
                );
                return SpkRotationOutcome::RotationFailed(message);
            }
        };
    let result = client
        .publish_bundle(store, handle, DEFAULT_OTK_COUNT)
        .await;
    let _ = client.close().await;

    match result {
        Ok(generated) => {
            let otks: Vec<([u8; 32], [u8; 32])> = generated
                .bundle
                .otks
                .iter()
                .zip(generated.otk_secrets.iter())
                .map(|(p, s)| (*p, **s))
                .collect();
            state
                .vault
                .set_bundle(generated.bundle.spk, *generated.spk_secret, otks, now_unix);
            SpkRotationOutcome::Rotated
        }
        Err(e) => {
            let message = e.to_string();
            eprintln!(
                "meridian chat: SPK rotation republish failed, continuing with the stale \
                 generation (fail-open — see task 6.2's Outcome section): {message}"
            );
            SpkRotationOutcome::RotationFailed(message)
        }
    }
}

/// Logs an escalating warning once `age` is past [`SPK_ROTATION_WARN_GRACE_MULTIPLE`] ×
/// `SPK_ROTATION_INTERVAL_SECS` — mirrors `apps/tui/src/worker.rs::warn_if_spk_overdue` exactly,
/// including the `age = None` "always warn" case (see that function's own doc comment for why).
fn warn_if_spk_overdue(age: Option<u64>) {
    let warn_threshold =
        SPK_ROTATION_INTERVAL_SECS.saturating_mul(SPK_ROTATION_WARN_GRACE_MULTIPLE);
    match age {
        None => {
            eprintln!(
                "meridian chat: SPK generation age is unknown (never published, or a session \
                 sealed before task 6.1) and due for rotation — continuing with the current key \
                 (fail-open) while a republish is attempted"
            );
        }
        Some(age) if age >= warn_threshold => {
            let multiples = age / SPK_ROTATION_INTERVAL_SECS;
            eprintln!(
                "meridian chat: SPK generation is {multiples}x overdue for rotation (age {age}s, \
                 target {SPK_ROTATION_INTERVAL_SECS}s) — continuing with the stale key (fail-open) \
                 while a republish is attempted"
            );
        }
        Some(_) => {}
    }
}

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
    // Roles are decided by key order so two peers both running `chat` establish exactly one X3DH,
    // independent of who types first (moved up from below so the TOFU-pin decision just below can
    // read it too).
    let initiator = account_pub.as_slice() <= peer_ik.as_slice();
    // (task 4.7) TOFU-record (or just refresh) this contact so `can_send` below has something to
    // consult — but only when this side already has a basis to want this contact pinned: it's the
    // initiator (deliberately reaching out to `peer_ik`, same posture as `contact add`) or a
    // session with `peer_ik` already exists **and there is no still-undecided `MessageRequest`
    // for it**. `state.has_session(&peer_ik)` alone is NOT sufficient to rule out an undecided
    // first-contact request: `ChatState::open_inbound_gated` installs the responder's ratchet
    // session as a side effect of processing the first prekey envelope *before* deciding whether
    // to gate it into `pending_requests` (`apps/core/src/chat.rs`'s `open_bytes`/
    // `open_inbound_gated`), so a session can already exist for a peer whose request the user has
    // not yet answered. Without the `pending_request(&peer_ik).is_none()` check, restarting this
    // process while a request sits undecided would silently TOFU-pin the sender on the next
    // invocation's startup — the exact premature-pin bug this task exists to close, just moved
    // from "first invocation" to "process restart before a decision" (found by this task's
    // required review, reproduced, and fixed here rather than deferred).
    // A responder with no session yet is the more common case that can land a still-gated
    // first-contact `MessageRequest` (task 2.10, `handle_inbound`'s `ChatError::MessageRequest`
    // arm): pinning here, before the user has even seen the intro and safety number, would
    // TOFU-pin a `Contact` regardless of what the user later decides, defeating
    // `reject_request`'s "no trace" guarantee (task 4.7's actual gap — see `answer_request`, which
    // owns the deferred pin for both cases). Never itself a key-change signal — see
    // `TrustStore::observe`'s doc for why a same-invocation `peer_ik` can't organically surface one;
    // that correlation has to come from a caller that actually knows two keys are the same contact
    // (`TrustStore::observe_key_change`), which this single fixed-peer relay chat has no basis to
    // invent on its own.
    if initiator || (state.has_session(&peer_ik) && state.pending_request(&peer_ik).is_none()) {
        trust.observe(peer_ik, &peer_hint, crate::now_unix());
        save_trust(&trust, store, handle)?;
    }

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

    // Only the initiator (role decided above) needs the peer's bundle; the responder derives
    // everything from the opening prekey message, so it just waits (avoiding a mutual fetch
    // deadlock at startup).
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

    // Task 6.2: the debounced periodic SPK-rotation check — a `tokio::time::interval_at` created
    // once, outside the loop below, so this is a real recurring wake independent of stdin/inbound
    // traffic (a session sitting fully idle for a week — no typed lines, no inbound envelopes —
    // would otherwise never re-enter `tokio::select!` at all, and so never get a chance to rotate).
    // Deliberately `interval_at` with a first deadline one full period out, not plain
    // `tokio::time::interval` (whose first `tick()` resolves immediately): an immediate first check
    // would mean every `chat` invocation pays a check (and, whenever `rotation_due` happens to read
    // `true` right at startup, a full republish) on top of the bundle `run` already just published
    // moments earlier — exactly the over-triggering this task's own file warns against.
    // `MissedTickBehavior::Delay` (not the default `Burst`): a week-scale staleness check has no
    // "catch up" obligation after a stall; one prompt check once this loop is live again is what's
    // wanted, never a burst of them.
    let mut rotation_tick = tokio::time::interval_at(
        tokio::time::Instant::now()
            + std::time::Duration::from_secs(SPK_ROTATION_CHECK_INTERVAL_SECS),
        std::time::Duration::from_secs(SPK_ROTATION_CHECK_INTERVAL_SECS),
    );
    rotation_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            maybe_line = rx.recv() => {
                match maybe_line {
                    Some(text) if text.trim().is_empty() => {}
                    Some(text) if awaiting_request => {
                        answer_request(&mut client, &mut state, &mut trust, store, handle, &account_pub, &peer_ik, &peer_hint, &peer_label, &text, json, &mut pending, &mut pending_key_change_ack, &mut awaiting_key_change_ack).await?;
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
                handle_inbound(&mut client, &mut state, &mut trust, store, handle, &account_pub, &deliver, &peer_hint, &peer_label, json, &mut pending, &mut awaiting_request, &mut pending_key_change_ack, &mut awaiting_key_change_ack).await?;
            }
            _ = rotation_tick.tick() => {
                // Fire-and-forget, like every other best-effort call this loop already makes
                // (`route_tolerant`'s own `let _ = ...` sends): a not-due or failed check must never
                // interrupt ordinary chat handling — `rotate_spk_if_due` already logs any failure.
                let _ = rotate_spk_if_due(&server, &mut state, store, handle, account_pub, crate::now_unix()).await;
            }
        }
        save_state(&state, store, handle)?;
        save_trust(&trust, store, handle)?;
        // (task 8.8, ADR 0024) Flush any mailbox row id `client.next_deliver()` accumulated this
        // iteration — never before `save_state` above has durably persisted whatever this
        // delivery's `handle_inbound` call mutated. `?` on `save_state`/`save_trust` above already
        // ends this loop before reaching here on a write failure, so an ack is only ever sent once
        // processing genuinely made it to disk — matches
        // `apps/tui/src/worker.rs::process_inbound_delivery`'s identical `persisted`-gated
        // reasoning. A no-op (no network I/O) on every iteration that wasn't a `next_deliver`
        // branch, or that delivered a live (non-mailbox) envelope — best-effort like every other
        // network call in this loop (`route_tolerant`'s own pattern): a failed ack just means the
        // row gets redrained (and harmlessly re-processed, per `eid` dedup) on the next reconnect.
        let _ = client.ack_pending_mailbox().await;
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
    trust: &mut TrustStore,
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
    // `meridian-core` is clock-free (wasm32) — see `crate::now_unix`. Goes through `ChatState`'s own
    // wrapper (task 4.9 second-round fixup), not `state.vault` directly, so the
    // `responder_session_ek` freshness history is pruned in lockstep with the vault's own generation
    // retirement.
    state.expire_previous_generation(crate::now_unix());

    // (task 8.8, review finding 1 — blocking) `deliver.from` is the wire value ChatState's own
    // sender check consumes, but it is NOT the real peer identity for a mailbox-drained push: it
    // is always `MAILBOX_DRAIN_FROM_PLACEHOLDER`. Everything below that treats "the sender" as an
    // identity — the message-request lookup, `deliver_content`'s display/routing target, and
    // `maybe_attempt_recovery`'s peer gating — needs the REAL sender, or (as verified: this used
    // to panic on `pending_request(&deliver.from).expect(...)` for a mailbox-drained first
    // contact, and crash the whole process via `seal_outbound`'s unguarded `?` on `NoSession` for
    // a mailbox-drained continuation message from an existing session) this misbehaves outright.
    // `effective_from` is the real identity: for a mailbox-drained delivery, `envelope.sender_pub`,
    // read via the same cheap, non-cryptographic parse `open_bytes`/`open_inbound_gated` already
    // perform on their own copy of `blob` — safe to read before authentication succeeds for
    // exactly the reason `open_inbound_gated`'s own early decode is safe (see that method's doc
    // comment): it can only affect map lookups and routing here, never a state mutation, since
    // nothing commits before `open_inbound_from_mailbox`'s own successful AEAD decrypt. A blob too
    // malformed to parse falls back to `deliver.from` — harmless, since `open_inbound_from_mailbox`
    // will independently fail to decode it too, landing in the catch-all `Err(e)` arm below, which
    // never uses `effective_from`.
    let effective_from = if deliver.mailbox_id.is_some() {
        meridian_core::envelope::MessageEnvelope::from_blob(deliver.blob.as_bytes())
            .map(|env| env.sender_pub)
            .unwrap_or(deliver.from)
    } else {
        deliver.from
    };

    // (task 8.8, ADR 0024) A mailbox-drained push (`mailbox_id.is_some()`, task 8.7) carries the
    // `[0u8; 32]` `from` placeholder, never a real routing-layer identity —
    // `open_inbound_from_mailbox` authenticates via `envelope.sender_pub` alone instead of
    // comparing against it. Every live/federated-live delivery (`mailbox_id: None`) keeps going
    // through the ordinary `open_inbound`, unchanged. This call still passes the literal
    // `deliver.from` (the placeholder, on a mailbox-drained push) — not `effective_from` — since
    // that parameter is the wire value the sender-mismatch check itself reasons about (and
    // ignores, on this path); `effective_from` is for every OTHER use of "the peer's identity"
    // below.
    let open_result = if deliver.mailbox_id.is_some() {
        state.open_inbound_from_mailbox(
            store,
            handle,
            account_pub,
            &deliver.from,
            deliver.blob.as_bytes(),
        )
    } else {
        state.open_inbound(
            store,
            handle,
            account_pub,
            &deliver.from,
            deliver.blob.as_bytes(),
        )
    };
    match open_result {
        Ok(content) => {
            deliver_content(
                client,
                state,
                trust,
                store,
                handle,
                account_pub,
                &effective_from,
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
                .pending_request(&effective_from)
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
        // (task 4.9) A ratchet desync. Still dropped exactly like any other rejection — see
        // `ChatError::Desync`'s doc comment — but repeated occurrences from the same peer may now
        // trigger the guarded receiver-side recovery below.
        Err(e @ ChatError::Desync) => {
            if json {
                println!("{{\"event\":\"rejected\",\"reason\":\"{e}\"}}");
            } else {
                eprintln!("! rejected an envelope from {peer_label}: {e}");
            }
            maybe_attempt_recovery(
                client,
                state,
                trust,
                store,
                handle,
                account_pub,
                &effective_from,
                peer_hint,
                peer_label,
                json,
            )
            .await
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

/// (task 4.9) Consult `meridian_core::chat::ChatState::recovery_recommended` after a `Desync`
/// classification and, only once the repeated-Desync threshold is crossed, attempt the guarded
/// receiver-side re-handshake — mirroring `fetch_with_retry`/`start_initiator_session`'s existing
/// pattern for original first contact, but through `ChatState::replace_session_as_initiator` via
/// `meridian_core::desync::attempt_recovery` instead.
///
/// **Ordering, precisely (design requirement 2).** `trust.can_send(peer_ik)` is consulted *before*
/// any network I/O — a peer currently `Warn`/`Blocked` from an unresolved key change must not get
/// an automatic re-handshake layered on top, and must not even cost a wasted fetch round-trip to
/// discover that. `note_recovery_attempted` is called on this early-refusal path too (not just
/// inside `attempt_recovery`'s own internal check, which only runs *after* a successful fetch), so
/// a gated peer's counter is rate-limited the same way a successfully-recovered peer's is — see
/// `DESYNC_RECOVERY_THRESHOLD`'s doc for why resetting on a refusal, not only a success, matters.
#[allow(clippy::too_many_arguments)]
async fn maybe_attempt_recovery(
    client: &mut SignalingClient,
    state: &mut ChatState,
    trust: &mut TrustStore,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    account_pub: &[u8; 32],
    peer_ik: &[u8; 32],
    peer_hint: &str,
    peer_label: &str,
    json: bool,
) -> Result<(), String> {
    if !state.recovery_recommended(peer_ik) {
        return Ok(());
    }

    if let gate @ (SendGate::Warn(_) | SendGate::Blocked(_)) = trust.can_send(peer_ik) {
        // Refused before any network I/O — see this function's doc comment.
        state.note_recovery_attempted(peer_ik);
        print_recovery_gate_line(&gate, peer_label, json);
        return Ok(());
    }

    if json {
        println!(
            "{{\"event\":\"desync_recovery_started\",\"from\":{}}}",
            json_string(peer_label)
        );
    } else {
        println!(
            "(recovering the session with {peer_label} after repeated failed decryption — \
             re-establishing a fresh secure channel)"
        );
    }

    let peer_bundle = match fetch_with_retry(client, *peer_ik, peer_hint, peer_label).await {
        Ok(b) => b,
        Err(e) => {
            // A fetch failure (including a substituted-key `BundleVerification` abort, which
            // `fetch_with_retry`'s generic, non-retried error arm already surfaces here rather than
            // silently retrying) must not be swallowed. The stale session is left untouched —
            // recovery simply did not happen this time, and the counter was NOT reset by this
            // branch (only `maybe_attempt_recovery`'s early gate-refusal and
            // `desync::attempt_recovery` itself reset it), so a fetch hiccup does not itself
            // suppress the next genuine recovery attempt.
            if json {
                println!(
                    "{{\"event\":\"desync_recovery_failed\",\"from\":{},\"reason\":{}}}",
                    json_string(peer_label),
                    json_string(&e)
                );
            } else {
                eprintln!("! could not recover the session with {peer_label}: {e}");
            }
            return Ok(());
        }
    };

    let outcome = meridian_core::desync::attempt_recovery(
        state,
        trust,
        store,
        handle,
        account_pub,
        peer_ik,
        &peer_bundle.account_pub,
        &peer_bundle.spk,
        peer_bundle.otks.first().copied(),
        peer_hint,
        crate::now_unix(),
    );

    match outcome {
        Ok(meridian_core::desync::RecoveryOutcome::Recovered) => {
            if json {
                println!(
                    "{{\"event\":\"desync_recovery_complete\",\"from\":{}}}",
                    json_string(peer_label)
                );
            } else {
                println!("(session with {peer_label} re-established)");
            }
            Ok(())
        }
        Ok(meridian_core::desync::RecoveryOutcome::Gated(gate)) => {
            print_recovery_gate_line(&gate, peer_label, json);
            Ok(())
        }
        Ok(meridian_core::desync::RecoveryOutcome::KeyChangeConflict) => {
            // (task 4.4's `TrustError::ConflictingContact` case) The fetched bundle's key already
            // names a different, independently-known contact — refused, never merged. Extremely
            // unlikely to be reachable via this CLI's own `fetch_bundle(peer_ik, ...)` call (see
            // `meridian_core::desync::attempt_recovery`'s doc comment), but handled rather than
            // assumed impossible.
            if json {
                println!(
                    "{{\"event\":\"desync_recovery_conflict\",\"from\":{}}}",
                    json_string(peer_label)
                );
            } else {
                eprintln!(
                    "! could not recover the session with {peer_label}: the fetched key already \
                     belongs to a different known contact — refused, not merged"
                );
            }
            Ok(())
        }
        Ok(meridian_core::desync::RecoveryOutcome::UnknownIdentitySurfaced(new_key)) => {
            // (review fixup) The fetched bundle surfaced a key with no prior contact record for
            // `peer_ik` at all — should not happen in practice (see
            // `meridian_core::desync::RecoveryOutcome::UnknownIdentitySurfaced`'s doc), but handled
            // rather than assumed impossible. No session was touched and no trust state was written
            // by `attempt_recovery` itself; this is surfaced distinctly rather than silently
            // TOFU-pinned and completed, mirroring how ordinary first contact always requires either
            // receiver gating or an explicit sender-initiated action. `TODO: confirm` the exact
            // follow-up UX with design (an explicit `meridian contact add`-style flow for the
            // surfaced key is the natural fit, but is not itself part of this task's scope).
            if json {
                println!(
                    "{{\"event\":\"desync_recovery_unknown_identity\",\"from\":{},\"surfaced_key\":{}}}",
                    json_string(peer_label),
                    json_string(&hex::encode(new_key))
                );
            } else {
                eprintln!(
                    "! could not recover the session with {peer_label}: the fetched bundle is \
                     signed by a key with no prior contact record at all — this requires explicit \
                     verification, not an automatic re-handshake"
                );
            }
            Ok(())
        }
        Err(e) => {
            if json {
                println!(
                    "{{\"event\":\"desync_recovery_failed\",\"from\":{},\"reason\":{}}}",
                    json_string(peer_label),
                    json_string(&e.to_string())
                );
            } else {
                eprintln!("! could not recover the session with {peer_label}: {e}");
            }
            Ok(())
        }
    }
}

/// Shared `Warn`/`Blocked` notice for a refused recovery attempt (task 4.9), in both `--json` and
/// plain modes — mirrors `print_gate_line`'s "the canonical reason always ends up somewhere the
/// user sees it" property, but framed as recovery being *paused* pending the existing key-change
/// resolution rather than as a send being blocked/held.
fn print_recovery_gate_line(gate: &SendGate, peer_label: &str, json: bool) {
    let (kind, reason) = match gate {
        SendGate::Warn(r) => ("warning", r.as_str()),
        SendGate::Blocked(r) => ("blocked", r.as_str()),
        SendGate::Ok => return,
    };
    if json {
        println!(
            "{{\"event\":\"desync_recovery_paused\",\"from\":{},\"gate\":\"{kind}\",\"reason\":{}}}",
            json_string(peer_label),
            json_string(reason)
        );
    } else {
        println!(
            "(recovery with {peer_label} is paused: {reason} — resolve this before an automatic \
             re-handshake can proceed)"
        );
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
/// (case-insensitive) accepts, anything else rejects.
///
/// **Accept (task 4.7):** delivers the held intro exactly like an ordinary message, and — the glue
/// this task adds — TOFU-pins `peer_ik` as a real [`meridian_core::trust::Contact`] via
/// [`TrustStore::observe`] (the request gate's own security properties — sender key, safety number,
/// intro shown before this point — are already correct from 2.10 and are not re-derived here; see
/// `run`'s doc comment on why this is the *first* `observe` call for a responder that had no prior
/// session, now that the unconditional early pin in `run` is deferred for exactly this case), then
/// offers an inline, optional petname assignment the same way `contact.rs`'s `cmd_add` does: only
/// when stdin is actually a TTY (never blocks a scripted/`--json` flow), value typed by the operator
/// only — never derived from `peer_hint`/`peer_label`/anything wire-observed (the petname-never-
/// from-wire invariant `contact.rs` documents at module level).
///
/// **Reject:** silent (see [`ChatState::reject_request`]'s doc comment on why nothing is sent back
/// to the sender) — and, matching that silence, `trust` is never touched: no `Contact` record is
/// created, no petname prompt, no trace at all of the rejected sender in the trust store.
#[allow(clippy::too_many_arguments)]
async fn answer_request(
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

            // (task 4.7) TOFU-pin the now-accepted sender. Idempotent/refreshing if `run` already
            // pinned this `peer_ik` (the initiator, or an already-established-session responder);
            // for the deferred first-contact-responder case this is the very first `observe` call
            // for this contact, made only now that the user has actually accepted.
            trust.observe(*peer_ik, peer_hint, crate::now_unix());

            // Offer a petname inline, exactly like `contact add`'s interactive prompt — TTY-gated
            // so a scripted/`--json` flow (stdin piped, never a TTY) never blocks on it.
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                if let Some(name) = crate::contact::prompt_petname()? {
                    trust
                        .set_petname(peer_ik, Some(name.clone()))
                        .map_err(|e| format!("setting petname for {peer_label}: {e}"))?;
                    if !json {
                        println!("  petname set: \"{name}\"");
                    }
                }
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
        // No `trust` interaction here at all (task 4.7): `reject_request` already discards the
        // held `MessageRequest`/session state on the `chat.rs` (core) side, and this branch must
        // not create a `Contact` record either, so a rejected sender leaves genuinely no trace in
        // either store.
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

    // -----------------------------------------------------------------------------------------
    // (task 6.2) `rotate_spk_if_due` — mirrors `apps/tui/tests/spk_rotation.rs` exactly (same
    // three properties, same fake-clock design: `now_unix` is an explicit argument this function
    // never derives from `SystemTime::now()` itself, so every check below is driven by arbitrary
    // `u64` timestamps with no real waiting). `meridian-cli` is a binary-only crate with no `lib`
    // target (see `apps/cli/Cargo.toml`), so — unlike `meridian-tui`, whose `tests/*.rs` integration
    // files can depend on it as a library — this is the only place these can live: a real,
    // in-process `meridian-rendezvous` server (the `meridian-rendezvous` dev-dependency this crate's
    // other integration tests already use) plus a plain `MemorySecretStore` account, driven directly
    // through `rotate_spk_if_due` with no CLI subprocess, no stdin/stdout, and no `sessions.bin` at
    // all (`rotate_spk_if_due` only ever mutates the `ChatState` it's handed in memory — `run`'s own
    // post-select `save_state` is what persists that in the real loop, and is out of scope here).
    //
    // 1. [`rotation_never_republishes_while_the_generation_is_under_the_interval`] — the "session
    //    under the interval never triggers an extra publish" half.
    // 2. [`rotation_republishes_once_due_then_not_again_immediately_after_and_again_next_interval`]
    //    — a simulated long session (two full `SPK_ROTATION_INTERVAL_SECS` periods, fake-clock
    //    driven) that republishes with no user action, and the debounce/no-over-triggering property:
    //    a republish resets the age clock, so the very next check must read `NotDue`.
    // 3. [`rotation_failure_leaves_the_stale_generation_in_service_fail_open`] — the fail-open
    //    decision recorded in this task's Outcome section: a due-but-unreachable republish must not
    //    clear or corrupt the existing (stale) vault entry.
    fn spawn_rotation_test_server() -> String {
        let store = std::sync::Arc::new(meridian_rendezvous::MemoryStore::new());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let config = meridian_rendezvous::Config::default();
                let state = meridian_rendezvous::AppState::new(config, store);
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(addr).unwrap();
                let _ = meridian_rendezvous::serve(state, listener).await;
            });
        });
        let addr = rx.recv().unwrap();
        format!("ws://{addr}")
    }

    /// A fresh account, registered against `server` by the real challenge–response `connect`
    /// handshake (`SignalingClient::connect` registers on first contact) — mirrors
    /// `apps/tui/tests/spk_rotation.rs::onboard` exactly. `MemorySecretStore` throughout:
    /// `rotate_spk_if_due`'s own store handling is generic over `SecretStore`, so a bare in-memory
    /// store is the simplest faithful fixture.
    async fn onboard_rotation_test_account(
        server: &str,
    ) -> (
        meridian_core::identity::MemorySecretStore,
        KeyHandle,
        [u8; 32],
    ) {
        let store = meridian_core::identity::MemorySecretStore::new();
        let account =
            meridian_core::identity::generate_account(&store, "self.example").expect("account");
        let handle = account.handle().clone();
        let account_pub = *account.public_key().as_bytes();
        let client = SignalingClient::connect(server, &store, &handle, account_pub, None, 1)
            .await
            .expect("connect registers the account");
        let _ = client.close().await;
        (store, handle, account_pub)
    }

    /// A `ChatState` whose vault already carries `published_at` — the fake-clock baseline every
    /// test below starts from, rather than the unknown-age (`None`) case task 6.1 already covers.
    fn seeded_state(published_at: u64) -> ChatState {
        let mut state = ChatState::default();
        state
            .vault
            .set_bundle([1u8; 32], [2u8; 32], Vec::new(), published_at);
        state
    }

    /// `state.vault`'s own `spk_published_at` is exactly `expected` — asserted the same way
    /// `apps/tui/tests/spk_rotation.rs::assert_vault_published_at_is` does (there is no direct
    /// accessor for the raw timestamp; `generation_age_secs(expected) == Some(0)` holds if and only
    /// if the vault's own publish timestamp is exactly `expected`).
    fn assert_state_published_at_is(state: &ChatState, expected: u64, context: &str) {
        // (test-engineer fix) mirrors the identical fix in `apps/tui/tests/spk_rotation.rs::
        // assert_vault_published_at_is` — see that function's own doc comment for the full
        // reasoning. `generation_age_secs(expected) == Some(0)` only proves `published_at >=
        // expected`: it silently saturates to `Some(0)`, not a mismatch, whenever the vault's real
        // `published_at` has moved *past* `expected`, exactly what an erroneous extra/early
        // republish would do — making every caller of this helper vacuous in the direction that
        // matters. Anchored instead against a sentinel `check_now` far beyond any value this test
        // suite could ever stamp, so the subtraction never saturates and pins `published_at` down
        // to an exact value.
        let check_now: u64 = u64::MAX / 2;
        assert_eq!(
            state.vault.generation_age_secs(check_now),
            Some(check_now - expected),
            "{context}: expected spk_published_at == {expected}"
        );
    }

    #[tokio::test]
    async fn rotation_never_republishes_while_the_generation_is_under_the_interval() {
        let server = spawn_rotation_test_server();
        let (store, handle, account_pub) = onboard_rotation_test_account(&server).await;

        let published_at: u64 = 1_000_000;
        let mut state = seeded_state(published_at);

        for offset in [
            0,
            1,
            SPK_ROTATION_INTERVAL_SECS / 2,
            SPK_ROTATION_INTERVAL_SECS - 1,
        ] {
            let now = published_at + offset;
            let outcome =
                rotate_spk_if_due(&server, &mut state, &store, &handle, account_pub, now).await;
            assert_eq!(
                outcome,
                SpkRotationOutcome::NotDue,
                "offset={offset} must not be due yet"
            );
        }

        assert_state_published_at_is(
            &state,
            published_at,
            "no check under the interval may have touched spk_published_at",
        );
    }

    #[tokio::test]
    async fn rotation_republishes_once_due_then_not_again_immediately_after_and_again_next_interval(
    ) {
        let server = spawn_rotation_test_server();
        let (store, handle, account_pub) = onboard_rotation_test_account(&server).await;

        let published_at: u64 = 2_000_000;
        let mut state = seeded_state(published_at);

        // Just before the first threshold: not due yet.
        let just_before = published_at + SPK_ROTATION_INTERVAL_SECS - 1;
        assert_eq!(
            rotate_spk_if_due(
                &server,
                &mut state,
                &store,
                &handle,
                account_pub,
                just_before
            )
            .await,
            SpkRotationOutcome::NotDue
        );
        assert_state_published_at_is(
            &state,
            published_at,
            "the not-due check just before the threshold must not have republished",
        );

        // At the threshold: due, and the republish succeeds with no user action — task 6.2's
        // headline property.
        let first_due = published_at + SPK_ROTATION_INTERVAL_SECS;
        assert_eq!(
            rotate_spk_if_due(&server, &mut state, &store, &handle, account_pub, first_due).await,
            SpkRotationOutcome::Rotated
        );
        assert_state_published_at_is(
            &state,
            first_due,
            "a successful rotation must stamp the new spk_published_at at the check's own now_unix",
        );

        // The debounce / no-over-triggering property: immediately after rotating, the generation's
        // age clock has restarted at zero, so the very next check must read NotDue and must not
        // touch `state.vault` again.
        assert_eq!(
            rotate_spk_if_due(
                &server,
                &mut state,
                &store,
                &handle,
                account_pub,
                first_due + 1
            )
            .await,
            SpkRotationOutcome::NotDue,
            "a republish must not be immediately followed by another one at the very next check"
        );
        assert_state_published_at_is(
            &state,
            first_due,
            "the immediately-following not-due check must not have moved spk_published_at again",
        );

        // Still not due partway through the second interval.
        let mid_second_interval = first_due + SPK_ROTATION_INTERVAL_SECS - 1;
        assert_eq!(
            rotate_spk_if_due(
                &server,
                &mut state,
                &store,
                &handle,
                account_pub,
                mid_second_interval
            )
            .await,
            SpkRotationOutcome::NotDue
        );

        // A full second interval later: due again, and rotates again — proving this is a real
        // recurring check across a simulated multi-week session, not a one-shot fuse.
        let second_due = first_due + SPK_ROTATION_INTERVAL_SECS;
        assert_eq!(
            rotate_spk_if_due(
                &server,
                &mut state,
                &store,
                &handle,
                account_pub,
                second_due
            )
            .await,
            SpkRotationOutcome::Rotated
        );
        assert_state_published_at_is(
            &state,
            second_due,
            "the second rotation must stamp the second check's own now_unix",
        );
    }

    #[tokio::test]
    async fn rotation_failure_leaves_the_stale_generation_in_service_fail_open() {
        // `server` is only needed to onboard a real, registered account; `rotate_spk_if_due` itself
        // is then handed a deliberately unreachable address instead (mirrors
        // `apps/tui/tests/spk_rotation.rs`'s own `"ws://127.0.0.1:1"` trick) rather than tearing a
        // real server down mid-test.
        let real_server = spawn_rotation_test_server();
        let (store, handle, account_pub) = onboard_rotation_test_account(&real_server).await;

        let published_at: u64 = 3_000_000;
        let mut state = seeded_state(published_at);
        let due_now = published_at + SPK_ROTATION_INTERVAL_SECS;

        let outcome = rotate_spk_if_due(
            "ws://127.0.0.1:1",
            &mut state,
            &store,
            &handle,
            account_pub,
            due_now,
        )
        .await;
        match outcome {
            SpkRotationOutcome::RotationFailed(message) => {
                assert!(
                    message.contains("connecting to"),
                    "expected a connect-stage error message, got {message:?}"
                );
            }
            other => panic!("expected RotationFailed against an unreachable server, got {other:?}"),
        }

        // Fail-open, the falsifiable half: the stale generation is untouched, not cleared or
        // corrupted — still exactly the one seeded above, still usable.
        assert_state_published_at_is(
            &state,
            published_at,
            "a failed republish must leave the existing (stale) generation exactly as it was",
        );
        // And the predicate still reports "due" afterward — the next check (whenever connectivity
        // allows) will try again, rather than this failure permanently suppressing future attempts.
        assert!(
            state.vault.rotation_due(due_now),
            "a failed rotation attempt must not mark the generation as no-longer-due"
        );
    }
}
