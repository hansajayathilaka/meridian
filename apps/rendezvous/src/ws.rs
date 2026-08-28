//! Per-connection WebSocket state machine: challenge → auth/register → serve
//! publish/fetch/route. Writes are funneled through one task so routed deliveries and request
//! replies share the sink without contention.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use meridian_proto::{
    error_codes, Auth, AuthOk, Bundle, Challenge, Deliver, ErrBody, Fetch, Frame, Op, Publish,
    PublishOk, RouteBody, RouteOk, TurnReq,
};
use serde::Serialize;
use tokio::sync::mpsc;

#[cfg(feature = "test-tamper-hook")]
use crate::auth::substitute_bundle;
use crate::auth::verify_auth;
use crate::federation::outbound::{
    fetch_foreign_bundle, route_foreign, FetchForeignError, RouteForeignError,
};
use crate::state::AppState;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Encode `body` into a frame and queue it for the writer task. Drops silently if the peer is gone.
async fn send(tx: &mpsc::Sender<Message>, op: Op, id: u64, body: &impl Serialize) {
    if let Ok(frame) = Frame::new(op, id, body) {
        if let Ok(bytes) = frame.to_bytes() {
            let _ = tx.send(Message::Binary(bytes)).await;
        }
    }
}

async fn send_err(tx: &mpsc::Sender<Message>, id: u64, code: &str, msg: &str) {
    send(
        tx,
        Op::Err,
        id,
        &ErrBody {
            code: code.to_string(),
            msg: msg.to_string(),
        },
    )
    .await;
}

/// Entry point from the axum upgrade handler.
pub async fn handle_socket(socket: WebSocket, state: Arc<AppState>, peer_ip: IpAddr) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Message>(64);

    // Single writer task owns the sink. On shutdown it closes the sink so the peer sees a clean
    // WebSocket close handshake rather than a reset.
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // 1) Challenge (server speaks first). id 0 marks a server-initiated frame.
    let nonce = crate::auth::new_nonce();
    let challenge = Challenge {
        nonce,
        server_time: now_secs(),
        server_domain: state.config.server.domain.clone(),
    };
    send(&tx, Op::Challenge, 0, &challenge).await;

    // 2) Authenticate + register. On any failure we send an error and drop the connection.
    let account_pub = match authenticate(&state, &mut stream, &tx, &nonce, peer_ip).await {
        Some(key) => key,
        None => {
            drop(tx);
            let _ = writer.await;
            return;
        }
    };

    // 3) Serve the authenticated session.
    let conn_id = state.next_conn_id();
    state.registry.add(account_pub, conn_id, tx.clone());
    state.metrics.conn_opened();

    serve(&state, &mut stream, &tx, &account_pub).await;

    // 4) Teardown.
    state.registry.remove(&account_pub, conn_id);
    state.metrics.conn_closed();
    drop(tx);
    let _ = writer.await;
}

/// Read exactly one frame and require it to be a valid `Auth`. Returns the authenticated key.
async fn authenticate(
    state: &Arc<AppState>,
    stream: &mut (impl StreamExt<Item = Result<Message, axum::Error>> + Unpin),
    tx: &mpsc::Sender<Message>,
    nonce: &[u8; 32],
    peer_ip: IpAddr,
) -> Option<[u8; 32]> {
    if !state.auth_limiter.check(ip_key(peer_ip).as_slice()) {
        send_err(tx, 0, error_codes::RATE_LIMITED, "too many auth attempts").await;
        return None;
    }

    let frame = next_frame(stream).await?;
    if frame.op != Op::Auth {
        send_err(tx, frame.id, error_codes::AUTH_REQUIRED, "expected auth").await;
        return None;
    }
    let auth: Auth = match frame.decode() {
        Ok(a) => a,
        Err(_) => {
            send_err(tx, frame.id, error_codes::BAD_REQUEST, "malformed auth").await;
            return None;
        }
    };

    if !verify_auth(nonce, &state.config.server.domain, &auth) {
        // A replayed auth (captured from another connection) lands here: its signature was over a
        // *different* nonce, so it fails against this connection's fresh challenge.
        send_err(tx, frame.id, error_codes::AUTH_FAILED, "bad signature").await;
        return None;
    }
    if !state.admission.admit(auth.invite.as_deref()) {
        send_err(tx, frame.id, error_codes::ADMISSION_DENIED, "not admitted").await;
        return None;
    }

    if state
        .store
        .register_account(auth.account_pub, admission_label(state), auth.max_bundle_v)
        .await
        .is_err()
    {
        send_err(
            tx,
            frame.id,
            error_codes::BAD_REQUEST,
            "registration failed",
        )
        .await;
        return None;
    }

    send(
        tx,
        Op::AuthOk,
        frame.id,
        &AuthOk {
            server_domain: state.config.server.domain.clone(),
        },
    )
    .await;
    Some(auth.account_pub)
}

/// The authenticated request loop.
async fn serve(
    state: &Arc<AppState>,
    stream: &mut (impl StreamExt<Item = Result<Message, axum::Error>> + Unpin),
    tx: &mpsc::Sender<Message>,
    account_pub: &[u8; 32],
) {
    while let Some(frame) = next_frame(stream).await {
        match frame.op {
            Op::Publish => handle_publish(state, tx, account_pub, &frame).await,
            Op::Fetch => handle_fetch(state, tx, account_pub, &frame).await,
            Op::Route => handle_route(state, tx, account_pub, &frame).await,
            Op::TurnReq => handle_turn(state, tx, account_pub, &frame).await,
            _ => send_err(tx, frame.id, error_codes::BAD_REQUEST, "unexpected op").await,
        }
    }
}

async fn handle_publish(
    state: &Arc<AppState>,
    tx: &mpsc::Sender<Message>,
    account_pub: &[u8; 32],
    frame: &Frame,
) {
    let publish: Publish = match frame.decode() {
        Ok(p) => p,
        Err(_) => return send_err(tx, frame.id, error_codes::BAD_REQUEST, "malformed").await,
    };
    let bundle = publish.bundle;
    // A client may only publish its OWN bundle, and it must be structurally sound.
    if &bundle.account_pub != account_pub || !bundle.structurally_valid() {
        return send_err(tx, frame.id, error_codes::BAD_BUNDLE, "invalid bundle").await;
    }
    let accepted = bundle.otks.len() as u16;
    if state.store.put_bundle(bundle).await.is_err() {
        return send_err(tx, frame.id, error_codes::BAD_REQUEST, "store failed").await;
    }
    send(
        tx,
        Op::PublishOk,
        frame.id,
        &PublishOk {
            accepted_otks: accepted,
        },
    )
    .await;
}

async fn handle_fetch(
    state: &Arc<AppState>,
    tx: &mpsc::Sender<Message>,
    account_pub: &[u8; 32],
    frame: &Frame,
) {
    if !state.fetch_limiter.check(account_pub.as_slice()) {
        return send_err(tx, frame.id, error_codes::RATE_LIMITED, "too many fetches").await;
    }
    let fetch: Fetch = match frame.decode() {
        Ok(f) => f,
        Err(_) => return send_err(tx, frame.id, error_codes::BAD_REQUEST, "malformed").await,
    };

    // Routing invariant (system-design.md §3.3 steps 2-4): `fetch.hint` absent, or equal to this
    // server's OWN domain, is a local fetch (unchanged path below). Any other hint means `target`
    // names an account this server is not authoritative for — federate the request to the hinted
    // server (task 2.7) rather than serving (or failing) locally. Comparison is case-insensitive
    // (DNS domains, RFC 4343), mirroring every other domain comparison in this crate. Structuring
    // this as an `if let Some(hint) = ...` (rather than a separate `is_foreign: bool` plus an
    // `unwrap_or_default` to recover `hint`) makes "a foreign branch only exists when there's an
    // actual hint string" a fact the type system carries, not just a comment.
    if let Some(hint) = &fetch.hint {
        if !hint.eq_ignore_ascii_case(&state.config.server.domain) {
            return handle_federated_fetch(state, tx, frame, hint, fetch.target).await;
        }
    }

    // Exact-key lookup only — there is no prefix/search path (anti-enumeration §3.5).
    let bundle = match state.store.get_bundle(&fetch.target).await {
        Ok(Some(b)) => b,
        Ok(None) => return send_err(tx, frame.id, error_codes::NOT_FOUND, "no bundle").await,
        Err(_) => return send_err(tx, frame.id, error_codes::BAD_REQUEST, "store failed").await,
    };
    // TEST HOOK (F17): the bundle-tamper substitution is compiled in only under the
    // `test-tamper-hook` cargo feature — absent from default/release builds entirely, not merely
    // gated by config. When the feature is off, `fetch.tamper` and `allow_test_tamper` are inert.
    #[cfg(feature = "test-tamper-hook")]
    let bundle = if fetch.tamper && state.config.server.allow_test_tamper {
        // substitute a bundle under a different key so a correct client aborts.
        substitute_bundle(&bundle)
    } else {
        bundle
    };
    #[cfg(not(feature = "test-tamper-hook"))]
    let _ = fetch.tamper;
    send(tx, Op::Bundle, frame.id, &Bundle { bundle }).await;
}

/// The federated branch of `handle_fetch` (task 2.7, system-design.md §3.3 steps 2-4): this
/// server (A) dials the hinted foreign server (B) via `federation::outbound::fetch_foreign_bundle`
/// and relays the result back to the client as the *same* `Op::Bundle`/`Op::Err` shape a local
/// fetch would use — the client cannot tell, from the frame shape alone, whether its bundle came
/// from local storage or across a federation boundary. Its OWN `verify_bundle` check (client-side,
/// unaffected by this task) is what actually anchors trust either way.
///
/// The client never dials `hint` itself — this function, running only on server A, is the sole
/// place a federated dial happens for a fetch. `tx`/`account_pub`'s connection is the client's
/// link to *this* server only.
async fn handle_federated_fetch(
    state: &Arc<AppState>,
    tx: &mpsc::Sender<Message>,
    frame: &Frame,
    hint: &str,
    target: [u8; 32],
) {
    match fetch_foreign_bundle(state, hint, target).await {
        Ok(fed_bundle) => {
            send(
                tx,
                Op::Bundle,
                frame.id,
                &Bundle {
                    bundle: fed_bundle.bundle,
                },
            )
            .await;
        }
        Err(e) => {
            let (code, msg) = federated_fetch_error_reply(hint, &e);
            send_err(tx, frame.id, code, &msg).await;
        }
    }
}

/// Translate a [`FetchForeignError`] into the client-visible `(code, msg)` pair, reusing the
/// `error_codes` this crate already defined for exactly this purpose rather than inventing new
/// client-visible codes here (2.9's job is copy/taxonomy polish, not this task's).
///
/// **Only `hint` — the domain the client itself already supplied — may appear in the returned
/// message text.** `FetchForeignError`'s own fields (`Discovery::domain`, `AddrResolution::host`,
/// `Dial::domain`) can carry server A's internal federation configuration instead: an
/// `Endpoint::host` may be an internal-DNS/service name never meant to be client-facing
/// (`federation::discovery::Endpoint`'s own doc comment), and `Dial::domain` is
/// `expected_domain` — in private-CA mode that's the operator's configured `pinned_identity`,
/// which by design can differ from `hint` (security-reviewer + code-reviewer finding on task
/// 2.7: an ordinary transient outage at the foreign server, no attack needed, would otherwise
/// leak that internal string to any of A's authenticated users on a dial failure).
fn federated_fetch_error_reply(hint: &str, e: &FetchForeignError) -> (&'static str, String) {
    match e {
        // We never even reached a foreign server — a connectivity/configuration outcome, distinct
        // from a foreign server actively refusing us (`fed_denied`, below).
        FetchForeignError::NotConfigured => (
            error_codes::FED_UNREACHABLE,
            "federation is not enabled on this server".to_string(),
        ),
        FetchForeignError::Discovery { .. } => (
            error_codes::FED_UNREACHABLE,
            format!("could not resolve federation partner {hint:?}"),
        ),
        FetchForeignError::AddrResolution { .. } => (
            error_codes::FED_UNREACHABLE,
            format!("could not resolve a dial address for federation partner {hint:?}"),
        ),
        FetchForeignError::Dial { .. } => (
            error_codes::FED_UNREACHABLE,
            format!("could not reach federation partner {hint:?}"),
        ),
        FetchForeignError::Protocol(_) => (
            error_codes::FED_UNREACHABLE,
            "federated fetch protocol error".to_string(),
        ),
        // (task 3.1, review finding F1) OUR OWN federation policy refused to dial `hint` at all —
        // never even a DNS lookup, let alone a connection attempt. Distinct from every arm above
        // (which all mean "we tried to reach org-b.test and couldn't") and from `Fed(fed_err)`'s
        // `POLICY_DENIED` case below (which means org-b.test itself answered and declined): this
        // is `fed_denied` without ever leaving this server, matching the same code a foreign
        // `POLICY_DENIED` reply produces so a client cannot distinguish "A wouldn't dial" from "B
        // wouldn't admit" by error code alone.
        FetchForeignError::Denied => (
            error_codes::FED_DENIED,
            format!("federation policy does not allow dialing {hint:?}"),
        ),
        // The foreign server DID answer — translate its structured `FedErr` into the closest
        // existing local code (never a new one — see this function's doc comment).
        FetchForeignError::Fed(fed_err) => {
            use meridian_proto::fed_error_codes;
            let code = if fed_err.code == fed_error_codes::POLICY_DENIED {
                error_codes::FED_DENIED
            } else if fed_err.code == fed_error_codes::RATE_LIMITED {
                error_codes::RATE_LIMITED
            } else if fed_err.code == fed_error_codes::NOT_FOUND {
                // The federated analogue of `not_found`: kept distinct so a client can tell "no
                // such account on this server" from "no such account at the org the hint named"
                // (the stale-hint case) — see `error_codes::NOT_FOUND_AT_HINT`'s own doc comment.
                error_codes::NOT_FOUND_AT_HINT
            } else {
                // `bad_request` from the peer, or any future/unknown fed error code: no existing
                // local code fits precisely, so fail closed to the generic connectivity/protocol
                // outcome rather than inventing a new client-visible code (2.9's job).
                error_codes::FED_UNREACHABLE
            };
            // `fed_err.msg` is NEVER forwarded here (task 3.21, finding N1): it is free-form text
            // chosen entirely by the foreign server, i.e. attacker-controlled the moment that
            // partner is hostile or compromised — 2.9's taxonomy sanitized `fed_err.code` into
            // `code` above, but did nothing about this field. Only the mapped `code` picks the
            // client-facing text below, same fixed-copy-per-branch pattern every other arm in this
            // match already uses; never a "the remote server said: ..." passthrough, which would
            // still leak attacker-chosen text into the victim's UI.
            let msg = match code {
                error_codes::FED_DENIED => "federation partner declined the request",
                error_codes::RATE_LIMITED => "federation partner is rate-limiting this server",
                error_codes::NOT_FOUND_AT_HINT => {
                    "no such account at the hinted federation partner"
                }
                _ => "federated fetch declined",
            };
            (code, msg.to_string())
        }
    }
}

async fn handle_route(
    state: &Arc<AppState>,
    tx: &mpsc::Sender<Message>,
    account_pub: &[u8; 32],
    frame: &Frame,
) {
    if !state.route_limiter.check(account_pub.as_slice()) {
        return send_err(tx, frame.id, error_codes::RATE_LIMITED, "too many routes").await;
    }
    let body: RouteBody = match frame.decode() {
        Ok(b) => b,
        Err(_) => return send_err(tx, frame.id, error_codes::BAD_REQUEST, "malformed").await,
    };

    // Routing invariant (system-design.md §3.3 steps 2-4, mirrors `handle_fetch`'s identical
    // branch, task 2.7): `body.to_hint` absent, or equal to this server's OWN domain, is a local
    // route (unchanged path below). Any other hint means `body.to` names an account this server
    // is not authoritative for — federate the request to the hinted server (task 2.8) rather than
    // deliver (or fail) locally. Same `if let Some(hint) = ...` structure `handle_fetch` uses
    // (not a separate `is_foreign: bool` + `unwrap_or_default`) so "a foreign branch only exists
    // when there's an actual hint string" is a fact the type system carries.
    if let Some(hint) = &body.to_hint {
        if !hint.eq_ignore_ascii_case(&state.config.server.domain) {
            return handle_federated_route(
                state,
                tx,
                frame,
                hint,
                body.to,
                *account_pub,
                body.blob.0,
            )
            .await;
        }
    }

    // Kept in case the recipient turns out to be offline and this falls through to the
    // mailbox-enqueue path below (T07) — both `deliver_one` and the tamper-hook plan below consume
    // `body.blob.0` regardless of whether the recipient is actually connected.
    let blob_for_mailbox = body.blob.0.clone();

    // The honest path, and the ONLY path compiled into a default/release build: exactly one
    // `Deliver`, to the requested recipient, carrying the client's bytes unaltered, with `from` set
    // to the key this connection authenticated as. The blob is never *inspected* — it stays opaque.
    #[cfg(not(feature = "test-tamper-hook"))]
    let delivered = match deliver_one(state, &body.to, *account_pub, body.blob.0) {
        Some(ok) => ok,
        None => return send_err(tx, frame.id, error_codes::BAD_REQUEST, "encode failed").await,
    };

    // TEST HOOKS (tasks 1.28 + 1.32): a compromised rendezvous mounting the relay attacks it can
    // actually mount — rewriting a blob in transit (1.28), and the key-material-free attacks that
    // pass the envelope signature check because they never touch the bytes: forging `Deliver.from`,
    // replay, reorder, drop, cross-delivery (1.32). Compiled in only under the `test-tamper-hook`
    // cargo feature — absent from default/release builds entirely (the block above is what ships) —
    // and gated at runtime by the umbrella flags plus each attack's own flag, so the
    // bundle-substitution demo is unaffected. Note the hook still never *inspects* the blob: it
    // moves, duplicates, withholds and (for 1.28) mutates opaque bytes, which is all a real relay
    // can do. With every mode flag off, `plan` is the identity and this is byte-for-byte the honest
    // path above.
    #[cfg(feature = "test-tamper-hook")]
    let delivered = {
        let plan =
            state
                .route_tamper
                .plan(&state.config.server, body.to, *account_pub, body.blob.0);
        let mut delivered = false;
        for d in plan.deliveries {
            match deliver_one(state, &d.to, d.from, d.blob) {
                Some(ok) => delivered |= ok,
                None => {
                    return send_err(tx, frame.id, error_codes::BAD_REQUEST, "encode failed").await
                }
            }
        }
        // A drop/reorder hook that withheld the blob still acks it as delivered, if the recipient is
        // in fact connected — that is the lie a real dropping relay tells, and a client's security
        // must not depend on being able to distinguish it from a true delivery.
        delivered || (plan.claim_delivered && state.registry.is_connected(&body.to))
    };

    if delivered {
        send(
            tx,
            Op::RouteOk,
            frame.id,
            &RouteOk {
                delivered: true,
                queued: false,
            },
        )
        .await;
    } else if state.config.mailbox.ttl_days == 0 {
        // TTL=0: the mailbox is genuinely disabled (pure-P2P mode), not just empty — unchanged
        // pre-T07 behavior, never attempt an enqueue.
        send_err(
            tx,
            frame.id,
            error_codes::NOT_CONNECTED,
            "recipient offline",
        )
        .await;
    } else {
        queue_to_mailbox(state, tx, frame, body.to, blob_for_mailbox).await;
    }
}

/// `MB` in `config.mailbox.quota_mb` means MiB (binary), matching this codebase's one other
/// documented size convention (`mrd.file/1`'s 64 KiB chunk size, task 7.5) — no design doc pins
/// this down explicitly (`TODO: confirm` already carried on `Mailbox::quota_mb`'s own doc comment,
/// task 8.1), so this is a reasonable disambiguation, not an invented requirement.
const MAILBOX_QUOTA_BYTES_PER_MB: u64 = 1024 * 1024;

/// The offline+mailbox-enabled branch of `handle_route` (T07, phase-8 architect consult point 4):
/// enqueue the recipient's ciphertext into their mailbox for later delivery-on-reconnect (8.7),
/// unless doing so would exceed their configured quota. Never a `RouteOk` on the quota-exceeded
/// path — a distinct `mailbox_full` error, per the wire consult 8.3 already shipped.
async fn queue_to_mailbox(
    state: &Arc<AppState>,
    tx: &mpsc::Sender<Message>,
    frame: &Frame,
    recipient: [u8; 32],
    blob: Vec<u8>,
) {
    let quota_bytes = state.config.mailbox.quota_mb as u64 * MAILBOX_QUOTA_BYTES_PER_MB;
    let current_bytes = match state
        .store
        .mailbox_size_bytes_for_recipient(&recipient)
        .await
    {
        Ok(n) => n,
        Err(_) => return send_err(tx, frame.id, error_codes::BAD_REQUEST, "store failed").await,
    };
    if current_bytes + blob.len() as u64 > quota_bytes {
        return send_err(
            tx,
            frame.id,
            error_codes::MAILBOX_FULL,
            "recipient's mailbox is full",
        )
        .await;
    }

    let now = now_secs();
    let ttl_secs = state.config.mailbox.ttl_days as u64 * 86_400;
    match state
        .store
        .mailbox_enqueue(recipient, blob, now, now + ttl_secs)
        .await
    {
        Ok(_id) => {
            send(
                tx,
                Op::RouteOk,
                frame.id,
                &RouteOk {
                    delivered: false,
                    queued: true,
                },
            )
            .await;
        }
        Err(_) => send_err(tx, frame.id, error_codes::BAD_REQUEST, "store failed").await,
    }
}

/// The federated branch of `handle_route` (task 2.8, system-design.md §3.3 step 5): this server
/// (A) dials the hinted foreign server (B) via `federation::outbound::route_foreign` — which
/// itself pre-checks target liveness via `reachable_foreign` before attempting the actual
/// `fed_route` round trip (architect decision #3) — and replies to the client with the *same*
/// `Op::RouteOk`/`Op::Err` shape a local route would use. The client never dials `hint` itself;
/// this function, running only on server A, is the sole place a federated route dial happens.
async fn handle_federated_route(
    state: &Arc<AppState>,
    tx: &mpsc::Sender<Message>,
    frame: &Frame,
    hint: &str,
    to: [u8; 32],
    from: [u8; 32],
    blob: Vec<u8>,
) {
    match route_foreign(state, hint, to, from, blob).await {
        Ok(()) => {
            send(
                tx,
                Op::RouteOk,
                frame.id,
                &RouteOk {
                    delivered: true,
                    queued: false,
                },
            )
            .await;
        }
        Err(e) => {
            let (code, msg) = federated_route_error_reply(hint, &e);
            send_err(tx, frame.id, code, &msg).await;
        }
    }
}

/// Translate a [`RouteForeignError`] into the client-visible `(code, msg)` pair (architect
/// decisions #1 and #3 on this task). Same "only `hint` may appear in the message text" rule as
/// [`federated_fetch_error_reply`] — `RouteForeignError`'s own fields can carry server A's
/// internal federation configuration (an `Endpoint::host` service name, a private-CA
/// `pinned_identity`), which must never leak to a client on a dial failure.
fn federated_route_error_reply(hint: &str, e: &RouteForeignError) -> (&'static str, String) {
    match e {
        // We never even reached a foreign server for the ACTUAL route attempt — a connectivity
        // axis, distinct from the target-liveness axis below (architect decision #3: "Genuine
        // failure to reach server B at all stays fed_unreachable").
        RouteForeignError::NotConfigured => (
            error_codes::FED_UNREACHABLE,
            "federation is not enabled on this server".to_string(),
        ),
        RouteForeignError::Discovery { .. } => (
            error_codes::FED_UNREACHABLE,
            format!("could not resolve federation partner {hint:?}"),
        ),
        RouteForeignError::AddrResolution { .. } => (
            error_codes::FED_UNREACHABLE,
            format!("could not resolve a dial address for federation partner {hint:?}"),
        ),
        RouteForeignError::Dial { .. } => (
            error_codes::FED_UNREACHABLE,
            format!("could not reach federation partner {hint:?}"),
        ),
        RouteForeignError::Protocol(_) => (
            error_codes::FED_UNREACHABLE,
            "federated route protocol error".to_string(),
        ),
        // Architect decision #1: a clean, pre-dial rejection — never reaches the wire at all.
        RouteForeignError::EnvelopeTooLarge { .. } => (
            error_codes::BAD_REQUEST,
            "envelope too large to route".to_string(),
        ),
        // Architect decision #3: the ENTIRE target-liveness axis — "target unknown," "target
        // known-offline," and "the reachability pre-check itself failed" — collapses to the same
        // code a local offline recipient already produces. Never a distinct "foreign offline"
        // code: that would be a fresh existence oracle this task must not introduce.
        RouteForeignError::TargetUnreachable => {
            (error_codes::NOT_CONNECTED, "recipient offline".to_string())
        }
        // (task 3.1, review finding F1) OUR OWN federation policy refused to dial `hint` at all —
        // never even a DNS lookup, let alone a connection attempt. Same reasoning as
        // `federated_fetch_error_reply`'s identical arm: distinct from every connectivity arm
        // above, and mapped to the same `fed_denied` a foreign `POLICY_DENIED` reply produces
        // below, so a client cannot tell "A wouldn't dial" apart from "B wouldn't admit."
        RouteForeignError::Denied => (
            error_codes::FED_DENIED,
            format!("federation policy does not allow dialing {hint:?}"),
        ),
        // The foreign server DID answer — translate its structured `FedErr` into the closest
        // existing local code (never a new one — see this function's doc comment), reusing
        // `federated_fetch_error_reply`'s exact mapping (task 2.7 precedent).
        RouteForeignError::Fed(fed_err) => {
            use meridian_proto::fed_error_codes;
            let code = if fed_err.code == fed_error_codes::POLICY_DENIED {
                error_codes::FED_DENIED
            } else if fed_err.code == fed_error_codes::RATE_LIMITED {
                error_codes::RATE_LIMITED
            } else {
                // `bad_request` from the peer, or any future/unknown fed error code: no existing
                // local code fits precisely, so fail closed to the generic connectivity/protocol
                // outcome rather than inventing a new client-visible code (2.9's job).
                error_codes::FED_UNREACHABLE
            };
            // `fed_err.msg` is NEVER forwarded here (task 3.21, finding N1) — same reasoning as
            // `federated_fetch_error_reply`'s identical arm: it's free-form text the foreign
            // server chose, attacker-controlled once that partner is hostile/compromised. Only
            // the mapped `code` picks the fixed client-facing text; never a "the remote server
            // said: ..." passthrough.
            let msg = match code {
                error_codes::FED_DENIED => "federation partner declined the request",
                error_codes::RATE_LIMITED => "federation partner is rate-limiting this server",
                _ => "federated route declined",
            };
            (code, msg.to_string())
        }
    }
}

/// Encode one `Deliver` and push it to every live connection for `to`. `Some(true)` if at least one
/// connection took it, `Some(false)` if the recipient is offline, `None` if encoding failed.
///
/// `from` and `blob` are parameters rather than being read from the request precisely so the
/// cfg-gated test hook can pass forged/duplicated/withheld values through the *same* code path a
/// real delivery takes — the hook decides *which* triples to emit, never how they are emitted.
fn deliver_one(
    state: &Arc<AppState>,
    to: &[u8; 32],
    from: [u8; 32],
    blob: Vec<u8>,
) -> Option<bool> {
    let deliver = Deliver {
        from,
        blob: meridian_proto::OpaqueBlob::new(blob),
        // A live route push, never a mailbox drain (T07's mailbox-drain push is 8.7's job) —
        // `mailbox_id` stays absent here.
        mailbox_id: None,
    };
    let bytes = Frame::new(Op::Deliver, 0, &deliver).ok()?.to_bytes().ok()?;
    if state.registry.send_to(to, Message::Binary(bytes)) {
        state.metrics.envelope_routed();
        Some(true)
    } else {
        Some(false)
    }
}

/// Mint an ephemeral TURN credential, distinct per request, for an authenticated client (T05, §5.4).
/// The server holds only the shared HMAC secret — no session state — so this is a pure function of
/// the clock and a fresh nonce. Reuse of one captured credential within its TTL is bounded by
/// coturn's `user-quota`, not rejected outright. Minting is refused (`turn_unavailable`) when no
/// secret is configured (air-gapped with no relay, or a dev server): the client then falls back to
/// the host/STUN ladder and `meridian doctor` names the blocked path.
async fn handle_turn(
    state: &Arc<AppState>,
    tx: &mpsc::Sender<Message>,
    account_pub: &[u8; 32],
    frame: &Frame,
) {
    if !state.turn_limiter.check(account_pub.as_slice()) {
        return send_err(
            tx,
            frame.id,
            error_codes::RATE_LIMITED,
            "too many turn requests",
        )
        .await;
    }
    // Body is empty in v1; decode to reject anything malformed rather than ignoring it.
    let _req: TurnReq = match frame.decode() {
        Ok(r) => r,
        Err(_) => return send_err(tx, frame.id, error_codes::BAD_REQUEST, "malformed").await,
    };
    if !state.turn.enabled() {
        return send_err(
            tx,
            frame.id,
            error_codes::TURN_UNAVAILABLE,
            "no relay configured",
        )
        .await;
    }
    let grant = crate::turn::mint_at(&state.turn, now_secs());
    state.metrics.turn_minted();
    send(tx, Op::TurnGrant, frame.id, &grant).await;
}

/// Read the next application frame, skipping ping/pong; `None` on close or error.
async fn next_frame(
    stream: &mut (impl StreamExt<Item = Result<Message, axum::Error>> + Unpin),
) -> Option<Frame> {
    while let Some(msg) = stream.next().await {
        let msg = msg.ok()?;
        match msg {
            Message::Binary(bytes) => return Frame::from_bytes(&bytes).ok(),
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => return None,
            Message::Text(_) => return None,
        }
    }
    None
}

fn ip_key(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

fn admission_label(state: &Arc<AppState>) -> &'static str {
    match state.config.server.admission {
        crate::config::Admission::Open => "open",
        crate::config::Admission::Invite => "invite",
    }
}
