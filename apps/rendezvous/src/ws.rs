//! Per-connection WebSocket state machine: challenge → auth/register → serve
//! publish/fetch/route. Writes are funneled through one task so routed deliveries and request
//! replies share the sink without contention.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use meridian_proto::{
    error_codes, Auth, AuthOk, Bundle, Challenge, Deliver, ErrBody, Fetch, Frame, Op, Publish,
    PublishOk, RouteBody, RouteOk,
};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::auth::{substitute_bundle, verify_auth};
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
    // Exact-key lookup only — there is no prefix/search path (anti-enumeration §3.5).
    let bundle = match state.store.get_bundle(&fetch.target).await {
        Ok(Some(b)) => b,
        Ok(None) => return send_err(tx, frame.id, error_codes::NOT_FOUND, "no bundle").await,
        Err(_) => return send_err(tx, frame.id, error_codes::BAD_REQUEST, "store failed").await,
    };
    let bundle = if fetch.tamper && state.config.server.allow_test_tamper {
        // TEST HOOK: substitute a bundle under a different key so a correct client aborts.
        substitute_bundle(&bundle)
    } else {
        bundle
    };
    send(tx, Op::Bundle, frame.id, &Bundle { bundle }).await;
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
    // Build the delivery frame WITHOUT ever inspecting `body.blob` — it stays opaque.
    let deliver = Deliver {
        from: *account_pub,
        blob: body.blob,
    };
    let Ok(frame_out) = Frame::new(Op::Deliver, 0, &deliver) else {
        return send_err(tx, frame.id, error_codes::BAD_REQUEST, "encode failed").await;
    };
    let Ok(bytes) = frame_out.to_bytes() else {
        return send_err(tx, frame.id, error_codes::BAD_REQUEST, "encode failed").await;
    };
    if state.registry.send_to(&body.to, Message::Binary(bytes)) {
        state.metrics.envelope_routed();
        send(tx, Op::RouteOk, frame.id, &RouteOk { delivered: true }).await;
    } else {
        // Offline delivery / mailbox is T07; here an offline recipient is an error.
        send_err(
            tx,
            frame.id,
            error_codes::NOT_CONNECTED,
            "recipient offline",
        )
        .await;
    }
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
