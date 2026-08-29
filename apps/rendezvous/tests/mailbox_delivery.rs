//! Task 8.7 acceptance: delivery-on-reconnect push + `MailboxAck` handling.
//!
//! `SignalingClient` (task 8.8's job) has no `MailboxAck`-sending capability yet, so the
//! ack-side tests here speak raw frames directly over the WebSocket — the same low-level
//! `recv_frame`/`send_frame`/`signed_auth` pattern `rendezvous.rs` already uses for its own
//! auth-replay test. `support::Acct`/`new_acct` are reused for account generation.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use meridian_identity::sign;
use meridian_proto::{
    Auth, Challenge, Deliver, Frame, MailboxAck, MailboxAckOk, Op, MAILBOX_DRAIN_FROM_PLACEHOLDER,
};
use meridian_rendezvous::{AppState, MemoryStore, Store};
use tokio_tungstenite::tungstenite::Message;

mod support;
use support::{base_config, new_acct, spawn_c2s, Acct};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn recv_frame(ws: &mut Ws) -> Frame {
    loop {
        match ws.next().await.unwrap().unwrap() {
            Message::Binary(b) => return Frame::from_bytes(&b).unwrap(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("unexpected ws message: {other:?}"),
        }
    }
}

async fn send_frame(ws: &mut Ws, frame: &Frame) {
    ws.send(Message::Binary(frame.to_bytes().unwrap()))
        .await
        .unwrap();
}

fn signed_auth(acct: &Acct, challenge: &Challenge) -> Auth {
    let mut to_sign = challenge.nonce.to_vec();
    to_sign.extend_from_slice(challenge.server_domain.as_bytes());
    let sig = sign(&acct.store, &acct.handle, &to_sign).unwrap();
    Auth {
        account_pub: acct.pubkey,
        sig: *sig.as_bytes(),
        invite: None,
        max_bundle_v: 1,
    }
}

/// Raw connect + challenge/auth handshake, stopping right after `AuthOk` — same handshake
/// `SignalingClient::connect` performs, but returning the bare WS stream so a test can send
/// frames `SignalingClient` doesn't know how to build yet (`MailboxAck`).
async fn raw_connect(acct: &Acct, url: &str) -> Ws {
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let challenge: Challenge = recv_frame(&mut ws).await.decode().unwrap();
    let auth = signed_auth(acct, &challenge);
    let auth_frame = Frame::new(Op::Auth, 1, &auth).unwrap();
    send_frame(&mut ws, &auth_frame).await;
    let reply = recv_frame(&mut ws).await;
    assert_eq!(reply.op, Op::AuthOk, "expected AuthOk, got {:?}", reply.op);
    ws
}

fn spawn_store() -> (Arc<MemoryStore>, Arc<AppState>) {
    let store = Arc::new(MemoryStore::new());
    let state = AppState::new(base_config("localhost"), store.clone());
    (store, state)
}

/// A realistic absolute future unix timestamp for directly-seeded rows' `expires_at` in this file
/// — see `mailbox_client_ack.rs`'s identical constant/doc comment for why: every test below
/// connects a REAL client, which triggers the REAL `ws::drain_mailbox` and its
/// `expires_at > now_secs()` filter (task 9.3, review finding F5).
const FAR_FUTURE_EXPIRES_AT: u64 = 9_999_999_999;

/// Deliverable 3, case 1: a client with N queued rows receives exactly N `Deliver` frames with
/// `mailbox_id` set, in `arrived_at`/`id` order, before any other traffic — proven by having a
/// live message arrive strictly after the N mailbox-drained ones.
#[tokio::test]
async fn mailbox_drain_delivers_queued_rows_in_order_before_other_traffic() {
    let (store, state) = spawn_store();
    let url = spawn_c2s(state).await;
    let bob = new_acct("localhost");
    let alice = new_acct("localhost");

    let payloads: Vec<Vec<u8>> = vec![vec![1, 1, 1], vec![2, 2], vec![3]];
    let mut ids = Vec::new();
    for (i, p) in payloads.iter().enumerate() {
        let id = store
            .mailbox_enqueue(bob.pubkey, p.clone(), 100 + i as u64, FAR_FUTURE_EXPIRES_AT)
            .await
            .unwrap();
        ids.push(id);
    }

    let mut bc = bob.connect(&url).await.unwrap();

    for (i, expected_blob) in payloads.iter().enumerate() {
        let msg: Deliver = bc.next_deliver().await.unwrap();
        assert_eq!(
            msg.mailbox_id,
            Some(ids[i]),
            "row {i} must arrive with its own mailbox id, in order"
        );
        assert_eq!(msg.from, MAILBOX_DRAIN_FROM_PLACEHOLDER);
        assert_eq!(msg.blob.as_bytes(), expected_blob.as_slice());
    }

    // "Before any other traffic": a live route sent only now must arrive strictly after all three
    // mailbox-drained pushes above, never interleaved ahead of them.
    let mut ac = alice.connect(&url).await.unwrap();
    let delivered = ac.route(bob.pubkey, vec![9, 9, 9]).await.unwrap();
    assert!(delivered);
    let live = bc.next_deliver().await.unwrap();
    assert_eq!(live.mailbox_id, None, "the live push carries no mailbox_id");
    assert_eq!(live.blob.as_bytes(), &[9, 9, 9]);
}

/// Deliverable 3, case 2: `MailboxAck{ids}` deletes exactly those rows and no others — including
/// the attack shape (a connected account acking an id it was never sent, belonging to a
/// *different* account's row), which must be a silent no-op, not a cross-account deletion.
#[tokio::test]
async fn mailbox_ack_deletes_only_the_acked_rows_scoped_to_the_acking_account() {
    let (store, state) = spawn_store();
    let url = spawn_c2s(state).await;
    let bob = new_acct("localhost");
    let alice = new_acct("localhost");

    let bob_id = store
        .mailbox_enqueue(bob.pubkey, vec![1], 0, FAR_FUTURE_EXPIRES_AT)
        .await
        .unwrap();
    let alice_id = store
        .mailbox_enqueue(alice.pubkey, vec![2], 0, FAR_FUTURE_EXPIRES_AT)
        .await
        .unwrap();

    let mut ws = raw_connect(&bob, &url).await;
    // Drain bob's own queued row first (the connection handler always drains post-AuthOk).
    let drained = recv_frame(&mut ws).await;
    assert_eq!(drained.op, Op::Deliver);

    // The attack shape: bob, authenticated as himself, acks BOTH his own row id and alice's —
    // never just a same-account partial ack.
    let ack = MailboxAck {
        ids: vec![bob_id, alice_id],
    };
    let ack_frame = Frame::new(Op::MailboxAck, 2, &ack).unwrap();
    send_frame(&mut ws, &ack_frame).await;
    let reply = recv_frame(&mut ws).await;
    assert_eq!(reply.op, Op::MailboxAckOk);
    let _: MailboxAckOk = reply.decode().unwrap();

    // Bob's own row is gone.
    assert!(store
        .mailbox_list_for_recipient(&bob.pubkey, 0)
        .await
        .unwrap()
        .is_empty());
    // Alice's row survives untouched — acking an id you were never sent, naming another
    // account's row, must be a no-op, never a cross-account deletion.
    let alice_rows = store
        .mailbox_list_for_recipient(&alice.pubkey, 0)
        .await
        .unwrap();
    assert_eq!(alice_rows.len(), 1);
    assert_eq!(alice_rows[0].id, alice_id);
}

/// Deliverable 3, case 3: deletion is ack-driven, not push-driven — a client that never acks keeps
/// its rows, provable by reconnecting and observing the exact same rows get redrained.
#[tokio::test]
async fn unacked_rows_survive_and_are_redrained_on_reconnect() {
    let (store, state) = spawn_store();
    let url = spawn_c2s(state).await;
    let bob = new_acct("localhost");

    let id_a = store
        .mailbox_enqueue(bob.pubkey, vec![1], 0, FAR_FUTURE_EXPIRES_AT)
        .await
        .unwrap();
    let id_b = store
        .mailbox_enqueue(bob.pubkey, vec![2], 1, FAR_FUTURE_EXPIRES_AT)
        .await
        .unwrap();

    // First connection: drain, never ack, disconnect.
    {
        let mut bc = bob.connect(&url).await.unwrap();
        let m1 = bc.next_deliver().await.unwrap();
        let m2 = bc.next_deliver().await.unwrap();
        assert_eq!(m1.mailbox_id, Some(id_a));
        assert_eq!(m2.mailbox_id, Some(id_b));
    } // dropped without ever sending MailboxAck.

    // Rows must still be there — never deleted just by being pushed.
    assert_eq!(
        store
            .mailbox_list_for_recipient(&bob.pubkey, 0)
            .await
            .unwrap()
            .len(),
        2
    );

    // Second connection redrains the SAME still-unacked rows.
    let mut bc2 = bob.connect(&url).await.unwrap();
    let m1 = bc2.next_deliver().await.unwrap();
    let m2 = bc2.next_deliver().await.unwrap();
    assert_eq!(m1.mailbox_id, Some(id_a));
    assert_eq!(m2.mailbox_id, Some(id_b));
}
