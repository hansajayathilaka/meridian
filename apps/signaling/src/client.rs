//! The async client half of the rendezvous protocol: connect, authenticate by account-key
//! challenge, publish a bundle, fetch-and-verify a peer bundle, and route/receive opaque envelopes.

use std::collections::VecDeque;

use futures_util::{SinkExt, StreamExt};
use meridian_identity::{sign, KeyHandle, SecretStore};
use meridian_proto::{
    Auth, AuthOk, Bundle, Challenge, Deliver, Fetch, Frame, MailboxAck, MailboxAckOk, Op,
    OpaqueBlob, PrekeyBundle, Publish, PublishOk, RouteBody, RouteOk, TurnGrant, TurnReq,
};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::bundle::{generate_bundle, verify_bundle, GeneratedBundle};
use crate::error::{Result, SignalError};

/// Install `ring` as the process-wide default `rustls` crypto provider, once. rustls 0.23 no
/// longer auto-selects a backend — `rustls::ClientConfig::builder()` (and `ServerConfig::builder()`)
/// **panics** if none is installed, so this must run before the first `wss://` TLS handshake this
/// process ever attempts.
///
/// Called at the top of [`SignalingClient::connect`] itself (previously this lived only in
/// `apps/cli/src/main.rs`'s `fn main()`, which meant every OTHER binary embedding `meridian-core`
/// — a future Tauri desktop backend, a mobile UniFFI host — would have hit the same "every `wss://`
/// connection panics" defect main.rs's own copy was written to fix, T3.13/F13). Putting it here
/// instead means it's impossible to reach a `wss://` handshake through this client without it
/// having run first, regardless of caller.
///
/// Idempotent: a second (or concurrent) call observes "already installed" and is silently
/// ignored — this crate links exactly one provider (`ring`, this crate's `Cargo.toml`), so there is
/// never a genuine choice to make here.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// The full outcome of a [`SignalingClient::route_with_hint_detailed`] call — mirrors
/// [`meridian_proto::RouteOk`]'s two fields exactly, so a mailbox-aware caller (task 8.15) can tell
/// "delivered live right now" from "queued into the recipient's offline mailbox, will arrive on
/// reconnect" (T07) from "genuinely not delivered" (neither field true — e.g. `ttl_days == 0` at the
/// recipient's server), rather than the collapsed single bool [`SignalingClient::route_with_hint`]
/// returns for callers that don't need the distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteOutcome {
    /// Pushed to a live connection right now.
    pub delivered: bool,
    /// Durably queued into the recipient's offline mailbox instead (T07) — always `false` when
    /// `delivered` is `true` (see [`RouteOk`]'s own doc comment: the two are mutually exclusive).
    pub queued: bool,
}

/// An authenticated client session to a rendezvous server.
pub struct SignalingClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u64,
    account_pub: [u8; 32],
    server_domain: String,
    /// Server-pushed [`Deliver`] frames that arrived while awaiting a request reply.
    pending_delivers: VecDeque<Deliver>,
    /// (task 8.8) Mailbox row ids collected off [`Deliver::mailbox_id`] as each mailbox-drained
    /// frame is handed to the caller via [`next_deliver`](Self::next_deliver), not yet covered by
    /// a [`MailboxAck`]. Flushed as one batched wire frame by
    /// [`ack_pending_mailbox`](Self::ack_pending_mailbox) — never sent automatically, so a caller
    /// controls exactly when "this envelope's processing is durable enough to ack" is true. See
    /// that method's own doc comment for the crash-safety reasoning (ack-after-processing, never
    /// ack-on-receipt).
    pending_mailbox_acks: Vec<u64>,
}

impl SignalingClient {
    /// Connect to `url` (`ws://` or `wss://`), complete the challenge–response handshake by
    /// signing `nonce ‖ server_domain` through `store`, and register the account.
    pub async fn connect(
        url: &str,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        account_pub: [u8; 32],
        invite: Option<String>,
        max_bundle_v: u16,
    ) -> Result<Self> {
        install_crypto_provider();
        let (ws, _resp) = connect_async(url)
            .await
            .map_err(|e| SignalError::Ws(e.to_string()))?;
        Self::handshake(ws, store, handle, account_pub, invite, max_bundle_v).await
    }

    /// Like [`Self::connect`], but takes an owned, cheaply-`clone()`-able `Arc<dyn SecretStore>`
    /// instead of a borrow, and performs the handshake's one signature
    /// (`sign(store, handle, &to_sign)`) inside [`tokio::task::spawn_blocking`] rather than
    /// synchronously on the calling task.
    ///
    /// **Why this exists (task 4.51).** `apps/tui/src/worker.rs::run_inbound_loop` calls
    /// [`Self::connect`] on every initial connect *and every reconnect attempt*, on
    /// `apps/cli/src/main.rs`'s single-threaded `current_thread` runtime. For a file-backed
    /// account, `sign()` there runs `FileSecretStore::use_key`, which performs a full, synchronous
    /// age/scrypt unwrap on every single call (~1.3 s measured — see that task's own Status
    /// section) — run directly on the calling task, that freezes *every* other task in the process
    /// (rendering, every other in-flight effect, this very loop's own message receipt) for the
    /// whole unwrap. `tokio::task::block_in_place` is not a legal alternative (it panics on a
    /// `current_thread` runtime); `spawn_blocking`'s closure must be `'static + Send`, which a
    /// borrowed `&dyn SecretStore` cannot satisfy — hence the owned `Arc` here rather than changing
    /// [`Self::connect`]'s own signature (every other caller — `cmd_register`, `cmd_chat`,
    /// `session_connect`, `republish_bundle`, … — keeps using the borrow-based [`Self::connect`]
    /// unchanged; this method is additive, not a replacement).
    ///
    /// **No new caching, no new residency.** This performs the exact same `sign()` call, against
    /// the exact same store, the exact same number of times per (re)connect as
    /// [`Self::connect`]/[`Self::handshake`] always did — only the thread it runs on changed.
    pub async fn connect_owned(
        url: &str,
        store: std::sync::Arc<dyn SecretStore>,
        handle: KeyHandle,
        account_pub: [u8; 32],
        invite: Option<String>,
        max_bundle_v: u16,
    ) -> Result<Self> {
        install_crypto_provider();
        let (ws, _resp) = connect_async(url)
            .await
            .map_err(|e| SignalError::Ws(e.to_string()))?;
        Self::handshake_owned(ws, store, handle, account_pub, invite, max_bundle_v).await
    }

    /// Same as [`Self::connect`], but trusting `ca_cert_pem` (one or more PEM certificates) as the
    /// **exclusive** TLS root instead of the OS/native trust store — for tests that stand up a
    /// self-signed `wss://` listener rather than reaching a real WebPKI-trusted host. Only built
    /// with `test-support` (this crate's `Cargo.toml`); never linked into a production binary.
    ///
    /// Calls [`install_crypto_provider`] first (below), same as [`Self::connect`], and this
    /// function's own `rustls::ClientConfig` is the first thing in a fresh test process to call
    /// `ClientConfig::builder()` (`apps/cli/tests/wss_tls.rs` defers its TLS-terminating test
    /// listener's `ServerConfig::builder()` call until after accepting the client's connection,
    /// specifically so no OTHER code in that process calls a rustls builder first).
    ///
    /// **Caveat (T3.13/F13 Outcome, read before trusting this as the mutation-check):** rustls
    /// 0.23's `ClientConfig::builder()`/`ServerConfig::builder()` silently self-install a default
    /// provider on first use when exactly one provider crate-feature is compiled in
    /// (`CryptoProvider::get_default_or_install_from_crate_features`) — true throughout this
    /// workspace, which only ever enables `ring`. That means deleting this function's (or
    /// [`Self::connect`]'s) call to [`install_crypto_provider`] does **not** make
    /// `wss_tls.rs` fail — rustls's own fallback quietly does the install instead. The genuinely
    /// mutation-sensitive proof for this task lives in `install_crypto_provider`'s own unit test,
    /// next to it below; this integration test still earns its keep by proving the rest of the
    /// `wss://` plumbing (root-trust wiring, the handshake, `connect_async_tls_with_config`) works
    /// end-to-end, just not that one specific line in isolation. See the task file's Outcome for
    /// the full investigation (an attempt to force genuine ambiguity via rustls's
    /// `custom-provider` feature broke an unrelated `dtls`/`webrtc` code path and was reverted).
    #[cfg(feature = "test-support")]
    pub async fn connect_with_test_ca_pem(
        url: &str,
        ca_cert_pem: &[u8],
        store: &dyn SecretStore,
        handle: &KeyHandle,
        account_pub: [u8; 32],
        invite: Option<String>,
        max_bundle_v: u16,
    ) -> Result<Self> {
        use rustls::pki_types::pem::PemObject;

        install_crypto_provider();
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(ca_cert_pem)
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| SignalError::Ws(format!("test CA pem: {e}")))?;
        if certs.is_empty() {
            return Err(SignalError::Ws("test CA pem: no certificates found".into()));
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| SignalError::Ws(format!("test CA pem: {e}")))?;
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(client_config));
        let (ws, _resp) =
            tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector))
                .await
                .map_err(|e| SignalError::Ws(e.to_string()))?;
        Self::handshake(ws, store, handle, account_pub, invite, max_bundle_v).await
    }

    /// Shared post-connect handshake: the server speaks first with a single-use challenge; sign
    /// `nonce ‖ server_domain` and register the account. Used by both [`Self::connect`] and (with
    /// `test-support`) [`Self::connect_with_test_ca_pem`] — the two differ only in how the
    /// underlying `WebSocketStream` was obtained.
    async fn handshake(
        ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        account_pub: [u8; 32],
        invite: Option<String>,
        max_bundle_v: u16,
    ) -> Result<Self> {
        let mut client = Self {
            ws,
            next_id: 1,
            account_pub,
            server_domain: String::new(),
            pending_delivers: VecDeque::new(),
            pending_mailbox_acks: Vec::new(),
        };

        // The server speaks first with a single-use challenge.
        let frame = client.recv_frame().await?;
        if frame.op != Op::Challenge {
            return Err(SignalError::Unexpected {
                got: frame.op,
                expected: "challenge",
            });
        }
        let challenge: Challenge = frame.decode()?;
        client.server_domain = challenge.server_domain.clone();

        // Sign nonce ‖ server_domain (domain binding defeats cross-server challenge replay).
        let mut to_sign = challenge.nonce.to_vec();
        to_sign.extend_from_slice(challenge.server_domain.as_bytes());
        let sig = sign(store, handle, &to_sign)?;

        let auth = Auth {
            account_pub,
            sig: *sig.as_bytes(),
            invite,
            max_bundle_v,
        };
        let reply = client
            .request(Op::Auth, &auth, Op::AuthOk, "auth_ok")
            .await?;
        let _ok: AuthOk = reply.decode()?;
        Ok(client)
    }

    /// The [`Self::connect_owned`]-only counterpart of [`Self::handshake`] — identical wire
    /// behavior and framing, differing only in running the one `sign()` call inside
    /// [`tokio::task::spawn_blocking`] against an owned `Arc<dyn SecretStore>` instead of
    /// synchronously against a borrow. See [`Self::connect_owned`]'s own doc comment for why.
    async fn handshake_owned(
        ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
        store: std::sync::Arc<dyn SecretStore>,
        handle: KeyHandle,
        account_pub: [u8; 32],
        invite: Option<String>,
        max_bundle_v: u16,
    ) -> Result<Self> {
        let mut client = Self {
            ws,
            next_id: 1,
            account_pub,
            server_domain: String::new(),
            pending_delivers: VecDeque::new(),
            pending_mailbox_acks: Vec::new(),
        };

        // The server speaks first with a single-use challenge.
        let frame = client.recv_frame().await?;
        if frame.op != Op::Challenge {
            return Err(SignalError::Unexpected {
                got: frame.op,
                expected: "challenge",
            });
        }
        let challenge: Challenge = frame.decode()?;
        client.server_domain = challenge.server_domain.clone();

        // Sign nonce ‖ server_domain (domain binding defeats cross-server challenge replay) —
        // off the calling task; see this method's own doc comment.
        let mut to_sign = challenge.nonce.to_vec();
        to_sign.extend_from_slice(challenge.server_domain.as_bytes());
        let sig = tokio::task::spawn_blocking(move || sign(store.as_ref(), &handle, &to_sign))
            .await
            .map_err(|e| SignalError::Ws(format!("signing task panicked: {e}")))??;

        let auth = Auth {
            account_pub,
            sig: *sig.as_bytes(),
            invite,
            max_bundle_v,
        };
        let reply = client
            .request(Op::Auth, &auth, Op::AuthOk, "auth_ok")
            .await?;
        let _ok: AuthOk = reply.decode()?;
        Ok(client)
    }

    /// The account key this session authenticated as.
    pub fn account_pub(&self) -> &[u8; 32] {
        &self.account_pub
    }

    /// The rendezvous domain this session is bound to.
    pub fn server_domain(&self) -> &str {
        &self.server_domain
    }

    /// Generate and publish a fresh prekey bundle (1 signed prekey + `otk_count` one-time
    /// prekeys). Returns the generated bundle *and its secret scalars* for the caller to persist.
    pub async fn publish_bundle(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        otk_count: usize,
    ) -> Result<GeneratedBundle> {
        let generated = generate_bundle(store, handle, self.account_pub, otk_count)?;
        let publish = Publish {
            bundle: generated.bundle.clone(),
        };
        let reply = self
            .request(Op::Publish, &publish, Op::PublishOk, "publish_ok")
            .await?;
        let _ok: PublishOk = reply.decode()?;
        Ok(generated)
    }

    /// Fetch a peer's bundle by **exact** account key and verify every signature under that key.
    /// A bundle that fails verification (including one claiming a different key) is a hard error —
    /// the client refuses to proceed rather than downgrading.
    ///
    /// `hint` is the wire-level routing hint (task 2.7, `docs/api/wire-protocol.md` §2): a plain
    /// domain string, `None` for a same-server (local) fetch, `Some(domain)` when `target` names an
    /// account this client believes lives at a *foreign* org's server. This client never dials
    /// `domain` itself — it only ever talks to the server it `connect`ed to (`self`'s own
    /// WebSocket); that server is solely responsible for deciding, from `hint`, whether to answer
    /// locally or federate the request onward (system-design.md §3.3 steps 2-4, ADR 0001: the hint
    /// is advisory routing information, never a trust input). The verification below is identical
    /// either way — it is the only trust anchor regardless of which path the bundle took.
    pub async fn fetch_bundle(
        &mut self,
        target: [u8; 32],
        hint: Option<String>,
        tamper: bool,
    ) -> Result<PrekeyBundle> {
        let fetch = Fetch {
            target,
            hint: hint.clone(),
            tamper,
        };
        let reply = self
            .request(Op::Fetch, &fetch, Op::Bundle, "bundle")
            .await
            .map_err(|e| crate::error::classify_federation_error(e, hint.as_deref()))?;
        let bundle: Bundle = reply.decode()?;
        verify_bundle(&target, &bundle.bundle)?;
        Ok(bundle.bundle)
    }

    /// Route an opaque, client-signed envelope to an online peer. Returns whether it was delivered
    /// live right now — `false` collapses both "queued into the recipient's offline mailbox, will
    /// arrive on reconnect" (T07) and "genuinely not delivered" into one bool; use
    /// [`route_with_hint_detailed`](Self::route_with_hint_detailed) when the caller needs to tell
    /// those apart.
    pub async fn route(&mut self, to: [u8; 32], blob: Vec<u8>) -> Result<bool> {
        self.route_with_hint(to, None, blob).await
    }

    /// Route an opaque, client-signed envelope to `to`, optionally naming a foreign-domain
    /// `hint` (task 2.8, `docs/api/wire-protocol.md` §2) — the wire-level routing hint that tells
    /// this client's own server to forward the envelope across a federation boundary
    /// (`FedRoute`, docs/api/federation-protocol-v1.md) rather than deliver locally. Same
    /// "this client never dials `hint` itself" caveat as
    /// [`fetch_bundle`](Self::fetch_bundle)'s identical parameter: only the server this client is
    /// `connect`ed to ever federates a request onward.
    ///
    /// Returns just `RouteOk.delivered` — see [`route_with_hint_detailed`](Self::route_with_hint_detailed)
    /// for a caller that also needs `RouteOk.queued` (T07, task 8.15: `delivered == false` no longer
    /// implies the envelope was dropped — it may have been durably queued into the recipient's
    /// mailbox instead).
    pub async fn route_with_hint(
        &mut self,
        to: [u8; 32],
        hint: Option<String>,
        blob: Vec<u8>,
    ) -> Result<bool> {
        self.route_with_hint_detailed(to, hint, blob)
            .await
            .map(|outcome| outcome.delivered)
    }

    /// Same request as [`route_with_hint`](Self::route_with_hint), but returns the full
    /// [`RouteOutcome`] instead of collapsing it to one bool — the mailbox-aware callers need to
    /// distinguish "queued for later delivery" (T07: `{delivered:false, queued:true}`) from
    /// "genuinely not delivered" (`{delivered:false, queued:false}`, e.g. `ttl_days == 0` at the
    /// recipient's server) rather than showing the same "offline, not delivered" copy for both.
    pub async fn route_with_hint_detailed(
        &mut self,
        to: [u8; 32],
        hint: Option<String>,
        blob: Vec<u8>,
    ) -> Result<RouteOutcome> {
        let body = RouteBody {
            to,
            to_hint: hint.clone(),
            blob: OpaqueBlob::new(blob),
        };
        let reply = self
            .request(Op::Route, &body, Op::RouteOk, "route_ok")
            .await
            .map_err(|e| crate::error::classify_federation_error(e, hint.as_deref()))?;
        let ok: RouteOk = reply.decode()?;
        Ok(RouteOutcome {
            delivered: ok.delivered,
            queued: ok.queued,
        })
    }

    /// Request an ephemeral TURN credential, distinct per request, for a new P2P session (T05,
    /// §5.4). The returned [`TurnGrant`] carries the candidate ladder (TURN/UDP → TURN/TCP →
    /// TURN/TLS-443) and an HMAC credential the client feeds straight into its ICE config — no
    /// static TURN secret ever touches the client (webrtc-nat-traversal invariant 4). Reuse of a
    /// captured credential within its TTL is bounded by coturn's `user-quota`, not rejected outright.
    /// A `turn_unavailable` error means the org runs no relay (air-gapped / dev); the caller falls
    /// back to the host/STUN ladder.
    pub async fn request_turn_credentials(&mut self) -> Result<TurnGrant> {
        let reply = self
            .request(
                Op::TurnReq,
                &TurnReq::default(),
                Op::TurnGrant,
                "turn_grant",
            )
            .await?;
        Ok(reply.decode()?)
    }

    /// Await the next envelope delivered to this client.
    ///
    /// (task 8.8) If the returned [`Deliver`] carries a [`Deliver::mailbox_id`] (a mailbox-drained
    /// push, task 8.7), that id is recorded internally as soon as this method hands the frame back
    /// — never sent over the wire yet. Call [`ack_pending_mailbox`](Self::ack_pending_mailbox),
    /// once the caller has durably processed everything it has received so far, to actually flush
    /// a `MailboxAck` covering every id accumulated since the last flush.
    pub async fn next_deliver(&mut self) -> Result<Deliver> {
        let deliver = if let Some(d) = self.pending_delivers.pop_front() {
            d
        } else {
            let frame = self.recv_frame().await?;
            match frame.op {
                Op::Deliver => frame.decode()?,
                Op::Err => return Err(SignalError::Server(frame.decode()?)),
                other => {
                    return Err(SignalError::Unexpected {
                        got: other,
                        expected: "deliver",
                    })
                }
            }
        };
        Self::record_mailbox_ack(&mut self.pending_mailbox_acks, &deliver);
        Ok(deliver)
    }

    /// (Task 9.6, phase-9 review finding F3.) Accumulate `deliver.mailbox_id`, if present, into
    /// `pending`, with **no attempt to verify it corresponds to an actual mailbox drain** — this
    /// client has no wire-level signal that distinguishes "a genuinely queued row this push just
    /// drained" from "an ordinary live delivery the server happened to tag with a `mailbox_id`
    /// anyway" (there is no drain-batch marker in the protocol, and adding one would be a
    /// `meridian-proto` wire change, not a fix to this call site).
    ///
    /// **This is an accepted, bounded trust boundary — the same class of question
    /// `docs/adr/0024-mailbox-drain-from-attestation.md` already reasoned through for
    /// `Deliver.from`, applied here to the sibling `mailbox_id` field.** Unlike `Deliver.from`
    /// (whose real trust anchor is `envelope.sender_pub` plus the ratchet AEAD, ADR 0024's whole
    /// point), `mailbox_id` has no cryptographic backstop of its own — the client simply trusts
    /// whatever the server sends, then echoes it back in a later `MailboxAck`. The blast radius of
    /// that trust is bounded server-side, not client-side: `Store::mailbox_delete_by_ids`
    /// (`apps/rendezvous/src/store.rs`, `ws.rs`'s `MailboxAck` handler) deletes only rows matching
    /// *both* an acked id *and* the authenticated connection's own `account_pub` — a buggy or
    /// malicious server can at worst trick this client into acking (and thereby losing) one of its
    /// **own** genuine queued mailbox rows early. It can never name another account's row (no
    /// cross-account capability — the scoping is structural, not a check that can be forgotten) and
    /// it never reveals anything about mailbox contents either way (no confidentiality break — the
    /// row, like every mailbox row, is ciphertext-only). Adding client-side drain-batch validation
    /// to close this residual would require a wire protocol change for a bound already this narrow;
    /// not undertaken here.
    ///
    /// One distinction from `Deliver.from` worth naming: that field's forgery is cryptographically
    /// inert (it feeds only a local equality check ADR 0024 already waives, never a stored-state
    /// mutation), while an acked `mailbox_id` DOES drive a real server-side `DELETE` once flushed —
    /// so unlike `Deliver.from`, this trust decision has a live side effect. It stays within the
    /// bound above regardless: the worst case is message loss on this account's own mailbox, which
    /// grants a malicious server no capability beyond what it already has by simply not delivering
    /// the message at all (`docs/security/threat-model.md`'s accepted A2: a malicious/compromised
    /// server can drop or delay messages, but never silently weaken a session or read plaintext).
    /// See `docs/architecture/features/07-offline-mailbox.md` for the written record of this
    /// decision and its bound.
    fn record_mailbox_ack(pending: &mut Vec<u64>, deliver: &Deliver) {
        if let Some(id) = deliver.mailbox_id {
            pending.push(id);
        }
    }

    /// (task 8.8, ADR 0024) Flush a `MailboxAck` covering every mailbox row id accumulated by
    /// [`next_deliver`](Self::next_deliver) since the last call to this method — one wire frame
    /// for the whole accumulated batch, not one per envelope. A no-op (no network I/O at all) when
    /// nothing is pending.
    ///
    /// **Callers must call this only once every accumulated envelope has been durably
    /// processed** — the local session/persistence state mutation each one caused (installing a
    /// session, advancing a ratchet, consuming a one-time prekey) must already be saved to disk —
    /// **never merely "received"**. The server deletes the acked rows unconditionally; acking
    /// before the corresponding processing is durable would lose the message forever on a crash
    /// between the ack and that persistence. This is why accumulation ([`next_deliver`]) and
    /// flushing (this method) are two separate steps instead of one: the caller, not this client,
    /// is the only party that knows when "processed" has actually become durable.
    ///
    /// On a request failure, the accumulated ids are restored (not dropped) so a caller that keeps
    /// using this same client can retry the flush later; a genuinely torn-down connection drops
    /// this in-memory state anyway once the caller reconnects with a fresh `SignalingClient` — the
    /// unacked rows simply get redrained on that reconnect (task 8.7's own guarantee), which is
    /// exactly the intended fail-safe, not a bug.
    pub async fn ack_pending_mailbox(&mut self) -> Result<()> {
        if self.pending_mailbox_acks.is_empty() {
            return Ok(());
        }
        let ids = std::mem::take(&mut self.pending_mailbox_acks);
        let body = MailboxAck { ids: ids.clone() };
        match self
            .request(Op::MailboxAck, &body, Op::MailboxAckOk, "mailbox_ack_ok")
            .await
        {
            Ok(reply) => {
                let _ok: MailboxAckOk = reply.decode()?;
                Ok(())
            }
            Err(e) => {
                self.pending_mailbox_acks.extend(ids);
                Err(e)
            }
        }
    }

    /// (task 8.8, review finding 2) Remove `id` from the pending-ack accumulator without sending
    /// anything, if it is still queued there — for a caller that discovers, after
    /// [`next_deliver`](Self::next_deliver) already accumulated a mailbox-tagged delivery's id,
    /// that THIS delivery's own processing did not durably persist (e.g. a local `sessions.bin`
    /// write failure). Without this, a later, unrelated delivery's own successful
    /// [`ack_pending_mailbox`](Self::ack_pending_mailbox) flush would sweep up this still-queued
    /// id and delete its mailbox row even though its local processing was never made durable —
    /// reproducing exactly the crash-between-ack-and-processing loss this task exists to avoid,
    /// just via the batch accumulator rather than a single-message race. A no-op if `id` is not
    /// currently queued (already flushed, or this delivery never carried a `mailbox_id` at all).
    pub fn discard_pending_mailbox_ack(&mut self, id: u64) {
        self.pending_mailbox_acks.retain(|&x| x != id);
    }

    /// Close the WebSocket cleanly.
    pub async fn close(mut self) -> Result<()> {
        self.ws
            .close(None)
            .await
            .map_err(|e| SignalError::Ws(e.to_string()))
    }

    // -- internals -----------------------------------------------------------

    async fn send(&mut self, op: Op, body: &impl Serialize) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let frame = Frame::new(op, id, body)?;
        let bytes = frame.to_bytes()?;
        self.ws
            .send(Message::Binary(bytes))
            .await
            .map_err(|e| SignalError::Ws(e.to_string()))?;
        Ok(id)
    }

    /// Send a request and read frames until the matching reply (buffering interleaved delivers).
    async fn request(
        &mut self,
        op: Op,
        body: &impl Serialize,
        expect: Op,
        expected_name: &'static str,
    ) -> Result<Frame> {
        let _id = self.send(op, body).await?;
        loop {
            let frame = self.recv_frame().await?;
            match frame.op {
                Op::Deliver => self.pending_delivers.push_back(frame.decode()?),
                Op::Err => return Err(SignalError::Server(frame.decode()?)),
                got if got == expect => return Ok(frame),
                got => {
                    return Err(SignalError::Unexpected {
                        got,
                        expected: expected_name,
                    })
                }
            }
        }
    }

    async fn recv_frame(&mut self) -> Result<Frame> {
        while let Some(msg) = self.ws.next().await {
            let msg = msg.map_err(|e| SignalError::Ws(e.to_string()))?;
            match msg {
                Message::Binary(bytes) => return Ok(Frame::from_bytes(&bytes)?),
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => return Err(SignalError::ClosedEarly("frame")),
                Message::Text(_) => return Err(SignalError::Ws("unexpected text frame".into())),
                _ => continue,
            }
        }
        Err(SignalError::ClosedEarly("frame"))
    }
}

#[cfg(test)]
mod tests {
    use super::{install_crypto_provider, SignalingClient};
    use meridian_proto::{Deliver, OpaqueBlob};

    /// T3.13/F13: deleting `install_crypto_provider`'s body (or its call site in
    /// [`super::SignalingClient::connect`]) must turn this test red — every `wss://` connection
    /// was dead on arrival (runtime panic, no `CryptoProvider`) before this was fixed, and nothing
    /// tested it. This is the narrowest possible non-vacuous check: it doesn't prove `connect()`
    /// itself calls this (the stronger, `test-support`-gated integration test in
    /// `apps/cli/tests/wss_tls.rs` does that, over a real self-signed TLS handshake), but it does
    /// prove the extracted function actually installs a usable default provider.
    #[test]
    fn install_crypto_provider_installs_a_default() {
        install_crypto_provider();
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "install_crypto_provider() must leave a default rustls CryptoProvider installed"
        );
    }

    /// Task 9.6 (phase-9 review finding F3), mirrors ADR 0024's reasoning shape for the sibling
    /// `Deliver.from` field. This client has no wire-level way to tell "a genuine mailbox drain"
    /// apart from "an ordinary live delivery the server happened to tag with a `mailbox_id`" — a
    /// `Deliver` carrying `from` that is neither the recipient's own key nor the ADR-0024
    /// `MAILBOX_DRAIN_FROM_PLACEHOLDER` sentinel looks exactly like a live push, yet still gets its
    /// `mailbox_id` accumulated for a future `MailboxAck` here. That is the accepted, bounded trust
    /// boundary this task documents (see `record_mailbox_ack`'s own doc comment and
    /// `docs/architecture/features/07-offline-mailbox.md`): worst case, the server tricks this
    /// client into acking one of its own genuine queued rows early — never another account's row,
    /// never a confidentiality break. This test proves the *documented* behavior (accumulate
    /// regardless of provenance), not an absence of validation — if a future change adds drain-batch
    /// validation instead, this test must be rewritten (not merely relaxed) to assert rejection.
    #[test]
    fn mailbox_id_on_a_live_looking_deliver_is_still_accumulated() {
        let live_looking_deliver = Deliver {
            // Neither the ADR-0024 mailbox-drain sentinel nor otherwise distinguishable from a
            // real, live-routed `Deliver` — an ordinary connection's own `account_pub` assertion.
            from: [7u8; 32],
            blob: OpaqueBlob(vec![1, 2, 3]),
            mailbox_id: Some(42),
        };
        let mut pending = Vec::new();
        SignalingClient::record_mailbox_ack(&mut pending, &live_looking_deliver);
        assert_eq!(
            pending,
            vec![42],
            "mailbox_id from ANY Deliver (drained or live-looking) accumulates unconditionally — \
             the accepted trust boundary task 9.6 documents, not a bug"
        );

        // A `Deliver` with no `mailbox_id` at all (the ordinary live-route shape) must never add
        // anything, regardless of `from`.
        let ordinary_live_deliver = Deliver {
            from: [9u8; 32],
            blob: OpaqueBlob(vec![4, 5, 6]),
            mailbox_id: None,
        };
        SignalingClient::record_mailbox_ack(&mut pending, &ordinary_live_deliver);
        assert_eq!(
            pending,
            vec![42],
            "a Deliver without mailbox_id must never be accumulated"
        );
    }
}
