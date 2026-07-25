//! Chat session manager (T03): the transport-agnostic glue that turns `mrd.chat/1` payloads into
//! signed, ratchet-encrypted [`MessageEnvelope`]s and back, and owns the persistable session state.
//!
//! This is deliberately I/O-free: it does not touch the network. The CLI (or any shim) fetches
//! bundles + routes/delivers opaque blobs via [`meridian_signaling`], and calls in here to
//! seal/open the content. That separation is the point of §4.3: the *same* ratcheted envelopes
//! ride the relay today and P2P/mailbox later, unchanged.
//!
//! Security: every inbound envelope is signature-verified under the sender's claimed identity key
//! **before** its payload is decrypted (crypto-protocols rule 4), and the claimed key is checked
//! against the routing `from`. The whole state is sealed at rest under a keystore-derived key.

use std::collections::BTreeMap;

use meridian_crypto::{at_rest, PrekeyMaterial, Session};
use meridian_envelope::{ChatContent, MessageEnvelope, Prekey};
use meridian_identity::{sign, verify, KeyHandle, PublicKey, SecretStore, Signature};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Errors from the chat session manager.
#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    #[error("crypto error: {0}")]
    Crypto(#[from] meridian_crypto::CryptoError),
    #[error("wire codec error: {0}")]
    Codec(#[from] meridian_proto::CodecError),
    #[error("keystore error: {0}")]
    Store(#[from] meridian_store::StoreError),
    /// The envelope's signature did not verify under its claimed sender key — reject, never
    /// downgrade (anonymity-and-retention "must never" #5).
    #[error("envelope signature verification failed")]
    BadSignature,
    /// The sender key inside the envelope did not match the routing `from`.
    #[error("envelope sender does not match routing origin")]
    SenderMismatch,
    /// A prekey message referenced a signed/one-time prekey we do not hold the secret for.
    #[error("no matching prekey secret for incoming session")]
    UnknownPrekey,
    /// A first message from an unknown peer arrived without the X3DH preamble.
    #[error("no session and no prekey preamble to establish one")]
    NoSession,
}

/// How long a *superseded* prekey generation stays usable after a republish, in seconds (task 1.31).
///
/// Every `session connect` / `chat` invocation republishes a fresh bundle, so a peer whose fetch
/// landed on the bundle that was current a moment ago would otherwise hit a hard
/// [`ChatError::UnknownPrekey`] on its X3DH init (a reconnect race, not a hostile input). 60 seconds
/// comfortably covers that race — fetch → X3DH → route → deliver is single-digit seconds even over a
/// relayed path with retries — while staying far below any real prekey-rotation period, so the
/// window in which a compromise of the *old* secrets could still open a session stays negligible.
/// Forward secrecy is bounded on both axes: at most **one** prior generation is ever retained
/// (see [`PrekeyVault::set_bundle`]) and it is dropped + zeroized once this window passes (see
/// [`PrekeyVault::expire_previous_generation`]).
pub const PREV_GENERATION_GRACE_SECS: u64 = 60;

/// One published one-time prekey's key pair (public + X25519 secret).
///
/// The secret is zeroized on drop (matching `meridian-crypto`'s `DoubleRatchet` style), so removing
/// an OTK from a generation — on consumption, expiry, or rotation — clears its key material.
#[derive(Clone, Serialize, Deserialize)]
struct Otk {
    #[serde(with = "b32")]
    public: [u8; 32],
    #[serde(with = "b32")]
    secret: [u8; 32],
}

impl Drop for Otk {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// The single retained *previous* prekey generation: the secrets behind the bundle that the most
/// recent [`PrekeyVault::set_bundle`] superseded, plus the absolute unix second at which they stop
/// being accepted. The expiry is stored absolute (not as a duration) precisely so it survives the
/// at-rest seal/open round-trip unchanged.
#[derive(Clone, Serialize, Deserialize)]
struct PrevGeneration {
    #[serde(with = "opt_b32", default)]
    spk_public: Option<[u8; 32]>,
    #[serde(with = "opt_b32", default)]
    spk_secret: Option<[u8; 32]>,
    #[serde(default)]
    otks: Vec<Otk>,
    #[serde(default)]
    expires_at_unix: u64,
}

impl PrevGeneration {
    /// Zeroize every secret-bearing field in place. Shared by [`Drop::drop`] and mirrors
    /// `meridian_crypto`'s ratchet convention.
    fn zeroize_secrets(&mut self) {
        if let Some(mut s) = self.spk_secret.take() {
            s.zeroize();
        }
        // Each `Otk`'s own `Drop` clears its secret too; do it here as well so an in-place
        // zeroize (without a drop) leaves nothing behind.
        for o in &mut self.otks {
            o.secret.zeroize();
        }
        self.otks.clear();
    }
}

impl Drop for PrevGeneration {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

/// The local secrets behind this account's *published* prekey bundle — needed to answer incoming
/// X3DH handshakes. One-time prekeys are consumed (removed) on first use.
///
/// A republish rotates the current generation into a single "previous" slot for
/// [`PREV_GENERATION_GRACE_SECS`] so a peer that fetched the just-superseded bundle can still
/// complete X3DH (task 1.31's reconnect race). One-time prekeys stay single-use *across* both
/// generations.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct PrekeyVault {
    #[serde(with = "opt_b32", default)]
    spk_public: Option<[u8; 32]>,
    #[serde(with = "opt_b32", default)]
    spk_secret: Option<[u8; 32]>,
    otks: Vec<Otk>,
    /// At most one superseded generation, retained for a bounded window. `serde(default)` so a
    /// state sealed before 1.31 still opens.
    #[serde(default)]
    previous: Option<PrevGeneration>,
}

impl PrekeyVault {
    /// Record the secrets for a freshly published bundle, rotating the outgoing generation into the
    /// bounded-lifetime "previous" slot.
    ///
    /// `now_unix` is the caller's wall clock in unix seconds: this crate is deliberately clock-free
    /// (it compiles to wasm32, where `std::time::SystemTime::now()` is unavailable), so time is
    /// injected rather than read here. The previous generation's expiry is recorded as
    /// `now_unix + PREV_GENERATION_GRACE_SECS` and enforced by
    /// [`expire_previous_generation`](Self::expire_previous_generation).
    ///
    /// Retention is hard-bounded to **one** generation: this replaces (and therefore zeroizes)
    /// whatever was in the previous slot, so a chain of republishes can never accumulate a tail of
    /// live prekey secrets.
    pub fn set_bundle(
        &mut self,
        spk_public: [u8; 32],
        spk_secret: [u8; 32],
        otks: impl IntoIterator<Item = ([u8; 32], [u8; 32])>,
        now_unix: u64,
    ) {
        let prior_public = self.spk_public.take();
        let prior_secret = self.spk_secret.take();
        let prior_otks = std::mem::take(&mut self.otks);
        // Assigning here drops the old `previous` (zeroizing it via `PrevGeneration::drop`).
        self.previous = match (prior_public, prior_secret) {
            (Some(p), Some(s)) => Some(PrevGeneration {
                spk_public: Some(p),
                spk_secret: Some(s),
                otks: prior_otks,
                expires_at_unix: now_unix.saturating_add(PREV_GENERATION_GRACE_SECS),
            }),
            // Nothing was published before (first-ever publish): nothing to retain, and any
            // older previous generation is dropped rather than carried forward.
            _ => None,
        };
        self.spk_public = Some(spk_public);
        self.spk_secret = Some(spk_secret);
        self.otks = otks
            .into_iter()
            .map(|(public, secret)| Otk { public, secret })
            .collect();
    }

    /// Drop + zeroize the retained previous generation once its grace window has passed.
    ///
    /// Time is supplied by the caller for the same reason as in [`set_bundle`](Self::set_bundle).
    /// Callers that answer incoming X3DH handshakes should call this (with a real wall clock)
    /// before opening inbound blobs, so a superseded generation fails closed with
    /// [`ChatError::UnknownPrekey`] once expired instead of being silently accepted.
    pub fn expire_previous_generation(&mut self, now_unix: u64) {
        let expired = self
            .previous
            .as_ref()
            .map(|p| now_unix >= p.expires_at_unix)
            .unwrap_or(false);
        if expired {
            self.previous = None;
        }
    }

    fn spk_secret_for(&self, spk_public: &[u8; 32]) -> Option<[u8; 32]> {
        // Exact match on the requested SPK only — never substitute a different one.
        if let (Some(p), Some(s)) = (self.spk_public, self.spk_secret) {
            if &p == spk_public {
                return Some(s);
            }
        }
        // Grace window: a fetch that landed on the just-superseded bundle must still complete.
        let prev = self.previous.as_ref()?;
        match (prev.spk_public, prev.spk_secret) {
            (Some(p), Some(s)) if &p == spk_public => Some(s),
            _ => None,
        }
    }

    /// Consume the secret for `opk_public`, whichever generation holds it.
    ///
    /// Single-use is enforced *across* generations: the OTK is removed from the current generation
    /// **and** from the retained previous one, so one published one-time prekey can never establish
    /// two sessions (a second attempt with the same public returns `None` →
    /// [`ChatError::UnknownPrekey`]).
    fn take_otk_secret(&mut self, opk_public: &[u8; 32]) -> Option<[u8; 32]> {
        let from_current = take_otk(&mut self.otks, opk_public);
        let from_prev = self
            .previous
            .as_mut()
            .and_then(|p| take_otk(&mut p.otks, opk_public));
        from_current.or(from_prev)
    }
}

/// Remove **every** entry matching `opk_public` from `otks`, returning the first secret found.
/// Removing all matches (rather than just the first) is what makes single-use robust even if the
/// same public somehow appears twice; each removed [`Otk`] zeroizes its own copy on drop.
fn take_otk(otks: &mut Vec<Otk>, opk_public: &[u8; 32]) -> Option<[u8; 32]> {
    let mut found = None;
    let mut i = 0;
    while i < otks.len() {
        if &otks[i].public == opk_public {
            let otk = otks.remove(i);
            if found.is_none() {
                found = Some(otk.secret);
            }
        } else {
            i += 1;
        }
    }
    found
}

/// The full persistable chat state: the prekey vault + all live sessions, keyed by peer identity.
#[derive(Default, Serialize, Deserialize)]
pub struct ChatState {
    pub vault: PrekeyVault,
    sessions: BTreeMap<[u8; 32], Session>,
}

impl ChatState {
    /// Whether a session with `peer_ik` already exists.
    pub fn has_session(&self, peer_ik: &[u8; 32]) -> bool {
        self.sessions.contains_key(peer_ik)
    }

    /// Insert an initiator session established elsewhere (after fetch+verify+X3DH).
    pub fn insert_session(&mut self, session: Session) {
        self.sessions.insert(session.peer_ik, session);
    }

    /// Establish an **initiator** session against a peer's already-verified bundle keys and store
    /// it. Idempotent per peer: a second call is a no-op so re-opening a chat keeps the live
    /// ratchet (no re-handshake). `peer_spk`/`peer_opk` come from the fetched, signature-verified
    /// bundle (caller MUST have verified it under `peer_ik`).
    pub fn start_initiator_session(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        peer_ik: &[u8; 32],
        peer_spk: &[u8; 32],
        peer_opk: Option<[u8; 32]>,
    ) -> Result<(), ChatError> {
        if self.sessions.contains_key(peer_ik) {
            return Ok(());
        }
        let (session, _material) =
            Session::initiate(store, handle, our_ik, peer_ik, peer_spk, peer_opk)?;
        self.sessions.insert(*peer_ik, session);
        Ok(())
    }

    /// Safety number for a peer session, if present.
    pub fn safety_number(&self, our_ik: &[u8; 32], peer_ik: &[u8; 32]) -> Option<String> {
        self.sessions.get(peer_ik).map(|s| s.safety_number(our_ik))
    }

    /// Build a signed, ratchet-encrypted envelope for `content` to `peer_ik`. See [`seal_bytes`] for
    /// the generic primitive; this is the `mrd.chat/1` convenience wrapper.
    ///
    /// [`seal_bytes`]: ChatState::seal_bytes
    pub fn seal_outbound(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        peer_ik: &[u8; 32],
        content: &ChatContent,
    ) -> Result<Vec<u8>, ChatError> {
        self.seal_bytes(store, handle, our_ik, peer_ik, &content.encode()?)
    }

    /// Seal an **arbitrary** ratchet plaintext into a signed [`MessageEnvelope`] blob on the session
    /// with `peer_ik`. The same primitive carries `mrd.chat/1` payloads and the P2P substrate's
    /// `SignalContent` (SDP/ICE/ctrl) over one ratchet — the transport-independence of §4.3: the
    /// same envelope bytes are valid over WSS routing, the mailbox, or a data channel.
    ///
    /// The session must already exist (initiator: [`Session::initiate`]; responder: created on first
    /// receive via [`open_bytes`](ChatState::open_bytes)).
    pub fn seal_bytes(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        peer_ik: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ChatError> {
        let session = self.sessions.get_mut(peer_ik).ok_or(ChatError::NoSession)?;
        let ct = session.encrypt(plaintext)?;
        let prekey = if session.needs_prekey() {
            session.prekey_material().map(to_wire_prekey)
        } else {
            None
        };
        let sig = sign(
            store,
            handle,
            &MessageEnvelope::signing_input(our_ik, &prekey, &ct),
        )?;
        let envelope = MessageEnvelope {
            sender_pub: *our_ik,
            prekey,
            ct,
            sig: *sig.as_bytes(),
        };
        Ok(envelope.to_blob()?)
    }

    /// Verify + decrypt an inbound opaque blob delivered from `from`, establishing a responder
    /// session if this is a prekey message. Returns the decoded chat payload.
    pub fn open_inbound(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        from: &[u8; 32],
        blob: &[u8],
    ) -> Result<ChatContent, ChatError> {
        let plaintext = self.open_bytes(store, handle, our_ik, from, blob)?;
        Ok(ChatContent::decode(&plaintext)?)
    }

    /// Verify + decrypt an inbound blob to its raw ratchet plaintext, establishing a responder
    /// session on a prekey message. The generic counterpart of [`open_inbound`](Self::open_inbound),
    /// used by the substrate to open `SignalContent` on the same ratchet as chat. Every inbound
    /// envelope is signature-verified under its claimed sender key **before** decryption, and the
    /// claimed key is checked against the routing `from` (crypto-protocols rule 4).
    pub fn open_bytes(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        from: &[u8; 32],
        blob: &[u8],
    ) -> Result<Vec<u8>, ChatError> {
        let envelope = MessageEnvelope::from_blob(blob)?;
        if &envelope.sender_pub != from {
            return Err(ChatError::SenderMismatch);
        }
        let pk = PublicKey::from_bytes(envelope.sender_pub).map_err(|_| ChatError::BadSignature)?;
        if !verify(
            &pk,
            &envelope.signing_bytes(),
            &Signature::from_bytes(envelope.sig),
        ) {
            return Err(ChatError::BadSignature);
        }

        // Establish a responder session on the first (prekey) message, if we don't have one.
        if !self.sessions.contains_key(&envelope.sender_pub) {
            let prekey = envelope.prekey.as_ref().ok_or(ChatError::NoSession)?;
            let material = PrekeyMaterial {
                ek_pub: prekey.ek_pub,
                used_spk: prekey.used_spk,
                used_opk: prekey.used_opk,
            };
            let spk_secret = self
                .vault
                .spk_secret_for(&prekey.used_spk)
                .ok_or(ChatError::UnknownPrekey)?;
            let opk_secret = match prekey.used_opk {
                Some(opk) => Some(
                    self.vault
                        .take_otk_secret(&opk)
                        .ok_or(ChatError::UnknownPrekey)?,
                ),
                None => None,
            };
            let session = Session::respond(
                store,
                handle,
                our_ik,
                &envelope.sender_pub,
                &material,
                &spk_secret,
                opk_secret,
            )?;
            self.sessions.insert(envelope.sender_pub, session);
        }

        let session = self
            .sessions
            .get_mut(&envelope.sender_pub)
            .ok_or(ChatError::NoSession)?;
        Ok(session.decrypt(&envelope.ct)?)
    }

    /// Serialize and seal the whole state under a key derived from the account key in `store`.
    pub fn seal_at_rest(
        &self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
    ) -> Result<Vec<u8>, ChatError> {
        let mut plaintext = Vec::new();
        ciborium::into_writer(self, &mut plaintext)
            .map_err(|e| meridian_proto::CodecError::Encode(e.to_string()))?;
        let key = self.store_key(store, handle)?;
        Ok(at_rest::seal(&key, &plaintext)?)
    }

    /// Open a state previously produced by [`seal_at_rest`](Self::seal_at_rest).
    pub fn open_at_rest(
        store: &dyn SecretStore,
        handle: &KeyHandle,
        sealed: &[u8],
    ) -> Result<Self, ChatError> {
        let key = store_key(store, handle)?;
        let plaintext = at_rest::open(&key, sealed)?;
        let state = ciborium::from_reader(&plaintext[..])
            .map_err(|e| meridian_proto::CodecError::Decode(e.to_string()))?;
        Ok(state)
    }

    fn store_key(
        &self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
    ) -> Result<[u8; 32], ChatError> {
        store_key(store, handle)
    }
}

fn store_key(store: &dyn SecretStore, handle: &KeyHandle) -> Result<[u8; 32], ChatError> {
    // Derive directly through the store (private key never leaves it), independent of any
    // signature algorithm's determinism (task 1.7, review finding F7).
    Ok(store.derive_key(handle, at_rest::STORE_KEY_INFO)?)
}

fn to_wire_prekey(m: &PrekeyMaterial) -> Prekey {
    Prekey {
        ek_pub: m.ek_pub,
        used_spk: m.used_spk,
        used_opk: m.used_opk,
    }
}

// Local byte-string serde helpers (kept private to the crate; proto's equivalents are pub(crate)).
mod b32 {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let v = serde_bytes_vec(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
    fn serde_bytes_vec<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a byte string")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = a.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V)
    }
}

mod opt_b32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&Wrap(*b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let o: Option<Wrap> = Option::deserialize(d)?;
        Ok(o.map(|w| w.0))
    }
    struct Wrap([u8; 32]);
    impl Serialize for Wrap {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            super::b32::serialize(&self.0, s)
        }
    }
    impl<'de> Deserialize<'de> for Wrap {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            Ok(Wrap(super::b32::deserialize(d)?))
        }
    }
}
