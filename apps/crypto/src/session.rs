//! A 1:1 E2EE session: X3DH establishment + the ongoing Double Ratchet, plus the persistable
//! state behind it. This is the unit the session layer stores (sealed) and drives.
//!
//! `Session` is `Serialize`/`Deserialize` so the caller can seal it under a keystore-derived key
//! for at-rest persistence (system-design §4.7) — it MUST never be written out unsealed.

use meridian_store::{KeyHandle, SecretStore};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::fingerprint::safety_number;
use crate::ratchet::DoubleRatchet;
use crate::x3dh;

/// The prekey material the initiator must transmit in its first envelope so the responder can
/// reconstruct X3DH: the ephemeral public key and which of the responder's prekeys were consumed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrekeyMaterial {
    pub ek_pub: [u8; 32],
    pub used_spk: [u8; 32],
    pub used_opk: Option<[u8; 32]>,
}

/// An established (or establishing) session with one peer identity.
#[derive(Serialize, Deserialize)]
pub struct Session {
    /// The peer's Ed25519 account identity key.
    pub peer_ik: [u8; 32],
    /// Whether we initiated (ran X3DH as Alice). Diagnostic / trust surface.
    pub initiator: bool,
    /// Set once we have successfully decrypted a message from the peer — proof the handshake
    /// completed on their side. Until then the initiator re-attaches the prekey preamble so a lost
    /// opening message doesn't strand the session (async X3DH).
    #[serde(default)]
    confirmed: bool,
    /// The prekey preamble to re-attach while unconfirmed (initiator only).
    #[serde(default)]
    prekey: Option<PrekeyMaterial>,
    ratchet: DoubleRatchet,
}

impl Session {
    /// Establish a session as the **initiator** against a verified peer bundle. Returns the new
    /// session and the [`PrekeyMaterial`] to attach to the first envelope. `peer_spk`/`peer_opk`
    /// come from the (already signature-verified) bundle.
    pub fn initiate(
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        peer_ik: &[u8; 32],
        peer_spk: &[u8; 32],
        peer_opk: Option<[u8; 32]>,
    ) -> Result<(Self, PrekeyMaterial)> {
        let out = x3dh::initiate(store, handle, our_ik, peer_ik, peer_spk, peer_opk)?;
        let ratchet = DoubleRatchet::init_initiator(
            out.result.root,
            out.used_spk,
            out.result.hka,
            out.result.nhkb,
            out.result.ad,
        )?;
        let material = PrekeyMaterial {
            ek_pub: out.ek_pub,
            used_spk: out.used_spk,
            used_opk: out.used_opk,
        };
        Ok((
            Self {
                peer_ik: *peer_ik,
                initiator: true,
                confirmed: false,
                prekey: Some(material.clone()),
                ratchet,
            },
            material,
        ))
    }

    /// Establish a session as the **responder** from a received prekey message. `spk_secret` and
    /// `opk_secret` are the X25519 secrets behind the prekeys the initiator used (looked up from
    /// the locally-held bundle secrets by `material.used_spk` / `material.used_opk`).
    #[allow(clippy::too_many_arguments)]
    pub fn respond(
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        peer_ik: &[u8; 32],
        material: &PrekeyMaterial,
        spk_secret: &[u8; 32],
        opk_secret: Option<[u8; 32]>,
    ) -> Result<Self> {
        let result = x3dh::respond(
            store,
            handle,
            our_ik,
            peer_ik,
            &material.ek_pub,
            spk_secret,
            opk_secret,
        )?;
        let ratchet = DoubleRatchet::init_responder(
            result.root,
            *spk_secret,
            material.used_spk,
            result.hka,
            result.nhkb,
            result.ad,
        );
        Ok(Self {
            peer_ik: *peer_ik,
            initiator: false,
            confirmed: true,
            prekey: None,
            ratchet,
        })
    }

    /// Ratchet-encrypt an outbound plaintext (the CBOR of a `mrd.chat/1` payload).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.ratchet.encrypt(plaintext)
    }

    /// Ratchet-decrypt an inbound ratchet message. Marks the session confirmed on success.
    pub fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let pt = self.ratchet.decrypt(message)?;
        self.confirmed = true;
        self.prekey = None;
        Ok(pt)
    }

    /// Whether the opening message(s) should still carry the X3DH prekey preamble: true for an
    /// initiator that has not yet received a reply.
    pub fn needs_prekey(&self) -> bool {
        self.initiator && !self.confirmed
    }

    /// The prekey preamble to attach while [`needs_prekey`](Self::needs_prekey) holds.
    pub fn prekey_material(&self) -> Option<&PrekeyMaterial> {
        self.prekey.as_ref()
    }

    /// The order-independent safety number for this session (needs our own identity key).
    pub fn safety_number(&self, our_ik: &[u8; 32]) -> String {
        safety_number(our_ik, &self.peer_ik)
    }
}
