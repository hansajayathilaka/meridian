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

    /// Ratchet-encrypt an outbound plaintext (the CBOR of a `mrd.chat/1` payload). The v2 AAD's
    /// per-message preamble component (ADR 0016 C3) is derived here from this session's own
    /// `needs_prekey()`/`prekey_material()` state — the exact same state the caller
    /// (`apps/core/src/chat.rs::seal_bytes`) separately reads, right after this call, to decide
    /// what `Prekey` (if any) to attach to the wire envelope. Both derivations MUST stay in lock
    /// step; see [`preamble_bytes`]'s own doc comment for why the encoding itself is duplicated
    /// (not shared) with `meridian_envelope::preamble_aad_bytes`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let preamble = self.outbound_preamble_bytes();
        self.ratchet.encrypt(plaintext, &preamble)
    }

    /// The v2 preamble-AAD bytes (ADR 0016 C3) that [`encrypt`](Self::encrypt) would bind into its
    /// *next* outbound message right now — i.e. exactly what a caller with no `MessageEnvelope` of
    /// its own (a lower-level test, or a future non-`meridian-envelope` caller) needs in order to
    /// exercise [`decrypt`](Self::decrypt)'s explicit-preamble contract correctly. Ordinary callers
    /// that do have a wire envelope should prefer `meridian_envelope::preamble_aad_bytes(&envelope.prekey)`
    /// on the RECEIVED envelope instead — this method reflects only this session's own local state
    /// and must never be used to build the argument to [`decrypt`](Self::decrypt) for an inbound
    /// message (see that method's doc comment for why).
    pub fn outbound_preamble_bytes(&self) -> Vec<u8> {
        preamble_bytes(self.outbound_prekey())
    }

    /// Ratchet-decrypt an inbound ratchet message. Marks the session confirmed on success.
    ///
    /// `preamble` MUST be the caller's [`preamble_bytes`]-shaped (or, at the wire layer,
    /// `meridian_envelope::preamble_aad_bytes`-shaped) encoding of the `Prekey` **actually present
    /// on the received envelope** — never a value reconstructed from this session's own local
    /// state. See [`crate::ratchet::DoubleRatchet::decrypt`]'s doc comment (ADR 0016 C3): this is
    /// the exact property that keeps a mutated preamble on a genuine envelope detectable rather
    /// than silently matching whatever the receiver already expected.
    pub fn decrypt(&mut self, message: &[u8], preamble: &[u8]) -> Result<Vec<u8>> {
        let pt = self.ratchet.decrypt(message, preamble)?;
        self.confirmed = true;
        self.prekey = None;
        Ok(pt)
    }

    /// This session's own prekey material, but only when [`needs_prekey`](Self::needs_prekey)
    /// holds — i.e. exactly the material [`encrypt`](Self::encrypt) should bind into its outbound
    /// AAD and the caller should attach to the wire envelope. `None` once confirmed (or for a
    /// responder, which never attaches a preamble).
    fn outbound_prekey(&self) -> Option<&PrekeyMaterial> {
        if self.needs_prekey() {
            self.prekey.as_ref()
        } else {
            None
        }
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

/// The canonical C3 preamble encoding (ADR 0016), over this crate's own local [`PrekeyMaterial`]
/// rather than `meridian_envelope::Prekey`. This crate cannot depend on `meridian-envelope` in
/// production code — the dependency direction runs the other way (`meridian-envelope` depends on
/// its sibling `meridian-proto` only, per F15/`apps/crypto/CLAUDE.md`), so the byte-identical
/// encoding is duplicated here on purpose rather than shared. Both fields' shapes are identical
/// (`ek_pub`/`used_spk`/`used_opk`), so the two encodings MUST be kept in lockstep by hand; the v2
/// conformance vectors (task 6.5) pin both together, and
/// `meridian-envelope`'s own `preamble_aad_bytes` doc comment cross-references this function.
fn preamble_bytes(prekey: Option<&PrekeyMaterial>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 32 + 1 + 32);
    match prekey {
        Some(p) => {
            out.push(1);
            out.extend_from_slice(&p.ek_pub);
            out.extend_from_slice(&p.used_spk);
            match &p.used_opk {
                Some(opk) => {
                    out.push(1);
                    out.extend_from_slice(opk);
                }
                None => out.push(0),
            }
        }
        None => out.push(0),
    }
    out
}
