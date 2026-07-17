//! Double Ratchet with **header encryption** (system-design §4.3), composed from the audited
//! primitives in [`crate::primitives`]. This is the message-protection layer that gives
//! forward secrecy and post-compromise security at per-message granularity, independent of the
//! transport underneath (§4.3 point 2).
//!
//! The construction follows Signal's *Double Ratchet with header encryption* (spec §5). The one
//! deliberate Meridian choice is the two shared header keys: X3DH derives `hk_ab` / `hk_ba`
//! (one per direction) which seed the header-key chains so that even the ratchet public keys and
//! message counters are hidden from anything that stores an envelope (§4.3, opacity audit).
//!
//! Wire framing of a ratchet message: `len(enc_header):u16-be ‖ enc_header ‖ ciphertext`. The
//! header plaintext is `ratchet_pub(32) ‖ PN:u32-be ‖ N:u32-be`. Both are covered by AEAD.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::primitives::{
    aead_open, aead_seal, dh, gen_dh, header_open, header_seal, kdf_ck, kdf_rk,
};

/// Maximum messages that may be skipped within a single receiving chain before a message that
/// finally advances it. Bounds the work and memory a peer can force per chain.
pub const MAX_SKIP: u32 = 1000;

/// Hard cap on retained skipped-message keys across all chains (out-of-order/dropped delivery).
/// Beyond this the oldest are dropped — a lost message stops being decryptable rather than letting
/// a peer grow our state without bound.
pub const MAX_SKIPPED_STORED: usize = 2000;

const HEADER_LEN: usize = 40;

/// A decoded ratchet header: `(ratchet_public_key, previous_chain_length, message_number)`.
type Header = ([u8; 32], u32, u32);

/// One retained message key for a message that arrived out of order (keyed by the header key of
/// its chain and its message number, since the ratchet public key is itself encrypted).
#[derive(Clone, Serialize, Deserialize)]
struct Skipped {
    hk: [u8; 32],
    n: u32,
    mk: [u8; 32],
}

/// Serializable Double Ratchet state for one peer-device session. Persisted (sealed at rest) so a
/// session survives process restarts and the ratchet continues without a re-handshake (T03 demo).
///
/// Secret-bearing fields are zeroized on drop. The whole struct is `Serialize`/`Deserialize` for
/// the encrypted session store — never write it out unsealed.
#[derive(Serialize, Deserialize)]
pub struct DoubleRatchet {
    rk: [u8; 32],
    dhs_priv: [u8; 32],
    dhs_pub: [u8; 32],
    dhr: Option<[u8; 32]>,
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    hks: Option<[u8; 32]>,
    hkr: Option<[u8; 32]>,
    nhks: [u8; 32],
    nhkr: [u8; 32],
    skipped: Vec<Skipped>,
    /// Associated data bound into every message AEAD: `IK_initiator ‖ IK_responder` from X3DH.
    ad: Vec<u8>,
}

impl DoubleRatchet {
    /// Zeroize every secret-bearing field in place. Shared by [`Drop::drop`] and by tests that need
    /// to observe zeroization without relying on post-drop memory inspection.
    fn zeroize_secrets(&mut self) {
        self.rk.zeroize();
        self.dhs_priv.zeroize();
        if let Some(mut c) = self.cks.take() {
            c.zeroize();
        }
        if let Some(mut c) = self.ckr.take() {
            c.zeroize();
        }
        if let Some(mut hk) = self.hks.take() {
            hk.zeroize();
        }
        if let Some(mut hk) = self.hkr.take() {
            hk.zeroize();
        }
        self.nhks.zeroize();
        self.nhkr.zeroize();
        for s in &mut self.skipped {
            s.mk.zeroize();
        }
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

impl DoubleRatchet {
    /// Initialise the **initiator's** ratchet (Alice) after X3DH. `responder_ratchet_pub` is Bob's
    /// signed prekey (the initial remote ratchet key); `hk_ab`/`hk_ba` are the shared header keys.
    pub fn init_initiator(
        root: [u8; 32],
        responder_ratchet_pub: [u8; 32],
        hk_ab: [u8; 32],
        hk_ba: [u8; 32],
        ad: Vec<u8>,
    ) -> Result<Self> {
        let (dhs_priv, dhs_pub) = gen_dh()?;
        let dh_out = dh(&dhs_priv, &responder_ratchet_pub);
        let (rk, cks, nhks) = kdf_rk(&root, &dh_out);
        Ok(Self {
            rk,
            dhs_priv: *dhs_priv,
            dhs_pub,
            dhr: Some(responder_ratchet_pub),
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            hks: Some(hk_ab),
            hkr: None,
            nhks,
            nhkr: hk_ba,
            skipped: Vec::new(),
            ad,
        })
    }

    /// Initialise the **responder's** ratchet (Bob). `ratchet_keypair` is Bob's signed prekey
    /// secret+public (the same key Alice used as the initial remote ratchet key).
    pub fn init_responder(
        root: [u8; 32],
        ratchet_priv: [u8; 32],
        ratchet_pub: [u8; 32],
        hk_ab: [u8; 32],
        hk_ba: [u8; 32],
        ad: Vec<u8>,
    ) -> Self {
        Self {
            rk: root,
            dhs_priv: ratchet_priv,
            dhs_pub: ratchet_pub,
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            hks: None,
            hkr: None,
            nhks: hk_ba,
            nhkr: hk_ab,
            skipped: Vec::new(),
            ad,
        }
    }

    /// Ratchet-encrypt `plaintext`, returning the framed ratchet message. Fails if this side has
    /// no sending chain yet (the responder must receive the first message before it can send).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cks = self
            .cks
            .ok_or(CryptoError::BadKey("no sending chain established yet"))?;
        let hks = self
            .hks
            .ok_or(CryptoError::BadKey("no sending header key yet"))?;
        let (next_ck, mk) = kdf_ck(&cks);
        self.cks = Some(next_ck);

        let header = encode_header(&self.dhs_pub, self.pn, self.ns);
        let enc_header = header_seal(&hks, &header)?;
        self.ns += 1;

        let aad = self.message_aad(&enc_header);
        let ct = aead_seal(&mk, plaintext, &aad)?;
        Ok(frame(&enc_header, &ct))
    }

    /// Ratchet-decrypt a framed ratchet message, advancing the ratchet (DH step / skipped keys) as
    /// needed. Out-of-order and lost messages are handled via retained skipped keys.
    pub fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let (enc_header, ct) = unframe(message).ok_or(CryptoError::Malformed)?;

        if let Some(pt) = self.try_skipped(enc_header, ct)? {
            return Ok(pt);
        }

        let (header, is_dh_ratchet) = self.decrypt_header(enc_header)?;
        let (dh_pub, pn, n) = header;

        if is_dh_ratchet {
            self.skip_message_keys(pn)?;
            self.dh_ratchet(dh_pub);
        }
        self.skip_message_keys(n)?;

        let ckr = self.ckr.ok_or(CryptoError::UndecryptableHeader)?;
        let (next_ck, mk) = kdf_ck(&ckr);
        self.ckr = Some(next_ck);
        self.nr += 1;

        let aad = self.message_aad(enc_header);
        aead_open(&mk, ct, &aad)
    }

    /// The peer's identity keys as bound at X3DH (`IK_initiator ‖ IK_responder`) — surfaced so the
    /// session layer can compute the safety number without re-deriving it.
    pub fn associated_data(&self) -> &[u8] {
        &self.ad
    }

    // -- internals -----------------------------------------------------------

    fn message_aad(&self, enc_header: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.ad.len() + enc_header.len());
        aad.extend_from_slice(&self.ad);
        aad.extend_from_slice(enc_header);
        aad
    }

    fn decrypt_header(&self, enc_header: &[u8]) -> Result<(Header, bool)> {
        if let Some(hkr) = self.hkr {
            if let Some(h) = header_open(&hkr, enc_header) {
                return Ok((decode_header(&h).ok_or(CryptoError::Malformed)?, false));
            }
        }
        if let Some(h) = header_open(&self.nhkr, enc_header) {
            return Ok((decode_header(&h).ok_or(CryptoError::Malformed)?, true));
        }
        Err(CryptoError::UndecryptableHeader)
    }

    fn dh_ratchet(&mut self, remote_pub: [u8; 32]) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.hks = Some(self.nhks);
        self.hkr = Some(self.nhkr);
        self.dhr = Some(remote_pub);

        let dh_out = dh(&self.dhs_priv, &remote_pub);
        let (rk, ckr, nhkr) = kdf_rk(&self.rk, &dh_out);
        self.rk = rk;
        self.ckr = Some(ckr);
        self.nhkr = nhkr;

        let (new_priv, new_pub) = gen_dh().expect("OS RNG available for ratchet step");
        self.dhs_priv.zeroize();
        self.dhs_priv = *new_priv;
        self.dhs_pub = new_pub;

        let dh_out = dh(&self.dhs_priv, &remote_pub);
        let (rk, cks, nhks) = kdf_rk(&self.rk, &dh_out);
        self.rk = rk;
        self.cks = Some(cks);
        self.nhks = nhks;
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        let Some(mut ckr) = self.ckr else {
            return Ok(());
        };
        if self.nr + MAX_SKIP < until {
            return Err(CryptoError::TooManySkipped);
        }
        let hkr = self.hkr.ok_or(CryptoError::UndecryptableHeader)?;
        while self.nr < until {
            let (next_ck, mk) = kdf_ck(&ckr);
            ckr = next_ck;
            self.skipped.push(Skipped {
                hk: hkr,
                n: self.nr,
                mk,
            });
            self.nr += 1;
        }
        self.ckr = Some(ckr);
        // Bound retained keys: drop oldest beyond the cap.
        if self.skipped.len() > MAX_SKIPPED_STORED {
            let overflow = self.skipped.len() - MAX_SKIPPED_STORED;
            self.skipped.drain(0..overflow);
        }
        Ok(())
    }

    fn try_skipped(&mut self, enc_header: &[u8], ct: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut found: Option<(usize, [u8; 32])> = None;
        for (i, s) in self.skipped.iter().enumerate() {
            if let Some(h) = header_open(&s.hk, enc_header) {
                let (_dh, _pn, n) = decode_header(&h).ok_or(CryptoError::Malformed)?;
                if n == s.n {
                    found = Some((i, s.mk));
                    break;
                }
            }
        }
        let Some((i, mk)) = found else {
            return Ok(None);
        };
        let aad = self.message_aad(enc_header);
        let pt = aead_open(&mk, ct, &aad)?;
        self.skipped.remove(i);
        Ok(Some(pt))
    }
}

fn encode_header(dh_pub: &[u8; 32], pn: u32, n: u32) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..32].copy_from_slice(dh_pub);
    out[32..36].copy_from_slice(&pn.to_be_bytes());
    out[36..40].copy_from_slice(&n.to_be_bytes());
    out
}

fn decode_header(bytes: &[u8]) -> Option<Header> {
    if bytes.len() != HEADER_LEN {
        return None;
    }
    let mut dh_pub = [0u8; 32];
    dh_pub.copy_from_slice(&bytes[0..32]);
    let pn = u32::from_be_bytes(bytes[32..36].try_into().ok()?);
    let n = u32::from_be_bytes(bytes[36..40].try_into().ok()?);
    Some((dh_pub, pn, n))
}

fn frame(enc_header: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + enc_header.len() + ct.len());
    out.extend_from_slice(&(enc_header.len() as u16).to_be_bytes());
    out.extend_from_slice(enc_header);
    out.extend_from_slice(ct);
    out
}

fn unframe(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    if bytes.len() < 2 {
        return None;
    }
    let eh_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let rest = &bytes[2..];
    if rest.len() < eh_len {
        return None;
    }
    Some((&rest[0..eh_len], &rest[eh_len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F6: `zeroize_secrets` (shared with `Drop`) must clear every secret-bearing field, including
    /// the four header-encryption keys (`hks`, `hkr`, `nhks`, `nhkr`) that were previously missed.
    #[test]
    fn drop_zeroizes_all_secret_fields_including_header_keys() {
        let mut ratchet = DoubleRatchet {
            rk: [1u8; 32],
            dhs_priv: [2u8; 32],
            dhs_pub: [3u8; 32],
            dhr: Some([4u8; 32]),
            cks: Some([5u8; 32]),
            ckr: Some([6u8; 32]),
            ns: 0,
            nr: 0,
            pn: 0,
            hks: Some([7u8; 32]),
            hkr: Some([8u8; 32]),
            nhks: [9u8; 32],
            nhkr: [10u8; 32],
            skipped: vec![Skipped {
                hk: [11u8; 32],
                n: 0,
                mk: [12u8; 32],
            }],
            ad: vec![13u8; 4],
        };

        // Sanity: every field we assert on below starts non-zero.
        assert_ne!(ratchet.rk, [0u8; 32]);
        assert_ne!(ratchet.dhs_priv, [0u8; 32]);
        assert_eq!(ratchet.cks, Some([5u8; 32]));
        assert_eq!(ratchet.ckr, Some([6u8; 32]));
        assert_eq!(ratchet.hks, Some([7u8; 32]));
        assert_eq!(ratchet.hkr, Some([8u8; 32]));
        assert_ne!(ratchet.nhks, [0u8; 32]);
        assert_ne!(ratchet.nhkr, [0u8; 32]);
        assert_ne!(ratchet.skipped[0].mk, [0u8; 32]);

        // Exercise the exact routine `Drop` runs, without actually dropping the struct, so the
        // fields remain observable afterwards.
        ratchet.zeroize_secrets();

        assert_eq!(ratchet.rk, [0u8; 32]);
        assert_eq!(ratchet.dhs_priv, [0u8; 32]);
        assert!(ratchet.cks.is_none());
        assert!(ratchet.ckr.is_none());
        assert!(ratchet.hks.is_none());
        assert!(ratchet.hkr.is_none());
        assert_eq!(ratchet.nhks, [0u8; 32]);
        assert_eq!(ratchet.nhkr, [0u8; 32]);
        assert_eq!(ratchet.skipped[0].mk, [0u8; 32]);
    }
}
