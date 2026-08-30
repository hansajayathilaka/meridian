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
//!
//! **v2 AAD (ADR 0016 C2/C3).** Every message AEAD's associated data is
//! `"mrd.env/2" ‖ AD ‖ prekey_preamble ‖ enc_header`: the domain tag and `AD` (the X3DH-derived
//! `IK_initiator ‖ IK_responder`) are baked into [`DoubleRatchet`]'s fixed `ad` field once, at
//! construction ([`DoubleRatchet::init_initiator`]/[`DoubleRatchet::init_responder`]); the
//! per-message `prekey_preamble` is threaded through [`DoubleRatchet::encrypt`]/
//! [`DoubleRatchet::decrypt`] by the caller. **The decrypt side must be given the RECEIVED preamble
//! bytes, never locally recomputed ones** — an implementation that "helpfully" rebuilds what it
//! locally expects the preamble to be reintroduces exactly the gap C3 exists to close (a mutated
//! preamble on a genuine envelope would then fail to be *detected* as mutated, since the AAD would
//! silently reflect the receiver's own expectation instead of what was actually sent). This module
//! has no way to enforce that from here — it only ever sees whatever bytes its caller passes — so
//! the call chain (`apps/crypto/src/session.rs` → `apps/core/src/chat.rs::open_bytes`) is what
//! must, and does, thread the bytes decoded from the actually-received envelope; see this crate's
//! own negative test below and `apps/core/src/chat.rs`'s doc comments for the receive-side half.

use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CryptoError, Result};
use crate::primitives::{
    aead_open, aead_seal, dh, gen_dh, header_open, header_seal, hkdf, kdf_ck, kdf_rk,
};

/// Maximum messages that may be skipped within a single receiving chain before a message that
/// finally advances it. Bounds the work and memory a peer can force per chain.
pub const MAX_SKIP: u32 = 1000;

/// Hard cap on retained skipped-message keys across all chains (out-of-order/dropped delivery).
/// Beyond this the oldest are dropped — a lost message stops being decryptable rather than letting
/// a peer grow our state without bound.
pub const MAX_SKIPPED_STORED: usize = 2000;

const HEADER_LEN: usize = 40;

/// Domain-separation tag baked into every ratchet message's AAD (ADR 0016 C3), as the leading
/// component of [`DoubleRatchet`]'s fixed `ad` field. MUST match
/// `meridian_envelope::ENVELOPE_DOMAIN` exactly — this crate cannot depend on `meridian-envelope`
/// in production code (`apps/crypto/CLAUDE.md`; the dependency direction runs the other way, and
/// `meridian-envelope` deliberately depends on nothing but its sibling `meridian-proto` — F15), so
/// the two constants are kept in lockstep by hand and pinned together by the v2 conformance vectors
/// (task 6.5).
const AAD_DOMAIN: &[u8] = b"mrd.env/2";

/// Fixed, crate-private HKDF salt for [`DoubleRatchet::encrypt_and_export`]/
/// [`DoubleRatchet::decrypt_and_export`]'s caller-facing `HKDF(mk, info)` (task 10.1,
/// `docs/api/stream-types-v1.md` §"Stream framing": `stream_key = HKDF(ratchet_export, info = ...)`).
/// Deliberately **not** the all-zero salt [`aead_seal`]/[`aead_open`] use for their own internal
/// `mk`-keyed HKDF (`MSG_INFO`) — using a distinct salt domain-separates this export from that
/// ciphertext-key derivation so the two can never collide, even in the (practically impossible)
/// case that a caller's opaque `info` happened to equal `MSG_INFO`.
const EXPORT_SALT: [u8; 32] = *b"MeridianRatchetExportSaltV1_0000";

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

/// Zeroize `mk` whenever a `Skipped` entry is dropped — whether via `zeroize_secrets`'s explicit
/// loop, a consuming `Vec::remove` in [`DoubleRatchet::try_skipped`] once the key is used, or the
/// eviction `Vec::drain` in [`DoubleRatchet::skip_message_keys`] once the retention cap is
/// exceeded. Field type stays plain `[u8; 32]` (not `Zeroizing<[u8; 32]>`) so `Skipped` keeps
/// deriving `Serialize`/`Deserialize` for the encrypted session store without a manual impl; this
/// `Drop` gives the same "always cleared, no matter which path removes the entry" guarantee.
impl Drop for Skipped {
    fn drop(&mut self) {
        self.mk.zeroize();
    }
}

/// Serializable Double Ratchet state for one peer-device session. Persisted (sealed at rest) so a
/// session survives process restarts and the ratchet continues without a re-handshake (T03 demo).
///
/// Secret-bearing fields are zeroized on drop. The whole struct is `Serialize`/`Deserialize` for
/// the encrypted session store — never write it out unsealed.
///
/// Deliberately **not** `Clone`: [`aead_seal`]/[`aead_open`] derive both the AEAD key and nonce
/// solely from the single-use message key `mk`, safe only if each `mk` is consumed exactly once. A
/// public `Clone` on this type would let any external holder fork a live session and, if either fork
/// later encrypted or decrypted at the same counter, reuse a key+nonce pair — catastrophic, not
/// merely availability-degrading (security-reviewer finding on task 2.13). [`Self::decrypt`] instead
/// stages its mutations via the crate-private [`Self::checkpoint`] below, confined to this module.
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
    /// The **fixed** (per-session, never-changing) component of every message AEAD's associated
    /// data: `"mrd.env/2" ‖ AD`, where `AD = IK_initiator ‖ IK_responder` from X3DH (ADR 0016 C3).
    /// Baked in once at construction by [`init_initiator_with_keypair`](Self::init_initiator_with_keypair)/
    /// [`init_responder`](Self::init_responder) — never rebuilt per message. The full per-message
    /// AAD additionally includes the per-message `prekey_preamble ‖ enc_header`; see
    /// [`message_aad`](Self::message_aad).
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

    /// Field-for-field copy, crate-module-private on purpose (see the struct's doc comment on why
    /// `DoubleRatchet` does not implement the public `Clone` trait). Used exclusively by
    /// [`Self::decrypt`] to stage mutations before authentication succeeds. The returned copy is
    /// either committed back into the live session (`*self = scratch`) or dropped — either way it
    /// goes through the same [`Drop`]/zeroization path as any other `DoubleRatchet`.
    fn checkpoint(&self) -> Self {
        Self {
            rk: self.rk,
            dhs_priv: self.dhs_priv,
            dhs_pub: self.dhs_pub,
            dhr: self.dhr,
            cks: self.cks,
            ckr: self.ckr,
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            hks: self.hks,
            hkr: self.hkr,
            nhks: self.nhks,
            nhkr: self.nhkr,
            skipped: self.skipped.clone(),
            ad: self.ad.clone(),
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
        let (dhs_priv, _dhs_pub) = gen_dh()?;
        Ok(Self::init_initiator_with_keypair(
            root,
            *dhs_priv,
            responder_ratchet_pub,
            hk_ab,
            hk_ba,
            ad,
        ))
    }

    /// **Test/vector-generation support only.** Identical to [`Self::init_initiator`] but takes
    /// the initiator's sending secret explicitly instead of drawing a fresh one from the OS
    /// CSPRNG, so a caller can build a byte-pinned starting state (`test-vectors/ratchet-v1.json`,
    /// task 1.6). Production code must always go through [`Self::init_initiator`] — never call
    /// this with an operational key. Flagged for security-reviewer sign-off.
    #[doc(hidden)]
    pub fn init_initiator_with_keypair(
        root: [u8; 32],
        dhs_priv: [u8; 32],
        responder_ratchet_pub: [u8; 32],
        hk_ab: [u8; 32],
        hk_ba: [u8; 32],
        ad: Vec<u8>,
    ) -> Self {
        let dhs_pub = XPublicKey::from(&StaticSecret::from(dhs_priv)).to_bytes();
        let dh_out = dh(&dhs_priv, &responder_ratchet_pub);
        let (rk, cks, nhks) = kdf_rk(&root, &dh_out);
        Self {
            rk,
            dhs_priv,
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
            ad: bake_ad(ad),
        }
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
            ad: bake_ad(ad),
        }
    }

    /// Ratchet-encrypt `plaintext` under AAD `self.ad ‖ preamble ‖ enc_header` (ADR 0016 C3),
    /// returning the framed ratchet message. `preamble` is the sender's own
    /// [`meridian_envelope::preamble_aad_bytes`]-shaped encoding of whatever `Prekey` it is (or is
    /// not) attaching to *this* envelope — the caller (`apps/crypto/src/session.rs::Session::encrypt`)
    /// derives it from its own session state, since it is what determines the wire envelope's
    /// `prekey` field too. Fails if this side has no sending chain yet (the responder must receive
    /// the first message before it can send).
    pub fn encrypt(&mut self, plaintext: &[u8], preamble: &[u8]) -> Result<Vec<u8>> {
        let cks = self
            .cks
            .ok_or(CryptoError::BadKey("no sending chain established yet"))?;
        let hks = self
            .hks
            .ok_or(CryptoError::BadKey("no sending header key yet"))?;
        let (next_ck, mk) = kdf_ck(&cks);
        // Wrapped immediately: if `header_seal`/`aead_seal` below fails and returns early via `?`,
        // `mk` is still cleared on drop instead of silently dropping the plaintext-in-memory copy
        // (security-reviewer finding on task 10.1).
        let mk = Zeroizing::new(mk);
        self.cks = Some(next_ck);

        let header = encode_header(&self.dhs_pub, self.pn, self.ns);
        let enc_header = header_seal(&hks, &header)?;
        self.ns += 1;

        let aad = self.message_aad(preamble, &enc_header);
        let ct = aead_seal(&mk, plaintext, &aad)?;
        Ok(frame(&enc_header, &ct))
    }

    /// Like [`Self::encrypt`], but additionally derives and returns a caller-scoped export of the
    /// one message key (`mk`) consumed for this ciphertext: `HKDF(mk, info)`. `info` is fully
    /// opaque to this crate — the caller (`apps/crypto/src/session.rs`, and eventually a stream
    /// type per `docs/api/stream-types-v1.md`'s `stream_key = HKDF(ratchet_export, info = "mrd/stream/"
    /// ‖ type ‖ sid)`) owns its exact byte encoding; this crate has no knowledge of stream types or
    /// stream ids (`TODO: confirm` — the concrete encoding is pinned by task 10.12's spec doc, not
    /// here).
    ///
    /// **Never returns `mk` itself, `cks`, `ckr`, or `rk` — only the one-way HKDF export of the one
    /// `mk` this call already consumed.** `mk` is used to seal `plaintext` exactly as in
    /// [`Self::encrypt`], then zeroized immediately after the export is derived (see
    /// [`export_and_zeroize`]) — it never leaves this function. Because the export is a fresh HKDF
    /// output keyed by `mk` (rather than `mk` reused or passed through), it cannot be inverted back
    /// to `mk`, nor does it grant any way to derive other messages' keys in this chain: it is scoped
    /// to exactly this one already-consumed `mk`. The returned key is caller-owned like any other
    /// secret this crate hands back — **the caller is responsible for zeroizing its own copy**; this
    /// crate cannot reach into caller-owned storage to do so.
    pub fn encrypt_and_export(
        &mut self,
        plaintext: &[u8],
        preamble: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32])> {
        let cks = self
            .cks
            .ok_or(CryptoError::BadKey("no sending chain established yet"))?;
        let hks = self
            .hks
            .ok_or(CryptoError::BadKey("no sending header key yet"))?;
        let (next_ck, mk) = kdf_ck(&cks);
        // Wrapped immediately for the same reason as in `encrypt`: `header_seal`/`aead_seal` below
        // can fail via `?` before `export_and_zeroize`'s own explicit clear ever runs.
        let mut mk = Zeroizing::new(mk);
        self.cks = Some(next_ck);

        let header = encode_header(&self.dhs_pub, self.pn, self.ns);
        let enc_header = header_seal(&hks, &header)?;
        self.ns += 1;

        let aad = self.message_aad(preamble, &enc_header);
        let ct = aead_seal(&mk, plaintext, &aad)?;
        // `export_and_zeroize` still takes `&mut [u8; 32]` and still explicitly zeroizes it
        // in-place (deref-coerced here to the buffer this `Zeroizing` owns) — kept rather than
        // simplified away, since `export_and_zeroize_clears_the_message_key_after_deriving_the_export`
        // pins that exact behavior against a plain (non-`Zeroizing`) array and must keep passing
        // unmodified. It also clears strictly earlier than this function's `Zeroizing` would on
        // drop, so it is not merely redundant duplication.
        let exported = export_and_zeroize(&mut mk, info);

        Ok((frame(&enc_header, &ct), exported))
    }

    /// Ratchet-decrypt a framed ratchet message, advancing the ratchet (DH step / skipped keys) as
    /// needed. Out-of-order and lost messages are handled via retained skipped keys.
    ///
    /// **Failure-atomic** per the Double Ratchet spec's "discard changes to the state object on
    /// failure": every mutation this call would make — the receiving-chain advance (`ckr`/`nr`),
    /// a DH-ratchet step, and any `skipped` entries populated while catching up to `n` — happens on
    /// a private [`Self::checkpoint`] of `self` and is committed back only after `aead_open` actually
    /// succeeds. A failed decrypt (bad ciphertext, or a byte-identical replay re-deriving a chain key
    /// that no longer matches) therefore leaves `self` byte-for-byte as it was, so a duplicate or
    /// forged envelope degrades exactly the one message instead of permanently wedging the chain
    /// against the sender (task 2.13).
    ///
    /// `preamble` MUST be the bytes actually received on this envelope (the caller's own
    /// [`meridian_envelope::preamble_aad_bytes`] encoding of the `Prekey` it just decoded off the
    /// wire, or of `None` if the envelope carried none) — **never** a value the caller reconstructs
    /// from its own local expectations. See the module doc's AAD section: an implementation that
    /// "helpfully" recomputes what it expects the preamble to be, rather than using what was
    /// actually sent, silently defeats the preamble-mutation detection ADR 0016 C3 exists to
    /// provide (a mutated preamble's AAD would then match the receiver's own expectation instead of
    /// reflecting the tampering) — see this module's `preamble_binding` tests below for the
    /// regression this guards against.
    pub fn decrypt(&mut self, message: &[u8], preamble: &[u8]) -> Result<Vec<u8>> {
        let (pt, mut mk) = self.decrypt_core(message, preamble)?;
        mk.zeroize();
        Ok(pt)
    }

    /// Like [`Self::decrypt`], but additionally derives and returns a caller-scoped export of the
    /// one message key (`mk`) consumed to authenticate and open this message: `HKDF(mk, info)`. See
    /// [`Self::encrypt_and_export`]'s doc comment for the full contract (`info` opacity, one-way
    /// export, zeroization, caller ownership) — it applies identically here, on the receive side.
    /// This includes the out-of-order/skipped-message path: whichever `mk` actually decrypted
    /// `message` (freshly derived from the receiving chain, or a retained skipped key) is the one
    /// exported — never any other message's key in this chain.
    pub fn decrypt_and_export(
        &mut self,
        message: &[u8],
        preamble: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32])> {
        let (pt, mut mk) = self.decrypt_core(message, preamble)?;
        let exported = export_and_zeroize(&mut mk, info);
        Ok((pt, exported))
    }

    /// The fixed component of this session's AAD — `"mrd.env/2" ‖ IK_initiator ‖ IK_responder`
    /// (ADR 0016 C3) — as baked in at construction. Note this now includes the leading domain tag,
    /// not just the bare X3DH `AD`; callers that need the raw identity-key pair (e.g. for a safety
    /// number) should not slice this apart, since the exact split is an implementation detail of
    /// this module, not a stable contract.
    pub fn associated_data(&self) -> &[u8] {
        &self.ad
    }

    // -- internals -----------------------------------------------------------

    /// Shared core of [`Self::decrypt`]/[`Self::decrypt_and_export`]: does everything the module
    /// doc comment on [`Self::decrypt`] describes (skipped-key lookup, header decrypt, failure-atomic
    /// DH-ratchet-via-`checkpoint`, AEAD open), but additionally surfaces the raw `mk` that was
    /// consumed so the export variant can HKDF-derive from it before either caller zeroizes it.
    /// Crate-private: `mk` must never reach a `pub` return type un-derived — see
    /// [`Self::decrypt_and_export`]'s doc comment for why only the HKDF export is public.
    fn decrypt_core(&mut self, message: &[u8], preamble: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let (enc_header, ct) = unframe(message).ok_or(CryptoError::Malformed)?;

        if let Some((pt, mk)) = self.try_skipped(preamble, enc_header, ct)? {
            return Ok((pt, mk));
        }

        let (header, is_dh_ratchet) = self.decrypt_header(enc_header)?;
        let (dh_pub, pn, n) = header;

        // From here on every mutation lands on `scratch`, not `self` — see the doc comment on
        // `decrypt` above.
        let mut scratch = self.checkpoint();

        if is_dh_ratchet {
            scratch.skip_message_keys(pn)?;
            scratch.dh_ratchet(dh_pub);
        }
        scratch.skip_message_keys(n)?;

        let ckr = scratch.ckr.ok_or(CryptoError::UndecryptableHeader)?;
        let (next_ck, mk) = kdf_ck(&ckr);
        // Wrapped immediately: `aead_open` below is the routine adversary-triggered failure path
        // (tampered/replayed/forged envelope) and returns early via `?` before reaching the
        // `Ok((pt, mk))` below — `mk` must still be cleared on that path, not just dropped as a
        // plain array (security-reviewer finding on task 10.1).
        let mk = Zeroizing::new(mk);
        scratch.ckr = Some(next_ck);
        scratch.nr += 1;

        let aad = scratch.message_aad(preamble, enc_header);
        let pt = aead_open(&mk, ct, &aad)?;

        // Only now, with authentication proven, does the advanced state become real. `scratch`'s
        // predecessor (the old `self`) is dropped in place by this assignment, which zeroizes its
        // secrets exactly as `Drop` normally would.
        *self = scratch;
        // `*mk` copies the 32 bytes out before `mk` (the `Zeroizing` local) drops at the end of
        // this scope and clears its own copy; the returned copy is the caller's responsibility to
        // zeroize, exactly as before this change (see `decrypt`/`decrypt_and_export` below).
        Ok((pt, *mk))
    }

    /// The full per-message AAD (ADR 0016 C3): `self.ad ‖ preamble ‖ enc_header`, i.e.
    /// `"mrd.env/2" ‖ AD ‖ prekey_preamble ‖ enc_header`. See [`Self::decrypt`]'s doc comment for
    /// the hard requirement that `preamble` be the actually-received bytes on the decrypt side.
    fn message_aad(&self, preamble: &[u8], enc_header: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.ad.len() + preamble.len() + enc_header.len());
        aad.extend_from_slice(&self.ad);
        aad.extend_from_slice(preamble);
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

    /// Look up and consume a retained skipped-message key matching this header/message-number,
    /// returning both the plaintext and the raw `mk` used, so [`Self::decrypt_core`] can hand the
    /// latter on to the export variants. `Ok(None)` means "not a skipped message" (fall through to
    /// the normal receiving-chain path in `decrypt_core`), not a failure.
    fn try_skipped(
        &mut self,
        preamble: &[u8],
        enc_header: &[u8],
        ct: &[u8],
    ) -> Result<Option<(Vec<u8>, [u8; 32])>> {
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
        // Wrapped immediately for the same reason as in `decrypt_core`: `aead_open` below is the
        // routine adversary-triggered failure path and returns early via `?`.
        let mk = Zeroizing::new(mk);
        let aad = self.message_aad(preamble, enc_header);
        let pt = aead_open(&mk, ct, &aad)?;
        // The removed `Skipped` entry's own copy of `mk` is zeroized on drop by `impl Drop for
        // Skipped`, regardless of this local's separate `Zeroizing` wrapper.
        self.skipped.remove(i);
        Ok(Some((pt, *mk)))
    }
}

/// Derive `HKDF(mk, info)` (the caller-facing "ratchet export" — task 10.1) and then zeroize `mk`
/// in place. Factored out of [`DoubleRatchet::encrypt_and_export`]/
/// [`DoubleRatchet::decrypt_and_export`] so both call the exact same code path, and so this crate's
/// own tests can pin the zeroization invariant by calling it directly rather than only inferring it
/// indirectly through a whole `encrypt`/`decrypt` call.
///
/// Uses [`EXPORT_SALT`] (fixed, crate-private) rather than `info` itself as the HKDF salt, so this
/// derivation is domain-separated from [`aead_seal`]/[`aead_open`]'s own internal `mk`-keyed HKDF
/// even if `info` happens to collide with that internal derivation's fixed info string.
fn export_and_zeroize(mk: &mut [u8; 32], info: &[u8]) -> [u8; 32] {
    let exported: [u8; 32] = hkdf(&EXPORT_SALT, mk, info);
    mk.zeroize();
    exported
}

/// Prepend [`AAD_DOMAIN`] to a session's raw X3DH `AD`, producing the fixed AAD component baked
/// into [`DoubleRatchet::ad`] at construction (ADR 0016 C3).
fn bake_ad(ad: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_DOMAIN.len() + ad.len());
    out.extend_from_slice(AAD_DOMAIN);
    out.extend_from_slice(&ad);
    out
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

    // -- task 6.3 (ADR 0016 C2/C3): v2 AAD construction ---------------------------------------

    /// A minimal, byte-fixed initiator/responder pair — enough to exercise AAD/encrypt/decrypt
    /// without going through X3DH (which lives one layer up, in `apps/crypto/src/session.rs`).
    /// Returns `(alice, bob, raw_ad)` so callers can independently reconstruct the expected AAD
    /// from the exact same raw `AD` bytes passed to construction.
    fn test_pair() -> (DoubleRatchet, DoubleRatchet, Vec<u8>) {
        let root = [0x42u8; 32];
        let hk_ab = [0x01u8; 32];
        let hk_ba = [0x02u8; 32];
        // Stand-in for X3DH's `AD = IK_initiator || IK_responder` — its exact contents don't
        // matter to this module, only that whatever is passed in ends up, byte-for-byte, as the
        // suffix of the baked `ad` field.
        let raw_ad = vec![0xAAu8; 64];
        let bob_priv = [0x10u8; 32];
        let bob_pub = XPublicKey::from(&StaticSecret::from(bob_priv)).to_bytes();
        let alice_priv = [0x20u8; 32];
        let alice = DoubleRatchet::init_initiator_with_keypair(
            root,
            alice_priv,
            bob_pub,
            hk_ab,
            hk_ba,
            raw_ad.clone(),
        );
        let bob =
            DoubleRatchet::init_responder(root, bob_priv, bob_pub, hk_ab, hk_ba, raw_ad.clone());
        (alice, bob, raw_ad)
    }

    /// Deliverable 2(a): the constructed `ad` field, and `message_aad`'s output, match the
    /// canonical C3 formula exactly: `ad = "mrd.env/2" || AD`, and
    /// `message_aad(preamble, enc_header) = ad || preamble || enc_header`
    /// (= `"mrd.env/2" || AD || prekey_preamble || enc_header`).
    #[test]
    fn aad_construction_matches_the_canonical_c3_formula() {
        let (alice, bob, raw_ad) = test_pair();

        let mut expected_fixed_ad = Vec::new();
        expected_fixed_ad.extend_from_slice(AAD_DOMAIN);
        expected_fixed_ad.extend_from_slice(&raw_ad);
        assert_eq!(
            alice.associated_data(),
            expected_fixed_ad.as_slice(),
            "the baked ad field must be exactly \"mrd.env/2\" || AD"
        );
        assert_eq!(bob.associated_data(), expected_fixed_ad.as_slice());

        let preamble = vec![1u8, 1, 1];
        let enc_header = vec![2u8, 2, 2, 2];
        let mut expected_aad = expected_fixed_ad.clone();
        expected_aad.extend_from_slice(&preamble);
        expected_aad.extend_from_slice(&enc_header);
        assert_eq!(alice.message_aad(&preamble, &enc_header), expected_aad);
    }

    /// Deliverable 2(b), the load-bearing negative test: decrypting with a preamble other than the
    /// one actually used to encrypt — standing in for an implementation that "helpfully"
    /// recomputes a locally-expected preamble instead of using the bytes actually received — must
    /// be rejected by the AEAD, never silently accepted. Guards against reintroducing exactly the
    /// gap ADR 0016 C3 exists to close (see this module's own doc comment and
    /// [`DoubleRatchet::decrypt`]'s).
    #[test]
    fn decrypt_with_a_locally_recomputed_preamble_instead_of_the_received_bytes_is_rejected() {
        let (mut alice, mut bob, _raw_ad) = test_pair();

        // The preamble actually attached to (and used to encrypt) this envelope — i.e. the "wire"
        // bytes a real receiver would decode off the envelope and hand to `decrypt` unchanged.
        let sent_preamble = vec![9u8, 8, 7];
        let msg = alice.encrypt(b"hello, bob", &sent_preamble).unwrap();

        // A receiver that instead reconstructs what IT locally expects the preamble to be (e.g.
        // from its own session state, ignoring what was actually on the wire) passes different
        // bytes. This must fail closed.
        let locally_recomputed_preamble = vec![1u8, 2, 3];
        assert_ne!(
            sent_preamble, locally_recomputed_preamble,
            "sanity: must actually differ"
        );
        let err = bob
            .decrypt(&msg, &locally_recomputed_preamble)
            .expect_err("a wrong preamble must fail the AEAD, not silently decrypt");
        assert!(
            matches!(err, CryptoError::Crypto),
            "expected an AEAD tag-mismatch failure, got {err:?}"
        );

        // `decrypt` is failure-atomic (task 2.13): the failed attempt above must not have mutated
        // `bob`'s state, so decrypting the SAME message with the genuinely-received preamble still
        // succeeds — proving the rejection above was specifically about the preamble mismatch, not
        // some other break, and that a receive-side bug can't be masked by a already-wedged ratchet.
        let pt = bob.decrypt(&msg, &sent_preamble).expect(
            "the genuinely-received preamble must still decrypt after the rejected attempt",
        );
        assert_eq!(pt, b"hello, bob");
    }

    // -- task 10.1: ratchet HKDF-export for per-stream keys -------------------------------------
    //
    // Invariant 5 (FS/PCS non-regression) is pinned by `apps/crypto/tests/session_roundtrip.rs`'s
    // `forward_secrecy_snapshot_cannot_decrypt_past` / `post_compromise_security_heals_after_round_trip`,
    // which this task leaves byte-for-byte unmodified; `cargo nextest run -p meridian-crypto` runs
    // it alongside the invariants 1-4 pinned here.

    /// Invariant 1 (one-wayness): the export API must never return the raw `mk` it consumed. Proxy
    /// check: since `aead_seal`/`aead_open` derive their AEAD key+nonce solely from `mk`, feeding
    /// the *exported* value back in as if it were `mk` must fail to open the very ciphertext it was
    /// consumed to produce — if `exported == mk`, this would succeed.
    #[test]
    fn encrypt_and_export_never_returns_the_raw_message_key() {
        let (mut alice, mut bob, _raw_ad) = test_pair();
        let preamble: Vec<u8> = Vec::new();
        let info = b"mrd/stream/test/one-wayness";

        let (msg, exported) = alice
            .encrypt_and_export(b"payload", &preamble, info)
            .unwrap();

        let (enc_header, ct) = unframe(&msg).unwrap();
        let aad = alice.message_aad(&preamble, enc_header);
        assert!(
            aead_open(&exported, ct, &aad).is_err(),
            "the exported key must never be usable as the raw mk that sealed this message"
        );

        // The real mk still does the real job, reached only through the normal (never-raw-exposed)
        // decrypt path.
        let (pt, _exported_recv) = bob.decrypt_and_export(&msg, &preamble, info).unwrap();
        assert_eq!(pt, b"payload");
    }

    /// Invariant 2 (no skip-ahead leak): holding the export for one message in a chain must not let
    /// a caller derive or otherwise use another message's key in that same chain. Builds three
    /// messages, has the receiver decrypt them out of order (exercising the skipped-key path for
    /// two of them), and checks pairwise distinctness plus that the third message's export cannot
    /// open either of the other two's ciphertexts.
    #[test]
    fn exporting_one_message_does_not_leak_other_messages_keys_in_the_same_chain() {
        let (mut alice, mut bob, _raw_ad) = test_pair();
        let preamble: Vec<u8> = Vec::new();
        let info = b"mrd/stream/test/skip-ahead";

        let (m0, exp0_send) = alice.encrypt_and_export(b"m0", &preamble, info).unwrap();
        let (m1, _) = alice.encrypt_and_export(b"m1", &preamble, info).unwrap();
        let (m2, _) = alice.encrypt_and_export(b"m2", &preamble, info).unwrap();

        // Bob receives m2 first: this DH-ratchets his receiving chain and stashes skipped keys for
        // messages 0 and 1 without ever exporting them.
        let (pt2, exp2) = bob.decrypt_and_export(&m2, &preamble, info).unwrap();
        assert_eq!(pt2, b"m2");

        // exp2 must not open m0's or m1's ciphertext as if it were their raw mk.
        let (eh0, ct0) = unframe(&m0).unwrap();
        let (eh1, ct1) = unframe(&m1).unwrap();
        let aad0 = bob.message_aad(&preamble, eh0);
        let aad1 = bob.message_aad(&preamble, eh1);
        assert!(
            aead_open(&exp2, ct0, &aad0).is_err(),
            "message 2's export must not decrypt message 0"
        );
        assert!(
            aead_open(&exp2, ct1, &aad1).is_err(),
            "message 2's export must not decrypt message 1"
        );

        // Bob now catches up via the retained skipped keys; each export is independent, and the
        // sender/receiver sides agree for message 0.
        let (pt0, exp0) = bob.decrypt_and_export(&m0, &preamble, info).unwrap();
        let (pt1, exp1) = bob.decrypt_and_export(&m1, &preamble, info).unwrap();
        assert_eq!(pt0, b"m0");
        assert_eq!(pt1, b"m1");

        assert_ne!(exp0, exp1);
        assert_ne!(exp1, exp2);
        assert_ne!(exp0, exp2);
        assert_eq!(
            exp0, exp0_send,
            "sender and receiver must agree on message 0's export"
        );
    }

    /// Invariant 3 (determinism): the same synchronized ratchet state plus the same `info` on both
    /// peers must yield an identical exported key (the round trip a real stream OPEN performs), and
    /// a different `info` against the very same `mk` must yield a different export (i.e. `info`
    /// genuinely participates in the derivation, this isn't a constant). `test_pair()` builds fully
    /// deterministic ratchet state (fixed keys, no RNG), so two independent calls to it produce
    /// byte-identical starting states, letting the second half of this test isolate `info`'s effect
    /// from `mk`'s.
    #[test]
    fn same_synchronized_state_and_info_on_both_peers_yields_identical_export() {
        let (mut alice, mut bob, _raw_ad) = test_pair();
        let preamble: Vec<u8> = Vec::new();
        let info = b"mrd/stream/file/sid-0001";

        let (msg, exported_by_sender) = alice
            .encrypt_and_export(b"open-stream", &preamble, info)
            .unwrap();
        let (pt, exported_by_receiver) = bob.decrypt_and_export(&msg, &preamble, info).unwrap();

        assert_eq!(pt, b"open-stream");
        assert_eq!(
            exported_by_sender, exported_by_receiver,
            "both ends of one synchronized ratchet message must derive the identical export"
        );

        let (mut alice2, _bob2, _raw_ad2) = test_pair();
        let (_msg2, exported_with_different_info) = alice2
            .encrypt_and_export(b"open-stream", &preamble, b"different-info")
            .unwrap();
        assert_ne!(
            exported_by_sender, exported_with_different_info,
            "different info against the same mk must yield a different export"
        );
    }

    /// Invariant 4 (zeroization): `mk` is cleared immediately after the HKDF-export is derived.
    /// Exercises [`export_and_zeroize`] directly — the exact routine `encrypt_and_export`/
    /// `decrypt_and_export` call — mirroring how `drop_zeroizes_all_secret_fields_including_header_keys`
    /// above tests `zeroize_secrets` directly rather than only inferring it via `Drop`.
    #[test]
    fn export_and_zeroize_clears_the_message_key_after_deriving_the_export() {
        let mut mk = [0x77u8; 32];
        let original = mk;

        let exported = export_and_zeroize(&mut mk, b"mrd/stream/test/zeroize");

        assert_eq!(
            mk, [0u8; 32],
            "mk must be zeroized immediately after HKDF-derivation"
        );
        assert_ne!(
            exported, [0u8; 32],
            "sanity: the export itself is not the degenerate all-zero case"
        );
        assert_ne!(
            exported, original,
            "the export must differ from the pre-zeroization mk value"
        );
    }
}
