//! Challenge–response authentication and registration admission.
//!
//! The server proves nothing about identity — it only checks that the connecting client controls
//! the account key it claims, by verifying an Ed25519 signature over `nonce ‖ server_domain`. The
//! per-connection nonce is single-use (a fresh one per socket), so a captured `auth` frame cannot
//! be replayed onto another connection. Ed25519 verification is the server's ONE crypto primitive
//! — it holds no session/ratchet code (ADR-8, the "cannot" list §2.3).

#[cfg(feature = "test-tamper-hook")]
use ed25519_dalek::{Signer, SigningKey};
use ed25519_dalek::{Verifier, VerifyingKey};
use meridian_proto::Auth;
#[cfg(feature = "test-tamper-hook")]
use meridian_proto::PrekeyBundle;

use crate::config::Admission;

/// A fresh 32-byte challenge nonce from the OS CSPRNG.
pub fn new_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).expect("OS RNG must be available");
    nonce
}

/// Verify an `auth` reply against the challenge this connection issued. Returns `true` only if the
/// signature over `nonce ‖ server_domain` checks out under the claimed account key.
pub fn verify_auth(nonce: &[u8; 32], server_domain: &str, auth: &Auth) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&auth.account_pub) else {
        return false;
    };
    let mut signed = nonce.to_vec();
    signed.extend_from_slice(server_domain.as_bytes());
    let sig = ed25519_dalek::Signature::from_bytes(&auth.sig);
    vk.verify(&signed, &sig).is_ok()
}

/// Registration admission — `open` accepts any key; `invite` requires a known token. OIDC gating
/// (§3.2) is a future admission variant; this trait is the seam it plugs into.
pub trait AdmissionPolicy: Send + Sync {
    fn admit(&self, invite: Option<&str>) -> bool;
}

pub struct OpenAdmission;
impl AdmissionPolicy for OpenAdmission {
    fn admit(&self, _invite: Option<&str>) -> bool {
        true
    }
}

pub struct InviteAdmission {
    pub tokens: Vec<String>,
}
impl AdmissionPolicy for InviteAdmission {
    fn admit(&self, invite: Option<&str>) -> bool {
        matches!(invite, Some(t) if self.tokens.iter().any(|k| k == t))
    }
}

/// Build the admission policy from config.
pub fn admission_from(
    admission: Admission,
    invite_tokens: Vec<String>,
) -> Box<dyn AdmissionPolicy> {
    match admission {
        Admission::Open => Box::new(OpenAdmission),
        Admission::Invite => Box::new(InviteAdmission {
            tokens: invite_tokens,
        }),
    }
}

/// TEST HOOK: produce a bundle that is internally valid but signed under a **different** key than
/// the one requested — the canonical malicious-server substitution (§3.3). A correct client
/// rejects it because `account_pub` no longer matches the key it asked for. Compiled in only under
/// the `test-tamper-hook` cargo feature (off by default, absent from release binaries — F17); when
/// enabled it's additionally gated at runtime by `allow_test_tamper = true`.
#[cfg(feature = "test-tamper-hook")]
pub fn substitute_bundle(original: &PrekeyBundle) -> PrekeyBundle {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS RNG must be available");
    let sk = SigningKey::from_bytes(&seed);
    let wrong_pub = sk.verifying_key().to_bytes();

    let spk_sig = sk.sign(&original.spk).to_bytes();
    let otk_sigs = original
        .otks
        .iter()
        .map(|otk| sk.sign(otk).to_bytes())
        .collect();

    PrekeyBundle {
        v: original.v,
        account_pub: wrong_pub,
        spk: original.spk,
        spk_sig,
        otks: original.otks.clone(),
        otk_sigs,
        device_record: None,
    }
}

/// TEST HOOK (task 1.28): actively **rewrite a routed blob in transit** — the malicious-relay
/// attack that [`substitute_bundle`] does not cover. Where bundle substitution attacks *key
/// distribution*, this attacks the *routed signaling path*: a compromised rendezvous mutating the
/// SDP/ICE envelopes that establish a P2P session, trying to swap in its own DTLS fingerprint and
/// terminate the session itself.
///
/// **What this hook can and cannot simulate, precisely.** It flips one byte in the middle of the
/// blob. It does **not** construct a substitute envelope carrying the attacker's own fingerprint,
/// because the server *cannot*: `meridian-rendezvous` does not depend on `meridian-envelope`, so
/// envelope/content types are not in scope for this crate at all (the F15 dependency split — see
/// `apps/envelope/src/lib.rs`), and it holds no ratchet state to encrypt an inner `SignalContent`
/// under. The "attacker fabricates a whole offer with its own fingerprint" case is covered
/// client-side instead, by `apps/core/tests/p2p_session.rs::fingerprint_mismatch_tears_down` via
/// `LoopbackTransport::new_mitm`.
///
/// **Do not read this as "the strongest attack a relay has".** It is not — it is the *cheapest*,
/// chosen because it needs no envelope knowledge whatsoever. Scope it precisely:
///
/// * A byte flip lands inside `ct` (see below) and is stopped **by the ratchet AEAD itself** — under
///   envelope v2 ([ADR 0016](../../../docs/adr/0016-envelope-deniability.md)) there is no earlier
///   signature check any more: a mutated ciphertext fails the AEAD tag on decrypt, never reaching the
///   §4.6 fingerprint cross-check.
/// * That is not a gap but an **impossibility for this server to do anything else**: `ct` is
///   AEAD-authenticated ciphertext under a key only the two ratchet peers hold, so this crate has
///   neither the key nor the plaintext needed to construct a rewrite that would still decrypt — it
///   can only flip bytes blind, which fails closed at the recipient. A rewrite that *survives*
///   decryption is unreachable for this server anyway: no `meridian-envelope` dependency, no sender
///   identity key, no ratchet state.
/// * Strictly stronger relay attacks exist and are all now covered **on the routing path**: bundle
///   substitution
///   ([`substitute_bundle`], right above — the server ends up holding real ratchet state with both
///   peers) → `tampered_bundle_is_rejected` + T08; transport-level fingerprint MITM →
///   `p2p_session.rs::fingerprint_mismatch_tears_down`; and the key-material-free attacks that reach
///   the recipient because they never touch the AEAD-authenticated bytes — a forged `Deliver.from`
///   (the server asserts that field itself, so forging it is free), **replay / reorder / drop /
///   cross-delivery** — which task **1.32** added as their own modes in
///   [`crate::route_tamper`], driven by `apps/cli/tests/relay_attacks.rs`. Those are the ones that
///   probe deeper: the forged origin reaches `ChatError::SenderMismatch`, the replay reaches the
///   ratchet, the cross-delivery reaches the X3DH prekey lookup.
/// * **Not modelled** — key-material-free attacks by this same adversary that no hook here covers,
///   listed so "covered on the routing path" is not misread as "covered". (1) **Stale-bundle
///   replay on the FETCH path:** `PrekeyBundle` carries `v` but no timestamp or generation counter,
///   so a malicious server can serve a correctly-signed *old* bundle forever and the fetcher cannot
///   detect it — pinning a victim to a never-rotating SPK, which is the compensating control ADR
///   0016 C1/R1 leans on. Arguably a spec gap, not only a test gap. (2) **Same OTK to many
///   fetchers:** `get_bundle` never consumes an OTK, so one one-time prekey can be handed to every
///   fetcher; single-use is enforced only at the responder's vault, so every initiator after the
///   first gets `UnknownPrekey` — an unattributable targeted DoS that looks like a crypto fault.
///   (3) **Reflection:** no mode echoes a blob back to its own sender. (4) **Selective per-device
///   delivery**, splitting a multi-device user's view. (5) **Skipped-key exhaustion** (ADR 0016 R2)
///   and (6) **delay past the SPK grace window**, which reorder does not reach.
/// * Still out of reach for *any* server-side hook, by construction: mutating the X3DH preamble
///   (`used_opk`/`used_spk`) is mutating bytes bound into the ratchet AEAD's associated data (ADR
///   0016 C3) and needs envelope types this crate does not have. ADR 0016's obligations for it are
///   discharged client-side, in `apps/core/tests/preamble_mutation.rs`.
///
/// Compiled in only under the `test-tamper-hook` cargo feature (off by default, absent from release
/// binaries — F17); additionally gated at runtime by `allow_test_tamper && allow_test_route_tamper`
/// (the umbrella) **and** `allow_test_route_rewrite` (this attack's own mode flag, added by 1.32).
#[cfg(feature = "test-tamper-hook")]
pub fn rewrite_routed_blob(original: &[u8]) -> Vec<u8> {
    let mut out = original.to_vec();
    if out.is_empty() {
        return out;
    }
    // Middle byte: lands inside `ct` for any realistic envelope. Per the note above, *which* byte is
    // not actually load-bearing — any mutation inside the AEAD-authenticated `ct` fails the tag on
    // decrypt regardless — but hitting `ct` keeps the simulated attack a plausible "rewrite the SDP"
    // rather than CBOR framing damage.
    let idx = out.len() / 2;
    out[idx] ^= 0xFF;
    out
}
