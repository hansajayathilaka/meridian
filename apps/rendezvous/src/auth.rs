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
