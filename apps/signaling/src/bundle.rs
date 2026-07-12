//! Prekey-bundle generation (client side) and the mandatory fetch-time verification.
//!
//! T02 does not run X3DH; it only produces a *signed* bundle to publish and rigorously verifies
//! bundles it fetches. The verification here is the whole security point of the feature: a bundle
//! that verifies under any key other than the one requested is a hard error.

use meridian_identity::{sign, verify, KeyHandle, PublicKey, SecretStore, Signature};
use meridian_proto::{PrekeyBundle, BUNDLE_VERSION, MAX_ONE_TIME_PREKEYS};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{Result, SignalError};

/// A freshly generated bundle plus the X25519 *secret* scalars behind its public prekeys. The
/// secrets are needed later for X3DH (T03); T02 hands them back to the caller to persist safely
/// (age-encrypted). TODO: confirm prekey-secret storage & rotation cadence in T03.
pub struct GeneratedBundle {
    pub bundle: PrekeyBundle,
    pub spk_secret: Zeroizing<[u8; 32]>,
    pub otk_secrets: Vec<Zeroizing<[u8; 32]>>,
}

fn new_x25519() -> Result<([u8; 32], [u8; 32])> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice()).map_err(|e| SignalError::Rng(e.to_string()))?;
    let secret = StaticSecret::from(*seed);
    let public = XPublicKey::from(&secret);
    Ok((secret.to_bytes(), public.to_bytes()))
}

/// Generate a signed prekey bundle for the account behind `handle`: one signed prekey plus
/// `otk_count` one-time prekeys (capped at [`MAX_ONE_TIME_PREKEYS`]), each public key signed by
/// the account key *through the store* (the private key never leaves it).
pub fn generate_bundle(
    store: &dyn SecretStore,
    handle: &KeyHandle,
    account_pub: [u8; 32],
    otk_count: usize,
) -> Result<GeneratedBundle> {
    let otk_count = otk_count.min(MAX_ONE_TIME_PREKEYS);

    let (spk_secret, spk_pub) = new_x25519()?;
    let spk_sig = sign(store, handle, &spk_pub)?;

    let mut otks = Vec::with_capacity(otk_count);
    let mut otk_sigs = Vec::with_capacity(otk_count);
    let mut otk_secrets = Vec::with_capacity(otk_count);
    for _ in 0..otk_count {
        let (sec, pubk) = new_x25519()?;
        let sig = sign(store, handle, &pubk)?;
        otks.push(pubk);
        otk_sigs.push(*sig.as_bytes());
        otk_secrets.push(Zeroizing::new(sec));
    }

    Ok(GeneratedBundle {
        bundle: PrekeyBundle {
            v: BUNDLE_VERSION,
            account_pub,
            spk: spk_pub,
            spk_sig: *spk_sig.as_bytes(),
            otks,
            otk_sigs,
            device_record: None,
        },
        spk_secret: Zeroizing::new(spk_secret),
        otk_secrets,
    })
}

/// Verify a fetched bundle against the **exact key it was requested for**. Returns `Ok(())` only
/// if every signature checks out under `requested`; any mismatch (including a bundle claiming a
/// different `account_pub`) is a hard [`SignalError::BundleVerification`].
pub fn verify_bundle(requested: &[u8; 32], bundle: &PrekeyBundle) -> Result<()> {
    if !bundle.structurally_valid() {
        return Err(SignalError::BundleVerification("malformed bundle"));
    }
    // The bundle must claim to be exactly the key we asked for. A server that returns a bundle for
    // a *different* key (even a validly self-signed one) is substituting an identity.
    if &bundle.account_pub != requested {
        return Err(SignalError::BundleVerification(
            "account key does not match request",
        ));
    }

    let pk = PublicKey::from_bytes(*requested)
        .map_err(|_| SignalError::BundleVerification("requested key is not a valid point"))?;

    if !verify(&pk, &bundle.spk, &Signature::from_bytes(bundle.spk_sig)) {
        return Err(SignalError::BundleVerification(
            "signed prekey signature invalid",
        ));
    }
    for (otk, sig) in bundle.otks.iter().zip(bundle.otk_sigs.iter()) {
        if !verify(&pk, otk, &Signature::from_bytes(*sig)) {
            return Err(SignalError::BundleVerification(
                "one-time prekey signature invalid",
            ));
        }
    }
    Ok(())
}
