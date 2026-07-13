//! Opacity audit harness (T03 deliverable 3): drive a scripted conversation through an in-process
//! stand-in for the rendezvous, capture **every byte the server would handle**, and assert the
//! server-visibility guarantees:
//!   (a) no plaintext message content appears anywhere in the routed bytes,
//!   (b) ratchet headers are encrypted — counters/ratchet keys are not visible, so repeated
//!       identical plaintexts yield *different* ciphertexts,
//!   (c) message **size** is the only content-dependent observable (equal-length plaintexts ⇒
//!       equal-length envelopes).
//!
//! This runs with no network and no real server, so it is deterministic and lives in CI (the test
//! at the bottom of this file). The `meridian demo opacity-audit` subcommand runs the same logic
//! and writes the captured transcript out for inspection.

use meridian_core::chat::ChatState;
use meridian_core::identity::{generate_account, AccountId, KeyHandle, MemorySecretStore};
use meridian_core::proto::{ChatContent, Frame, Op, OpaqueBlob, RouteBody};
use meridian_core::signaling::generate_bundle;

/// The result of an audit run.
pub struct AuditReport {
    /// Number of routed envelopes the server handled.
    pub envelopes: usize,
    /// Plaintext leaks detected (0 on success).
    pub leaks: usize,
    /// The captured "pcapish" transcript: every routing frame the server handled, concatenated.
    pub transcript: Vec<u8>,
}

struct Party {
    store: MemorySecretStore,
    account: AccountId,
    state: ChatState,
}

impl Party {
    fn new(hint: &str) -> Self {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, hint).expect("account");
        Self {
            store,
            account,
            state: ChatState::default(),
        }
    }
    fn ik(&self) -> [u8; 32] {
        *self.account.public_key().as_bytes()
    }
    fn handle(&self) -> KeyHandle {
        self.account.handle().clone()
    }
    fn seal(&mut self, peer: &[u8; 32], content: &ChatContent) -> Vec<u8> {
        let ik = self.ik();
        self.state
            .seal_outbound(&self.store, &self.handle(), &ik, peer, content)
            .expect("seal")
    }
    fn open(&mut self, from: &[u8; 32], blob: &[u8]) -> ChatContent {
        let ik = self.ik();
        self.state
            .open_inbound(&self.store, &self.handle(), &ik, from, blob)
            .expect("open")
    }
}

/// Capture the exact bytes the server routes for one envelope: a `Route` frame carrying the
/// opaque blob (this is what a rendezvous receives and forwards, byte-for-byte).
fn routed_bytes(to: &[u8; 32], blob: &[u8]) -> Vec<u8> {
    let body = RouteBody {
        to: *to,
        blob: OpaqueBlob::new(blob.to_vec()),
    };
    Frame::new(Op::Route, 0, &body)
        .expect("frame")
        .to_bytes()
        .expect("frame bytes")
}

/// Run the scripted audit with `rounds` ping-pong exchanges (plus the targeted opacity probes).
/// Returns [`AuditReport`] on success, or `Err` describing the first leak/violation.
pub fn run_audit(rounds: usize) -> Result<AuditReport, String> {
    let mut alice = Party::new("chat.a");
    let mut bob = Party::new("chat.b");
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    // Bob publishes; Alice establishes the session against the (verified) bundle.
    let bob_bundle = generate_bundle(&bob.store, &bob.handle(), bob_ik, 10).expect("bundle");
    let otks: Vec<([u8; 32], [u8; 32])> = bob_bundle
        .bundle
        .otks
        .iter()
        .zip(bob_bundle.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    bob.state
        .vault
        .set_bundle(bob_bundle.bundle.spk, *bob_bundle.spk_secret, otks);
    alice
        .state
        .start_initiator_session(
            &alice.store,
            &alice.handle(),
            &alice_ik,
            &bob_ik,
            &bob_bundle.bundle.spk,
            bob_bundle.bundle.otks.first().copied(),
        )
        .expect("start session");

    // Everything the server sees, and every plaintext secret we must never find in it.
    let mut transcript: Vec<u8> = Vec::new();
    let mut frames: usize = 0;
    let mut secrets: Vec<Vec<u8>> = Vec::new();
    // Blob sizes for two same-length and one different-length plaintext (property c/b probes).
    let mut probe_same: Vec<(usize, Vec<u8>)> = Vec::new();

    let push = |transcript: &mut Vec<u8>, frames: &mut usize, to: &[u8; 32], blob: &[u8]| {
        transcript.extend_from_slice(&routed_bytes(to, blob));
        *frames += 1;
    };

    // --- Targeted opacity probes -------------------------------------------------------------
    // Two identical-length, identical-content messages must yield equal-size but *different*
    // ciphertext blobs (header encryption hides the advancing counter); a longer message must
    // yield a larger blob (size is the only observable).
    for body in ["AAAAAAAA", "AAAAAAAA", "AAAAAAAAAAAAAAAA"] {
        let id = [frames as u8; 16];
        secrets.push(body.as_bytes().to_vec());
        secrets.push(id.to_vec());
        let content = ChatContent::Text {
            id,
            body: body.to_string(),
        };
        let blob = alice.seal(&bob_ik, &content);
        probe_same.push((body.len(), blob.clone()));
        push(&mut transcript, &mut frames, &bob_ik, &blob);
        let deliver_frame = Frame::new(
            Op::Deliver,
            0,
            &meridian_core::proto::Deliver {
                from: alice_ik,
                blob: OpaqueBlob::new(blob.clone()),
            },
        )
        .unwrap()
        .to_bytes()
        .unwrap();
        transcript.extend_from_slice(&deliver_frame);
        assert_eq!(bob.open(&alice_ik, &blob), content);
    }
    // (b) equal plaintext ⇒ different ciphertext.
    if probe_same[0].1 == probe_same[1].1 {
        return Err("header/counter leak: identical plaintexts produced identical blobs".into());
    }
    // (c) equal plaintext length ⇒ equal blob length; longer ⇒ longer.
    if probe_same[0].1.len() != probe_same[1].1.len() {
        return Err("size leak: equal-length plaintexts produced different-size blobs".into());
    }
    if probe_same[2].1.len() <= probe_same[0].1.len() {
        return Err("size relationship broken: longer plaintext did not grow the blob".into());
    }

    // --- General ping-pong with unique content + receipts ------------------------------------
    for i in 0..rounds {
        let a_id = [(0x10 + (i as u8 & 0x0f)); 16];
        let a_body = format!("alice secret message number {i} \u{1f510}");
        secrets.push(a_body.as_bytes().to_vec());
        secrets.push(a_id.to_vec());
        let blob = alice.seal(
            &bob_ik,
            &ChatContent::Text {
                id: a_id,
                body: a_body.clone(),
            },
        );
        push(&mut transcript, &mut frames, &bob_ik, &blob);
        let got = bob.open(&alice_ik, &blob);
        assert_eq!(
            got,
            ChatContent::Text {
                id: a_id,
                body: a_body
            }
        );

        // Bob's delivery receipt (also opaque).
        let r = bob.seal(&alice_ik, &ChatContent::Receipt { ack: a_id });
        push(&mut transcript, &mut frames, &alice_ik, &r);
        alice.open(&bob_ik, &r);

        // Bob replies with his own secret.
        let b_id = [(0x80 + (i as u8 & 0x0f)); 16];
        let b_body = format!("bob confidential reply {i}");
        secrets.push(b_body.as_bytes().to_vec());
        secrets.push(b_id.to_vec());
        let blob = bob.seal(
            &alice_ik,
            &ChatContent::Text {
                id: b_id,
                body: b_body.clone(),
            },
        );
        push(&mut transcript, &mut frames, &alice_ik, &blob);
        alice.open(&bob_ik, &blob);
    }

    // --- (a) no plaintext anywhere in the server-visible bytes -------------------------------
    let mut leaks = 0;
    for secret in &secrets {
        if !secret.is_empty() && contains(&transcript, secret) {
            leaks += 1;
        }
    }
    if leaks > 0 {
        return Err(format!("{leaks} plaintext leak(s) found in routed bytes"));
    }

    Ok(AuditReport {
        envelopes: frames,
        leaks,
        transcript,
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opacity_audit_passes() {
        let report = run_audit(50).expect("audit must pass");
        assert_eq!(report.leaks, 0);
        assert!(report.envelopes > 100);
        assert!(!report.transcript.is_empty());
    }
}
