//! TEST HOOK (task 1.32): the malicious-relay attacks on the **routed** path that a byte-level
//! rewrite (task 1.28, [`crate::auth::rewrite_routed_blob`]) cannot reach.
//!
//! # Why this module exists
//!
//! 1.28's rewrite is provably stopped at the Ed25519 envelope signature: `MessageEnvelope` has four
//! fields and its signing input covers `sender_pub + prekey + ct`, with `sig` the remainder, so
//! *every* byte is either signed or is the signature and any mutation must fail CBOR decode or
//! `verify`. A routing-only relay nevertheless has strictly stronger attacks that need **no key
//! material** and **do** pass the signature check, because they never touch the bytes:
//!
//! * **`spoof_from`** — `Deliver.from` is asserted by the *server*, not by the client, so forging it
//!   is free. Probes `ChatError::SenderMismatch`.
//! * **`replay`** — re-deliver a previously-delivered blob, byte-identical.
//! * **`reorder`** / **`drop`** — hold blobs and emit them out of order, or withhold one entirely
//!   while still replying `route_ok{delivered:true}`. (A *delay* is the degenerate case of a
//!   reorder, so it gets no separate flag.)
//! * **`cross_deliver`** — take a valid envelope captured from one session and hand it to a
//!   *different* recipient.
//!
//! # The hard constraint: byte-level buffering ONLY
//!
//! Everything here operates on `Vec<u8>` and `[u8; 32]` routing keys. Nothing in this module
//! constructs, decodes, signs, or inspects an envelope, and it must stay that way:
//! `meridian-rendezvous` depends on `meridian-proto` and nothing else from the workspace
//! (`tools/lint-server-no-core.sh`), so envelope/content types are not in scope for this crate at
//! all — and payload opacity (`tools/lint-no-serde-on-blob.sh`) forbids giving them structure here
//! even if they were. That restriction is not an inconvenience: it is exactly the capability set of
//! a real routing relay, which is what makes these simulated attacks faithful.
//!
//! # Gating (F17)
//!
//! The whole module is `#[cfg(feature = "test-tamper-hook")]` — absent from default/release builds,
//! not merely disabled. At runtime every mode requires `allow_test_tamper &&
//! allow_test_route_tamper` (the umbrella gate) **plus** its own flag, all `false` by default. The
//! per-mode flags are kept as separate booleans rather than one enum deliberately: it matches the
//! existing `allow_test_tamper` / `allow_test_route_tamper` style, and it lets the inertness tests
//! set every mode at once and assert that delivery is *still* byte-identical and single, which one
//! enum's `None` variant could not express.
//!
//! Modes compose (they are applied in a fixed order below), but they are **intended to be used one
//! at a time**: each harness cell turns on exactly one, so the outcome it asserts is attributable to
//! that attack and not to an interaction.

use std::collections::HashSet;
use std::sync::Mutex;

use crate::config::Server;

/// One outbound `Deliver` the server has decided to emit: recipient, claimed origin, opaque bytes.
/// All three are exactly what `handle_route` would have used honestly — the hook's only power is to
/// change *which* triples get emitted, and to lie about `from`.
#[derive(Clone)]
pub struct Delivery {
    pub to: [u8; 32],
    pub from: [u8; 32],
    pub blob: Vec<u8>,
}

/// What `handle_route` should do with one `route` request.
pub struct RoutePlan {
    /// Deliveries to emit now, in order.
    pub deliveries: Vec<Delivery>,
    /// Reply `route_ok{delivered:true}` (if the recipient is in fact connected) even though nothing
    /// was emitted for them. This is the *lie* a dropping/delaying relay tells, and simulating it is
    /// the point: the client must not be able to distinguish "delivered" from "swallowed" by the
    /// ack, so its security must not depend on that ack.
    pub claim_delivered: bool,
}

impl RoutePlan {
    /// The honest plan: deliver exactly what was routed, once.
    pub fn passthrough(to: [u8; 32], from: [u8; 32], blob: Vec<u8>) -> Self {
        Self {
            deliveries: vec![Delivery { to, from, blob }],
            claim_delivered: false,
        }
    }
}

/// Byte-level buffers backing the stateful modes. Held in [`crate::state::AppState`], so it is
/// process-wide (a real relay's view) rather than per-connection.
#[derive(Default)]
pub struct RouteTamper {
    inner: Mutex<Buffers>,
}

#[derive(Default)]
struct Buffers {
    /// `reorder`: the single blob currently withheld, released behind the next one.
    held: Option<Delivery>,
    /// `cross_deliver`: the first blob seen anywhere on this server, replayed at *other* recipients.
    captured: Option<Delivery>,
    /// `drop`: senders whose first routed blob has already been swallowed.
    dropped_first_from: HashSet<[u8; 32]>,
}

impl RouteTamper {
    /// Decide what to emit for one `route` request from `from` to `to`.
    ///
    /// `blob` is moved through untouched unless a mode says otherwise; no mode parses it.
    pub fn plan(&self, cfg: &Server, to: [u8; 32], from: [u8; 32], blob: Vec<u8>) -> RoutePlan {
        // Umbrella gate first: with route tampering off, this is byte-for-byte the honest path.
        if !(cfg.allow_test_tamper && cfg.allow_test_route_tamper) {
            return RoutePlan::passthrough(to, from, blob);
        }

        // 1.28's in-transit rewrite, now behind its own mode flag like every other attack.
        let blob = if cfg.allow_test_route_rewrite {
            crate::auth::rewrite_routed_blob(&blob)
        } else {
            blob
        };
        // Forge the routing origin. Flipping a bit of the authenticated key is enough: the receiver
        // compares `Deliver.from` against the *signed* `sender_pub` inside the envelope, so any
        // value other than the real sender's key exercises that check. (The server has no third
        // party's key to substitute, and needs none.)
        let from = if cfg.allow_test_route_spoof_from {
            let mut spoofed = from;
            spoofed[0] ^= 0x01;
            spoofed
        } else {
            from
        };

        let current = Delivery { to, from, blob };
        let mut deliveries: Vec<Delivery> = Vec::new();

        // Cross-delivery: capture the first blob this server ever routes, then inject that captured
        // envelope — valid, correctly signed, but belonging to a *different* session — ahead of
        // every subsequent recipient's real traffic. The injected copy keeps its ORIGINAL `from`, so
        // it is not a `from` forgery: it is a genuine envelope delivered to the wrong person.
        if cfg.allow_test_route_cross_deliver {
            let mut buf = self.inner.lock().unwrap();
            match &buf.captured {
                None => buf.captured = Some(current.clone()),
                Some(captured) => deliveries.push(Delivery {
                    to,
                    from: captured.from,
                    blob: captured.blob.clone(),
                }),
            }
        }

        // Drop: swallow each sender's FIRST routed blob and pass the rest. Dropping *everything*
        // would be an uninteresting total outage; swallowing the opening message is the sharp case,
        // because that is the one carrying the X3DH preamble.
        if cfg.allow_test_route_drop {
            let first = self.inner.lock().unwrap().dropped_first_from.insert(from);
            if first {
                return RoutePlan {
                    deliveries,
                    claim_delivered: true,
                };
            }
        }

        // Reorder: hold one blob back and release it *behind* the next one, so the recipient sees
        // 2,1. Nothing is lost — this is a pure permutation, which is what distinguishes it from
        // `drop` and what the ratchet's skipped-key handling is supposed to tolerate.
        if cfg.allow_test_route_reorder {
            let held = self.inner.lock().unwrap().held.take();
            match held {
                None => {
                    self.inner.lock().unwrap().held = Some(current);
                    return RoutePlan {
                        deliveries,
                        claim_delivered: true,
                    };
                }
                Some(previous) => {
                    deliveries.push(current.clone());
                    deliveries.push(previous);
                }
            }
        } else {
            deliveries.push(current.clone());
        }

        // Replay: emit the same bytes a second time, to the same recipient, with the same `from`.
        // A byte-identical duplicate is the whole attack — no mutation, so it passes the signature
        // check and reaches the ratchet.
        if cfg.allow_test_route_replay {
            deliveries.push(current);
        }

        RoutePlan {
            deliveries,
            claim_delivered: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn armed() -> Server {
        Server {
            allow_test_tamper: true,
            allow_test_route_tamper: true,
            ..Server::default()
        }
    }

    const TO: [u8; 32] = [7u8; 32];
    const FROM: [u8; 32] = [9u8; 32];

    /// The umbrella gate alone changes nothing: with no mode flag set, planning is the identity.
    #[test]
    fn umbrella_gate_alone_is_passthrough() {
        let t = RouteTamper::default();
        let plan = t.plan(&armed(), TO, FROM, vec![1, 2, 3]);
        assert_eq!(plan.deliveries.len(), 1);
        assert_eq!(plan.deliveries[0].blob, vec![1, 2, 3]);
        assert_eq!(plan.deliveries[0].from, FROM);
        assert!(!plan.claim_delivered);
    }

    /// Every mode flag is additionally gated on the umbrella: with `allow_test_route_tamper` off,
    /// turning them all on is still the identity.
    #[test]
    fn mode_flags_require_the_umbrella_gate() {
        let mut cfg = Server {
            allow_test_tamper: true,
            allow_test_route_tamper: false,
            ..Server::default()
        };
        cfg.allow_test_route_rewrite = true;
        cfg.allow_test_route_spoof_from = true;
        cfg.allow_test_route_replay = true;
        cfg.allow_test_route_reorder = true;
        cfg.allow_test_route_drop = true;
        cfg.allow_test_route_cross_deliver = true;

        let t = RouteTamper::default();
        let plan = t.plan(&cfg, TO, FROM, vec![1, 2, 3]);
        assert_eq!(plan.deliveries.len(), 1);
        assert_eq!(plan.deliveries[0].blob, vec![1, 2, 3]);
        assert_eq!(plan.deliveries[0].from, FROM);
    }

    #[test]
    fn spoof_from_changes_only_the_origin() {
        let mut cfg = armed();
        cfg.allow_test_route_spoof_from = true;
        let t = RouteTamper::default();
        let plan = t.plan(&cfg, TO, FROM, vec![1, 2, 3]);
        assert_eq!(plan.deliveries.len(), 1);
        assert_ne!(plan.deliveries[0].from, FROM);
        assert_eq!(
            plan.deliveries[0].blob,
            vec![1, 2, 3],
            "spoofing the origin must not touch the opaque payload"
        );
    }

    #[test]
    fn replay_emits_byte_identical_duplicate() {
        let mut cfg = armed();
        cfg.allow_test_route_replay = true;
        let t = RouteTamper::default();
        let plan = t.plan(&cfg, TO, FROM, vec![1, 2, 3]);
        assert_eq!(plan.deliveries.len(), 2);
        assert_eq!(plan.deliveries[0].blob, plan.deliveries[1].blob);
        assert_eq!(plan.deliveries[0].from, plan.deliveries[1].from);
    }

    #[test]
    fn reorder_holds_one_then_releases_behind_the_next() {
        let mut cfg = armed();
        cfg.allow_test_route_reorder = true;
        let t = RouteTamper::default();

        let first = t.plan(&cfg, TO, FROM, vec![1]);
        assert!(first.deliveries.is_empty());
        assert!(first.claim_delivered, "a held blob must still be acked");

        let second = t.plan(&cfg, TO, FROM, vec![2]);
        let order: Vec<Vec<u8>> = second.deliveries.iter().map(|d| d.blob.clone()).collect();
        assert_eq!(order, vec![vec![2], vec![1]], "must arrive 2 then 1");
    }

    #[test]
    fn drop_swallows_only_the_first_blob_per_sender() {
        let mut cfg = armed();
        cfg.allow_test_route_drop = true;
        let t = RouteTamper::default();

        let first = t.plan(&cfg, TO, FROM, vec![1]);
        assert!(first.deliveries.is_empty());
        assert!(
            first.claim_delivered,
            "the interesting lie: swallowed but acked as delivered"
        );

        let second = t.plan(&cfg, TO, FROM, vec![2]);
        assert_eq!(second.deliveries.len(), 1);
        assert_eq!(second.deliveries[0].blob, vec![2]);
    }

    #[test]
    fn cross_deliver_injects_the_captured_envelope_at_the_next_recipient() {
        let mut cfg = armed();
        cfg.allow_test_route_cross_deliver = true;
        let t = RouteTamper::default();

        let first = t.plan(&cfg, TO, FROM, vec![0xAA]);
        assert_eq!(first.deliveries.len(), 1, "the first route passes normally");

        let other: [u8; 32] = [11u8; 32];
        let second = t.plan(&cfg, other, FROM, vec![0xBB]);
        let blobs: Vec<Vec<u8>> = second.deliveries.iter().map(|d| d.blob.clone()).collect();
        assert_eq!(
            blobs,
            vec![vec![0xAA], vec![0xBB]],
            "the captured envelope is injected ahead of the recipient's real traffic"
        );
        assert!(second.deliveries.iter().all(|d| d.to == other));
    }
}
