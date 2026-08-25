#!/usr/bin/env bash
# mitm-sim harness — a malicious rendezvous substitutes a prekey bundle under a different key; a
# correct client MUST verify the bundle under the exact requested key and abort (no downgrade).
#
# T02 wires the first, load-bearing case: the substituted-bundle abort at both the library layer
# (meridian-signaling::verify_bundle) and the CLI layer (`fetch-bundle --tamper` fails closed).
# T04 EXTENDS it to the transport layer: SDP/ICE ride inside ratchet-encrypted envelopes, so a relay
# seeing only ciphertext cannot read or forge the inner SDP, and the DTLS fingerprint is cross-checked
# against the identity-bound value after the handshake — a mismatch (a MITM that terminated DTLS)
# tears the session down 100% of the time (§4.6).
# Task 1.28 ADDS the relay-as-adversary case: a real rendezvous actively REWRITING routed blobs in
# transit, driven through a real dial/answer (below). Scope it precisely — a byte-level rewrite
# breaks the Ed25519 envelope signature, so it is stopped at envelope AUTHENTICATION, strictly
# EARLIER than the §4.6 fingerprint cross-check, which that path never reaches. No test exists in
# which a hostile *relay* causes §4.6 to fire, and none can by mutation: every envelope byte is
# either signed or is the signature, so any mutation fails CBOR decode or signature verification
# first. Fingerprint binding is proven separately, with an honest relay.
# Task 1.32 ADDS the relay attacks that need no key material and DO pass the signature check because
# they never touch the bytes — a forged Deliver.from, replay, reorder, drop, cross-delivery — plus
# the X3DH preamble mutations ADR 0016 requires, which a relay cannot mount (no envelope types
# server-side) and which are therefore driven client-side.
# T08 EXTENDS this harness with the tofu/verified trust-state matrix — do not delete these cases.
# See docs/testing/strategy.md §3 and docs/security/threat-mitigation-matrix.md.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "[mitm-sim] substituted-bundle abort (library + CLI)…"
cargo test -q -p meridian-rendezvous --features test-tamper-hook --test rendezvous tampered_bundle_is_rejected
cargo test -q -p meridian-cli --test rendezvous_demo full_rendezvous_demo
echo "[mitm-sim] OK: client aborts on a bundle signed under any other key."

echo "[mitm-sim] DTLS fingerprint-binding teardown (T04 §4.6)…"
cargo test -q -p meridian-core --test p2p_session fingerprint_mismatch_tears_down
cargo test -q -p meridian-core --test p2p_session relay_path_connects_healthily
echo "[mitm-sim] OK: fingerprint mismatch tears the session down; a healthy relay path still binds"
echo "  matching fingerprints."

# 1.28: the relay itself is the adversary. A real meridian-rendezvous (test-tamper-hook +
# allow_test_route_tamper) rewrites every routed signaling blob while two peers run a real
# dial/answer. Asserts BOTH that no session establishes (fail-closed) and that the RESPONDER rejects
# at the envelope-authentication layer specifically (SessionError::Chat — matched on the variant, so
# it survives ADR 0016's move of the detector from the signature to the ratchet AEAD). Pinning the
# side and the error class is deliberate: accepting "either side errored somehow" would go green if
# the hook became inert and an unrelated relay error fired. Ships with a control case through an
# honest relay, so the adversarial assertion cannot pass vacuously either.
echo "[mitm-sim] active relay-rewrite of routed blobs (1.28)…"
cargo test -q -p meridian-cli --test relay_rewrite
echo "[mitm-sim] OK: a rendezvous rewriting routed blobs is detected at the envelope signature"
echo "  check (earlier than the §4.6 fingerprint check, which this path never reaches) and cannot"
echo "  establish a session; the same flow through an honest relay does establish."

# 1.32: the attacks a routing relay mounts WITHOUT touching the bytes, so the signature check waves
# them through and they reach the ratchet — which no earlier cell does. One server-side mode flag per
# attack (spoof_from / replay / reorder / drop / cross_deliver), each armed alone, each pinning the
# SPECIFIC error variant on the SPECIFIC side: SenderMismatch for a forged Deliver.from, a ratchet
# refusal for a byte-identical replay, UnknownPrekey for a cross-delivered envelope. Reorder is the
# deliberate exception: it must SUCCEED (a permutation of authentic messages is what the ratchet's
# skipped-key handling exists for), so that cell asserts nothing is lost or forged and proves the
# swap really happened. Drop asserts denial stays denial — the relay lies "delivered: true" and the
# message is simply gone. Each cell has a control through an honest relay.
echo "[mitm-sim] relay attacks that PASS the signature check (1.32)…"
cargo test -q -p meridian-cli --test relay_attacks
echo "[mitm-sim] OK: forged from / replay / cross-delivery are each refused with their own"
echo "  diagnosable error; reorder is tolerated without forgery; a dropped message stays dropped."

# 1.32 + ADR 0016 test obligations: X3DH preamble mutation (used_opk -> None, used_opk -> another
# held OTK, used_spk -> previous generation) and a forged prekey envelope claiming from = Alice.
# NOT a relay cell by construction: meridian-rendezvous has no envelope types (lint-server-no-core),
# so it cannot reach the preamble even in a test hook — these are driven directly against
# ChatState::open_inbound. Each asserts all four of ADR 0016's properties: rejected at the SIGNATURE
# specifically, OTK pool depth unchanged, no session installed, and the genuine envelope still opens
# afterwards. That last pair is the anti-DoS property: rejection costs the recipient nothing.
echo "[mitm-sim] X3DH preamble mutation + prekey-depletion (1.32 / ADR 0016)…"
cargo test -q -p meridian-core --test preamble_mutation
echo "[mitm-sim] OK: a mutated preamble is rejected before the vault is touched — no prekey burned,"
echo "  no poisoned session, and the genuine envelope still establishes."

# 2.12: the A2×2 CROSS-ORG cell — threat-mitigation-matrix.md names T06 as the owner of A2×2, the
# dual-side MITM/malicious-server-substitution mitigation, and this is what actually proves it.
# Extends the single-hop bundle-substitution cell above (line ~27) across a federation boundary:
# TWO real meridian-rendezvous servers, org-a (honest, dials out) and org-b (malicious, the
# `test-tamper-hook` federated fetch extension armed), talking real s2s mTLS. Org B lies to org A
# about bob's real, already-published prekey bundle over `fed_fetch_bundle`; Alice's client — which
# only ever talks to org-a — must abort via its OWN verify_bundle check, pinned to
# SignalError::BundleVerification specifically (never a bare unwrap_err), exactly mirroring how
# 1.28 pinned the responder's rejection to Rejected(Chat(BadSignature)) rather than "somebody
# errored". A companion structural-inertness cell (in the same file, `#[cfg(not(feature =
# "test-tamper-hook"))]`) proves the hook does not exist at all without the cargo feature — it only
# executes under the package-scoped `cargo test -p meridian-rendezvous` CI step (see
# .github/workflows/ci.yml's "Tamper-hook" steps), not under this filtered invocation.
echo "[mitm-sim] cross-org malicious-server bundle substitution (2.12 / A2×2)…"
cargo test -q -p meridian-rendezvous --features test-tamper-hook --test federation_abuse \
  cross_org_malicious_server_bundle_substitution_is_rejected_by_the_client
echo "[mitm-sim] OK: org B lying about bob's bundle over the FEDERATED fetch path is caught by"
echo "  alice's own client-side verify_bundle check (SignalError::BundleVerification), even though"
echo "  alice never talks to org B directly."

# T08 (task 4.10): the tofu/pinned/verified TRUST-STATE MATRIX — the headline acceptance criterion
# of Feature 08. Everything above proves a fully malicious rendezvous cannot complete an undetected
# substitution on FIRST contact (no prior trust record at all). This section closes the remaining
# question: can it complete one against a contact alice ALREADY has a relationship with — including
# during task 4.9's guarded desync re-handshake window, the one place in the whole system where a
# *different* signing key can legitimately reach TrustStore at all (every live fetch path pins the
# signature to the exact requested key, per meridian_signaling::verify_bundle, and rejects a
# substitution before TrustStore is ever consulted — see apps/core/src/desync.rs's own doc comment).
echo "[mitm-sim] T08 trust-state matrix: substitute-key attacks against tofu / pinned / verified…"

echo "  -- network+CLI layer: tampered fetch against a PRE-EXISTING (already-pinned) contact --"
cargo test -q -p meridian-cli --test mitm_preexisting_contact
echo "     OK: fails closed identically to the fresh-contact case (T02), AND leaves the"
echo "     pre-existing trust record byte-identical — no phantom key-change state, no new contact"
echo "     row for the attacker's key."

echo "  -- decision-gate layer: a substituted key surfaced during 4.9's recovery window --"
cargo test -q -p meridian-core --test desync_recovery \
  attempt_recovery_routes_a_surfaced_key_change_through_the_gate_never_bypassing_it
echo "     OK: routed through the IDENTICAL task-4.4 key-change gate as any other key-change"
echo "     discovery — never bypassed just because a recovery flow was already in progress."

echo "  -- decision-gate layer: gated (Warn/Blocked) refusals never leave a stale bypass window --"
cargo test -q -p meridian-core --test desync_recovery \
  attempt_recovery_is_refused_while_gated_and_succeeds_once_the_gate_clears
echo "     OK: a gated recovery attempt touches no session state; only an explicit, genuine"
echo "     mark_verified/acknowledge_key_change clears it."

echo ""
echo "[mitm-sim] T08 pass/fail matrix (0 = attacker success, silent or otherwise):"
echo "  state    | live substitution (fresh contact, T02) | live substitution (pre-existing"
echo "           |                                         | contact, this section)          | substitution during 4.9 recovery window"
echo "  ---------+-----------------------------------------+----------------------------------+----------------------------------------"
echo "  tofu/new | 0 successes (BundleVerification, fatal) | n/a (this section starts pinned) | n/a (recovery requires an existing session)"
echo "  pinned   | 0 successes (BundleVerification, fatal) | 0 successes, trust unchanged     | 0 silent successes; Warn shown, exact"
echo "           |                                         |                                  | verification-ux.md wording, no session installed"
echo "  verified | 0 successes (BundleVerification, fatal) | n/a (fresh-contact cell is tofu) | 0 successes; Blocked, exact"
echo "           |                                         |                                  | verification-ux.md wording, no session installed"
echo "[mitm-sim] OK: 0 silent successes against verified; 0 successes against pinned without the"
echo "  exact verification-ux.md warning shown."

# Task 5.5 (review finding F5): the T08 matrix above only ever drove substitution/recovery through
# `apps/cli/src/chat.rs`'s relay path. Before this task, NEITHER the TUI's own persistent inbound
# loop (`meridian_tui::worker::run_inbound_loop`) NOR the P2P dial/accept substrate
# (`apps/core/src/session.rs`) held a single TrustStore/can_send reference — a MITM against an
# already-established conversation on either of those paths went undetected. This section closes
# that gap, extending the SAME task-4.4/4.9 gate machinery (never itself modified) into both.
echo ""
echo "[mitm-sim] task 5.5: receive-side key-change detection wired into the TUI + P2P substrate…"

echo "  -- P2P substrate layer: a substituted key against an already-established P2P session --"
cargo test -q -p meridian-core --test session
echo "     OK: P2pSession::recover_from_desync — a real dial/answer session over LoopbackTransport —"
echo "     warns (pinned) / hard-blocks (verified) a key substitution surfaced during its own"
echo "     receive-side desync recovery exactly like the CLI's maybe_attempt_recovery, refuses an"
echo "     automatic re-handshake outright when the session's own peer is already gated, is a true"
echo "     no-op below the recovery threshold, and leaves the real, already-established session with"
echo "     the genuine peer perfectly healthy throughout."

echo "  -- TUI layer: run_inbound_loop's own desync-recovery gate, over a real rendezvous --"
cargo test -q -p meridian-tui --test inbound_delivery \
  repeated_desync_against_an_already_blocked_contact_never_bypasses_can_send
echo "     OK: a real peer's repeated, authentic-but-undecryptable envelopes against a contact"
echo "     already Blocked from an unresolved key change never bypass TrustStore::can_send's early"
echo "     gate to attempt an automatic re-handshake — trust.bin stays byte-identical, and the live"
echo "     conversation is still healthy afterward. (The complementary substitution-detection half —"
echo "     that a genuine key change surfaced by a fresh bundle IS detected and blocked — is the P2P"
echo "     substrate cell above: a real SignalingClient::fetch_bundle pins its response to the exact"
echo "     requested key, so an on-the-wire substitution against an already-known peer fails closed"
echo "     at that fetch, structurally before this TUI path's own attempt_worker_recovery ever"
echo "     reaches meridian_core::desync::attempt_recovery — see that function's own doc comment.)"
