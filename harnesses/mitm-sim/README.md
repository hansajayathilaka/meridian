# mitm-sim

Purpose and acceptance: see [docs/testing/strategy.md](../../docs/testing/strategy.md) and the
[threat→mitigation matrix](../../docs/security/threat-mitigation-matrix.md). Run: `./run.sh`.

Every cell is adversarial and asserts a *negative* property. Per
[harnesses/CLAUDE.md](../CLAUDE.md), a failure here is a real defect — never weakened to go green.

## Cells

| # | Attack | Where the defence is | Cell |
|---|---|---|---|
| T02 | Rendezvous substitutes a prekey bundle under a different key | bundle signature verified under the **exact requested key** | `meridian-rendezvous::tampered_bundle_is_rejected`, `meridian-cli::full_rendezvous_demo` |
| T04 | MITM terminates DTLS | §4.6 fingerprint cross-check against the identity-bound value | `meridian-core::p2p_session::fingerprint_mismatch_tears_down` (+ a healthy-path control) |
| 1.28 | Relay **rewrites** a routed blob in transit | Ed25519 envelope signature | `meridian-cli::relay_rewrite` (+ honest-relay control) |
| 1.32 | Relay forges `Deliver.from` | `ChatState::open_bytes` sender/origin cross-check → `SenderMismatch` | `meridian-cli::relay_attacks` |
| 1.32 | Relay **replays** a blob byte-identically | ratchet: the message key for that counter is gone | `meridian-cli::relay_attacks` |
| 1.32 | Relay **reorders** blobs | *tolerated by design* — skipped-message keys; asserts nothing lost or forged | `meridian-cli::relay_attacks` |
| 1.32 | Relay **drops** a blob while acking `delivered: true` | conceded DoS (threat-model goal 6); asserts denial stays denial | `meridian-cli::relay_attacks` |
| 1.32 | Relay **cross-delivers** one session's envelope to another peer | X3DH prekey lookup → `UnknownPrekey` | `meridian-cli::relay_attacks` |
| 1.32 / [ADR 0016](../../docs/adr/0016-envelope-deniability.md) | X3DH **preamble mutation** + prekey depletion | envelope signature covers the preamble; rejection consumes no OTK and installs no session | `meridian-core::preamble_mutation` |
| 4.10 (T08) | Rendezvous substitutes a bundle's key against a contact alice **already has a trust record for** (not just first contact) | same exact-key pin as T02; failed attempt leaves the pre-existing trust record byte-identical | `meridian-cli::mitm_preexisting_contact` |
| 4.10 (T08) | A substituted key is surfaced during task 4.9's guarded desync-recovery bundle-refetch window, against a **pinned** contact | routed through the identical task-4.4 key-change gate — `SendGate::Warn`, `TrustState::PinnedKeyChanged`, canonical `verification-ux.md` wording, no session installed | `meridian-core::desync_recovery::attempt_recovery_routes_a_surfaced_key_change_through_the_gate_never_bypassing_it` |
| 4.10 (T08) | Same, against a **verified** contact | `SendGate::Blocked`, `TrustState::Blocked`, canonical `verification-ux.md` wording, no session installed, `acknowledge_key_change` refused | same test, verified-state case |

## Scope boundaries (read before extending)

* **1.28's byte rewrite cannot reach the ratchet.** `MessageEnvelope` has four fields and its signing
  input covers `sender_pub + prekey + ct`, with `sig` the remainder — every byte is either signed or
  is the signature, so any mutation fails CBOR decode or `verify` first. That is an *impossibility*
  for this server, not a coverage gap. No test has a hostile **relay** cause the §4.6 fingerprint
  check to fire, and none can by mutation; fingerprint binding is proven separately (T04), with an
  honest relay.
* **1.32's attacks are the ones that get past that**, because they never touch the bytes. They are
  what actually exercises the sender/origin check, the ratchet, and the X3DH prekey lookup against a
  hostile server. Each has its own server-side mode flag, is armed alone, and pins a *specific* error
  variant on a *specific* side — "somebody errored somehow" is how these cells go green vacuously.
* **Preamble mutation is deliberately not a relay cell.** `meridian-rendezvous` depends only on
  `meridian-proto` (`tools/lint-server-no-core.sh`), so it has no envelope types and cannot reach
  `used_opk`/`used_spk` even in a test hook. Those cells drive `ChatState::open_inbound` directly.
* **Every adversarial cell has a control** proving the flow otherwise succeeds. Without one, a
  fail-closed assertion is satisfied by any unrelated breakage.
* **Not modelled (known gaps) — the frontier, so the next session sees it instead of inferring
  completeness.** 1.32 covers the routing path; these are the same key-material-free adversary and
  are *not* covered anywhere:
  1. **Stale-bundle replay on the FETCH path.** `PrekeyBundle` carries `v` but no timestamp or
     generation counter, so a malicious server can serve a correctly-signed *old* bundle forever —
     the client's signature check passes and the fetcher cannot detect staleness. This pins a victim
     to a never-rotating SPK, which is exactly the compensating control ADR 0016 C1/R1 leans on for
     envelope v2. Arguably a spec gap, not only a test gap.
  2. **Same OTK handed to many fetchers.** `get_bundle` never consumes an OTK; single-use is enforced
     only at the responder's vault, so every initiator after the first gets `UnknownPrekey` — an
     unattributable targeted DoS that presents as a crypto fault, plus forward-secrecy degradation.
  3. **Reflection** — echoing a blob back to its own sender, or to the sender with a forged `from`.
     Cheap to add on top of the existing buffers.
  4. **Selective per-device delivery.** `Registry::send_to` fans out to all of an account's
     connections; a relay can deliver to one device only, splitting a multi-device user's view.
     (`drop` is per-account, not per-device.)
  5. **Skipped-key exhaustion** (ADR 0016 R2) — `reorder` swaps exactly two blobs; withholding one
     and forwarding N forces up to `MAX_SKIPPED_STORED` derivations. Untested from the relay side.
  6. **Delay past the SPK grace window** (`PREV_GENERATION_GRACE_SECS`) — a prekey envelope held past
     it must fail closed, not be silently accepted. `reorder` covers ordering, not aging.
* **Open defect this harness measured but does not assert:** one replayed envelope permanently wedges
  the receiving ratchet (`Ratchet::decrypt` commits `ckr`/`nr` before `aead_open` without rollback).
  Tracked as [task 2.13](../../docs/tasks/phase-2/2.13-ratchet-replay-dos.md); the replay cell
  deliberately asserts only "never accepted twice", because asserting today's behaviour would
  entrench it.
* **T08's matrix (task 4.10) does not re-attack the fetch layer three times.** `meridian_signaling::
  verify_bundle` pins every live fetch to the *exact requested key*, regardless of the caller's
  pre-existing trust state — a substitution is rejected before `TrustStore` is ever consulted, which
  T02 already proves for a fresh contact. What 4.10 actually adds is the two places that claim was
  not yet load-bearing: (a) that the same fetch-layer rejection holds — and, the part T02 alone does
  not check, leaves the trust record untouched — once alice already has a relationship with the
  target (`mitm_preexisting_contact`), and (b) the *one* path in the system where a genuinely
  different signing key can legitimately reach `TrustStore` at all: task 4.9's guarded desync
  recovery, whose `attempt_recovery` takes the fetched bundle's owner key as a parameter separate
  from the peer identity precisely so this is testable without a live network layer (see
  `apps/core/src/desync.rs`'s own doc comment). "tofu" (brand-new contact) has no separate 4.10 cell
  of its own: the state a first-contact bundle substitution is tested from is exactly what T02
  already exercises, and desync recovery is only reachable once a session already exists — a
  same-attack-different-starting-state cell there would be vacuous.
