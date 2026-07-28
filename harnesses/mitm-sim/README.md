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
* T08 extends this harness with the tofu/verified trust-state matrix — do not delete existing cells.
