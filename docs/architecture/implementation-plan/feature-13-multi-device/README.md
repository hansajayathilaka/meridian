> **Nav:** [plan index](../README.md) · **Milestone M3** · [canonical spec: T13](../../features/13-multi-device.md) · [ADR 0005 multi-device](../../../adr/0005-multi-device.md) · [threat model](../../../security/threat-model.md)

# Feature 13 — Multi-Device Support

**Milestone:** M3 · **Depends on:** Feature 08, Feature 11 · **Canonical spec:**
[T13](../../features/13-multi-device.md).

**Goal (from spec).** One shareable ID, several devices: account-signed device records, QR provisioning,
per-device-pair sessions with fan-out, per-device revocation — and the **ghost-device attack demonstrably
detected**. **`[ADR]`** ADR 0005 + **`[SEC]`** throughout.

**Exit acceptance (spec §Acceptance).** Fan-out N×M correctness (every message on every active device
exactly once); forged record rejected 100%; key-theft ghost surfaced 100% on verified contacts; revoked
device decrypts nothing after propagation; provisioning transfer never observable at the server.

| Task | Scope | Tags | Depends on | Status |
|---|---|---|---|---|
| F13.1 | Signed, versioned, append-only device record (add/revoke) published to home rendezvous | [ADR][SEC] | M3 F11 | ☐ |
| F13.2 | Peer-side fetch + verify under account key; device-list-change alerts wired into T08 trust states | [SEC] | F13.1, F08 | ☐ |
| F13.3 | QR provisioning: existing device → new device P2P delegation (account key never leaves old device / server) | [ADR][SEC] | F13.1 | ☐ |
| F13.4 | Sender fan-out to all active peer devices + own other devices | [SEC] | F13.2 | ☐ |
| F13.5 | Revocation + immediate session invalidation for the revoked device | [SEC] | F13.1 | ☐ |
| F13.6 | Optional old→new history sync over an E2E stream (reuses `mrd.file/1`) | — | F13.3, F09 | ☐ |
| F13.7 | Ghost-device harness (forged record + key-theft variants) + `multi-device-v1.md` | [ADR][SEC] | F13.2 | ☐ |

- **F13.1 [ADR][SEC]** — device record with **last-writer-wins on the account-signed version counter** (deterministic merge — document it; racing adds corrupt trust UX if implicit). Review: architect + security-reviewer. Tests: append/revoke ordering. DoD 3,4,5.
- **F13.2 [SEC]** — device-list change on a `verified` contact ⇒ **same blocking semantics as key change** (T08). Tests: change surfaced + blocks. DoD 4.
- **F13.3 [ADR][SEC]** — provisioning delegation P2P; **account private key never touches the server**. Tests: provisioning transfer not observable at server (opacity audit extended). DoD 4.
- **F13.4 [SEC]** — fan-out. Tests: 2 accounts × 2 devices → every message once per active device. DoD 2.
- **F13.5 [SEC]** — revocation. Tests: revoked device decrypts nothing post-propagation. DoD 4.
- **F13.6** — history sync reusing file machinery. Tests: old→new sync E2E. DoD 4.
- **F13.7 [ADR][SEC]** — the **ghost-device harness** (finally makes the DoD-named `ghost-device` harness real): forged record rejected (bad sig); key-theft ghost **surfaced** (detection, not prevention — §4.5 honest claim). Review: security-reviewer. Tests: forged rejected 100%; key-theft surfaced 100% on verified. DoD 2,7.
