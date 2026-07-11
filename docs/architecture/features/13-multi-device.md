<!-- Source: tasks/T13-multi-device.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T13 — Multi-Device Support

**Priority:** P3 · **Design refs:** §4.5, ADR-5 · **Depends on:** T08, T11 · **Indicative effort:** 3–4 eng-weeks

## Goal
One shareable ID, several devices: account-signed device records, QR-mediated provisioning, per-device-pair sessions with fan-out, per-device revocation — and the ghost-device attack demonstrably detected.

## Scope
In: signed, versioned, append-only device record (add/revoke entries) published to home rendezvous; peer-side fetch + verification under the account key, with device-list-change alerts wired into the T08 trust states (change on a `verified` contact ⇒ same blocking semantics as key change); provisioning: existing device displays QR → new device scans → encrypted delegation transfer P2P (account private key never leaves the old device, never touches the server); sender fan-out to all active peer devices *and* own other devices; revocation flow + immediate session invalidation for the revoked device; optional history sync old→new device over an E2E stream (reuses `mrd.file/1` machinery).
Out: MLS/groups interaction (Phase 3), device count > 5 optimization, escrow of any kind (§12 Q2 — restated as a hard no here).

## Deliverables
1. Device-record module + provisioning flow (CLI, desktop, browser; mobile follows in a T12 patch release).
2. **Ghost-device harness:** malicious rendezvous inserts a device entry it minted → peers must reject (bad signature) ; then the harder variant — a *stolen account key* signs a real ghost device → peers must *surface* the device-list change alert (detection, not prevention — matching §4.5's honest claim).
3. `multi-device-v1.md` incl. revocation semantics and the fan-out cost note.

## Working output (demo script)
```
$ meridian devices list            # phone/CLI: 1 device
— desktop app: "Link device" → shows QR → scan with CLI (--scan-file) —
  [provision] delegation received P2P; device #2 active
$ # message from bob arrives on BOTH devices; reply from either continues one conversation
$ meridian-mitm-sim --attack ghost-device --forged     # → rejected: record signature invalid
$ meridian-mitm-sim --attack ghost-device --key-theft  # → peers shown blocking device-change alert
$ meridian devices revoke 2        # device 2's next connection attempt: sessions dead, must re-link
```

## Acceptance criteria
Fan-out correctness: N×M matrix (2 accounts × 2 devices each) — every message on every active device exactly once; forged record rejected 100%; key-theft ghost surfaced 100% on verified contacts; revoked device can decrypt nothing sent after revocation propagates; provisioning transfer never observable at the server (opacity audit extended).

## Risks / notes
Device-record versioning conflicts (two adds racing) need a deterministic merge rule — pick last-writer-wins on account-signed version counter and document it; this is the kind of edge that corrupts trust UX if left implicit.
