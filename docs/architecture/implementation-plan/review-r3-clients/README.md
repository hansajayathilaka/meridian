> **Nav:** [plan index](../README.md) · [review-phase template](../review-phase-template.md) · [anonymity & retention](../../../security/anonymity-and-retention.md) · [Definition of Done](../../../../CONTRIBUTING.md)

# Review R3 — Clients & Multi-Device (closes Milestone M3)

Closes **M3 (Features 11 Browser/Desktop, 13 Multi-Device, 12 Mobile, 15 Location/Stickers)** via the
[review-phase template](../review-phase-template.md). `R3.<m>` remediation tasks are fixed here before M4.

**Status:** ☐ not started (runs when F11/F12/F13/F15 are all built).

## Inputs
- **Milestone under review:** M3 — Features 11, 12, 13, 15.
- **New/changed surfaces:** the WASM/browser + Tauri + mobile shims; IndexedDB/Keystore/Keychain stores;
  the push-send path; device records + provisioning + ghost-device harness; two new Tier-1 stream types;
  the interop matrix + cross-platform conformance vectors.
- **Most-sensitive change:** **the client attack surface + cross-platform key handling.** Deepest pass:
  (a) push payload content-freeness (zero envelope bytes — "must never #3"); (b) conformance vectors
  byte-identical across CLI/browser/desktop/mobile (interop integrity); (c) the shared-core/thin-shim
  boundary held (no networking/crypto fork per platform); (d) ghost-device detection (forged rejected,
  key-theft surfaced); (e) location egress in air-gapped mode (no public tile URL); (f) hardware-backed
  key storage + signed-update supply chain.

## The five areas
1. **Security review** — push content-freeness CI check, IndexedDB/DPAPI/StrongBox/SecureEnclave storage,
   served-JS trust caveat, signed-updater rejection of tampered updates, device-record signatures, and
   location precision quantization-before-encryption.
2. **Completed-work review** — F11/F12/F13/F15 vs acceptance + DoD (interop 9/9, WASM <4 MB, wake p95
   <10 s, fan-out N×M, ghost detection 100%, expiry ±5 s, zero air-gapped egress).
3. **Missing tasks** — cross-platform conformance vectors actually byte-identical; the ghost-device
   harness now real; CODEOWNERS on core crates enforcing the additive-only stream rule for location/stickers.
4. **Gaps needing new steps** — any per-platform networking/crypto fork; any core-crate edit for the new
   stream types.
5. **Future risks** — iOS background-delivery physics (honest in-app copy), libwebrtc build-maintenance
   ops tax, browser web-origin trust problem.

## Findings & remediation
Findings → `findings.md`; each actionable finding → an `R3.<m>` task here, driven with
[`/next-task`](../../../../.claude/commands/next-task.md). **M4 does not start until this gate is clear.**
