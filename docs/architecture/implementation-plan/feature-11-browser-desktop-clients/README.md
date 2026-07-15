> **Nav:** [plan index](../README.md) · **Milestone M3** · [canonical spec: T11](../../features/11-browser-desktop-clients.md) · [ADR 0010 Tauri](../../../adr/0010-desktop-shell-tauri.md) · [ADR 0012 browser UI](../../../adr/0012-browser-ui-framework.md)

# Feature 11 — Browser & Desktop Clients

**Milestone:** M3 · **Depends on:** Features 04–09 · **Canonical spec:**
[T11](../../features/11-browser-desktop-clients.md).

**Goal (from spec).** The same protocol + identity + conformance vectors running as a WASM-core browser
client and a Tauri desktop app, proving the shared-core/thin-shim strategy and cross-implementation interop
with the CLI. **`[ADR]`** ADR 0010/0012 + **`[SEC]`** (client key storage, served-JS trust, signed updates).

**Exit acceptance (spec §Acceptance).** All interop cells pass; WASM bundle <4 MB gz; browser refresh
restores sessions from IndexedDB (ratchet continuity); desktop updater rejects unsigned/tampered updates;
identical safety numbers across platforms (the T08 fixtures).

> **Depends on M0 T2.7** (wasm32 build validation) — schedule the WASM smoke build day-1.

| Task | Scope | Tags | Depends on | Status |
|---|---|---|---|---|
| F11.1 | `meridian-core` → wasm32 bundle (<4 MB gz) + WASM smoke | [ADR] | M0 T2.7 | ☐ |
| F11.2 | Browser `Transport` shim over `RTCPeerConnection` (wasm-bindgen; zero networking fork) | [ADR][SEC] | F11.1 | ☐ |
| F11.3 | IndexedDB-backed encrypted store (ratchet continuity across refresh) | [SEC] | F11.1 | ☐ |
| F11.4 | Browser UI: chat, contacts, verify-QR (camera), file, message-requests | — | F11.2, F11.3 | ☐ |
| F11.5 | Tauri desktop shell: in-process core, native Transport, DPAPI `SecretStore`, shared UI | [ADR][SEC] | F11.2 | ☐ |
| F11.6 | Signed desktop release + updater with signature verification (§9.4) | [SEC] | F11.5 | ☐ |
| F11.7 | Cross-impl interop matrix in CI ({CLI,browser,desktop}² × {chat,file,verify}) + conformance vectors | [SEC] | F11.4, F11.5 | ☐ |
| F11.8 | `web-deployment-guide.md` (served-JS trust caveat + CSP baseline) | [SEC] | F11.4 | ☐ |

- **F11.1 [ADR]** — the wasm build; if M0 T2.7 slipped it bites here. Tests: bundle-size gate; WASM smoke. DoD 1.
- **F11.2 [ADR][SEC]** — the shim that proves *why Transport is a trait*: enforce **zero networking code forks**. Review: architect + security-reviewer. Tests: browser P2P connect. DoD 5,6.
- **F11.3 [SEC]** — encrypted IndexedDB store; key non-extractable via WebCrypto where possible. Tests: refresh restores ratchet. DoD 4.
- **F11.4** — browser UI surface. Tests: chat/file/verify flows. DoD 4.
- **F11.5 [ADR][SEC]** — Tauri shell reusing the UI codebase; DPAPI store. Review: architect. Tests: desktop chat/file. DoD 4,5.
- **F11.6 [SEC]** — signed MSI + updater that **rejects unsigned/tampered updates** (§9.4 supply chain). Tests: tampered update rejected. DoD 4.
- **F11.7 [SEC]** — the 9-cell interop matrix + **byte-identical conformance vectors** (T01/T08) across CLI/browser/desktop. Tests: 9/9 green; vectors byte-identical. DoD 3.
- **F11.8 [SEC]** — the served-JS trust caveat (§6) verbatim + CSP baseline; enterprises serve from their own audited origin or prefer desktop. DoD 7.
