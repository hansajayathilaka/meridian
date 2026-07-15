> **Nav:** [plan index](../README.md) · **Milestone M3** · [canonical spec: T12](../../features/12-mobile-clients.md) · [anonymity & retention](../../../security/anonymity-and-retention.md) · [threat model](../../../security/threat-model.md)

# Feature 12 — Mobile Clients (Android & iOS)

**Milestone:** M3 · **Depends on:** Feature 10, Feature 11 · **Canonical spec:**
[T12](../../features/12-mobile-clients.md).

**Goal (from spec).** Native Android (Compose) and iOS (SwiftUI) over UniFFI to the same core: chat, files,
calls with OS call integration, and **content-free push wake** — plus the air-gapped Android fallback.
**`[SEC]`** dominant: push payloads must contain **no envelope bytes, not even ciphertext** ("must never #3").

**Exit acceptance (spec §Acceptance).** Wake-to-delivery p95 <10 s both platforms; **payload
content-freeness asserted by a CI check on the push-send path**; call audio routes through OS call UI;
StrongBox/SecureEnclave used when available; conformance vectors pass on-device.

| Task | Scope | Tags | Depends on | Status |
|---|---|---|---|---|
| F12.1 | UniFFI Kotlin/Swift bindings to `meridian-core` | [ADR] | M3 F11 | ☐ |
| F12.2 | Platform WebRTC (libwebrtc) `Transport`/media shim | [ADR] | F12.1, F10 | ☐ |
| F12.3 | Keystore-StrongBox / Keychain-SecureEnclave `SecretStore` | [SEC] | F12.1 | ☐ |
| F12.4 | Content-free push wake (FCM/APNs) + CI content-freeness assertion | [SEC] | F12.1 | ☐ |
| F12.5 | CallKit / ConnectionService integration (background ring) | — | F12.2 | ☐ |
| F12.6 | Air-gapped Android mode: foreground-service WebSocket instead of FCM | [SEC] | F12.4 | ☐ |
| F12.7 | On-device conformance vectors in CI + `mobile-push.md` + battery/soak report | [SEC] | F12.4 | ☐ |

- **F12.1 [ADR]** — UniFFI bindings. Review: architect. Tests: binding smoke both platforms. DoD 5.
- **F12.2 [ADR]** — platform libwebrtc shim; document the build pipeline as a **deliverable, not tribal knowledge**. DoD 5.
- **F12.3 [SEC]** — hardware-backed key storage; attested in a diagnostics screen. Tests: StrongBox/SecureEnclave used when offered. DoD 4.
- **F12.4 [SEC]** — the load-bearing privacy task: push = wake ping only. **CI check on the push-send code path asserts zero message bytes** in the payload. Review: security-reviewer. Tests: payload content-freeness. DoD 4.
- **F12.5** — OS call UI; lock-screen answer. Tests: background ring → answer. DoD 4.
- **F12.6 [SEC]** — air-gapped Android (FCM blocked) via foreground-service WS; restate the §9.3 iOS-no-push limitation in-app. Tests: delivery with FCM blocked. DoD 4,7.
- **F12.7 [SEC]** — on-device vectors + honest push doc (exact FCM/APNs payload schema, reviewable) + battery soak (wake-to-message p95). DoD 3,7.
