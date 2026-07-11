<!-- Source: tasks/T12-mobile-clients.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T12 — Mobile Clients (Android & iOS)

**Priority:** P3 · **Design refs:** §6 · **Depends on:** T10, T11 · **Indicative effort:** 6–8 eng-weeks (both platforms)

## Goal
Native Android (Compose) and iOS (SwiftUI) clients over UniFFI bindings to the same core: chat, files, calls with OS call integration, and content-free push wake — plus the air-gapped Android fallback.

## Scope
In: UniFFI Kotlin/Swift bindings; platform WebRTC (libwebrtc builds) as the `Transport`/media shim; Keystore-StrongBox / Keychain-SecureEnclave `SecretStore`; **push = content-free wake ping** ("connect to your rendezvous") via FCM/APNs — assert in code that notification payloads contain no envelope bytes, not even ciphertext (§6); CallKit / ConnectionService integration (incoming ring while backgrounded); background delivery semantics per-OS documented honestly (iOS fetch limits); air-gapped Android mode: persistent foreground-service WebSocket instead of FCM; conformance vectors on-device in CI (emulator/simulator).
Out: air-gapped iOS push (impossible — restate the §9.3 named limitation in-app when configured for an air-gapped org), tablets/watch, T15 features.

## Deliverables
1. `meridian-android` (APK + Play listing draft) and `meridian-ios` (TestFlight build).
2. Push architecture note `mobile-push.md` — including the exact FCM/APNs payload schema, reviewable for content-freeness.
3. Battery/soak report: 24 h idle with live registration, wake-to-message latency distribution.

## Working output (demo script)
```
— phone locked in pocket, app killed by OS —
$ meridian chat mrd1:<phone-user>@org-a.test     # send from CLI
  → phone shows notification within seconds; opening app: message present, ratchet intact
— cross-org video call CLI/desktop → phone rings via CallKit/ConnectionService, accept, talk —
$ adb shell dumpsys / Console: pushed payload contains routing wake only — zero message bytes
— air-gap demo: FCM blocked at the firewall, foreground-service mode → delivery still works —
```

## Acceptance criteria
Wake-to-delivery p95 < 10 s on both platforms; payload content-freeness asserted by a CI check on the push-send code path; call audio routes through OS call UI (lock-screen answer works); StrongBox/SecureEnclave used when hardware offers it (attested in a diagnostics screen); conformance vectors pass on-device.

## Risks / notes
iOS background-delivery limitations are physics here, not a bug — set expectations in-app copy. libwebrtc build maintenance is the long-term ops tax this task signs the team up for; document the build pipeline as a deliverable, not tribal knowledge.
