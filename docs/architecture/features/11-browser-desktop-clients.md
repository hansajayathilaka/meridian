<!-- Source: tasks/T11-browser-desktop-clients.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T11 — Browser & Desktop Clients

**Priority:** P2 · **Design refs:** §6, §2.1 · **Depends on:** T04–T09 (T10 for calls in-scope-if-ready) · **Indicative effort:** 4–5 eng-weeks

## Goal
The same protocol, identity, and conformance vectors running as (a) a WASM-core browser client and (b) a Tauri desktop app (Windows first) — proving the shared-core/thin-shim strategy and cross-implementation interop with the CLI.

## Scope
In: `meridian-core` → wasm32 build; browser `Transport` shim over the browser's RTCPeerConnection via wasm-bindgen (this is *why* Transport is a trait — enforce that zero networking code forks); IndexedDB-backed encrypted store; browser UI: chat, contacts, verification QR (camera scan), file send/receive, message requests; Tauri shell: core in-process, native `Transport` (from T04), DPAPI `SecretStore`, same UI codebase; signed desktop release + updater with signature verification (§9.4); conformance suite: T01/T08 test vectors must produce byte-identical IDs and safety numbers across CLI/browser/desktop.
Out: mobile (T12), web-push, multi-device (T13 — one device per platform for now), the web-origin trust problem beyond documenting it (§6 caveat lands verbatim in the deployment guide: enterprises serve the web client from their own audited origin or prefer desktop).

## Deliverables
1. `meridian-web` (static bundle, servable from the org's rendezvous host or any origin) + `meridian-desktop` (Tauri, signed MSI).
2. Cross-implementation interop matrix in CI: {CLI, browser, desktop}² × {chat, file, verify}.
3. `web-deployment-guide.md` incl. the served-JS trust caveat and CSP baseline.

## Working output (demo script)
```
$ docker compose -f demo/two-orgs up && open https://org-a.test/app
  — create identity in browser (key non-extractable via WebCrypto where possible) —
$ meridian chat mrd1:<browser-user>@org-a.test    # CLI ↔ browser, cross-org optional
  — chat + 200 MB file transfer browser↔CLI; safety numbers match on both, verified by QR —
$ # desktop: install signed MSI on a Windows VM, repeat the matrix
$ ci: interop matrix 9/9 green, conformance vectors byte-identical ✔
```

## Acceptance criteria
All interop cells pass; WASM bundle < 4 MB gz; browser refresh restores sessions from IndexedDB (ratchet continuity); desktop updater rejects an unsigned/tampered update in test; identical safety numbers across platforms for the same key pair (the T08 fixtures).

## Risks / notes
The ratchet library's wasm32 story was de-risked in T03 — if that slipped, it bites here; schedule the WASM smoke build as day-1 of this task regardless.
