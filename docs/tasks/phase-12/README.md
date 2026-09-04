<!-- Copy this file to docs/tasks/phase-N/README.md. Created by /pick-next-phase (build) or
     /start-review-phase (review); the todo list is filled by /plan-phase or /plan-review-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 12 — Browser & Desktop Clients

**Kind:** build · **Status:** open — 6/20 tasks done · **Reviews phase(s):** n/a (pending a future `/start-review-phase`)

## Goal
Ship **[T11 — Browser & Desktop Clients](../../architecture/features/11-browser-desktop-clients.md)**:
the same `meridian-core`, identity, and conformance vectors running as (a) a WASM-core browser client
and (b) a Tauri desktop app (Windows first), proving the shared-core/thin-shim strategy — `Transport` is
a trait specifically so zero networking code forks per platform. Acceptance = a green
{CLI, browser, desktop}² interop matrix (chat, file transfer, verification) in CI, byte-identical T01/T08
conformance vectors (IDs, safety numbers) across all three implementations, a sub-4 MB gzipped WASM
bundle, ratchet continuity across a browser refresh (IndexedDB-backed store), and a desktop updater that
rejects an unsigned/tampered update.

## Chosen feature(s) / scope
- **T11 — Browser & Desktop Clients** — [spec](../../architecture/features/11-browser-desktop-clients.md)
  · Priority **P2** · depends on **T04–T09** (all done ✔; T04 since Phase 0, T05/T06 by Phase 2, T08 by
  Phase 4, T07 by Phase 8, T09 by Phase 10) · indicative effort 4–5 eng-weeks.

In scope per the spec: `meridian-core` → wasm32 build; a browser `Transport` shim over the browser's
`RTCPeerConnection` via wasm-bindgen; an IndexedDB-backed encrypted store; browser UI (chat, contacts,
verification QR via camera scan, file send/receive, message requests); a Tauri shell (core in-process,
native `Transport` reused from T04, DPAPI `SecretStore`, same UI codebase); a signed desktop
release + updater with signature verification (§9.4); and the cross-implementation interop matrix in CI.
Out of scope per the spec: mobile (T12), web-push, multi-device (T13 — one device per platform for now),
and solving the web-origin trust problem beyond documenting it (the served-JS trust caveat lands verbatim
in the deployment guide — enterprises serve the web client from their own audited origin or prefer
desktop). The spec's dependency line also lists "T10 for calls in-scope-if-ready" — T10 has not shipped,
so call UI is not part of this phase's scope; nothing in the spec's actual Scope → In list requires it.

## Dependency check
T11's dependency row is **T04–T09** ([roadmap.md](../../architecture/roadmap.md) line 23), all closed by
the end of Phase 10 (T04 in Phase 0; T05/T06 in Phase 2; T08 in Phase 4; T07 in Phase 8; T09 in Phase 10).
No feature blocks T11 today.

The unblocked set at this point in the tracker is **{T10, T11, T14, T16}** — T09's closure (Phase 10)
satisfies T11 (deps T04–T09) and T16 (deps T09); T05/T06 already satisfied T10; T06/T07 already satisfied
T14. T11 is chosen over the other three:

- **Priority tier.** T10 and T11 both carry **P2**; T14 is **P3**; T16 is **P4** ("the payoff task,"
  explicitly the lowest tier in its own spec). T11 and T10 both outrank T14 and T16 outright; T14 and T16
  stay valid choices for later phases but aren't competitive against a P2 item right now.

- **Critical-path test** — the same test Phase 2 used to pick T06 over T08/T09, and Phase 10 used to pick
  T09 over T10/T14. Between the two P2 candidates, T11 is the stronger pick: **T11 is now the sole
  remaining gate on T13** (Multi-Device, deps T08+T11 — T08 closed in Phase 4) **and on T15** (Location &
  Stickers, deps T09+T11 — T09 closed in Phase 10), and it jointly gates **T12** (Mobile, deps T10+T11)
  alongside T10. T10, by contrast, gates only T12, and only jointly with T11 — the same shape that got T10
  passed over in Phase 10 ("T09 is the sole gate on T11... T14 gates nothing"; picking T10 there would
  have unblocked nothing new on its own). The parallel holds again here: picking T10 alone would still
  leave T12 blocked on T11, while picking T11 alone fully unblocks T13 and T15 outright and gets T12
  halfway there. **T14 and T16 both gate nothing** — neither appears in any other feature's dependency row
  in the roadmap table; both are leaves in the dependency DAG, same as T14 was when passed over in Phase
  10.

- **Track structure confirms it.** Track D is `17→11→12→15`
  ([roadmap.md](../../architecture/roadmap.md) "Parallel tracks" section) — T17 closed in Phase 4, so T11
  is Track D's next item, already in sequence. T10 belongs to the separate Track B (`04→05→09→10→16`);
  nothing forces Track B and Track D into the same phase, and T10 remains fully valid to pick next —
  likely a natural candidate for Phase 13, since closing it would then fully unblock T12.

- **Not bundled with T10, T14, or T16 — no forced prerequisite, no meaningful code-path overlap.** T11's
  dependency line only *optionally* invites T10 ("in-scope-if-ready"); since T10 hasn't shipped, there is
  nothing to bundle, unlike Phase 4's forced T08+T17 bundle (a hard prerequisite for T17's verification
  screens). T14 (ops/deploy tooling) and T16 (SSH/fs tunnels) share no code path with T11's
  WASM-core/browser-shim/Tauri-shell/IndexedDB work. Being simultaneously unblocked doesn't by itself
  justify a bundle — Phase 10 kept T09 separate from T10/T14 on the same reasoning.

- **Effort note.** T11 is indicatively 4–5 eng-weeks, the largest single-feature scope picked as a phase
  since T09 (2 eng-weeks) — a WASM build, browser `Transport` shim, IndexedDB store, Tauri shell, and a
  full {CLI, browser, desktop}² interop matrix. Large enough to justify a phase on its own rather than
  being diluted by a bundle, matching T09's own precedent.

**T10, T14, and T16 all remain valid, unblocked choices for a later build phase.**

## Architect consult: substrate/store/signing decisions settled before task breakdown

An architect consult ran before task breakdown (Phase-8/Phase-10-style), because T11 raises genuine
design questions no existing ADR fully settles:

1. **Desktop needs no new `SecretStore` or `Transport` implementation.** `apps/store::OsSecretStore`
   is already cross-platform (`keyring-core`, with `windows-native-keyring-store`/
   `apple-native-keyring-store`/`zbus-secret-service-keyring-store` already resolved in `Cargo.lock`) and
   `apps/transport::WebRtcTransport` is already native, tokio-based, with no CLI-specific coupling —
   both are directly reusable from a Tauri Rust backend (in-process, full OS access, per ADR 0010) as-is.
   Desktop's work is Tauri *integration*: a new `apps/desktop` crate wiring these in, plus the shared
   Svelte UI (ADR 0012), plus Tauri command/event plumbing. No task in this phase implements a new
   desktop-side `SecretStore`/`Transport`.
2. **Browser client-local store** needed a new ADR — ADR 0021 is explicitly scoped to the terminal
   client's filesystem/`at_rest::seal` substrate, which doesn't transfer to a browser sandbox (no
   filesystem). [ADR 0026](../../adr/0026-browser-client-local-store.md) decides: a new
   `WebCryptoSecretStore` backed by non-extractable WebCrypto `CryptoKey`s (the first `SecretStore` impl
   that can honestly report `nonextractable() == true`), plus IndexedDB records sealed with the
   existing, unmodified `meridian_crypto::at_rest::seal`/`open` under a derived key — same
   schema-versioning/fail-closed discipline as ADR 0021, ported to IndexedDB records instead of files.
3. **`meridian-core` does not compile to `wasm32-unknown-unknown` today**, confirmed by dependency-graph
   audit (three independent blockers: `meridian-signaling`'s unconditional `tokio-tungstenite`
   dependency has no wasm32 story; `apps/core/src/session.rs` and `meridian-transport`'s default build
   call `tokio::time` directly; `meridian-store`'s `getrandom 0.3` needs its `wasm_js` backend opt-in
   configured, and `wasm32-unknown-unknown` isn't yet in `rust-toolchain.toml`). This mirrors Phase 10's
   task 10.4 precedent exactly: a dedicated substrate-completion arc (tasks 12.1 and 12.4 below) must
   land — zero browser-UI-specific logic — before the real browser `Transport` shim / `meridian-wasm`
   crate work starts. No new ADR needed; this implements already-accepted design (`stack.md`'s "one
   core, five targets"), the same no-ADR call 10.4 made.
4. **Desktop signed release + updater** needed a new ADR — ADR 0022/0023 deliberately deferred code
   signing project-wide ("no tagged release, no known external consumer yet"), but T11's acceptance
   criterion ("desktop updater rejects an unsigned/tampered update") is an auto-apply path, a materially
   different risk than a passive checksum-verified download, crossing that deferral's own reopening
   trigger for this one channel. [ADR 0027](../../adr/0027-desktop-signed-updates.md) decides: Tauri's
   own built-in updater-plugin signing scheme (minisign-style, CI-held private key) satisfies the
   criterion; OS-trusted Authenticode/notarization signing stays deferred, same trigger as 0022/0023.
5. **No TUI surface task.** T11 ships new client *platforms* (browser, desktop) for content types
   (chat, file, verification) that already have TUI surfaces from Phases 4/10 — no new stream type or
   protocol-level user-visible capability is introduced for the TUI to lag behind, so Definition of Done
   gate 9 does not apply to this phase. Recorded here explicitly per the CLAUDE.md convention for a
   feature with no TUI surface.

Two scoping calls the planner made that aren't spelled out in any doc (flagged, not silently taken):
the signaling WebSocket transport seam (12.4) is its own task, separate from the toolchain/`getrandom`/
timer task (12.1) — the former is a new internal trait/seam inside one crate, the latter is cross-cutting
build configuration touching several leaf crates, and bundling them would violate "one focused change
per task"; and the new `WebCryptoSecretStore` trait impl lives in `apps/store` (mirrors `os.rs`/`file.rs`/
`mem.rs`) while the IndexedDB record-sealing/schema module (ADR 0026 conditions 2–5) lives in the new
`apps/wasm` crate, because `meridian-crypto` (needed for sealing) already depends on `meridian-store`
(`stack.md`'s acyclic graph) — putting the sealing code inside `apps/store` alongside the trait impl
would create a cycle. ADR 0026 itself leaves this split open, so this isn't re-litigating the ADR.

Full breakdown: [Tasks (todo)](#tasks-todo) below.

## Tasks (todo)
<!-- Filled by /plan-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->

**Wave 1 — independent**
- [x] **12.1** `wasm32` substrate: toolchain + `getrandom` backend + timer seam — [file](./12.1-wasm32-substrate-toolchain-getrandom-timer.md)
- [x] **12.2** `shared-ui` package + `MeridianClientAdapter` TS interface — [file](./12.2-shared-ui-client-adapter-interface.md)
- [x] **12.3** `apps/desktop` Tauri crate scaffold (Rust side) — [file](./12.3-desktop-tauri-crate-scaffold.md)

**Wave 2 — depends on Wave 1**
- [x] **12.4** `meridian-signaling` WebSocket transport seam (depends on 12.1) — [file](./12.4-signaling-ws-transport-seam.md)
- [~] **12.5** `WebCryptoSecretStore` in `apps/store`, wasm32-gated (depends on 12.1) — [file](./12.5-webcrypto-secret-store.md)
- [x] **12.6** Desktop TS adapter (depends on 12.2, 12.3) — [file](./12.6-desktop-ts-adapter.md)
- [x] **12.7** Core messaging screens: chat + contacts + message-requests (depends on 12.2) — [file](./12.7-core-messaging-screens.md)
- [ ] **12.8** Verification screen: QR camera-scan safety-number compare (depends on 12.2, 12.7) — [file](./12.8-verification-screen.md)
- [ ] **12.9** File transfer screen (depends on 12.2, 12.7) — [file](./12.9-file-transfer-screen.md)

**Wave 3 — depends on Wave 2**
- [ ] **12.10** `meridian-wasm` crate scaffold + smoke build + bundle-size report (depends on 12.4) — [file](./12.10-meridian-wasm-crate-scaffold.md)

**Wave 4 — depends on Wave 3**
- [ ] **12.11** Browser `Transport` shim (depends on 12.10) — [file](./12.11-browser-transport-shim.md)
- [ ] **12.12** Browser IndexedDB sealed store, `apps/wasm` (depends on 12.10, 12.5) — [file](./12.12-browser-indexeddb-sealed-store.md)

**Wave 5 — depends on Wave 4**
- [ ] **12.13** Browser wasm adapter (depends on 12.2, 12.11, 12.12) — [file](./12.13-browser-wasm-adapter.md)

**Wave 6 — app shells**
- [ ] **12.14** `apps/web` app shell (depends on 12.13, 12.7, 12.8, 12.9) — [file](./12.14-web-app-shell.md)
- [ ] **12.15** `apps/desktop` app shell (depends on 12.6, 12.7, 12.8, 12.9) — [file](./12.15-desktop-app-shell.md)

**Wave 7**
- [ ] **12.16** Desktop signed release + updater pipeline, ADR 0027 (depends on 12.15, 12.3) — [file](./12.16-desktop-signed-updater-pipeline.md)

**Wave 8 — cross-cutting verification**
- [ ] **12.17** {CLI, browser, desktop}² interop matrix CI job (depends on 12.14, 12.15) — [file](./12.17-interop-matrix-ci.md)
- [ ] **12.18** T01/T08 conformance-vector byte-identity check across CLI/browser/desktop (depends on 12.13, 12.15) — [file](./12.18-cross-client-conformance-vectors.md)

**Wave 9 — docs + phase exit**
- [ ] **12.19** `web-deployment-guide.md` (depends on 12.14) — [file](./12.19-web-deployment-guide.md)
- [ ] **12.20** Phase exit: acceptance demo + doc sync (depends on 12.16, 12.17, 12.18, 12.19) — [file](./12.20-phase-exit-acceptance-demo.md)

## Exit criteria
Phase 12 is done when every task is `[x]`, the tree is green (`cargo build --workspace`,
`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `pnpm` checks for
the web/desktop shells), docs are synced, and the feature's acceptance demo — the
{CLI, browser, desktop}² interop matrix (chat, file, verify) plus the byte-identical conformance-vector
check — runs clean. Then the next command is `/start-review-phase`.
