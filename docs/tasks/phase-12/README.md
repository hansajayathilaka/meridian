<!-- Copy this file to docs/tasks/phase-N/README.md. Created by /pick-next-phase (build) or
     /start-review-phase (review); the todo list is filled by /plan-phase or /plan-review-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 12 — Browser & Desktop Clients

**Kind:** build · **Status:** planning · **Reviews phase(s):** n/a (pending a future `/start-review-phase`)

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

## Tasks (todo)
<!-- Filled by /plan-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
- [ ] **12.1** <title> — [file](./12.1-<slug>.md)

## Exit criteria
Phase 12 is done when every task is `[x]`, the tree is green (`cargo build --workspace`,
`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `pnpm` checks for
the web/desktop shells), docs are synced, and the feature's acceptance demo — the
{CLI, browser, desktop}² interop matrix (chat, file, verify) plus the byte-identical conformance-vector
check — runs clean. Then the next command is `/start-review-phase`.
