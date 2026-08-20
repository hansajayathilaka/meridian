<!-- Feature spec with runnable acceptance demo. Added post-handoff (not one of the original 38
     source documents) — see docs/INDEX.md "Additions after handoff". -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [TUI client design](../tui-client.md) · [system design](../system-design.md) · [verification UX](../../security/verification-ux.md)

# T17 — Terminal TUI Client

**Priority:** P1 (first end-user-facing client) · **Design refs:** §6 (terminal client), §3.5 (message
requests), §4.4 (safety numbers), [stack.md §1/§4](../stack.md) · **Depends on:** T01–T05 (all done;
T06 done, so cross-org IDs work too) · **Indicative effort:** ~3 eng-weeks

## Goal
A **complete, friendly chat application in the terminal** — from "I have nothing" (no keypair, no
account) to a running 1:1 end-to-end-encrypted conversation with a contact list that survives
restarts, driven entirely by an interactive [ratatui](../stack.md) UI rather than by remembering
subcommands.

The existing `meridian` CLI already exposes every capability as a scriptable subcommand
(`id new`, `register`, `chat`, `session connect`, `config`, `doctor`). T17 does **not** replace it:
the CLI stays the headless/demo surface, and the TUI becomes the surface a human uses. Both call the
same `meridian-core`; no protocol logic is added here.

T17 is also the point where "the TUI is the reference user surface" becomes a project rule — see
[Definition of Done gate 9](../../../CONTRIBUTING.md#definition-of-done-every-change-must-satisfy)
and the [extension contract](../tui-client.md#8-extension-contract--every-feature-ships-a-tui-surface).

## Scope

**In:**
- **Onboarding**: first run with no account → guided identity creation (Ed25519 keypair via
  `meridian-identity`, OS keystore or passphrase-wrapped keyfile), the `mrd1:…@domain` ID plus its QR
  rendered in-terminal, then rendezvous registration + prekey-bundle publish.
- **Unlock** on subsequent runs (masked passphrase for the file store, no prompt for OS keystore).
- **Contact list**: add by pasting an `mrd1:` ID (or importing a QR image), local petnames, trust
  state (`new | pinned | verified | blocked`), filter/search, per-contact relay-policy override.
- **Chat**: conversation pane with scrollback, composer with multi-line input, delivery state per
  message, unread markers, restart-persistent history.
- **Message requests**: the first-contact gate (§3.5 / task 2.10) as a reviewable queue — sender key,
  safety number, short intro, accept/reject.
- **Verification**: 60-digit safety number + QR side by side, mark-verified, block, and the
  **un-softenable** key-change handling from [verification-ux.md](../../security/verification-ux.md)
  (verified → composer hard-blocked; pinned → prominent acknowledge-to-continue).
- **Local store**: contacts, history, and outbox as JSON documents, sealed at rest with the existing
  `meridian_crypto::at_rest` primitive under the SecretStore-derived key (realizing
  [data-model.md §2](../data-model.md#2-client-local-store-encrypted-via-secretstore-key)), plus a
  `--export-json` dump for inspection/backup.
- **Config**: `config.toml` (figment + `MERIDIAN_TUI__*` env, mirroring
  [ADR 0018](../../adr/0018-rendezvous-config-loading.md)'s pattern) for theme, keymap, timestamps,
  bell, retention, reconnect backoff.
- **Discoverability**: `F1` help overlay, `Ctrl-K` command palette, status bar showing connection +
  transport path + relay policy, and a diagnostics view wrapping `doctor`.
- **The extension registry** that later features use to add a renderer / palette command / pane
  without touching the TUI core, including graceful placeholder rendering for unknown stream types.

**Out:**
- Any new protocol, wire type, or crypto. If the TUI seems to need one, that is a defect in the plan.
- Group chat (Phase 3 design), calls/media (T10 — a terminal cannot render video; the surface arrives
  with T10 itself), file transfer (T09 — its TUI surface ships with T09 per DoD gate 9), multi-device
  (T13), offline delivery (T07 — until then the outbox is a *local* retry queue and the UI must say so).
- Mouse-driven or GUI-grade layout; the TUI must be fully keyboard-operable.
- Sharing the on-disk store format with the browser/desktop clients — the schema here is client-local
  and versioned; a portable format would need its own contract.

## Decisions to ratify (ADR obligations for this phase)
`/plan-phase` must schedule these **before** any code:

1. **ADR 0020 — TUI packaging.** Recorded intent: a new `apps/tui` crate (`meridian-tui`) owning all
   ratatui/crossterm code, launched by a thin `meridian tui` subcommand in `meridian-cli` behind a
   default-on `tui` feature, so harness/CI builds can stay lean with `--no-default-features`.
   Alternatives to weigh: a standalone `meridian-tui` binary, or putting the TUI directly in
   `meridian-cli`.
2. **ADR 0021 — client-local store & config formats.** Recorded intent: JSON documents sealed with
   `at_rest::seal` under the `SessionStoreKey/v1`-derived key; TOML for human-edited config; explicit
   `--export-json` rather than a persistent-plaintext opt-out. The rejected alternative
   (`store.encrypt = false`) must be recorded as rejected, with reasoning, not silently dropped.

Full proposed design, including the schemas both ADRs decide on:
[architecture/tui-client.md](../tui-client.md).

## Deliverables
1. `apps/tui` (`meridian-tui`): Elm-style `App` state + `update`/`render` split, screen stack, event
   loop over `crossterm` + a tokio worker channel, terminal guard that restores the terminal on panic
   or signal.
2. `meridian tui` subcommand in `meridian-cli` (feature `tui`, default on).
3. `meridian-tui::store`: sealed JSON contacts/history/outbox store + migrations + `--export-json`.
4. `meridian-tui::config`: `config.toml` loading via figment with env overrides and fail-closed
   parsing.
5. `meridian-tui::surface`: the extension registry (renderer / palette command / pane) + unknown-
   stream-type placeholder.
6. Tests: `TestBackend` snapshot tests per screen, an **at-rest audit** harness (the on-disk
   counterpart to `demo opacity-audit`: no plaintext message body, petname, or key material in any
   file the TUI writes), a key-change adversarial test asserting the composer is blocked, and a
   panic-restores-terminal test.
7. Docs: [tui-client.md](../tui-client.md) kept in sync, the two ADRs, and the
   [screen-flow diagram](../diagrams/tui-screen-flow.mermaid).

## Working output (demo script)
```
$ cargo run -p meridian-rendezvous &          # or: just two-orgs, for the cross-org variant
$ meridian tui                                # no account on disk → onboarding
  — pick keystore (OS keychain / passphrase file), enter org hint —
  — keypair generated, mrd1:…@org-a.test shown with QR, "registered ✔ bundle published ✔" —
  — ^N, paste the peer's mrd1: ID, petname "bob" —
  — peer runs `meridian tui` too and sees a message request: key + safety number + intro —
  — accept → both sides chat; ^V shows the same 60-digit safety number on both → mark verified —
$ pkill meridian-tui && meridian tui          # restart
  — contact list, petnames, full history, and the ratchet session all restored, no re-handshake —
$ meridian tui --export-json /tmp/dump && jq '.contacts[0].petname' /tmp/dump/contacts.json
  "bob"
$ ci: screen snapshots green, at-rest audit green, key-change block test green ✔
```

## Acceptance criteria
- A user with **no prior state** reaches a delivered, verified message using only on-screen
  affordances — no man page, no subcommand memorization.
- Renders correctly at **80×24**, degrades to a single pane below 80 columns, is legible with
  `NO_COLOR=1` and `ui.unicode = false`, and refuses gracefully (pointing at the CLI's `--json`
  modes) on `TERM=dumb` or a non-TTY stdout.
- Restart restores contacts, history, and ratchet state; no re-handshake, no duplicate messages
  (local dedup by message id).
- **Key change on a verified contact blocks sending** until re-verification, with the canonical
  wording from [verification-ux.md](../../security/verification-ux.md); no dismiss-without-verify
  path exists anywhere in the UI.
- The at-rest audit finds no plaintext message body, petname, or key material in any file the TUI
  writes.
- A panic or `SIGINT` leaves the terminal usable (cooked mode, main screen, cursor visible).
- An envelope carrying an unregistered stream type renders as a labeled placeholder rather than
  breaking the transcript or the app.

## Risks / notes
- **Terminal restoration is a reliability invariant, not a nicety.** A crash that leaves raw mode on
  is the single most damaging bug class in a TUI. Ship the guard + its test in the first task.
- **Dependency weight**: ratatui + crossterm + image/QR pull into the `meridian` binary that also
  drives every acceptance demo. The `tui` feature flag (ADR 0020) is what keeps demo/CI builds lean —
  verify `--no-default-features` still builds and the existing demos still run.
- **Do not imply store-and-forward** before T07 lands: a message to an offline peer fails visibly and
  stays in the outbox as *local* retry. Copy must not say "delivered when they come online".
- **Un-softenable UX under keyboard pressure**: the block/warning modals are exactly where a "make it
  less annoying" change will be tempting. The security-reviewer treats softening as blocking.
- History growth is unbounded by default (`history.retain_days = 0`); prune-on-start is opt-in and
  must never silently delete without the count being shown.
