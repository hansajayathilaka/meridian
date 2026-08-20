<!-- Design document for the terminal TUI client (T17). Added post-handoff; not one of the original
     38 source documents. The FEATURE contract is docs/architecture/features/17-terminal-tui-client.md;
     this file is the design behind it. Where the two disagree, the feature spec wins on scope and
     this file wins on structure. -->
> **Nav:** [docs index](../INDEX.md) · [feature 17](./features/17-terminal-tui-client.md) · [screen flow](./diagrams/tui-screen-flow.mermaid) · [data model](./data-model.md) · [verification UX](../security/verification-ux.md) · [stack](./stack.md)

# Terminal TUI Client — Design

The terminal client is Meridian's **first end-user surface**: the one place where the whole system —
key creation, registration, contacts, trust, chat — is usable by a human without knowing any
subcommands. This document is the design of record for it.

**Nothing here adds protocol.** Every capability the TUI shows already exists in `meridian-core`
(T01–T06). If a screen appears to need a new wire type, key, or crypto operation, that is a planning
defect — stop and raise it, do not invent (root [CLAUDE.md](../../CLAUDE.md) convention).

---

## 1. Shape of the thing

| | |
|---|---|
| **Crate** | `apps/tui` → `meridian-tui` (proposed; ratified by **ADR 0020**) |
| **Entry point** | `meridian tui` — a thin subcommand in `meridian-cli` behind a default-on `tui` feature |
| **UI library** | [ratatui](./stack.md) + `crossterm` backend (per stack.md §1, "Terminal client") |
| **Runtime** | tokio; UI render loop never awaits network I/O directly |
| **Depends on** | `meridian-core` only (like every other shim) |
| **Config** | `$MERIDIAN_HOME/tui/config.toml` (figment + `MERIDIAN_TUI__*` env) |
| **Data** | `$MERIDIAN_HOME/tui/*.json`, sealed at rest (proposed; ratified by **ADR 0021**) |

`$MERIDIAN_HOME` defaults to `~/.config/meridian` and already holds `account.json`, `policy.json`,
and `sessions.bin` (`apps/cli/src/account.rs`). The TUI adds a `tui/` subdirectory and **never**
redefines those three — it reads the account descriptor and relay policy through the same code paths
the CLI uses.

### Relationship to the CLI
The CLI stays the **scriptable and demo surface**: every feature's acceptance demo runs through
`meridian <subcommand> --json`, unchanged. The TUI is the **human** surface over the same core. Two
rules keep them from drifting:

1. **No protocol logic in either.** Both orchestrate `meridian-core`
   (`apps/cli/CLAUDE.md` already states this for the CLI; it binds the TUI identically).
2. **Anything the TUI can do, the CLI can already do headlessly.** The TUI is allowed to be *nicer*,
   never *more capable*. If a TUI feature has no headless equivalent, add the CLI surface too.

---

## 2. Information architecture

One window, a **screen stack** (push/pop, `Esc` pops), with the main screen being a three-region
chat layout. Overlays (help, palette, modals) render on top without unmounting what is beneath.

**The mockup below is the design's target composed screen — it does not exist as a single rendered
view today.** No `Screen::Main` combines Contacts + conversation + composer + status bar into one
layout; each pane it shows (Contacts, Chat, Requests) is a separate, independently-built and
independently-tested `Screen` today. See
[§10](#10-current-implementation-status-as-of-task-428) for what is actually reachable in a live run.

```
┌ Meridian ─────────────────────────── mrd1:ab12…7f@org-a.test ── ● connected ─┐
│ Contacts ⌕            │ bob · verified ✓                                      │
│  ● bob      verified  │  ┌──────────────────────────────────────────────────┐ │
│  ● alice    pinned    │  │ 14:02  bob   hey, are you around?                │ │
│  ▲ carol    key change│  │ 14:02  you   just got here                   ✓✓  │ │
│  ○ dave     new       │  │ ── unread ─────────────────────────────────────  │ │
│ ─ Requests (2) ─────  │  │ 14:07  bob   pushed the branch                   │ │
│  ? mrd1:9c…@org-b     │  └──────────────────────────────────────────────────┘ │
├───────────────────────┴──────────────────────────────────────────────────────┤
│ ▏type a message…                                             Enter send        │
├──────────────────────────────────────────────────────────────────────────────┤
│ ^K palette  n contact  v verify  F1 help │ P2P direct │ policy: direct │ ▲2    │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Screens
Full transitions: [tui-screen-flow.mermaid](./diagrams/tui-screen-flow.mermaid). **This table is the
design's target shape.** As of task 4.28 several "Reached by" cells describe a route that does not
exist yet in `App::handle_key`/`App::handle_worker` — see
[§10](#10-current-implementation-status-as-of-task-428) for exactly which, and why.

| Screen | Purpose | Reached by (design) |
|---|---|---|
| **Onboarding** | No account on disk → keystore choice, org hint, keypair generation, ID + QR, register + publish bundle | first run |
| **Unlock** | Existing file-backed account → masked passphrase | startup (OS keystore skips it) |
| **Main** | Contacts + conversation + composer + status bar | after unlock |
| **Add contact** | Paste an `mrd1:` ID or import a QR image, assign a petname | `n` on the Contacts screen |
| **Requests** | First-contact gate queue (§3.5): sender key, safety number, intro, accept/reject | `^R` (global), or `r` on the Contacts screen |
| **Verify** | 60-digit safety number + QR, mark verified, block | `v` on a selected contact — including a contact created by **accepting a message request** (task 4.42): accepting synthesizes that sender's contacts row, so `Esc` back to Main lists them like any other contact and both `Enter` (chat) and `v` (verify) work unchanged |
| **Contact detail** | Trust state, key history, per-contact relay policy, petname, block/delete | `Enter` on a contact with the detail toggle |
| **Settings** | Server URL, relay policy, theme, timestamps, bell, retention | palette → *Settings* |
| **Diagnostics** | `doctor` output, live connection/transport state, why a path was chosen | palette → *Diagnostics* |
| **Help** | Full keymap, generated from the binding table so it cannot go stale | `F1` |
| **Palette** | Fuzzy-searchable list of every command, with its binding | `^K` |

### Modals (block input beneath them)
`Confirm` (destructive actions) · `KeyChangeBlocked` (verified contact — hard stop) ·
`KeyChangeWarning` (pinned contact — acknowledge to continue) · `Error`.

The two key-change modals are **not** ordinary dialogs; see §6.

---

## 3. Interaction model

**Both** arrow keys and vim-style motions work everywhere. Nothing requires a mouse; mouse support is
optional and off by default (it steals terminal text selection, which users rely on for copying).

| Scope | Keys |
|---|---|
| Global | `F1` help · `^K` palette · `^Q` quit · `Esc` back / close overlay |
| Contacts | `↑↓`/`j k` move · `Enter` open · `n` new · `r` requests · `v` verify · `p` petname · `b` block · `/` filter |
| Conversation | `PgUp`/`PgDn`, `^U`/`^D` scroll · `Home`/`End` · `g`/`G` top/bottom · `u` jump to first unread |
| Composer | `Enter` send · `A-Enter`/`^J` newline · `^U` clear · `↑` recall last sent · `^W` delete word |

`Tab` is bound per-screen with a different local meaning each time (composer/transcript focus in
Chat, id/QR-path focus in Contacts, field focus in Onboarding) — there is no global "cycle panes"
binding, and `Shift-Tab`/`S-Tab` is not bound anywhere in this crate today. `^Q` quits immediately and
unconditionally; there is no confirmation prompt for unsent composer input. See
[§10](#10-current-implementation-status-as-of-task-428).

Rules:
- **Every command is reachable from the palette**, so nothing is discoverable only by memory. The
  palette lists the binding next to each entry — it teaches the keymap while being used.
- **The help screen is generated from the binding table**, so a rebinding in `config.toml` is
  reflected without a doc edit.
- **`Esc` always means "back"** and never destroys typed input.
- **No modal auto-dismisses**, ever (§6, and [verification-ux.md](../security/verification-ux.md)
  prohibition 1).

### Terminal constraints (part of the acceptance criteria)
- Minimum **80×24**. Below 80 columns the contacts pane collapses into a toggled overlay rather than
  truncating the conversation.
- `NO_COLOR=1` honored; a 16-color fallback and `ui.unicode = false` (ASCII glyphs) are both
  first-class, not degraded afterthoughts — status is conveyed by **glyph + label**, never by color
  alone.
- `TERM=dumb`, non-TTY stdout, or a terminal smaller than the minimum → a plain-text message naming
  the equivalent headless CLI command, exit code 1. Never a garbled screen.
- The TUI runs on the **alternate screen**, so conversation text is not left in the user's scrollback
  after exit (§6).

---

## 4. Runtime structure

An Elm-style split, chosen because it makes the whole UI testable headlessly with
`ratatui::backend::TestBackend`:

```
        crossterm events ─┐
   tokio worker events ───┼──► AppEvent ──► App::update(&mut self, ev) ──► Vec<Effect>
             tick (250ms) ┘                        │                            │
                                                   ▼                            ▼
                                          App::render(&self, frame)      worker task runs it
                                          (pure, no I/O, no await)       (network, store, crypto)
```

- **`App` owns all state**; `update` is synchronous and pure apart from mutating `App`; `render` is
  pure. Neither ever performs I/O or awaits.
- **`Effect`** is the only way to reach the network, the keystore, or the disk (`SendMessage`,
  `FetchBundle`, `PublishBundle`, `PersistHistory`, `Unlock`, …). A worker task executes effects and
  reports back as `AppEvent::…`, so a slow rendezvous can never freeze the UI.
- **Rendering is at most 60 fps and only on change** (event- or tick-driven), so an idle TUI is idle.
- **Terminal guard**: raw mode + alternate screen are entered by an RAII guard whose `Drop` restores
  them, installed together with a panic hook and `SIGINT`/`SIGTERM` handler. Restoration is a
  reliability invariant with its own test (T17 acceptance criteria).
- **Backpressure**: inbound envelopes arriving faster than render are coalesced; the conversation
  view keeps a bounded in-memory window over the on-disk history rather than loading whole
  conversations.

---

## 5. Local store & configuration

Realizes [data-model.md §2](./data-model.md#2-client-local-store-encrypted-via-secretstore-key) for
the terminal client. Formats and the at-rest posture are ratified by **ADR 0021**; the schemas below
are the proposal that ADR decides on.

```
$MERIDIAN_HOME/                     ~/.config/meridian by default
  account.json                      (existing) non-secret account descriptor
  policy.json                       (existing) relay policy, org/user/contact scope
  sessions.bin                      (existing) sealed ratchet + prekey vault
  tui/
    config.toml                     NEW — human-edited, never written by the app
    contacts.json                   NEW — sealed
    history/<peer-pubkey-hex>.jsonl NEW — sealed, append-only
    outbox.json                     NEW — sealed, local retry queue
    state.json                      NEW — plaintext UI state (last conversation, pane widths, scroll)
```

**Sealing.** Every file marked *sealed* is a JSON document encrypted with the existing
`meridian_crypto::at_rest::seal` (XChaCha20-Poly1305) under the key derived from the account key via
`STORE_KEY_INFO` — the same mechanism `sessions.bin` already uses. The *content* is plain JSON; the
*container* is not. `meridian tui --export-json <path>` writes the same documents unsealed, on
demand, for inspection or backup — which is why no persistent-plaintext mode is offered (ADR 0021
records that alternative as considered and rejected).

`state.json` is deliberately **not** sealed and must therefore contain no petnames, no message text,
and no key material — only view geometry and a conversation index. This is an invariant the at-rest
audit test checks.

### `contacts.json` (v1)
```jsonc
{
  "v": 1,
  "contacts": [
    {
      "pubkey": "3f9a…",                  // 64 lowercase hex — the primary key, not the petname
      "id": "mrd1:3f9a…@org-b.test",       // full ID as entered, for display and routing hint
      "hint": "org-b.test",
      "petname": "bob",                    // LOCAL ONLY — never taken from the wire
      "trust": "pinned",                   // new | pinned | verified | blocked
      "pinned_key_history": [
        { "pubkey": "3f9a…", "first_seen": 1762934400, "last_seen": 1763020800 }
      ],
      "device_record_version_seen": null,  // reserved for T13 multi-device
      "policy_override": null,             // direct | prefer-relay | relay-only | null (inherit)
      "added_at": 1762934400,
      "last_activity_at": 1763020800,
      "unread": 0
    }
  ]
}
```

### `history/<peer-pubkey-hex>.jsonl` (v1)
One JSON object per line, append-only, so a partial write costs at most the last message:
```jsonc
{ "v": 1, "mid": "8c1f…", "dir": "out", "ts": 1763020800, "stream": "mrd.chat/1",
  "body": "pushed the branch", "state": "delivered" }
```
- `mid` is a **locally generated** 128-bit message id used for dedup and for matching delivery
  updates. It is *not* a wire field: envelope-level `eid` arrives with envelope v2
  ([ADR 0016](../adr/0016-envelope-deniability.md) C7), and the store must adopt it for dedup when it
  does. <!-- TODO: confirm the eid → mid migration when envelope v2 is specified. -->
- `state` ∈ `composing | pending | sent | delivered | failed | received`. Until T07 (offline mailbox)
  exists, `pending` means *this client will retry while it is running* — the UI says exactly that and
  never implies server-side store-and-forward.
- `stream` is the stream-type id, so future stream types append to the same transcript and unknown
  ones render as a placeholder (§8).

### `config.toml`
Human-authored, commented, and **never rewritten by the app** (settings changed in the UI are written
back with comments preserved, or the UI states that a change is session-only). Loaded with figment:
`Toml::file(config.toml)` merged with `Env::prefixed("MERIDIAN_TUI__").split("__")`, mirroring
`apps/cli/src/policy.rs` and [ADR 0018](../adr/0018-rendezvous-config-loading.md). A missing file is
not an error (defaults apply); a **malformed one is** — fail closed, consistent with the rest of the
client.

Precedence: **CLI flags > environment > `config.toml` > defaults.**

```toml
# Meridian TUI configuration. Everything here has a working default.

[account]
# server = "wss://rendezvous.org-a.test"    # default: the value used at registration

[ui]
theme      = "auto"        # auto | dark | light | mono
unicode    = true          # false = ASCII-only glyphs (no box drawing, no emoji)
mouse      = false         # true breaks terminal text selection in some emulators
timestamps = "relative"    # relative | clock | off
compact    = false         # denser message rows
bell       = "message"     # never | message | mention
osc52_copy = false         # opt-in: copy via OSC 52 (some multiplexers log clipboard writes)

[history]
retain_days                   = 0       # 0 = keep forever; N = prune older than N days at startup
max_messages_per_conversation = 10000   # 0 = unlimited

[network]
policy               = "inherit"        # inherit policy.json, or direct | prefer-relay | relay-only
reconnect_backoff_ms = [500, 1000, 2000, 5000, 15000]

[keys]
# Rebind any command from the palette, e.g.:
# quit = "ctrl-q"
```

### Migrations
Every file carries `"v"`. On a version bump the store migrates forward in place after writing a
`.bak` copy, and refuses to run against a **newer** schema than it understands (fail closed, with a
message naming the version) rather than silently discarding fields.

---

## 6. Security & privacy rules (binding)

These follow from [threat-model.md](../security/threat-model.md),
[anonymity-and-retention.md](../security/anonymity-and-retention.md), and
[verification-ux.md](../security/verification-ux.md). The
[security-reviewer](../../.claude/agents/security-reviewer.md) treats a violation as blocking.

1. **Key-change handling is un-softenable.**
   - *Verified* contact, key or device-record change → the composer is **disabled** and a hard-stop
     banner replaces it. The only actions are **Verify** and **Block**. There is no
     "trust anyway", no timed dismissal, no "don't ask again".
   - *Pinned* contact → a prominent modal that must be acknowledged, with **Verify** as the primary
     action.
   - The wording preserves the canonical intent in verification-ux.md verbatim in meaning, including
     the interception possibility. No screen may paraphrase it into reassurance.
2. **Petnames are local.** They are never read from the wire and never sent. The contacts pane shows
   the key fingerprint alongside the petname wherever a spoofed display name could mislead.
3. **Alternate screen, always.** Conversation content must not survive in terminal scrollback after
   exit. Nothing sensitive is ever written to `stdout` outside the alternate screen.
4. **No content in logs.** An optional `--log-file` records structured UI/network events with message
   bodies, petnames, and full IDs elided (truncated key prefixes only), per the anonymity model's
   must-never list. There is no debug flag that turns content logging on.
5. **No secret ever renders.** Private keys and passphrases never appear on screen (masked input),
   in `state.json`, in the palette history, or in the composer's recall buffer.
6. **Clipboard is opt-in.** OSC 52 copy is off by default because some multiplexers and terminal
   emulators persist or mirror clipboard writes.
7. **Message requests reveal nothing extra.** Before acceptance the UI shows only what §3.5 and task
   2.10 already expose (sender key, safety number, short intro). Rejection semantics follow the
   existing gate — the TUI adds no new signal to the sender.
8. **Honest scope in copy.** The word "anonymous" does not appear. The status bar says what is true:
   E2EE, and whether the path is direct or relayed. See the
   [anonymity-model skill](../../.claude/skills/anonymity-model/SKILL.md).
9. **No telemetry, ever.** Nothing about usage leaves the machine.
10. **Failure is visible.** A message that could not be delivered is shown as failed. The UI never
    renders an optimistic checkmark for a send the transport did not confirm.

---

## 7. What the user sees when things go wrong

Good terminal UX is mostly good failure UX. Each of these has a defined presentation:

| Condition | Presentation |
|---|---|
| Rendezvous unreachable | Status bar `● reconnecting (3/5)`, backoff from config, composer stays usable, sends queue locally with a visible `pending` state |
| Peer offline (pre-T07) | Message marked `failed` with "not delivered — <petname> is offline" and a retry action. **Never** "will deliver later" |
| Federation `closed` / stale hint | The client error taxonomy from task 2.9, rendered as a one-line explanation plus what the user can do |
| Bundle verification failure | Hard error, no fallback, wording from verification-ux.md; the contact is not added |
| Ratchet desync | The fresh-X3DH auto-recovery decision (task 1.18) with its user-visible notice — not silent |
| Locked keystore / wrong passphrase | Retry with attempt count, no lockout invented (`TODO: confirm` an attempt policy if one is ever wanted) |
| Terminal too small | Live message with the required size, redrawn on resize — not a crash |

---

## 8. Extension contract — every feature ships a TUI surface

This is the rule the TUI exists to make possible, and it is enforced by **Definition of Done gate 9**
in [CONTRIBUTING.md](../../CONTRIBUTING.md). It mirrors the
[stream-type registry](../../.claude/skills/stream-type-authoring/SKILL.md)'s philosophy: a new
feature **registers** its surface, it does not edit the TUI core.

A feature adds any subset of three things, all registered, none requiring edits to the event loop,
layout engine, or store:

1. **A message renderer**, keyed by stream-type id (`mrd.file/1`, `mrd.location/1`, `mrd.call/1`),
   which turns a transcript entry into rows.
2. **Palette commands** (and optional key bindings), which appear in the palette and in the generated
   help automatically.
3. **A pane or screen**, pushed onto the screen stack (e.g. a transfer list for T09, a call status
   panel for T10).

**Forward compatibility:** an entry whose stream type has no registered renderer displays as
`[unsupported: mrd.foo/1 — update your client]` rather than breaking the transcript. A client that
does not understand a stream type must remain fully usable.

**The gate, in practice.** When a phase plans a user-visible feature, one of its tasks is the TUI
surface, and that task's file names it explicitly. A feature with genuinely no user surface
(server-only, infra, CI) states that in its task file instead — the point is that the decision is
recorded, not that every task grows a UI. Features whose surfaces are already anticipated:

| Feature | Expected TUI surface |
|---|---|
| T07 offline mailbox | Outbox becomes real store-and-forward; `pending` copy changes accordingly |
| T08 verification & trust | Deepens the Verify screen (QR scan-from-file, trust transitions) |
| T09 file transfer | `mrd.file/1` renderer + a transfers pane with progress/resume |
| T10 calls | `mrd.call/1` renderer + call status panel (audio only; video is send/receive-and-save) |
| T13 multi-device | Device list in contact detail, provisioning QR display |
| T15 location/stickers | `mrd.location/1` renderer (coordinates + link), sticker placeholder |
| T16 tunnels | `meridian tunnel` status pane |

---

## 9. Testing

Per [testing/strategy.md](../testing/strategy.md), with the TUI's own additions:

- **Screen snapshots** — every screen and modal rendered through `ratatui::backend::TestBackend` at
  80×24 and at a narrow width, asserted against checked-in text snapshots. These catch layout
  regressions and, because the canonical warning copy is in them, catch softened security wording too.
- **At-rest audit** — the on-disk counterpart to `demo opacity-audit`: script a conversation, then
  assert that no file the TUI wrote contains a message body, a petname, or key material. Failing this
  is a security defect, never a test to relax.
- **Key-change adversarial test** — flip a verified contact's key and assert the composer is blocked
  and no send path exists.
- **Terminal restoration test** — force a panic mid-render and assert raw mode and the alternate
  screen are undone.
- **Store round-trip + migration tests** — v1 documents, a forward migration, and a refuse-to-open
  assertion for a newer schema version.
- **Update-function unit tests** — because `update` is pure, most interaction logic is testable
  without a terminal at all.

---

## 10. Current implementation status (as of task 4.28)

Sections 1–9 above are this document's design of record — the target shape T17 was scoped to. This
section is the honest, as-shipped picture task 4.28 (the phase's exit gate) is required to keep in
sync with it, written after actually running `meridian tui` end to end (not just reading source).
**Read this section before treating any "reached by" cell above, or the mockup in §2, as something you
can do in a real session today.**

### What is real and live-reachable today
- The **environment gate** (`apps/cli/src/tui.rs::check_environment`): `TERM=dumb`, a non-TTY stdout,
  and a terminal smaller than 80×24 are all refused with the documented plain-text message and exit
  code 1, exactly as §3 describes. Confirmed by this task and by its own unit tests.
- The **terminal guard**: raw mode/alternate screen are restored on normal exit, and `Ctrl-Q` quits
  cleanly and restores the terminal even from a screen stuck mid-effect (see below) — confirmed
  empirically in this task, not just by the panic-restores-terminal unit test.
- **Onboarding's own sub-step state machine** (`ChooseStore → OrgHint → Generating → ShowIdentity →
  Registering → PublishingBundle`), up to the point where it needs a worker to actually do something
  (see the blocking gap below).
- Four **global key chords**, checked unconditionally ahead of whatever screen is on top:
  `Ctrl-Q` (quit), `F1` (Help), `Ctrl-K` (Palette), `Ctrl-R` (push `Screen::Requests` with an **empty**
  queue — there is no live `meridian_core::chat::ChatState` anywhere in this crate yet to snapshot
  `pending_requests()` from). Any *registered* palette command's own binding also fires globally; today
  exactly one command is registered (`nav.diagnostics`).
- **Every individual screen** — Onboarding, Unlock, Contacts, Contact detail, Chat, Requests, Verify,
  Settings, Help, Palette, Diagnostics — is fully built, with real `handle_key`/`handle_worker`/`render`
  logic, and independently proven via `ratatui::backend::TestBackend` snapshot tests and unit tests
  (including the security-critical ones: the key-change adversarial test, the at-rest audit, the
  fingerprint-alongside-petname checks). None of this is fake or stubbed *inside* a screen.
- Config loading, the sealed local store round-trip, and the at-rest audit are real and pass against
  the actual on-disk files these screens would write.

### The two gaps that mean no live session exists end to end

**1. There is no `Preflight` step and no `Screen::Main`.** `App::new()` unconditionally starts on
`Screen::Onboarding` — it never checks for an existing `account.json` to route to `Screen::Unlock` or
past onboarding entirely, the way §2's screen table and the (now-corrected)
[screen-flow diagram](./diagrams/tui-screen-flow.mermaid) describe. Onboarding's own completion swaps
to a bare `Screen::Placeholder` ("screen content lands in later tasks"), because `Screen::Main` does
not exist. `Screen::Unlock`, `Contacts`, `ContactDetail`, `Chat`, `Verify`, and `Settings` are each
fully built and tested (above) but are reached in this crate's own test suite **only** by constructing
them directly and calling `App::push_screen` — nothing in `App::handle_key`/`App::handle_worker` ever
pushes any of them during a live run. The one real exception is `Contacts → ContactDetail` via `Enter`,
which *is* wired screen-to-screen — but only once `Contacts` is already on the stack, which today only
happens in a test. `Contacts`'s own `v` key shows a "Verify is not implemented yet (task 4.22) — press
v again to dismiss" stand-in notice rather than pushing the real (fully built) `Screen::Verify`.

**2. `apps/tui/src/lib.rs::run_worker` is still an inert stub.** Unchanged since task 4.11's own
placeholder scope, it does not execute an `Effect` against `meridian-core` at all — it just echoes
whatever `Effect` it received straight back wrapped in `WorkerEvent::Completed`, with no outcome ever
populated (`crate::screens::diagnostics`'s own module doc names this precisely: "today's
unconditional-success, no-op-payload stub"). Every screen's `handle_worker` only advances past a
`WorkerEvent::Completed` carrying a **populated** outcome (e.g. `GenerateAccountEffect { outcome:
Some(account), .. }`); since the stub never populates one, the match falls through to a no-op and the
screen simply never moves on.

**This second gap is the one that actually blocks the acceptance demo, and it is more fundamental than
gap 1.** It means a real `meridian tui` session cannot progress past Onboarding's own first effect —
confirmed empirically for this task:

```
$ meridian tui                          # passphrase-wrapped keyfile, hint "org-a.test"
  … ChooseStore → OrgHint proceed normally …
  "Generating your identity for @org-a.test… please wait…"
  ← hangs here indefinitely. No error, no timeout, no progress.
  Ctrl-Q still quits and restores the terminal cleanly.
```

### What this means for the T17 acceptance demo

**The demo script in
[17-terminal-tui-client.md](./features/17-terminal-tui-client.md)'s "Working output" section —
onboarding → verified chat → restart-persists → key-change-blocks, driven entirely by `meridian tui` —
does not run end to end today.** It gets exactly as far as submitting the org-domain hint on a fresh
account and then hangs forever on "Generating your identity…". Nothing past that point (registration,
bundle publish, the contact list, chat, verification, restart) is reachable from a live run, even
though every one of those screens' own internal logic is genuinely built and tested in isolation.

This was never a task in this phase's 28-task breakdown — each of 4.16–4.27 explicitly, repeatedly
scoped "wiring this screen into live navigation" and "wiring `run_worker` to actually execute this
`Effect`" out, deferring both to "a future task" in nearly every module's own doc comments (see e.g.
`Screen::Chat`'s, `Screen::Verify`'s, and `crate::screens::diagnostics`'s doc comments). No task ever
was that future task. Closing it needs at least:
- A **Preflight** step (detect `account.json`, route to `Unlock`/`Onboarding`/past both) and a real
  **`Main`** screen (or equivalent live navigation) that actually pushes `Contacts`/`Chat`/`Verify`/
  `Requests`/`Settings` with real, loaded data, per every screen's own "future Preflight step" doc
  comments.
- A **real `run_worker`** that dispatches each `Effect` variant to the matching `meridian-core` call
  (`generate_account`, `SignalingClient::connect`/`publish_bundle`, `route_tolerant`, the sealed-store
  read/write helpers, …) and reports a populated outcome back — not the task-4.11 stub.

Tracked as follow-up in [docs/tasks/phase-4/README.md](../tasks/phase-4/README.md)'s exit criteria
and [docs/tasks/README.md](../tasks/README.md)'s carry-forward section, mirroring how this phase
already carries forward 4.22's Verify-screen-height note into 4.26.

---

## 11. Current implementation status (as of task 4.38 — the phase's second exit-gate attempt)

Section 10 above is frozen as task 4.28's own historical record (several other task files link to it
by that exact anchor); this section is the follow-up, written after tasks 4.29–4.37 closed both gaps
4.28 found — and after actually re-running the demo, live, a second time, exactly as 4.28 did.

**Both of 4.28's own gaps are now closed for real.** `Preflight` (4.37) genuinely routes an existing
account to `Unlock`/straight to `Screen::Main`; `Screen::Main` (4.36) is real, live navigation, not a
placeholder; `run_worker`/`worker::dispatch` (4.30–4.34) genuinely executes every effect it used to
echo back inertly — `GenerateAccount`, `Register`, `PublishBundle`, `Unlock`, `LoadSession`,
`AddContact`, `ImportContactQr`, `SetPetname`, `SetUserBlocked`, `SetPolicyOverride`, `DeleteContact`,
`AcceptRequest`, `RejectRequest`, `MarkVerified`, `AcknowledgeKeyChange`, `SendMessage`,
`PersistHistory`, `SaveSetting`, `RunDoctor` — against real `meridian-core` calls and real sealed-store
files. A persistent inbound-delivery loop (4.35) really does forward decrypted content to `App` live.
Onboarding on a fresh `$MERIDIAN_HOME`, through registration and bundle publish, genuinely completes
end to end — confirmed twice, independently, exactly as 4.28's own bar required (once by 4.38 itself,
live via a PTY-driven `meridian tui` process; the second, independent confirmation is the reviewer/
test-engineer sign-off that follows 4.38, per that task's own scope).

**The T17 acceptance demo still does not pass end to end — for two reasons, one already flagged, one
newly discovered by this same re-run.**

**1. The already-flagged file-backed-account gap (task 4.37's own Status section) is real, and now
reproduced live**, not just reasoned about. `worker.rs::open_account_store` — the helper `AddContact`/
`SetPetname`/`SetUserBlocked`/`SetPolicyOverride`/`DeleteContact`/`AcceptRequest`/`RejectRequest`/
`MarkVerified`/`AcknowledgeKeyChange`/`SendMessage`/`PersistHistory` all call — re-derives a fresh
`SecretStore` per dispatch, and fails closed for a passphrase-keyfile account (no cached, already-
unwrapped store to reuse). Confirmed by literally driving `meridian tui` under a PTY: a file-backed
account onboards, registers, publishes a bundle, and reaches a live, connected `Screen::Main` —
genuinely further than 4.28's own hang — but pressing `n` to add a contact then fails with exactly the
message that function's own code names: *"Could not add this contact. this account is passphrase-
protected — this action from a live TUI session isn't supported yet for file-backed accounts (no
cached, already-unlocked store to reuse); use the CLI instead."* `Ctrl-Q` still restores the terminal
cleanly from that error dialog.

**2. A previously-undiscovered defect, found by this task's own new two-process regression test
(`apps/tui/tests/live_session_e2e.rs`), blocks first-contact receiving for *every* account type,
including OS-keystore.** `apps/cli/src/main.rs::cmd_register` (the exact call sequence
`worker::handle_publish_bundle` mirrors) has always had a latent version of this same gap:
`SignalingClient::publish_bundle`'s own doc comment is explicit that it "[r]eturns the generated bundle
*and its secret scalars* for the caller to persist" — but `cmd_register` never persists them, and
neither does `worker::handle_publish_bundle`. In the CLI this is harmless: `apps/cli/src/chat.rs::run`
(the CLI's actual "start chatting" entry point) unconditionally republishes its **own** fresh bundle —
`client.publish_bundle(...)` immediately followed by `state.vault.set_bundle(...)` and `save_state(...)`
— every single time it runs, before it is ever capable of receiving anything, so the `cmd_register`-time
bundle is never actually relied on for a real receive. **`meridian-tui` has no equivalent step
anywhere.** `Effect::PublishBundle` is dispatched exactly once, from `screens/onboarding.rs`, at
account-creation time, and never again — not from `Screen::Main`'s construction, not from
`inbound_handoff`/`run_inbound_loop`'s spawn (4.35), not on a later `Unlock`/`LoadSession`. So the one
bundle a T17-onboarded account ever publishes is the vault-less one, and it is the **only** bundle a
peer can ever X3DH-initiate against. When they do, `ChatState::open_inbound` cannot resolve the OTK/SPK
secret scalar for that bundle (`PrekeyVault` never had them) and fails closed with
`ChatError::UnknownPrekey` ("no matching prekey secret for incoming session") —
`process_inbound_delivery` drops it silently (an `eprintln!` only, no user-visible signal on either
side). Reproduced live, twice: once via `apps/tui/tests/live_session_e2e.rs` (two real, separate OS
processes, a real in-process rendezvous server, real `worker::dispatch`/`run_inbound_loop` — the
responder's own inbound loop logs exactly this rejection the moment the initiator's message arrives),
and independently confirmed to be root-caused correctly by tracing `apps/cli/src/chat.rs::run`'s own
working design as the counter-example. **This is more fundamental than finding 1**: it blocks the
demo's "peer sees a message request" step even for an OS-keystore account that has no file-backed
gap to hit at all (not independently re-confirmed via a live `meridian tui` PTY session for the
OS-keystore case specifically — this sandbox has no working platform Secret Service even after
installing `gnome-keyring`, the same headless-environment limitation `tests/load_session.rs`'s own
module doc already names — but the defect lives entirely in `worker.rs`/`meridian-core`, not in any
screen, so there is no reason to expect an OS-keystore account to behave differently).

**Verdict: the T17 acceptance demo does not run end to end today.** Not a regression from 4.28 (this
phase is a great deal further along — a live session now exists, reaches a connected `Screen::Main`,
and the onboarding/registration/publish path is solid) but two distinct, real defects still block it:
one already flagged and now reproduced live (4.37's file-backed gap), one newly found by this task's
own live re-run and its new regression test (no live bundle republish/vault persistence for any account
type). Neither is fixed here, per this task's own explicit scope — see
[docs/tasks/phase-4/4.38-t17-acceptance-demo-closure.md](../tasks/phase-4/4.38-t17-acceptance-demo-closure.md)'s
own Status section for the full evidentiary writeup, and
[docs/tasks/README.md](../tasks/README.md)'s carry-forward section for where this now stands in the
tracker.

**Update (task 4.39): Defect A (finding 2 above — no bundle republish/vault persistence) is now
closed.** The rest of this section is left as 4.38's own historical record (several other task files
link into it by anchor), but the paragraph immediately above no longer describes the current state of
finding 2. `worker::republish_bundle` (`apps/tui/src/worker.rs`) now runs once per session — wired
into `apps/tui/src/lib.rs::run_worker`'s existing `inbound_handoff` branch, immediately before
`run_inbound_loop` is spawned, guarded by the same one-shot `inbound_started` flag — and performs the
exact connect → `publish_bundle` → `vault.set_bundle(...)` → save sequence
`apps/cli/src/chat.rs::run` always did, closing the gap this section originally found: a peer's
first-contact message can now be decrypted, for either account type.
`apps/tui/tests/live_session_e2e.rs`'s own `LIVE_E2E_RUN` gate (added as a stopgap so this
known-reproducing regression test would not hard-block CI) has been removed and the test now passes
unconditionally — see [4.39's own Status section](../tasks/phase-4/4.39-prekey-bundle-republish.md) for
the full writeup, including its own new narrow tests at the `worker::dispatch`/`inbound_handoff`
boundary. **Finding 1 above (Defect B — the file-backed-account gap in `worker.rs::open_account_store`)
is still open**, tracked by [4.40](../tasks/phase-4/4.40-file-backed-live-session-store.md) (not yet
started as of this update). The T17 acceptance demo therefore still does not run end to end for a
file-backed account — only the OS-keystore path, and only the specific first-contact-receive step this
section's finding 2 covered, is unblocked by 4.39 alone. A third, hopefully-final exit-gate re-attempt
(4.41) is still needed once 4.40 also lands — see
[docs/tasks/phase-4/README.md](../tasks/phase-4/README.md)'s exit criteria for where this now stands.

**Update (task 4.43): the performance defect 4.39's own fix introduced for file-backed accounts is now
closed.** The 4.39 note above stays as written (historical record, like §10 and the rest of §11); this
adds what it did not yet know. 4.39 wired `worker::republish_bundle` to `InboundHandoff::store`, which
for a file-backed account is a raw `FileSecretStore` — and `FileSecretStore::use_key`/`derive_key` each
run a **full age/scrypt unwrap on every call**. A republish is `1 + DEFAULT_OTK_COUNT` = 101
signatures, so every file-backed session start froze on "Unlocking" for ~3 minutes (4.39 recorded
"> 90 s and climbing"; 4.41 measured 188.0 s/188.8 s live; 4.43 re-measured **194.5 s** from a completed
`Effect::Unlock` to `run_inbound_loop`'s spawn, and **211.5 s** from the "Unlocking" screen to a
rendered `Screen::Main` in a real PTY-driven `meridian tui`).

`worker::inbound_handoff` now also builds an **unwrap-once** `MemorySecretStore`
(`InboundHandoff::bulk_signing_store`) via the same `unwrap_keyfile_for_bulk_signing` helper
`open_store_for_bulk_signing` uses for onboarding's own `PublishBundle` — one `export_seed` for the
whole 101-signature burst instead of 101 of them (O(1) scrypt, not O(prekeys)). `run_worker` hands that
store to `republish_bundle` and **drops it before spawning `run_inbound_loop`**, so raw-seed residency
ends at republish completion rather than at process exit — which is why this change *reduces* key
residency rather than extending it (the same seed was previously materialized 101 times across those
~190 s). `InboundHandoff::store`, and therefore `run_inbound_loop`'s own behavior, is byte-for-byte
unchanged, as is the OS-keystore branch. Same measurements after the fix: **1.92 s** completed-`Unlock`
→ spawn, **3.6 s** "Unlocking" → `Screen::Main`. The republish deliberately remains *on* the critical
path to `Screen::Main` (recorded decision, not an oversight — see 4.43's own Status section). Full
writeup, methodology and machine conditions:
[4.43's own Status section](../tasks/phase-4/4.43-file-backed-republish-performance.md).

**Where the residual ~1.5-2 s actually goes — and what that means for the residency bound.** Measured
separately after the fix, `republish_bundle` itself is **~0.052 s** of the ~1.45-1.92 s
completed-`Unlock` → spawn window; **~97% of it is the single age/scrypt keyfile unwrap**
`inbound_handoff` now performs once (~1.4-1.6 s at the shipped scrypt parameters). Two consequences,
both worth stating precisely rather than rounding to "the republish takes ~2 s":

- The `MemorySecretStore`'s raw-seed residency is **~50 ms**, not ~2 s — it is constructed *after* the
  expensive unwrap and dropped at republish completion. The security rationale for this shape (residency
  reduced, not extended) is therefore stronger than a "~2 s" reading of it suggests.
- A file-backed session start will stay **~1.5-2 s regardless of the republish**, because that floor is
  one unavoidable passphrase-KDF unwrap — that is what scrypt is for. Later work chasing residual
  file-backed latency (e.g. the T17 exit-gate re-attempt) should not attribute it to this path; the only
  ways down are KDF parameters or fewer unwraps per session, both separate decisions.

**Update (task 4.42): Defect C — the responder side of a first contact was a dead end — is now
closed.** Task 4.41's exit-gate attempt found that accepting a message request left the sender
reachable from *no* screen at all: `Effect::AcceptRequest` wrote only `trust.bin`/`sessions.bin`, and
§2's contacts list is driven by `contacts.json`, so the accepted sender never appeared in it — and
could not be added by hand either, because a `MessageRequest` carries no routing hint, so the
resulting `Contact` has `hint == ""` and `Contact::id_string()` genuinely fails (`validate_hint`
rejects an empty hint). There was therefore no string the "add contact" form would have accepted; the
gap was structural, not a missing button. Two changes close it, and no new ADR was needed
(nothing here changes trust semantics — an accept still produces a TOFU pin and nothing more):

- `worker::run_accept_request` now also upserts and saves that sender's sealed `contacts.json` row
  (`id: ""`, `hint: ""`, `conv_handle: None`), on exactly the same `accepted || pin_still_owed` guard
  as the pin, so a retry never fabricates a row for a sender with no session. **No hint-less `mrd1:`
  id form was invented** — that would touch the wire-critical `meridian-identity` crate and
  contradict [ADR 0001](../adr/0001-identity-scheme.md); the row renders through the existing
  petname → hint → short-pubkey fallback, i.e. as the same fingerprint the Requests pane showed.
- `App::apply_accepted_request` replays the same three mutations into the live `Screen::Main` beneath
  the Requests screen (`trust.observe` with the **worker-supplied** timestamp, the contacts-row
  update, and an in-memory `chat.accept_request`), so the sender is reachable immediately rather than
  only after the next restart, `v` → Verify → mark-verified has a contact record to transition, and
  an accepted request no longer re-appears on the next `^R`. A **rejected** one still can, within the
  same session — that half is unchanged and deliberately out of 4.42's scope.

Screen-level coverage for this lives in `apps/tui/tests/accept_to_chat.rs` (real key events through
`App`, real `worker::dispatch` against a real sealed `$MERIDIAN_HOME`, plus a restart rebuilt from
disk only) — the layer `live_session_e2e.rs` structurally cannot reach, which is why three exit-gate
attempts passed while this was broken.

**Update (task 4.46): the fourth defect 4.45's own T17 exit-gate attempt found — `Effect::AddContact`
never reconciled into the live in-memory `TrustStore` — is now closed.** This is the initiator-side
mirror of 4.42's Defect C immediately above: an initiator who added a contact via the plain `n`-add
flow could send them a first-contact message and still get `TrustError::UnknownContact` pressing
`v`→`v`→`y`, because `worker::run_add_contact`'s real `trust.bin`/`contacts.json` writes never synced
into `MainState::trust`/`main.contacts` for the rest of that session — only a restart picked them up
(`MainState::from_session` rebuilds `trust` fresh from `trust.bin` at boot, so the bug was a pure
live-session staleness gap, never a persistence one). `App::apply_added_contact` (`apps/tui/src/app.rs`)
closes it, reusing `App::apply_accepted_request`'s exact `live_trust_idx` stack-walk verbatim in
structure: locate `Screen::Main`, scan above it for a `Screen::Chat`/`Screen::Verify` frame (where
`MainState::trust` would have been `std::mem::take`n), and route `trust.observe(added.pubkey, "",
added.added_at)` there if one exists, else directly onto `Screen::Main`. No new trust decision is
made anywhere in this fix — it replays exactly what the worker already wrote, mirroring 4.42's own
"TOFU is not verification" guardrail.

A second, closely related interleaving gap was traced during this task's planning pass and fixed in
the same diff, not deferred: unlike `AcceptRequest` (dispatched from a separately-pushed
`Screen::Requests`), `Effect::AddContact` is dispatched from `Screen::Main`'s own embedded
`ContactsState.add` sub-flow — and `Ctrl-R` is a genuinely global, unconditional binding, checked in
`App::handle_key` before any screen-specific key interception, reachable even mid `AddContactState::
Adding`. Pressing it there pushes `Screen::Requests` on top of `Screen::Main` while the effect is still
in flight; without a fix, the completion would then route through the per-screen fallback dispatch to
`Screen::Requests` (whose own `requests::handle_worker` forwards nothing) instead of `Screen::Main`, so
`contacts::handle_worker`'s `AddContactState::Adding` arm — the only place that closes the sub-flow and
upserts the display row — would never run: the add-contact form would be stuck in `Adding` forever, and
the new contact would never appear in the live Contacts list for the rest of the session. `App::
apply_added_contact` therefore also calls `contacts::apply_update` and resets `main.contacts.add` to
`None` **unconditionally**, on whichever `Screen::Main` frame exists, regardless of what is on top of
the stack — and runs strictly before the per-screen fallback dispatch, so resetting `add` to `None`
here pre-empts the per-screen `Adding` arm rather than racing it: `contacts::apply_update` runs
exactly once, from `App::apply_added_contact`, in both the ordinary and interleaved cases
(`contacts::apply_update` is in fact an idempotent upsert-by-pubkey and would tolerate a genuine
double call too, but no such double call actually occurs — guaranteed by construction (the
reset-before-dispatch ordering above), confirmed during review by instrumenting the per-screen
`Adding` arm and observing it never runs in either of this task's regression tests).

Screen-level coverage for both properties lives in `apps/tui/tests/accept_to_chat.rs`:
`add_contact_makes_the_added_peer_reachable_for_verify` (same-session add-then-verify, no restart) and
`a_ctrl_r_interleaved_while_add_contact_is_in_flight_still_reconciles_the_live_contacts_list` (the
interleaving-gap regression) — reusing that file's existing real-key-event/real-worker/real-sealed-
`$MERIDIAN_HOME` harness rather than duplicating it into a new file.
