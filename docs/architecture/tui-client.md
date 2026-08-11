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
│ ^K palette  ^N contact  ^V verify  F1 help │ P2P direct │ policy: direct │ ▲2  │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Screens
Full transitions: [tui-screen-flow.mermaid](./diagrams/tui-screen-flow.mermaid).

| Screen | Purpose | Reached by |
|---|---|---|
| **Onboarding** | No account on disk → keystore choice, org hint, keypair generation, ID + QR, register + publish bundle | first run |
| **Unlock** | Existing file-backed account → masked passphrase | startup (OS keystore skips it) |
| **Main** | Contacts + conversation + composer + status bar | after unlock |
| **Add contact** | Paste an `mrd1:` ID or import a QR image, assign a petname | `^N` |
| **Requests** | First-contact gate queue (§3.5): sender key, safety number, intro, accept/reject | `^R`, or the Requests section of the contacts pane |
| **Verify** | 60-digit safety number + QR, mark verified, block | `^V` on a selected contact |
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
| Global | `F1` help · `^K` palette · `^Q` quit (confirm if unsent input) · `Tab`/`S-Tab` cycle panes · `Esc` back / close overlay |
| Contacts | `↑↓`/`j k` move · `Enter` open · `n` new · `r` requests · `v` verify · `p` petname · `b` block · `/` filter |
| Conversation | `PgUp`/`PgDn`, `^U`/`^D` scroll · `Home`/`End` · `g`/`G` top/bottom · `u` jump to first unread |
| Composer | `Enter` send · `A-Enter`/`^J` newline · `^U` clear · `↑` recall last sent · `^W` delete word |

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
