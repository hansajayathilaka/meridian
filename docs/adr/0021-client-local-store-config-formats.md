<!-- Source: this decision (task 4.2, T17 planning). -->
> **Nav:** [ADR index](./README.md) · [tui-client.md §5](../architecture/tui-client.md#5-local-store--configuration) ·
> [data-model.md §2](../architecture/data-model.md#2-client-local-store-encrypted-via-secretstore-key) ·
> precedent [ADR 0018](./0018-rendezvous-config-loading.md)

# ADR 0021: Client-local store & config formats (terminal client)

**Options — at-rest sealing:** (A) plaintext JSON on disk, relying on filesystem permissions alone;
(B) **every content file sealed with `meridian_crypto::at_rest::seal` (XChaCha20-Poly1305) under the
key derived from the account key via `STORE_KEY_INFO`, the same mechanism `sessions.bin` already uses,
with an explicit `meridian tui --export-json <path>` as the only unsealed-export path (chosen)**;
(C) a `store.encrypt = false` config toggle that persists plaintext on disk.

**Trade-offs.** A is what most terminal chat clients ship and costs nothing to implement, but directly
contradicts this project's own security posture: `data-model.md §2` already commits the client-local
store to encryption-at-rest, and an unencrypted `contacts.json`/history file on a shared or
lost/compromised device leaks exactly the peer identities, petnames, and message content the rest of
the system (X3DH, Double Ratchet, safety numbers) works to protect end-to-end. B reuses a mechanism
that already exists and is already audited (`sessions.bin`'s sealing) rather than inventing a second
at-rest scheme, and gives users an explicit, logged, one-shot escape hatch (`--export-json`) for the
legitimate cases (backup, migration, debugging) without a standing plaintext mode. C looks like a
reasonable "power user" knob but is actually a footgun: once offered, it is one config edit away from
being silently on, defeats the audit invariant this ADR also establishes (4.27's at-rest audit can no
longer assume "everything except `state.json` is sealed"), and every other sealed-at-rest surface in
this codebase (`sessions.bin`) has never offered an unseal toggle. **Decision: B**, and **C is
explicitly rejected** — `store.encrypt = false` (or any equivalent persistent-plaintext opt-out) must
not be added to `config.toml` without a superseding ADR.

**Options — config format:** (A) JSON, matching the sealed stores; (B) YAML; (C) **TOML via `figment`,
mirroring `apps/cli/src/policy.rs` and [ADR 0018](./0018-rendezvous-config-loading.md) (chosen)**.
**Trade-offs.** `config.toml` is the one file in this layout a human is expected to hand-edit and
re-read with its own comments intact — JSON has no comment syntax, and YAML's whitespace sensitivity
and multi-document ambiguity are a worse fit for a small, mostly-flat settings file than TOML's
section-per-concern shape. `figment` is already the project's chosen config-loading tool
([ADR 0018](./0018-rendezvous-config-loading.md)); reusing `Toml::file` + `Env::prefixed
("MERIDIAN_TUI__").split("__")` keeps precedence rules (CLI flags > environment > `config.toml` >
defaults) and fail-closed-on-malformed-file behavior identical to the CLI's own `policy.toml` loading
instead of a third bespoke parser. **Decision: C.** (`figment` itself only reads/merges; the
comment-preserving write-back condition 3 below requires is a separate concern for
[4.14](../tasks/phase-4/4.14-tui-config.md) to implement, e.g. via `toml_edit` — this ADR fixes the
read-side format and precedence, not the write-back library.)

## Binding conditions

1. **Layout**, under `$MERIDIAN_HOME` (unchanged: `~/.config/meridian` by default), a new `tui/`
   subdirectory alongside the existing `account.json` / `policy.json` / `sessions.bin`:
   ```
   tui/config.toml                     human-edited, never rewritten wholesale by the app
   tui/contacts.json                   sealed
   tui/history/<peer-pubkey-hex>.jsonl sealed, append-only
   tui/outbox.json                     sealed, local retry queue
   tui/state.json                      unsealed — see condition 2
   ```
2. **Sealing boundary, drawn precisely.** `contacts.json`, every `history/*.jsonl`, and `outbox.json`
   are sealed (XChaCha20-Poly1305 container; plain JSON content inside). `state.json` is the **one**
   deliberate exception — it is unsealed plaintext, and in exchange it is restricted to hold only view
   geometry and a conversation index: **no petname, no message body, no key material, and no
   contact-identifying content (pubkey, `mrd1:` id, routing hint, or any index whose ordering trivially
   correlates 1:1 with `contacts.json`'s own row order)** may ever be written to `state.json`. The
   "last-open conversation" is represented as an **opaque, locally-generated, non-identifying handle**
   (e.g. a random token minted when a conversation is first opened and stored alongside the contact's
   entry in the *sealed* `contacts.json`, with only the token — never the pubkey or `id` — mirrored into
   `state.json`) — never the contact's pubkey, its `mrd1:` id string, or a positional index into
   `contacts.json`. This is a binding invariant, not a convention —
   [4.27](../tasks/phase-4/4.27-at-rest-audit-harness.md)'s at-rest audit harness enforces it by
   scanning `state.json` for petname-, body-, key-, **and contact-identifier-shaped** content (pubkey
   hex, `mrd1:` prefix, known petname strings) on every run this ADR gates.
3. **`config.toml` is TOML, loaded via `figment`** (`Toml::file(config.toml)` merged with
   `Env::prefixed("MERIDIAN_TUI__").split("__")`), precedence CLI flags > environment > `config.toml` >
   defaults, matching [ADR 0018](./0018-rendezvous-config-loading.md)'s CLI-store treatment. A missing
   file is not an error (defaults apply); a malformed one is fatal (fail closed), same as the rest of
   the client. The app never rewrites the file wholesale — UI-driven setting changes either write back
   preserving comments or are stated as session-only.
4. **`--export-json <path>` is the only unsealed-export mechanism.** It writes the same JSON documents
   the sealed stores hold, decrypted, to an explicit user-chosen path, on demand. No config flag, env
   var, or code path may cause persistent plaintext writes of sealed content anywhere else.
5. **Schema versioning.** Every JSON document (sealed or not) carries a top-level `"v"` field. On a
   version bump the store migrates forward in place after writing a `.bak` copy of the pre-migration
   file, and **refuses to open a file whose version is newer than the running binary understands** —
   fail closed with a message naming the unsupported version, never silently discarding unknown fields.
5b. **A sealed file that fails to *open* is fatal, not a reason to reinitialize.** AEAD authentication
   failure on `contacts.json`, any `history/*.jsonl`, or `outbox.json` — wrong/rotated key, corruption,
   or tampering — is a hard, fail-closed error, identical to `sessions.bin`'s existing behavior
   (`apps/cli/src/chat.rs`'s `load_state` propagates `at_rest::open`'s error and only falls back to a
   fresh/default state on `NotFound`, never on a decrypt/auth failure). This matters specifically for
   `contacts.json`'s `pinned_key_history`: silently reinitializing an empty contact store on open-failure
   would erase the pinned-key trust state that defeats a server key-substitution attack over time — the
   exact protection [threat-model.md](../security/threat-model.md)'s A2 adversary is meant to be caught
   by. A missing file (`NotFound`) is the only case that legitimately falls back to an empty/default
   store.
6. **`mid` (local message id) is not a wire field.** History entries key on a locally generated 128-bit
   id for dedup and delivery-state matching; this is separate from envelope-level `eid`, which arrives
   with envelope v2 ([ADR 0016](./0016-envelope-deniability.md) C7). The store must adopt `eid` for
   dedup once envelope v2 lands — tracked as a `TODO: confirm` in `tui-client.md §5`, not resolved by
   this ADR.

## Rejected alternative (recorded per scope)

**`store.encrypt = false`.** Rejected above under the sealing trade-off: it reintroduces a standing
plaintext mode this project's threat model doesn't accept, undermines the at-rest audit's ability to
assert an unconditional invariant, and has no precedent elsewhere in the codebase's own sealed-storage
surface (`sessions.bin`). If a future, genuinely new use case needs it, it requires a superseding ADR
that re-litigates this trade-off explicitly, not a config default flip.

## Accepted residual risks

**R1 — `state.json`'s conversation index is itself a mild metadata leak.** Even restricted to an
opaque handle plus pane geometry, "some conversation was open, and the UI was in this shape" is
metadata about usage patterns (a device was actively used, roughly how many conversations exist by
handle count), visible to anyone with filesystem access without needing the account key or the sealed
`contacts.json` the handle resolves against. This is accepted as the cost of letting the UI restore its
last view without a decrypt-on-every-keystroke cost, and is a strictly smaller exposure than the full
sealing boundary already closes — the opaque handle alone does not identify *which* contact, unlike a
pubkey or `mrd1:` id would. No trigger to reopen; flagged so a future reviewer doesn't mistake it for
an oversight.

## Consequence

[4.14](../tasks/phase-4/4.14-tui-config.md) (`meridian-tui::config`) and
[4.15](../tasks/phase-4/4.15-tui-store.md) (`meridian-tui::store`) implement this shape directly — no
alternative format or sealing scheme may be introduced by those tasks without amending this ADR.
[4.27](../tasks/phase-4/4.27-at-rest-audit-harness.md)'s audit harness is the mechanical check that
condition 2's boundary holds.
