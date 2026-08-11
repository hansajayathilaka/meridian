<!-- Source: this decision (task 4.1, T17 planning). -->
> **Nav:** [ADR index](./README.md) · [tui-client.md §1](../architecture/tui-client.md#1-shape-of-the-thing) ·
> [feature 17](../architecture/features/17-terminal-tui-client.md) · precedent [ADR 0009](./0009-monorepo-tooling.md)

# ADR 0020: TUI packaging — crate shape, entry point, dependency direction

**Options — crate shape:** (A) a standalone `meridian-tui` binary with its own `main.rs`, invoked
directly (`meridian-tui` on `$PATH`) rather than through the `meridian` CLI; (B) fold ratatui/crossterm
code directly into `meridian-cli` as a `tui` module; (C) **a new `apps/tui` crate (`meridian-tui`),
launched by a thin `meridian tui` subcommand in `meridian-cli` behind a default-on `tui` feature
(chosen)**.

**Trade-offs.** A gives the TUI its own binary identity, but every other user-facing entry point in
this workspace is a `meridian <subcommand>` — a second top-level binary means two things to install,
two `--help` trees, and no natural way to share `apps/cli`'s already-built account/policy loading
(`apps/cli/src/account.rs`) without either a crate dependency from `meridian-tui` back onto
`meridian-cli` (wrong direction — the CLI is the orchestration surface, not a library to embed) or
duplicating that logic. B avoids the second-binary problem but pulls ratatui, crossterm, and every
future screen module into `meridian-cli` itself, so a lean `--no-default-features` build (the shape
`demo/two-orgs` and CI scripts already rely on to stay fast) now carries a full TUI dependency tree it
never uses, and it blurs `apps/cli/CLAUDE.md`'s existing "CLI orchestrates `meridian-core`, no protocol
logic" boundary with a second, UI-shaped boundary inside the same crate. C keeps `meridian` as the one
binary users install, keeps the TUI's dependency tree (ratatui, crossterm) opt-in via a default-on
`tui` Cargo feature on `meridian-cli` so `--no-default-features` stays lean, and gives the TUI its own
crate to grow screens in without bloating `meridian-cli`'s own module tree.

**Decision: C.**

## Binding conditions

1. **New crate:** `apps/tui`, package name `meridian-tui`. Owns all ratatui/crossterm code — no
   terminal-rendering code lands anywhere else in the workspace.
2. **Entry point:** `meridian tui` — a subcommand added to `meridian-cli`'s existing `clap` command
   tree, gated behind a Cargo feature named `tui`, **default-on**. `cargo build -p meridian-cli
   --no-default-features` must still succeed and must not pull in ratatui/crossterm.
3. **Dependency direction:** `meridian-cli` depends on `meridian-tui`; `meridian-tui` depends on
   `meridian-core` only (identity, session, transport, trust — the same core every other client shim
   consumes), **never** on `meridian-cli`. This is a hard acyclicity rule, mechanically checkable the
   same way `tools/lint-server-no-core.sh` already checks the server side. Concretely:
   `cargo tree -p meridian-tui -e normal,build` (checked at both default features and
   `--all-features`) must show no workspace crate outside the allowlist `{meridian-tui,
   meridian-core}` — in particular, `meridian-cli` must never appear at any depth. A
   `tools/lint-tui-no-cli.sh` equivalent, mirroring `lint-server-no-core.sh`'s allowlist approach,
   should land when [4.11](../tasks/phase-4/4.11-tui-crate-skeleton-terminal-guard.md) introduces the
   crate.
   - This direction is deliberate for [4.13](../tasks/phase-4/4.13-extract-account-home-layout-core.md):
     the account-descriptor and `$MERIDIAN_HOME` helpers `apps/cli/src/account.rs` already owns must
     move *into* `meridian-core` (not stay in `meridian-cli` for `meridian-tui` to reach across and
     import), so both the CLI and the TUI consume the same extracted helpers as peers, neither
     depending on the other's private module tree.
4. **No protocol logic in `meridian-tui`.** Same rule `apps/cli/CLAUDE.md` already states for the CLI
   (root [CLAUDE.md](../../CLAUDE.md), `tui-client.md §1`): the TUI orchestrates `meridian-core`, it
   does not reimplement X3DH, ratchet, trust-state transitions, or wire framing. If a screen appears to
   need new protocol surface, that is a planning defect, not something to improvise in `apps/tui`.
5. **Capability parity, one direction only:** anything the TUI can do, the CLI must already be able to
   do headlessly (`meridian <subcommand> --json`) — the TUI is allowed to be *nicer*, never *more
   capable*. A TUI feature with no CLI equivalent is a scope defect in whichever task adds it.

## Rejected alternatives (recorded per `tui-client.md §1`)

- **Standalone `meridian-tui` binary.** Rejected: fragments the single-binary install story this
  project has kept since T01, and would need its own copy of (or a wrong-direction dependency on)
  `meridian-cli`'s account/policy loading.
- **Fold directly into `meridian-cli`.** Rejected: forces the TUI's ratatui/crossterm dependency tree
  onto every `meridian-cli` build regardless of feature flags in practice (a module can't easily be
  Cargo-feature-gated to the same degree a separate crate can without significant `#[cfg]` surgery
  throughout `apps/cli`), and collapses two distinct boundaries (orchestration vs. rendering) into one
  crate.

## Accepted residual risks

**R1 — Two crates now share the account/home-layout surface.** Once [4.13](../tasks/phase-4/4.13-extract-account-home-layout-core.md)
lands, both `meridian-cli` and `meridian-tui` read the same `meridian-core` helpers for
`$MERIDIAN_HOME`, `account.json`, and `policy.json`. A behavior change to those helpers now has two
consumers to keep in sync instead of one. This is the intended trade-off of condition 3 above (shared
core beats either duplication or a wrong-direction dependency), not a gap — but future changes to
those helpers must consider both call sites, and their tests should live in `meridian-core` where both
crates' behavior is verified once rather than twice.

## Consequence

No terminal-rendering dependency (ratatui, crossterm) is added anywhere except `apps/tui`. `apps/cli`
gains one new Cargo feature (`tui`, default-on) and one new subcommand wired to `meridian-tui`'s entry
point. `apps/cli/Cargo.toml` currently has no non-empty default feature set and CI runs no
`--no-default-features` build for it today, so condition 2's lean-build check is new surface, not a
continuation of existing coverage: [4.12](../tasks/phase-4/4.12-tui-subcommand-env-gate.md) must both
add `cargo build -p meridian-cli --no-default-features` as a task-level test *and* wire it into
`.github/workflows/ci.yml` so it stays enforced, not just a one-time local check. Tasks
[4.11](../tasks/phase-4/4.11-tui-crate-skeleton-terminal-guard.md) (crate skeleton) and
[4.12](../tasks/phase-4/4.12-tui-subcommand-env-gate.md) (subcommand wiring) implement this shape;
[4.13](../tasks/phase-4/4.13-extract-account-home-layout-core.md) implements the `meridian-core`
extraction condition 3 requires. `docs/architecture/diagrams/build-target-topology.mermaid` still
draws `meridian-cli` calling into the terminal directly, with no `meridian-tui` node — it predates
this decision and is now stale; 4.11 must update it alongside adding the crate, so the diagram doesn't
silently diverge from this ratified shape.
