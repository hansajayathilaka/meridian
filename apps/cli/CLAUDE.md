# CLAUDE.md — apps/cli (`meridian-cli`)

Scoped memory. Inherits [root](../../CLAUDE.md) + [apps/CLAUDE.md](../CLAUDE.md). The terminal client —
Meridian's **reference client and demo driver**; each feature's acceptance demo runs here first.

Read first: the relevant [feature spec](../../docs/architecture/features/)'s "Working output (demo
script)" — the CLI is where those demos are wired.

## Rules
- **The CLI is the canonical demo surface.** Keep the commands in each feature spec's demo runnable and
  in sync; a broken demo is a failed acceptance criterion.
- **The interactive UI is not here.** T17 puts ratatui in `apps/tui` (`meridian-tui`); this crate only
  gains a thin `meridian tui` launcher behind a default-on `tui` feature, so `--no-default-features`
  keeps demo/CI builds free of the TUI dependency tree. Design:
  [docs/architecture/tui-client.md](../../docs/architecture/tui-client.md) · spec:
  [feature 17](../../docs/architecture/features/17-terminal-tui-client.md).
- Business/protocol logic belongs in the core crates, not in CLI command handlers — the CLI orchestrates
  and presents, it doesn't own protocol behaviour.
- Warning/verification copy is canonical and un-softenable ([verification-ux](../../docs/security/verification-ux.md));
  never auto-dismiss or reword security prompts.
- No plaintext, keys, or raw identifiers to stdout/logs beyond what the anonymity model allows.
- Assigned to the **rust-dev** agent.
