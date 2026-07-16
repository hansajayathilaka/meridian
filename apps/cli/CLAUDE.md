# CLAUDE.md — apps/cli (`meridian-cli`)

Scoped memory. Inherits [root](../../CLAUDE.md) + [apps/CLAUDE.md](../CLAUDE.md). The terminal client —
Meridian's **reference client and demo driver**; each feature's acceptance demo runs here first.

Read first: the relevant [feature spec](../../docs/architecture/features/)'s "Working output (demo
script)" — the CLI is where those demos are wired.

## Rules
- **The CLI is the canonical demo surface.** Keep the commands in each feature spec's demo runnable and
  in sync; a broken demo is a failed acceptance criterion.
- Business/protocol logic belongs in the core crates, not in CLI command handlers — the CLI orchestrates
  and presents, it doesn't own protocol behaviour.
- Warning/verification copy is canonical and un-softenable ([verification-ux](../../docs/security/verification-ux.md));
  never auto-dismiss or reword security prompts.
- No plaintext, keys, or raw identifiers to stdout/logs beyond what the anonymity model allows.
- Assigned to the **rust-dev** agent.
