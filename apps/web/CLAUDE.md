# CLAUDE.md — apps/web (browser client)

Scoped memory. Inherits [root](../../CLAUDE.md) + [apps/CLAUDE.md](../CLAUDE.md). SvelteKit UI over the
**WASM build of `meridian-core`**. Currently a scaffold (index.html, package.json, src/main.ts).

Read first: [core-api-contracts](../../docs/api/core-api-contracts.md),
[api-contracts skill](../../.claude/skills/api-contracts/SKILL.md),
[anonymity-model skill](../../.claude/skills/anonymity-model/SKILL.md).

## Rules
- **No bespoke crypto or wire types in JS/TS.** Identity, keys, ratchet, framing all run in the WASM
  core; the web layer only calls it. The web client must match the conformance vectors byte-for-byte.
- **Leak nothing the anonymity model forbids** — no plaintext, identifiers, or contact metadata to
  logs, analytics, storage, or third-party requests.
- Keep the WASM boundary thin and typed; UI state is not a place to reimplement protocol logic.
- Assigned to the **web-dev** agent; security-sensitive surfaces also go to **security-reviewer**.
