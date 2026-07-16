# CLAUDE.md — apps/rendezvous (`meridian-rendezvous`)

Scoped memory. Inherits [root](../../CLAUDE.md) + [apps/CLAUDE.md](../CLAUDE.md). The server: axum +
tokio + sqlx. It only helps peers rendezvous and relays opaque blobs — it never sees plaintext.

Read first: [anonymity-model skill](../../.claude/skills/anonymity-model/SKILL.md) "must never" list,
[rendezvous-protocol-v1](../../docs/api/rendezvous-protocol-v1.md),
[monitoring](../../docs/operations/monitoring.md).

## Rules
- **Never depends on `meridian-core`** — only `meridian-proto`. Enforced by
  `tools/lint-server-no-core.sh` / `just lint-invariants`.
- **No plaintext, no contact graph, no raw client IDs** in logs, storage, or metrics. No structured
  (de)serialization of opaque payloads (`lint-no-serde-on-blob`).
- **Metrics are allowlisted** — export only what `tools/metrics-allowlist.txt` permits
  (`lint-metrics-allowlist`).
- **No secrets in the repo.** TURN uses ephemeral per-session HMAC credentials.
- Adversarial-input mindset: verify signatures before acting on any field; fail closed.
- Route changes through **security-reviewer** + **architect**; ops surface through **devops**.
