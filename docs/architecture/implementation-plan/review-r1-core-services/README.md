> **Nav:** [plan index](../README.md) · [review-phase template](../review-phase-template.md) · [threat model](../../../security/threat-model.md) · [Definition of Done](../../../../CONTRIBUTING.md)

# Review R1 — Core Services & Protocol Trust (closes Milestone M1)

The review gate that closes **M1 (Features 06 Federation, 08 Verification/Trust, 07 Mailbox)**. It
instantiates the [review-phase template](../review-phase-template.md): a security-weighted, five-area
review of everything M1 touched, then `R1.<m>` remediation tasks fixed here before M2 starts.

**Status:** ☐ not started (runs when F06/F07/F08 are all built).

## Inputs
- **Milestone under review:** M1 — Features 06, 07, 08.
- **New/changed surfaces:** the federation module (s2s mTLS, discovery, forwarding, policy) and
  `federation-protocol-v1.md`; the trust module + contact store; the mailbox store + admin tooling; the
  extended `mitm-sim` and opacity audit.
- **Most-sensitive change:** **federation as a new trust boundary** — a second org's server enters the
  path. The deepest pass goes to: cross-org key trust (bundle substitution fails closed under the
  requested key), the federation edge's anti-abuse posture, mailbox retention invariants (ciphertext-only,
  TTL, no convenience features — ADR 0007), and that **no cross-org contact graph** is materialized
  server-side beyond per-request routing.

## The five areas to cover (see the template for the loop)
1. **Security review** — cross-org malicious-server MITM (both directions), the message-request gate as
   anti-enumeration, mailbox "must never #6" (no search/read-state/sync crept in), and metadata exposure
   across the federation boundary vs `anonymity-and-retention.md`.
2. **Completed-work review** — F06/F07/F08 against their spec acceptance sections and the DoD (both
   discovery modes, `closed`-policy rejection, TTL=0 disable, verified-key-change blocking, MITM matrix).
3. **Missing tasks** — `federation-protocol-v1.md` conformance vectors; safety-number vectors consumed;
   opacity audit extended cross-org and to at-rest DB pages; error handling at the federation edge.
4. **Gaps needing new steps** — any divergence from ADR 0002 / ADR 0007 / the trust-state diagram.
5. **Future risks** — federation abuse at scale, stale-hint UX, mailbox metadata (padding/batching is a
   Phase-3 follow-up — confirm it's recorded, not silently dropped).

## Findings & remediation
- Findings report → `findings.md` in this folder (most-severe first, file:line cited).
- Each actionable finding → an `R1.<m>` task here (standard fields + [ADR]/[SEC] tags), driven with
  [`/next-task`](../../../../.claude/commands/next-task.md) until green.
- **M2 does not start until this gate is clear.**
