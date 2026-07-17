<!-- Source: REPO-01-languages-and-frameworks §6 ADR-R5. -->
> **Nav:** [ADR index](./README.md) · [stack](../architecture/stack.md)

# ADR 0013: Server web framework — axum
**Options:** (A) **axum (chosen)**; (B) actix-web; (C) Go rewrite.
**Trade-offs:** C would abandon the shared-`meridian-proto` guarantee (server and clients agreeing on wire types by *compiling the same crate*) — a real safety loss for a marginal ops gain. A and B are both strong Rust choices; axum's tower middleware ecosystem fits the rate-limiting/mTLS/observability needs cleanly and it shares tokio with the rest of the tree. **Decision: A.** **Consequence:** the whole backend is Rust; the small team maintains one language server-to-client.

