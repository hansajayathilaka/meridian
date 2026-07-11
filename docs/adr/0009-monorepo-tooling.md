<!-- Source: REPO-01-languages-and-frameworks §6 ADR-R1. -->
> **Nav:** [ADR index](./README.md) · [stack](../architecture/stack.md)

# ADR 0009: Monorepo tooling — native toolchains + thin task runner
**Options:** (A) Bazel/Buck2; (B) Nx; (C) moon; (D) **Cargo workspace + pnpm + Gradle + SPM, glued by `just`/`xtask` (chosen)**.
**Trade-offs:** A is hermetic and scales to huge polyglot repos but imposes a heavy, full-time build-engineering tax and fights Cargo's native ergonomics — wrong for a 2–5 person team. B is excellent for JS but treats Rust as a second-class plugin, and Rust *is* our spine. C (moon) is a genuinely good polyglot task runner with real caching; it's the closest competitor. D uses each ecosystem's idiomatic tool (nothing exotic for a new hire to learn), keeps the Rust workspace pristine, and adds only a thin recipe layer. **Decision: D**, with **moon as a documented escape hatch** — if cross-language incremental caching becomes a measured bottleneck, moon layers on top without restructuring. **Consequence:** no free cross-language build graph; acceptable at this scale, revisited if CI wall-clock exceeds a set budget.

