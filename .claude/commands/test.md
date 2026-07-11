---
description: Run and fix tests for a scope.
---
Run and, if needed, fix tests for: **$ARGUMENTS**

1. Consult the [test strategy](../../docs/testing/strategy.md) to identify which layers apply to this scope (unit, property, integration/demo, adversarial harness, conformance vectors, soak).
2. Run the narrowest relevant command first, widening only as needed:
   - Rust: `cargo nextest run -p <crate>` then `cargo nextest run --workspace`.
   - Conformance vectors: the cross-impl fixture check (must be byte-identical across CLI/WASM/mobile).
   - Adversarial: the `mitm-sim` / opacity-audit / ghost-device harnesses if identity, crypto, or signaling changed.
3. For failures: reproduce, isolate, fix the **root cause** (not the test), and re-run. Never weaken an assertion to make a security test pass — an opacity-audit or MITM-sim failure is a real defect (see [threat model](../../docs/security/threat-model.md)).
4. Report pass/fail per layer and what you changed.
