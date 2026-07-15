> **Nav:** [plan index](../README.md) · [messaging envelope v1](../../../api/messaging-envelope-v1.md) · [test strategy](../../../testing/strategy.md)

# Phase 2 — Freeze the crypto: conformance vectors + hygiene

*The swap is correct but unpinned. These convert "frozen" from a doc claim into a byte-checked CI reality
before the browser/mobile ports (Features 11/12) implement the same spec against nothing. All are
**[SEC]**; wire-frozen vector tasks are **[ADR]** (a vector defines the wire).*

**Gate before this phase:** Phases 0–1.

| Task | Scope (one line) | Tags | Depends on | Status |
|---|---|---|---|---|
| [T2.1](./T2.1-x3dh-vectors.md) | X3DH known-answer vectors + CI runner | [ADR][SEC] | — | ☐ |
| [T2.2](./T2.2-ratchet-vectors.md) | Double Ratchet transcript vectors | [ADR][SEC] | T2.1 | ☐ |
| [T2.3](./T2.3-envelope-bundle-vectors.md) | Envelope + prekey-bundle vectors | [ADR][SEC] | — | ☐ |
| [T2.4](./T2.4-safety-number-vectors.md) | Safety-number vectors + value test | [SEC] | — | ☐ |
| [T2.5](./T2.5-zeroization.md) | Zeroize X3DH master secret + ratchet header keys | [SEC] | — | ☐ |
| [T2.6](./T2.6-at-rest-key-derivation.md) | Dedicated at-rest key-derivation op on `SecretStore` | [ADR][SEC] | T2.3 | ☐ |
| [T2.7](./T2.7-wasm-aarch64-build.md) | wasm32 + aarch64 build validation in CI | — | T2.1, T2.2, T2.3 | ☐ |
