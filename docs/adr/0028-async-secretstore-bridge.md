<!-- Resolves the SecretStore sync/async gap task 12.5's own review found in ADR 0026's Decision B
     ("zero trait changes" claim). Required architect pre-check for task 12.13 (browser wasm adapter);
     see docs/tasks/phase-12/12.13-browser-wasm-adapter.md's Risks/notes and
     docs/tasks/phase-12/12.5-webcrypto-secret-store.md's Outcome for the finding this corrects. -->
> **Nav:** [ADR index](./README.md) · [ADR 0026 (browser client-local store)](./0026-browser-client-local-store.md) ·
> [core API contracts](../api/core-api-contracts.md) · [apps/store/src/webcrypto.rs](../../apps/store/src/webcrypto.rs)

# ADR 0028: Async `SecretStore` bridge for browser WebCrypto operations

**Status:** **Accepted.** **Scope-corrects** [ADR 0026](./0026-browser-client-local-store.md)'s Decision B
claim that `WebCryptoSecretStore` is "implementable against the existing `SecretStore` trait with zero
trait changes" — that claim is factually wrong (see Context) — and adds a new binding condition. Does
**not** reopen ADR 0026's actual backing choice (`WebCryptoSecretStore` via non-extractable `CryptoKey`s
remains the decision); this ADR only corrects how that choice is reached at the call site.

## Context

`SecretStore`'s frozen trait (`apps/store/src/lib.rs`, `docs/api/core-api-contracts.md`) is fully
synchronous. Every `crypto.subtle` (WebCrypto) operation is Promise-based by spec. There is no safe way
to block a single-threaded `wasm32-unknown-unknown` call on an in-flight Promise: `std::thread::park`
doesn't actually park on this target (confirmed empirically during task 12.5 — a naive `block_on` would
busy-spin forever without ever yielding to the JS event loop that resolves the Promise), and the two
real bridging mechanisms — a `SharedArrayBuffer`/`Atomics.wait` worker bridge (needs a dedicated worker
plus `COOP`/`COEP` cross-origin-isolation deployment headers, which no doc in this repo anticipates —
checked `docs/tasks/phase-12/12.19-web-deployment-guide.md`, the only doc that could plausibly cover
this) or Binaryen `--asyncify` — were both out of scope for task 12.5 and remain disproportionate here.

Task 12.5 built `WebCryptoSecretStore` correctly given this constraint: its `impl SecretStore` trait
methods deliberately return `StoreError::Backend(sync_bridge_unavailable())` for the three secret-touching
operations rather than hang or fabricate a result; the real logic lives in inherent `async fn store/
use_key/derive_key/nonextractable` methods with the same names. This is sound, but it means
`meridian_identity::generate_account`/`sign` (`apps/identity/src/keys.rs`) — the actual `&dyn
SecretStore`/generic-`<S: SecretStore>` dyn-dispatch call sites production code uses — always fail
against a `WebCryptoSecretStore`. Task 12.13 (browser wasm adapter) cannot ship real account
generate/sign operations without resolving this, and per this repo's own binding-ADR rule, an ADR whose
text asserts something the shipped code has already proven false needs a formal correction, not a silent
task-diff fix.

## Options — bridging `SecretStore` to `crypto.subtle`'s async API

**(A) A new, non-object-safe async companion trait `AsyncSecretStore`**, implemented only by
`WebCryptoSecretStore`, consumed by new generic-bound sibling helpers in `apps/identity/src/keys.rs`
(`generate_account_async`/`sign_async`) that reuse every non-store-touching line (hint validation, seed
generation, the account's storage label, signature construction) verbatim from the existing
`generate_account`/`sign` — a single source of truth both platforms share. Deliberately simpler than
`Transport`'s `async_trait`/boxed-`Send`-future/`AssertSend` machinery (`apps/wasm/src/transport.rs`):
`Transport` needs that because multiple concrete backends are selected polymorphically behind `&dyn
Transport`; `SecretStore` has exactly one async-capable backend on `wasm32` (`WebCryptoSecretStore`, no
runtime polymorphism requirement), so a plain trait with native `async fn` methods (stable Rust, no
boxing, no `Send` bound) suffices.

**(B) A worker + `SharedArrayBuffer`/`Atomics.wait` bridge**, making the existing synchronous trait
genuinely work on `wasm32` by blocking on a real OS-level primitive inside a dedicated worker. Rejected:
requires `COOP`/`COEP` cross-origin-isolation deployment headers with no story anywhere in this repo
today, and would require modifying `WebCryptoSecretStore`/the store itself — out of task 12.13's own
declared scope (its Scope → Out list routes any store-insufficiency finding back to 12.5/12.12, not a
workaround inside 12.13). Disproportionate infrastructure for a problem (A) solves without it.

**(C) The browser adapter (task 12.13) reimplements `generate_account`/`sign`'s orchestration directly**
against `WebCryptoSecretStore`'s async inherent methods, without ever going through the shared
`meridian_identity` helpers. Rejected: `generate_account`/`sign` do more than call the store — hint
validation (`crate::id::validate_hint`), CSPRNG seed generation, public-key derivation, and the account's
storage label (`hex_lower(public_key.as_bytes())`, a private helper) — and `meridian-identity` is
wire-critical and conformance-vectored (`apps/identity/CLAUDE.md`). Letting the browser path re-derive
this orchestration independently risks silent drift the next time `validate_hint` or the labeling scheme
changes on the native side — exactly the duplication task 12.12's own crate-placement reasoning (ADR
0026) already goes out of its way to avoid for the sealing code.

## Decision: A

```rust
/// Async twin of `SecretStore` (core-api-contracts.md's frozen sync trait), for targets where the
/// platform key-store API is only reachable via `Future`s (today: wasm32's `crypto.subtle`). Not
/// object-safe by design — unlike `Transport`, wasm32 has exactly one async-only backend
/// (`WebCryptoSecretStore`), so a generic bound is enough; this deliberately skips `async_trait`'s
/// boxing/`Send`-bound machinery (see `apps/wasm/src/transport.rs`'s `AssertSend` for why `Transport`
/// needed that and this doesn't). Same three operation names, same inputs/outputs as `SecretStore` —
/// an async view of the same surface, not a new capability.
pub trait AsyncSecretStore {
    async fn store(&self, label: &str, secret: &[u8]) -> Result<KeyHandle>;
    async fn use_key(&self, h: &KeyHandle, op: SignOrDh, input: &[u8]) -> Result<Vec<u8>>;
    fn nonextractable(&self) -> bool;
    async fn derive_key(&self, h: &KeyHandle, info: &[u8]) -> Result<[u8; 32]>;
}
```

`WebCryptoSecretStore`'s existing `impl SecretStore` (the honest-error stub from task 12.5) is
**unchanged** — kept for `&dyn SecretStore`/generic-`<S: SecretStore>` compatibility (diagnostics,
anything genuinely platform-generic that never needs the browser path to actually succeed).

## Binding conditions

1. `WebCryptoSecretStore`'s synchronous `impl SecretStore` methods remain honest-error stubs — never
   made to hang, block, or fabricate a result. They are not removed by this ADR.
2. All real browser account-key operations (account generation, signing) go through the new
   `AsyncSecretStore` trait plus `meridian_identity::generate_account_async`/`sign_async` — never a
   second, independently-maintained reimplementation of that orchestration logic inside `apps/wasm`.
3. `AsyncSecretStore` is additive, non-object-safe, and implemented only where a real async backend
   exists (`WebCryptoSecretStore` today) — it does not replace or widen `SecretStore` itself, and no
   other `SecretStore` impl (`OsSecretStore`, `FileSecretStore`, `MemorySecretStore`) needs to implement
   it.

## Consequence

Formally closes the gap task 12.5's own review flagged (a correct implementation-time finding that ADR
0026's Decision B rationale did not hold) rather than leaving it live only as a code-comment `TODO:
confirm`. Corrects ADR 0026's Decision-B "zero trait changes" claim — treat that sentence in ADR 0026 as
superseded by this ADR's Context section; ADR 0026's actual backing choice (`WebCryptoSecretStore` via
non-extractable `CryptoKey`s) is otherwise unchanged and remains binding. Unblocks task 12.13 (browser
wasm adapter) to wire real `generate_account`/`sign` operations through `apps/wasm`'s `#[wasm_bindgen]`
surface as `async fn`s (wasm-bindgen generates a Promise-returning JS binding for these natively) backed
by `WebCryptoSecretStore` + the new async helpers, with no special-casing needed at the TS
(`MeridianClientAdapter`) layer.
