/**
 * `WasmMeridianClientAdapter` — the concrete {@link MeridianClientAdapter} (task 12.2,
 * `shared-ui/src/lib/adapter.ts`) implementation for the browser shell, over `meridian-wasm`'s
 * compiled `#[wasm_bindgen]` bindings (task 12.10, extended by task 12.13 — see this file's own
 * "Reading this file" section below for what task 12.13 step 2 added to `apps/wasm/src/lib.rs`
 * itself). Mirrors `apps/desktop/ui/src/adapter.ts`'s (task 12.6) own shape and GAP-comment
 * convention: every deviation from a genuine, real call into the wasm boundary is called out in a
 * comment tagged **GAP**, never silently worked around or reimplemented in TypeScript.
 *
 * ## Reading this file — the dominant finding this task made
 * `apps/wasm/src/lib.rs` (task 12.10, extended by 12.13 step 1) exports **only identity primitives**
 * today: `generateAccount`, `WasmAccount.sign`, `verify`, `safetyNumber` (all four confirmed by
 * reading the actually-compiled `apps/wasm/pkg/meridian_wasm.d.ts`, not assumed). Neither
 * `BrowserTransport` (task 12.11) nor `IndexedDbStore` (task 12.12) carry **any**
 * `#[wasm_bindgen]` surface at all — both are plain, `wasm32`-only Rust types reachable only from
 * other Rust code (their own crate-internal test suites) until this task added exactly one, minimal,
 * additive exception (see below). There is **no** `meridian-wasm` binding anywhere for:
 * - a session/chat orchestration layer (`meridian_core::chat::ChatState`, X3DH, the ratchet) —
 *   `openConversation`/`sendChat`/`onMessage`/`onMessageRequest`/`acceptMessageRequest`/
 *   `rejectMessageRequest` have nothing to call;
 * - a trust store (`meridian_core::trust::TrustStore`) — `trustState`/`sendGateState`/
 *   `acknowledgeKeyChange`/`listContacts`/`addContact`/`renamePetname`/`blockContact`/
 *   `unblockContact`/`listConversations`/`loadHistory`/`markConversationRead`/`markVerified` have
 *   nothing to call;
 * - the stream registry (`meridian_core::streams`) — `openStream`/`onStreamFrame`/`sendFile`/
 *   `listTransfers`/`acceptTransfer`/`rejectTransfer` have nothing to call.
 *
 * None of these can be implemented against today's real bindings without either (a) inventing a
 * second, TypeScript-side reimplementation of session/trust/stream-registry orchestration — exactly
 * the "no bespoke crypto or wire types in JS/TS" invariant `apps/web/CLAUDE.md` forbids, since that
 * orchestration is inseparable from X3DH/ratchet/envelope logic — or (b) fabricating a successful
 * result with no real backing. Every method in that list below therefore fails closed with a
 * `MeridianAdapterError("unavailable", …)`, documented individually, rather than doing either. This
 * is a **much larger** gap than any individual GAP task 12.6's own adapter found — it is reported
 * here, prominently, as this task's own primary finding: unblocking the methods above needs a
 * dedicated, reviewed follow-up (a `WasmSession`/`WasmChatState`-shaped addition to `apps/wasm`,
 * composing `meridian_core::chat::ChatState` + `BrowserTransport` + `WebCryptoSecretStore`, plus a
 * `#[wasm_bindgen]` surface over `IndexedDbStore`), not something invented under this task's own
 * TS-adapter scope.
 *
 * ## Account persistence across a reload — a second, distinct structural gap
 * {@link WasmMeridianClientAdapter.openAccount} is *also* a GAP, for a different, equally structural
 * reason: `WebCryptoSecretStore` (task 12.5) imports the account seed as a **non-extractable**
 * `crypto.subtle` `CryptoKey` and (correctly, by design) never exposes the raw seed again — so there
 * is no byte value this adapter could hand to `IndexedDbStore` to "seal and restore" later even if
 * `IndexedDbStore` had a `#[wasm_bindgen]` surface to call (it doesn't — see above). The only sound
 * way to survive a reload with a non-extractable key is to persist the actual `CryptoKey` object
 * itself (IndexedDB natively supports storing/retrieving `CryptoKey`s via structured clone, still
 * non-extractable on the far side) — but `WasmAccount` exposes no accessor for its own `CryptoKey`s
 * (`apps/store/src/webcrypto.rs`'s `KeySet` is a private field with no getter), and
 * `IndexedDbStore`'s only two record shapes (`put_sealed`/`put_state`) are both JSON-only, unable to
 * carry a `CryptoKey` object at all. **This is a real design gap in ADR 0026/ADR 0028, not something
 * this task's own TS-only scope can close** — flagged here explicitly (candidate: a follow-up ADR
 * amendment, analogous to ADR 0028's own precedent for the sync/async gap, specifying how a
 * non-extractable account `CryptoKey` set is meant to survive a reload). `generateAccount` itself is
 * unaffected and fully real; only *re-opening* a previously-generated account after this adapter
 * instance is discarded is impossible today.
 *
 * ## What task 12.13 step 2 *did* add to `apps/wasm/src/lib.rs`
 * One thin, additive `#[wasm_bindgen]` wrapper, `WasmTransport`, around the existing, unmodified,
 * already-reviewed (12.11) `BrowserTransport` — a 1:1 marshaling pass-through with zero new
 * negotiation/ICE/crypto logic (see that type's own doc comment in `apps/wasm/src/lib.rs`). This
 * repo's own scope rule for this task ("do NOT change `BrowserTransport`/the store — report
 * insufficiency, don't work around it") is about their *own* files (`apps/wasm/src/transport.rs`,
 * `apps/wasm/src/store/indexeddb.rs`), both left byte-for-byte untouched; `WasmTransport` only wires
 * the *already-shipped* `BrowserTransport` into this crate's own exported surface, which
 * `apps/wasm/src/lib.rs`'s own pre-existing module doc already named as the next, expected step.
 * {@link MeridianClientAdapter} itself has **no** transport-level method (its own top doc comment:
 * "No `Transport`/`SecretStore` surface… never something a screen touches") — so `WasmTransport` is
 * deliberately *not* surfaced through this adapter class at all; this file's own integration test
 * (`adapter.browser.test.ts`) imports it directly from `meridian-wasm` to prove the real substrate
 * `sendChat`/`onMessage` will eventually ride on already works end to end, without pretending
 * `sendChat` itself is implemented.
 */

import init, {
  generateAccount as wasmGenerateAccount,
  type WasmAccount,
} from "meridian-wasm";
// Vite's `?url` import gives back a dev-server-served URL for the compiled `.wasm` binary itself —
// `init()`'s own default (`new URL('meridian_wasm_bg.wasm', import.meta.url)`) resolves correctly at
// the module-graph level but Vite's dev server does not serve it with a `Wasm`-appropriate response
// on every route (observed directly against this task's own browser test harness: `instantiateStreaming`
// fails with a non-`application/wasm` MIME type and the streaming-fallback fetch instead receives
// Vite's SPA-fallback `index.html`). Passing the asset's own resolved URL sidesteps that fallback path
// entirely — a plain build-tooling routing detail, not a WASM-boundary or protocol concern.
// eslint-disable-next-line import/no-unresolved
import wasmUrl from "meridian-wasm/meridian_wasm_bg.wasm?url";

import type {
  ChatMessage,
  Contact,
  ConversationSummary,
  FileTransferSummary,
  MeridianClientAdapter,
  MeridianId,
  MessageRequest,
  SafetyNumber,
  SendGateState,
  SendResult,
  StreamHandle,
  StreamOpenResult,
  TrustState,
} from "shared-ui";
import { MeridianAdapterError } from "shared-ui";

// ---------------------------------------------------------------------------
// wasm module init — memoized, so every adapter instance shares one `WebAssembly.Module`
// instantiation (mirrors the standard wasm-bindgen `--target web` usage pattern; re-instantiating
// per adapter would still be *correct*, just wasteful).
// ---------------------------------------------------------------------------

let wasmReady: Promise<void> | null = null;

function ensureWasmInit(): Promise<void> {
  wasmReady ??= init({ module_or_path: wasmUrl }).then(() => undefined);
  return wasmReady;
}

/** Flattens a rejected `generateAccount(hint)` call's message into a {@link MeridianAdapterError}.
 * Mirrors `meridian_identity::validate_hint`'s one stable error wording
 * (`apps/identity/src/error.rs`: `"invalid hint: {0}"`) — the only failure mode `generateAccount`
 * can genuinely produce against caller input. */
function mapGenerateAccountError(err: unknown): MeridianAdapterError {
  if (err instanceof MeridianAdapterError) return err;
  const message = err instanceof Error ? err.message : String(err);
  if (message.includes("invalid hint")) {
    return new MeridianAdapterError("invalid_id", message);
  }
  return new MeridianAdapterError("unknown", message);
}

/** Throws the shared shape every GAP'd method below uses — see this file's own top doc comment for
 * the full report of *why* each of these has nothing real to call. */
function gap(method: string, reason: string): never {
  throw new MeridianAdapterError(
    "unavailable",
    `${method}: ${reason} — see apps/web/src/lib/adapter.ts's own top doc comment for the full gap report`,
  );
}

const NO_SESSION_ORCHESTRATION =
  "meridian-wasm exports no session/chat orchestration (ChatState/X3DH/ratchet) yet, only identity primitives";
const NO_TRUST_STORE =
  "meridian-wasm exports no trust-store binding (TrustStore) yet, only identity primitives";
const NO_STREAM_REGISTRY =
  "meridian-wasm exports no stream-registry binding yet, only identity primitives";

export class WasmMeridianClientAdapter implements MeridianClientAdapter {
  private account: WasmAccount | null = null;
  private accountId: MeridianId | null = null;

  // -------------------------------------------------------------------------
  // Account — the one slice of this interface with a real binding to call.
  // -------------------------------------------------------------------------

  /** Real: `meridian-wasm`'s `generateAccount(hint)` — genuine Ed25519 keypair generation backed by
   * a fresh `WebCryptoSecretStore` (non-extractable `crypto.subtle` `CryptoKey`s, ADR 0026/0028). */
  async generateAccount(hint: string): Promise<MeridianId> {
    await ensureWasmInit();
    let account: WasmAccount;
    try {
      account = await wasmGenerateAccount(hint);
    } catch (err) {
      throw mapGenerateAccountError(err);
    }
    this.account?.free();
    this.account = account;
    this.accountId = account.id;
    return account.id;
  }

  /**
   * GAP (structural — see this file's top doc comment, "Account persistence across a reload"):
   * `WasmAccount`'s non-extractable `CryptoKey`s cannot be exported, and no `#[wasm_bindgen]`
   * surface exists to persist/restore the `CryptoKey` objects themselves (the only sound way to
   * survive a reload with them) or to reconstruct an account from any other `descriptor` shape.
   * `descriptor` is accepted for interface conformance only and always fails closed.
   */
  async openAccount(descriptor: unknown): Promise<MeridianId> {
    void descriptor;
    gap(
      "openAccount",
      "no CryptoKey-persistence or account-reconstruction binding exists yet (see this file's " +
        "own top doc comment's 'Account persistence across a reload' section)",
    );
  }

  currentAccount(): MeridianId | null {
    return this.accountId;
  }

  /** Frees the wasm-side `WasmAccount` (releasing its linear-memory allocation) and discards this
   * adapter's own reference — the account's `CryptoKey`s themselves become unreachable garbage for
   * `crypto.subtle` to collect, the closest this adapter can get to "discarding in-memory key
   * material" without a dedicated wasm-side zeroize hook (none exists on `WasmAccount` today). */
  async closeAccount(): Promise<void> {
    this.account?.free();
    this.account = null;
    this.accountId = null;
  }

  // -------------------------------------------------------------------------
  // Sessions & messaging — GAP, see this file's top doc comment.
  // -------------------------------------------------------------------------

  async openConversation(peer: MeridianId): Promise<void> {
    void peer;
    gap("openConversation", NO_SESSION_ORCHESTRATION);
  }

  async sendChat(peer: MeridianId, body: string): Promise<SendResult> {
    void peer;
    void body;
    gap("sendChat", NO_SESSION_ORCHESTRATION);
  }

  /** No inbound event source exists to route to a subscriber (see this file's top doc comment) —
   * the callback is registered, so a caller's unsubscribe function stays well-formed, but it will
   * never fire against this adapter today. Mirrors the desktop adapter's identical
   * `onStreamFrame`-shaped GAP. */
  onMessage(cb: (peer: MeridianId, msg: ChatMessage) => void): () => void {
    void cb;
    return () => {};
  }

  onMessageRequest(cb: (req: MessageRequest) => void): () => void {
    void cb;
    return () => {};
  }

  async acceptMessageRequest(from: MeridianId, petname?: string): Promise<void> {
    void from;
    void petname;
    gap("acceptMessageRequest", NO_TRUST_STORE);
  }

  async rejectMessageRequest(from: MeridianId): Promise<void> {
    void from;
    gap("rejectMessageRequest", NO_TRUST_STORE);
  }

  async trustState(peer: MeridianId): Promise<TrustState> {
    void peer;
    gap("trustState", NO_TRUST_STORE);
  }

  async sendGateState(peer: MeridianId): Promise<SendGateState> {
    void peer;
    gap("sendGateState", NO_TRUST_STORE);
  }

  async acknowledgeKeyChange(peer: MeridianId): Promise<void> {
    void peer;
    gap("acknowledgeKeyChange", NO_TRUST_STORE);
  }

  // -------------------------------------------------------------------------
  // Contacts / trust — GAP, see this file's top doc comment.
  // -------------------------------------------------------------------------

  async listContacts(): Promise<Contact[]> {
    gap("listContacts", NO_TRUST_STORE);
  }

  async addContact(id: MeridianId, petname?: string): Promise<Contact> {
    void id;
    void petname;
    gap("addContact", NO_TRUST_STORE);
  }

  async renamePetname(id: MeridianId, petname: string | null): Promise<void> {
    void id;
    void petname;
    gap("renamePetname", NO_TRUST_STORE);
  }

  async blockContact(id: MeridianId): Promise<void> {
    void id;
    gap("blockContact", NO_TRUST_STORE);
  }

  async unblockContact(id: MeridianId): Promise<void> {
    void id;
    gap("unblockContact", NO_TRUST_STORE);
  }

  async listConversations(): Promise<ConversationSummary[]> {
    gap("listConversations", NO_TRUST_STORE);
  }

  async loadHistory(
    peer: MeridianId,
    opts?: { limit?: number; before?: string },
  ): Promise<ChatMessage[]> {
    void peer;
    void opts;
    gap("loadHistory", NO_SESSION_ORCHESTRATION);
  }

  async markConversationRead(peer: MeridianId): Promise<void> {
    void peer;
    gap("markConversationRead", NO_TRUST_STORE);
  }

  // -------------------------------------------------------------------------
  // Verification — GAP: real `safetyNumber`/`verify` bindings exist (see this file's top doc
  // comment), but this method needs a *peer's* raw pubkey, and decoding one out of a `MeridianId`
  // string in TypeScript would mean reimplementing `mrd1:` id parsing (base32 + checksum +
  // multicodec, `apps/identity/src/id.rs`) here — exactly the "reimplement wire/identity logic in
  // TS" invariant this codebase forbids (the same reasoning `apps/desktop/ui/src/adapter.ts`'s own
  // `pubkeyToId` doc comment already documents for the identical problem on desktop). Without a real
  // `TrustStore` binding (see this file's top doc comment) there is no other source for a peer's
  // pubkey bytes, so this fails closed rather than parsing the id itself.
  // -------------------------------------------------------------------------

  async safetyNumber(peer: MeridianId): Promise<SafetyNumber> {
    void peer;
    gap(
      "safetyNumber",
      "no trust-store binding exists to resolve a peer's raw pubkey, and decoding one out of a " +
        "MeridianId string here would mean reimplementing mrd1: id parsing in TypeScript (forbidden)",
    );
  }

  async markVerified(peer: MeridianId): Promise<void> {
    void peer;
    gap("markVerified", NO_TRUST_STORE);
  }

  // -------------------------------------------------------------------------
  // Streams / file ops — GAP, see this file's top doc comment.
  // -------------------------------------------------------------------------

  async openStream(peer: MeridianId, streamType: string, params: unknown): Promise<StreamOpenResult> {
    void peer;
    void streamType;
    void params;
    gap("openStream", NO_STREAM_REGISTRY);
  }

  onStreamFrame(cb: (streamId: StreamHandle, frame: Uint8Array) => void): () => void {
    void cb;
    return () => {};
  }

  async sendFile(peer: MeridianId, file: Blob, fileName: string): Promise<StreamOpenResult> {
    void peer;
    void file;
    void fileName;
    gap("sendFile", NO_STREAM_REGISTRY);
  }

  async listTransfers(): Promise<FileTransferSummary[]> {
    gap("listTransfers", NO_STREAM_REGISTRY);
  }

  async acceptTransfer(streamId: StreamHandle): Promise<void> {
    void streamId;
    gap("acceptTransfer", NO_STREAM_REGISTRY);
  }

  async rejectTransfer(streamId: StreamHandle): Promise<void> {
    void streamId;
    gap("rejectTransfer", NO_STREAM_REGISTRY);
  }
}
