/**
 * `MeridianClientAdapter` — the framework-agnostic TypeScript boundary between the shared UI
 * (Svelte screens, task 12.7-12.9) and a concrete platform backend (browser wasm-bindgen: task
 * 12.13; desktop Tauri `invoke`/`listen`: task 12.6). ADR 0012: "the WASM boundary is
 * framework-agnostic (plain TS API), so a later swap to React touches only the view layer" — this
 * file imports nothing from Svelte (or any framework) and nothing from the wire layer.
 *
 * ## What this boundary is NOT (apps/web/CLAUDE.md, apps/CLAUDE.md)
 * - **No crypto, no framing, no wire types.** Identity, keys, ratchet, safety-number computation,
 *   QR codec, ID parsing/checksumming, and trust-state transitions all run in `meridian-core`
 *   (WASM / in-process Tauri). Everything here is a *view-shaped result* (strings, numbers,
 *   booleans, small unions) handed back by core; nothing here re-derives or re-encodes a protocol
 *   value, and nothing exposes envelopes, bundles, keys, ciphertext, or `meridian-proto` shapes.
 *   Peers are addressed by an opaque {@link PeerId} string, never by raw key bytes.
 * - **Not invented.** Every operation below is derived from what `apps/cli` and `apps/tui`
 *   already call into `meridian-core` (and, where noted, the sibling local store the TUI keeps).
 *   The `Derived from` tag on each operation names the source. Operations neither client calls
 *   today (e.g. bulk "list conversations", unread counts, a graphical QR renderer, file resume)
 *   are deliberately absent; see the "Not in this interface" note at the bottom of the file.
 * - **Not a place for secrets.** No operation returns key material, seeds, or ciphertext. The one
 *   secret that crosses this boundary inbound is a passphrase ({@link KeyProtection},
 *   {@link MeridianClientAdapter.unlockAccount}); implementations MUST NOT retain, log, or echo it,
 *   and the fake/test doubles must not either (anonymity model: no secret/identifier leakage to
 *   logs, analytics, or the DOM).
 *
 * Timestamps are Unix seconds (`number`), matching core's `now_unix`. Every method is `async`
 * because both real backends cross an async boundary (wasm-bindgen promise / Tauri `invoke`).
 */

// ---------------------------------------------------------------------------------------------
// Shared value types (all view-shaped; none mirrors a wire/proto type)
// ---------------------------------------------------------------------------------------------

/**
 * Opaque, adapter-issued handle naming one peer principal (key-only identity, `same_principal`
 * semantics — core-api-contracts.md "Identity"). For a contact this is its canonical `mrd1:` ID
 * string as returned by core's `to_id_string`; for a message-request sender who was never dialed
 * (no advisory hint) it is whatever string the adapter can use to address that principal.
 * The UI MUST treat it as an opaque key: compare for equality, pass it back to the adapter, and
 * never parse, slice, or derive a display name from it (petnames come only from explicit local
 * user input — system-design.md §3.1).
 *
 * `TODO: confirm` — whether core's canonical `mrd1:` string is well-defined for a hint-less
 * message-request sender (`MessageRequest` carries only `sender_ik`/`safety_number`/`intro`; see
 * the TUI's `AcceptRequestRequest` doc), or whether the adapter must mint its own handle there.
 */
export type PeerId = string;

/**
 * Mirror of `meridian_core::trust::TrustState` (core-api-contracts.md `trust_state`), kebab-cased.
 * The UI renders it faithfully; it never derives or "softens" it (verification-ux.md).
 */
export type TrustState = 'new' | 'pinned' | 'verified' | 'blocked' | 'pinned-key-changed';

/**
 * Result of core's send gate (`TrustStore::can_send`). `reason` is core's canonical,
 * un-softenable text and MUST be rendered verbatim. `blocked` is a hard stop (only
 * {@link MeridianClientAdapter.markVerified} clears a key-change block); `warn` is blocking until
 * {@link MeridianClientAdapter.acknowledgeKeyChange}. UI MUST honor block-on-verified (D06,
 * core-api-contracts.md "Sessions & messaging").
 */
export type SendGate =
  | { readonly kind: 'ok' }
  | { readonly kind: 'warn'; readonly reason: string }
  | { readonly kind: 'blocked'; readonly reason: string };

/** Per-contact relay-policy override (TUI `PolicyOverride`; CLI `config` relay policy values). */
export type RelayPolicy = 'direct' | 'prefer-relay' | 'relay-only';

/**
 * How the account's private key is protected at rest (TUI `StoreChoice`: `Os` | `File{passphrase}`).
 * `platform` = the backend's own non-extractable keystore (OS keystore on desktop, WebCrypto/
 * IndexedDB on the browser — 12.5); `passphrase` = a passphrase-wrapped keyfile.
 * `TODO: confirm` — whether the browser (12.5) offers `passphrase` at all, or only `platform`.
 */
export type KeyProtection =
  | { readonly kind: 'platform' }
  | { readonly kind: 'passphrase'; readonly passphrase: string };

/** The local account as the UI needs to show it (TUI `GeneratedAccount`, minus raw key bytes). */
export interface AccountSummary {
  /** The account's own `mrd1:…` ID string, from core's `to_id_string`. Public by design. */
  readonly id: string;
  /** Short display label for the account (TUI `GeneratedAccount.label`). */
  readonly label: string;
}

/** Outcome of probing for an existing account at startup (TUI `LoadSessionOutcome`). */
export type AccountLoadResult =
  | { readonly kind: 'no-account' }
  /** An account exists but its key is passphrase-protected and not yet unlocked. */
  | { readonly kind: 'locked' }
  | { readonly kind: 'ready'; readonly account: AccountSummary };

/** Core's `parse_id` result: validated + canonicalised by core, never by the UI. */
export interface ParsedId {
  readonly id: string;
  /** The advisory `@domain` routing hint (never authoritative, never a petname). */
  readonly hint: string;
}

/** `meridian_core::crypto::{safety_number, display_groups}` — computed by core, order-independent. */
export interface SafetyNumber {
  /** The raw 60-digit number — also the exact payload the verification QR encodes. */
  readonly digits: string;
  /** The same number grouped for human comparison (`display_groups`). */
  readonly display: string;
}

/** A grayscale image for core's `decode_luma` (row-major, one byte per pixel). */
export interface LumaImage {
  readonly width: number;
  readonly height: number;
  readonly luma: Uint8Array;
}

/** One key ever pinned for a contact (core `PinnedKey`, with the key itself reduced to display). */
export interface PinnedKeyInfo {
  /** Short, display-only fingerprint of the pinned key (adapter-supplied; never parsed by UI). */
  readonly fingerprint: string;
  readonly firstSeen: number;
  readonly lastSeen: number;
}

/**
 * One contact row (core `Contact` via `TrustStore::contacts()` — the CLI's `contact list --json`
 * fields `id/petname/hint/state/user_blocked`, plus the pin history the TUI contact-detail shows).
 * Deliberately carries no `unread`/`lastActivityAt`: those are TUI-local store fields, not core
 * state (see "Not in this interface").
 */
export interface ContactSummary {
  readonly peerId: PeerId;
  /** Full `mrd1:…` ID string for display of the id itself (CLI `contact list`). */
  readonly id: string;
  /** Local-only display name; set only by explicit user input, `null` when none. */
  readonly petname: string | null;
  readonly hint: string;
  /** Short key fingerprint, always shown alongside a petname (tui-client.md §6 rule 2). */
  readonly fingerprint: string;
  readonly trust: TrustState;
  /** Purely local, user-initiated block (independent of the key-change `blocked` state). */
  readonly userBlocked: boolean;
  readonly pinnedKeyHistory: readonly PinnedKeyInfo[];
  /** `null` = use the global relay policy. TUI-local store field. */
  readonly policyOverride: RelayPolicy | null;
  readonly addedAt: number;
}

/** TUI `MessageState` — the same enum for every stream type, file transfers included. */
export type MessageState =
  | 'composing'
  | 'pending'
  | 'sent'
  | 'delivered'
  | 'failed'
  | 'received';

/** One transcript entry (TUI `HistoryEntry`, minus the storage schema version). */
export interface ChatMessage {
  /** Locally-minted 128-bit message id, hex (the id receipts acknowledge). */
  readonly mid: string;
  readonly direction: 'in' | 'out';
  readonly ts: number;
  /** Stream-type name this entry belongs to, e.g. `mrd.chat/1`. Opaque to the UI. */
  readonly stream: string;
  readonly body: string;
  readonly state: MessageState;
}

/**
 * What sending actually produced (TUI `SentMessage`, mirroring the CLI's `RouteOutcome`).
 * `delivered === false && queued === true` = durably queued server-side (T07 mailbox), will arrive
 * on the peer's reconnect; `delivered === false && queued === false` = not delivered, nothing to
 * wait for.
 */
export interface SentMessage {
  readonly mid: string;
  readonly ts: number;
  readonly delivered: boolean;
  readonly queued: boolean;
}

/**
 * A pending first-contact message request (core `MessageRequest`; system-design.md §3.5): never
 * auto-delivered, never auto-accepted. `safetyNumber` is shown next to the intro so the user can
 * eyeball it *before* deciding.
 */
export interface MessageRequest {
  readonly senderId: PeerId;
  readonly safetyNumber: string;
  /** The decrypted intro text, or `null` when the first envelope was not text (a receipt). */
  readonly introText: string | null;
}

// --- file transfer (`mrd.file/1`) -------------------------------------------------------------

/**
 * Where a file to send comes from. `blob` = a browser `File`/`Blob` (drag-drop, picker);
 * `path` = a native filesystem path (desktop / CLI `send <path>`).
 */
export type FileSource =
  | { readonly kind: 'blob'; readonly blob: Blob; readonly name: string }
  | { readonly kind: 'path'; readonly path: string };

export type TransferDirection = 'send' | 'receive';

/** TUI `TransferStatus` (UI-only `ResumeRequested` omitted: resume is not dispatched anywhere). */
export type TransferStatus = 'in-progress' | 'completed' | 'stalled' | 'failed';

/**
 * One transfer's state (TUI `TransferEntry` + core `SendProgress`). Reflects only what the
 * transport actually reported — never an assumed stronger integrity property than the protocol
 * currently provides (task 12.9 risk note).
 */
export interface TransferInfo {
  /** Opaque display id; never a full pubkey or path. */
  readonly transferId: string;
  readonly peerId: PeerId;
  readonly name: string;
  readonly direction: TransferDirection;
  readonly totalBytes: number;
  readonly bytesDone: number;
  readonly status: TransferStatus;
  /** Present only when `status === 'failed'`. */
  readonly failureReason?: string;
  /** Average throughput so far (core `SendProgress.bytes_per_sec`), when reported. */
  readonly bytesPerSecond?: number;
}

/**
 * An inbound `mrd.file/1` OPEN awaiting the user's decision (the `FileStream` ask-user hook).
 * Offers core auto-accepts (small image from an established contact) or rejects outright
 * (first-contact) never surface here — only the "ask the user" verdict does.
 */
export interface FileOffer {
  readonly transferId: string;
  readonly peerId: PeerId;
  readonly name: string;
  readonly size: number;
}

// --- push events ------------------------------------------------------------------------------

/** TUI `ConnectionState` (wording is rendered by the UI; kept structural here). */
export type ConnectionState =
  | { readonly kind: 'disconnected' }
  | { readonly kind: 'connecting' }
  | { readonly kind: 'connected' }
  | { readonly kind: 'reconnecting'; readonly attempt: number; readonly max: number };

/**
 * Push-style updates from the platform (TUI `InboundEvent` + `ConnectionStatus`; extended with
 * the file-transfer events the TUI's transfers pane models). Already verified + decrypted by core
 * before the adapter emits them — the UI never sees ciphertext.
 */
export type ClientEvent =
  | { readonly type: 'message-request'; readonly request: MessageRequest }
  | { readonly type: 'message'; readonly peerId: PeerId; readonly message: ChatMessage }
  /** A delivery receipt for one of our own sent messages; `mid` is the acknowledged message. */
  | { readonly type: 'receipt'; readonly peerId: PeerId; readonly mid: string }
  | { readonly type: 'connection'; readonly state: ConnectionState }
  /** A contact's trust state / send gate changed (key change, verify, block). Re-query it. */
  | { readonly type: 'trust-changed'; readonly peerId: PeerId }
  | { readonly type: 'file-offer'; readonly offer: FileOffer }
  | { readonly type: 'transfer'; readonly transfer: TransferInfo };

export type ClientEventListener = (event: ClientEvent) => void;
/** Call to stop receiving events. Idempotent. */
export type Unsubscribe = () => void;

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/**
 * Failure kinds the UI can branch on. Derived from the core errors the existing clients already
 * distinguish: `parse_id` failure (`invalid-id`), `TrustError::UnknownContact`
 * (`unknown-contact`), `TrustError::NotAcknowledgeable` (`not-acknowledgeable`), a refused send
 * gate (`send-blocked`), and locked/absent account states. Anything else is `internal`.
 */
export type AdapterErrorCode =
  | 'invalid-id'
  | 'unknown-contact'
  | 'not-acknowledgeable'
  | 'send-blocked'
  | 'no-account'
  | 'locked'
  | 'wrong-passphrase'
  | 'not-found'
  | 'internal';

/**
 * The only error type adapter methods reject with. `message` MUST NOT contain plaintext message
 * bodies, key material, passphrases, or peer identifiers beyond what the anonymity model allows.
 */
export class MeridianAdapterError extends Error {
  readonly code: AdapterErrorCode;

  constructor(code: AdapterErrorCode, message: string) {
    super(message);
    this.name = 'MeridianAdapterError';
    this.code = code;
  }
}

// ---------------------------------------------------------------------------------------------
// The interface
// ---------------------------------------------------------------------------------------------

export interface MeridianClientAdapter {
  // ---- Account (core-api-contracts.md "Identity"; TUI onboarding/unlock; CLI `id`/`register`) ----

  /**
   * Probe for an existing account at startup.
   * Derived from: TUI `Effect::LoadSession` / `LoadSessionOutcome::{NoAccount, Loaded}`.
   */
  loadAccount(): Promise<AccountLoadResult>;

  /**
   * Mint a fresh account (keypair generated and stored inside core, key never crosses this
   * boundary) and persist its non-secret descriptor.
   * Derived from: `generate_account` (core-api-contracts.md); TUI `Effect::GenerateAccount`
   * (`GenerateAccountRequest{store, hint}`); CLI `id new --hint --store`.
   * @param hint the advisory `@domain` hint for the new ID.
   */
  generateAccount(hint: string, protection: KeyProtection): Promise<AccountSummary>;

  /**
   * Unlock a passphrase-protected account; rejects `wrong-passphrase` on failure.
   * Derived from: TUI `Effect::Unlock` (`UnlockRequest{keyfile, passphrase}`; the adapter owns
   * where its keyfile lives).
   */
  unlockAccount(passphrase: string): Promise<AccountSummary>;

  /**
   * Authenticate to the rendezvous server (optionally redeeming an invite) so the account can
   * receive. Derived from: TUI `Effect::Register`; CLI `register --server --invite`.
   */
  registerAccount(server: string, invite?: string): Promise<void>;

  /**
   * Publish a fresh prekey bundle (with `otkCount` one-time keys) to the server.
   * Derived from: TUI `Effect::PublishBundle`; CLI `register`/bundle publication.
   * @returns how many one-time prekeys were published.
   */
  publishBundle(server: string, otkCount: number): Promise<{ readonly otkCount: number }>;

  /**
   * Validate and canonicalise an `mrd1:` ID string via core. The UI MUST call this rather than
   * validating the checksum/format itself; rejects `invalid-id`.
   * Derived from: `parse_id` (core-api-contracts.md); CLI `id parse`; TUI contacts screen's
   * synchronous `parse_id` before `Effect::AddContact`.
   */
  parseId(input: string): Promise<ParsedId>;

  // ---- Contacts (CLI `contact`, TUI contacts/contact-detail screens) -----------------------------

  /**
   * All contacts, in a stable order chosen by the adapter.
   * Derived from: `TrustStore::contacts()` — CLI `contact list`; TUI contacts screen.
   */
  listContacts(): Promise<readonly ContactSummary[]>;

  /**
   * TOFU-pin a peer's current key (`TrustStore::observe`) and, only if `petname` is given, assign
   * it (`set_petname`). A re-add of a known contact returns its real current record and MUST NOT
   * clobber an existing petname when `petname` is omitted. `petname` MUST come only from explicit
   * user input — never from `id`/hint/QR (system-design.md §3.1).
   * Derived from: CLI `contact add`; TUI `Effect::AddContact`.
   */
  addContact(id: string, petname?: string): Promise<ContactSummary>;

  /**
   * Set (string) or clear (`null`) a contact's local petname; rejects `unknown-contact`.
   * Derived from: `TrustStore::set_petname` — CLI `contact rename`; TUI `Effect::SetPetname`.
   */
  setPetname(peerId: PeerId, petname: string | null): Promise<void>;

  /**
   * Local, user-initiated block/unblock; rejects `unknown-contact`.
   * Derived from: `TrustStore::set_user_blocked` — CLI `contact block`; TUI `Effect::SetUserBlocked`.
   */
  setUserBlocked(peerId: PeerId, blocked: boolean): Promise<void>;

  /**
   * Set or clear (`null`) a contact's relay-policy override.
   * Derived from: TUI `Effect::SetPolicyOverride`. Stored in the TUI-local contacts store, not in
   * core's `TrustStore` — `TODO: confirm` where the web/desktop backends persist it (12.12).
   */
  setPolicyOverride(peerId: PeerId, policy: RelayPolicy | null): Promise<void>;

  /**
   * Remove a contact's local display entry — and ONLY that. Binding rule: delete MUST NOT reset,
   * clear, or downgrade trust state, `userBlocked`, or pinned-key history. A blocked contact stays
   * blocked, and a verified-then-key-changed contact stays gated, across delete + re-add; a
   * re-add observes the existing trust record (state untouched) exactly as `TrustStore::observe`
   * does. This mirrors the TUI, whose delete removes only the local `contacts.json` entry and
   * leaves core's `TrustStore` record untouched ("no new core-crate deletion primitive").
   * Otherwise delete-then-re-add would be a bypass of the block-on-verified invariant (D06).
   * Derived from: TUI `Effect::DeleteContact`.
   */
  deleteContact(peerId: PeerId): Promise<void>;

  // ---- Trust & verification (core-api-contracts.md; CLI `verify`; TUI verify screen) -------------

  /** Derived from: `trust_state` (core-api-contracts.md); `TrustStore::trust_state`. */
  getTrustState(peerId: PeerId): Promise<TrustState>;

  /**
   * The send gate the UI MUST consult before offering to send (never cached by the UI).
   * Derived from: `TrustStore::can_send` — CLI chat send path; TUI chat/verify screens.
   */
  getSendGate(peerId: PeerId): Promise<SendGate>;

  /**
   * The safety number for (own key, `peerId`'s key).
   * Derived from: `safety_number`/`display_groups` — CLI `verify`; TUI verify screen.
   */
  getSafetyNumber(peerId: PeerId): Promise<SafetyNumber>;

  /**
   * Mark verified — call ONLY after a confirmed out-of-band safety-number match (an exact match;
   * a partial/ambiguous scan MUST NOT reach here). The only path that clears a key-change
   * `blocked` state. Rejects `unknown-contact`.
   * Derived from: `mark_verified` (core-api-contracts.md); CLI `verify`; TUI `Effect::MarkVerified`.
   */
  markVerified(peerId: PeerId): Promise<void>;

  /**
   * Acknowledge a *pinned* contact's key change (re-pin). Rejects `not-acknowledgeable` for a
   * verified/blocked contact (only re-verification clears that).
   * Derived from: `TrustStore::acknowledge_key_change`; TUI `Effect::AcknowledgeKeyChange`.
   */
  acknowledgeKeyChange(peerId: PeerId): Promise<void>;

  /**
   * Decode a QR from a grayscale image (camera frame or uploaded image); resolves to the decoded
   * payload string (a safety number's digits, or an `mrd1:` ID), compared/validated by the caller
   * through core ({@link getSafetyNumber}/{@link parseId}), never by string-munging in the UI.
   * Derived from: `decode_luma` — CLI `verify --scan-file`; TUI `Effect::ImportContactQr`.
   */
  decodeQr(image: LumaImage): Promise<string>;

  /**
   * Render `payload` as a text QR (core's `render_terminal`, a monospace block-character string).
   * Derived from: `render_terminal` — CLI `verify`/`id show --qr`; TUI verify screen.
   * `TODO: confirm` — a pixel/SVG QR for the web is NOT something either client calls today; see
   * "Not in this interface".
   */
  renderQrText(payload: string): Promise<string>;

  // ---- Chat (core-api-contracts.md "Sessions & messaging"; CLI `chat`; TUI chat screen) ----------

  /**
   * Seal and route one `mrd.chat/1` text message. The UI MUST consult {@link getSendGate} and see
   * `ok` first (as the TUI does), AND the adapter MUST re-check the gate (`can_send`) in this same
   * call and reject with `send-blocked` for both `blocked` and `warn` gates — defence in depth
   * against a stale or buggy UI; the UI check is not the only line. (`TODO: confirm` whether
   * `meridian-core`'s own send path also enforces `can_send`; the design does not state the
   * enforcement point, so the adapter enforces it regardless.)
   * Derived from: `send_chat` (core-api-contracts.md); CLI `chat` `send_text`; TUI `Effect::SendMessage`.
   */
  sendMessage(peerId: PeerId, body: string): Promise<SentMessage>;

  /**
   * The persisted transcript with `peerId`, oldest first.
   * Derived from: TUI `Effect::LoadHistory` (`store::history::load_or_default`). This is a TUI
   * local-store read, not a `meridian-core` call — the browser/desktop adapters back it with
   * their own sealed store (12.12 / 12.3).
   */
  loadHistory(peerId: PeerId): Promise<readonly ChatMessage[]>;

  // ---- Message requests (system-design.md §3.5; CLI `answer_request`; TUI requests screen) -------

  /**
   * Pending first-contact requests.
   * Derived from: `ChatState::pending_requests()` — TUI `Screen::Requests`.
   */
  listMessageRequests(): Promise<readonly MessageRequest[]>;

  /**
   * Accept: `ChatState::accept_request`, *then* TOFU-pin the sender (`TrustStore::observe`) — in
   * that order (never pin before the user decides). Resolves to the new contact record.
   * Rejects `not-found` if no such pending request.
   * Derived from: CLI `answer_request` accept branch; TUI `Effect::AcceptRequest`.
   */
  acceptMessageRequest(senderId: PeerId): Promise<ContactSummary>;

  /**
   * Reject: discards the request and the session behind it, sending nothing back (leaves no
   * trace). Derived from: `ChatState::reject_request`; TUI `Effect::RejectRequest`.
   */
  rejectMessageRequest(senderId: PeerId): Promise<void>;

  // ---- File transfer (`mrd.file/1`; CLI `send`; TUI file renderer + transfers pane) --------------

  /**
   * Start sending one file to `peerId`. Resolves once the transfer is opened; progress and
   * completion arrive as `transfer` events. Same gate rule as {@link sendMessage}: the adapter
   * MUST re-check `can_send` in this call and reject with `send-blocked` for `blocked` and `warn`
   * gates.
   * Derived from: `meridian_streams::send_file` / `SendProgress` — CLI `send <id> <path>...`.
   */
  sendFile(peerId: PeerId, file: FileSource): Promise<TransferInfo>;

  /** Known transfers, both directions. Derived from: TUI transfers pane (`TransferEntry`). */
  listTransfers(): Promise<readonly TransferInfo[]>;

  /**
   * Answer a `file-offer` event: accept or reject an inbound `mrd.file/1` OPEN.
   * Derived from: `FileStream::with_ask_user` hook — CLI `send` responder prompt.
   */
  answerFileOffer(transferId: string, accept: boolean): Promise<void>;

  // ---- Events -----------------------------------------------------------------------------------

  /**
   * Subscribe to push-style updates. Returns an idempotent unsubscribe function. Listeners MUST
   * NOT throw into the adapter; an adapter isolates listener failures.
   * Derived from: TUI `AppEvent::{Inbound, ConnectionStatus}` (`run_inbound_loop`).
   */
  subscribe(listener: ClientEventListener): Unsubscribe;
}

// ---------------------------------------------------------------------------------------------
// Not in this interface (reported back rather than invented — see task 12.2 "Risks / notes")
// ---------------------------------------------------------------------------------------------
//
// - Bulk "list conversations" / unread counts / last-activity: neither client calls such a core
//   query. The TUI keeps `unread`/`last_activity_at` in its own local `contacts.json` cache, not
//   in `meridian-core`. A conversation list is `listContacts()` + `loadHistory()`; unread tracking
//   would be a new (core or per-client-store) design decision.
// - A graphical (pixel/SVG/matrix) QR render for the web: only the text `render_terminal` exists.
// - File resume / cancel, auto-accept threshold setting, and delivering a received file's bytes
//   to the browser: the TUI's resume affordance dispatches nothing yet; the CLI writes to `--out`.
// - Global settings (relay policy, server URL, retention): TUI settings screen / CLI `config`
//   only; not needed by screens 12.7-12.9, additive later.
