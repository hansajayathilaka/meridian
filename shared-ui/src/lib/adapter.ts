/**
 * `MeridianClientAdapter` — the platform-agnostic TS boundary ADR 0012 calls for ("the WASM
 * boundary is framework-agnostic (plain TS API), so a later swap to React touches only the view
 * layer"). Screens (12.7-12.9) are written once against this interface plus
 * {@link FakeMeridianClientAdapter}; the browser (12.13, wasm-bindgen over `meridian-wasm`, 12.10)
 * and desktop (12.6, Tauri commands over the native `meridian-core`) shells each implement it once,
 * concretely, and are otherwise interchangeable from a screen's point of view.
 *
 * ## Where this comes from
 * Mirrors the operation surface named in
 * `docs/api/core-api-contracts.md` (account generate/open, chat send/receive, contacts/trust,
 * stream/file ops, verification) — see that doc's "Identity", "Sessions & messaging", and "Stream
 * registry" sections. Enumeration operations (`listContacts`, `listConversations`) are NOT in that
 * doc (its operation list is explicitly "illustrative, not exhaustive") — see this file's
 * "Enumeration operations" section below for how each was derived (or, for `listConversations`,
 * deliberately NOT derived) from `apps/cli`/`apps/tui`'s existing call sites into `meridian-core`.
 *
 * ## What this deliberately leaves out (task 12.2 scope + `apps/web/CLAUDE.md`)
 * - **No raw crypto/signing primitives** (`core-api-contracts.md`'s `sign`/`verify`/`same_principal`).
 *   No screen this interface serves needs to sign or verify arbitrary bytes directly — that's an
 *   internal detail of `sendChat`/`openConversation`/`markVerified` inside the concrete adapters.
 *   Exposing it here would be exactly the "reimplement wire/protocol logic in the UI layer" the web
 *   CLAUDE.md forbids, just one level removed (a screen could technically DIY an envelope out of
 *   `sign`+opaque bytes instead of calling `sendChat`).
 * - **No wire types.** Every shape below is either a primitive, an opaque hex/string id, an opaque
 *   `Uint8Array` blob, or a small display-oriented DTO (`Contact`, `ChatMessage`, ...) distinct from
 *   (and never a re-encoding of) `meridian-proto`'s envelope/bundle wire structs. A concrete adapter
 *   maps from the real wire/core types to these; this file has no knowledge of CBOR, envelope
 *   framing, or ratchet state.
 * - **No `Transport`/`SecretStore` surface.** Those are the *platform* traits a concrete adapter's
 *   own implementation composes underneath this interface (WebRTC/keystore specifics) — never
 *   something a screen touches.
 *
 * ## Enumeration operations — the flagged open question (task 12.2 Risks/notes)
 * `core-api-contracts.md` names no bulk "list contacts" or "list conversations" query. Resolved by
 * grepping `apps/cli`/`apps/tui`'s existing command handlers for what they already call into
 * `meridian-core` for the equivalent behavior:
 *
 * - **`listContacts` — real core precedent found and mirrored.**
 *   `meridian_core::trust::TrustStore::contacts(&self) -> impl Iterator<Item = &Contact>`
 *   (`apps/core/src/trust.rs`) is already the live bulk-enumeration call both `apps/cli`
 *   (`apps/cli/src/contact.rs::cmd_list`: `trust.contacts().collect()`) and `apps/tui` (via its own
 *   `contacts.json` cache seeded from the same `TrustStore`, `apps/tui/src/store/contacts.rs`) use
 *   for "list contacts". `listContacts` below is backed by that existing core method — not a new
 *   core-level query.
 * - **`listConversations` — TODO: confirm, NO core precedent found; do not silently invent one.**
 *   `meridian_core::chat::ChatState` has no public enumeration of its `sessions`/`pending_requests`
 *   maps (`apps/core/src/chat.rs`: `sessions: BTreeMap<...>` is a private field; the only public
 *   accessors are peer-keyed lookups — `has_session(&peer_ik)`, `pending_request(&sender_ik)`,
 *   `pending_requests()` for *requests only*, not established conversations). Neither `apps/cli`
 *   (which only ever runs one `chat <id>` session per process — there is nothing to enumerate) nor
 *   `apps/tui` calls a core-level "list conversations" query either: `apps/tui`'s own conversation
 *   list (`apps/tui/src/screens/contacts.rs`) is built entirely from its own local, TUI-private
 *   `contacts.json` cache (`apps/tui/src/store/contacts.rs`'s `ContactRecord.last_activity_at` /
 *   `.unread`, deliberately duplicating what `TrustStore` tracks per that module's own doc comment)
 *   — never from a `meridian-core` bulk query. Per this task's Risks/notes: since no existing client
 *   calls a genuine core-level "list conversations" query today, this method is declared here (every
 *   screen needs *some* way to enumerate threads) but is **not** backed by a claimed core operation.
 *   Concrete adapters (12.6, 12.13) MUST resolve it the same way `apps/tui` already does — materialize
 *   it from local, client-side conversation metadata (contacts + per-peer history/unread, mirroring
 *   `apps/tui/src/store/contacts.rs` + `apps/tui/src/store/history.rs`) — and must NOT add a new
 *   bulk-session query to `meridian-core` to back it without a separate, dedicated review (that would
 *   be a `meridian-core` API change, out of this task's scope; see `apps/CLAUDE.md`'s "additive
 *   stream types touch the registry only" sibling rule for the general shape of that constraint).
 */

/** Canonical `mrd1:<base32 key>@hint` account/contact identity string (`meridian_core::identity`). */
export type MeridianId = string;

/** Lowercase-hex-encoded 32-byte Ed25519 public key — the trust/session primary key. */
export type PubkeyHex = string;

/**
 * Order-independent safety-number display data
 * (`meridian_core::crypto::{safety_number, display_groups}`). `raw` is the 60 ASCII digits;
 * `grouped` is the same digits pre-formatted for display (5-digit groups) — a concrete adapter
 * calls `display_groups` itself and hands back the result; this file does not reimplement the
 * grouping.
 */
export interface SafetyNumber {
  raw: string;
  grouped: string;
}

/** Mirrors `meridian_core::trust::TrustState` (`apps/core/src/trust.rs`). */
export type TrustState = "new" | "pinned" | "verified" | "blocked" | "pinned_key_changed";

/**
 * Mirrors `meridian_core::trust::SendGate` (`apps/core/src/trust.rs`) — the un-softenable send
 * gate `apps/cli/src/chat.rs::send_gated` consults before every outbound text send. A screen reads
 * this to decide what to render *before* attempting `sendChat`; `sendChat` itself still enforces it
 * server-side-of-the-adapter (never bypassable by skipping the read) — see `sendChat`'s doc comment.
 */
export type SendGateState =
  | { kind: "ok" }
  | { kind: "warn"; reason: string }
  | { kind: "blocked"; reason: string };

/** Mirrors `meridian_core::trust::Contact` (`apps/core/src/trust.rs`), display-oriented subset. */
export interface Contact {
  id: MeridianId;
  pubkey: PubkeyHex;
  /** Advisory `@domain` routing hint — never authoritative for identity (system-design.md §3.1). */
  hint: string;
  /** LOCAL ONLY. Never populated from any wire field — see `apps/cli/src/contact.rs`'s module doc. */
  petname: string | null;
  trust: TrustState;
  /** Purely local, user-initiated block — independent of `trust === "blocked"` (key-change block). */
  userBlocked: boolean;
}

/**
 * One enumerable conversation thread for the conversation-list screen (12.7). See this file's
 * "Enumeration operations" section: `TODO: confirm` how a concrete adapter backs this — no
 * `meridian-core` bulk session query exists today, so this is expected to be materialized
 * client-side from `contact` + local history metadata, not a new core call.
 */
export interface ConversationSummary {
  contact: Contact;
  /** Unix seconds of the most recent activity (sent or received) with this contact, if any. */
  lastActivityAt: number | null;
  unreadCount: number;
  lastMessagePreview: string | null;
}

export type MessageDirection = "in" | "out";

/** Mirrors `apps/tui/src/store/history.rs::MessageState` (the closest existing precedent for a
 * per-message delivery-state enumeration; `meridian-core` itself does not name this set, it is a
 * client-local UI concept every existing client already tracks). */
export type MessageDeliveryState =
  | "composing"
  | "pending"
  | "sent"
  | "delivered"
  | "failed"
  | "received";

/** One decrypted, verified chat message (`meridian_core::envelope::ChatContent::Text`). */
export interface ChatMessage {
  /** Locally-generated 128-bit message id, lowercase hex (`ChatContent::Text.id`). */
  id: string;
  direction: MessageDirection;
  timestamp: number;
  /** The stream-type id this message arrived/was sent under, e.g. `"mrd.chat/1"`. */
  streamType: string;
  body: string;
  state: MessageDeliveryState;
}

/** A first-contact message request gated by `ChatState::open_inbound` (system-design.md §3.5). */
export interface MessageRequest {
  from: MeridianId;
  safetyNumber: SafetyNumber;
  /** The held opening message, shown alongside the accept/reject prompt. */
  introPreview: string | null;
}

/** Outcome of a chat send (`meridian_core::signaling::RouteOutcome`, display-oriented). */
export interface SendResult {
  id: string;
  delivered: boolean;
  /** Queued in the recipient's offline mailbox (T07) — see `sent_line`'s three-way mapping in
   * `apps/cli/src/chat.rs` for the precedent this mirrors. */
  queued: boolean;
}

/** Opaque handle for an open `meridian-core` stream (`meridian_core::streams::StreamId`). */
export type StreamHandle = string;

/** Result of `openStream` (mirrors `core-api-contracts.md`'s `open_stream`). */
export interface StreamOpenResult {
  streamId: StreamHandle;
}

/**
 * One `mrd.file/1` (T09) transfer's summary, for a transfers pane
 * (mirrors `apps/tui/src/streams/file.rs::TransferState`, display-oriented subset).
 *
 * **`state: "complete"` reports transport-level completion only — never a claim of verified
 * integrity.** `mrd.file/1`'s per-chunk merkle proof delivery is not fully wired into the real send
 * path yet (Phase 11 fix-task 11.8's residual, inherited as-is by task 12.9 — see that task's own
 * Scope→Out note). A screen rendering this state must say no more than what it is: "transfer
 * complete" / "failed", never "verified" or "corruption-free" — that stronger claim isn't something
 * any adapter today actually reports.
 */
export interface FileTransferSummary {
  streamId: StreamHandle;
  peer: MeridianId;
  direction: MessageDirection;
  fileName: string;
  totalBytes: number;
  transferredBytes: number;
  state: "offered" | "in_progress" | "paused" | "complete" | "failed" | "rejected";
}

/**
 * Structured adapter error. `code` is a short, stable, machine-matchable token (screens branch on
 * it); `message` is human-readable and safe to display (never includes plaintext content or raw
 * identifiers beyond what the anonymity model already allows to surface locally — see the
 * anonymity-model skill). Concrete adapters map their own error taxonomy
 * (`meridian_core::trust::TrustError`, `meridian_core::chat::ChatError`,
 * `meridian_core::signaling::SignalError`, ...) onto this one common shape so screens do not need
 * per-platform error handling.
 */
export class MeridianAdapterError extends Error {
  constructor(
    public readonly code:
      | "unknown_contact"
      | "unknown_conversation"
      | "conflicting_contact"
      | "send_blocked"
      | "send_warn_unacknowledged"
      | "no_pending_request"
      | "no_session"
      | "not_connected"
      | "invalid_id"
      | "unavailable"
      | "unknown",
    message: string,
  ) {
    super(message);
    this.name = "MeridianAdapterError";
  }
}

/**
 * The platform-agnostic client boundary. Every method is `async` (or returns an unsubscribe
 * function for event streams) so a concrete adapter can freely cross a WASM/worker/IPC boundary
 * underneath — screens never assume same-tick synchronous completion.
 */
export interface MeridianClientAdapter {
  // ---------------------------------------------------------------------
  // Account (core-api-contracts.md "Identity")
  // ---------------------------------------------------------------------

  /**
   * Generates a fresh account (`generate_account` + a caller-supplied routing hint) and makes it
   * the adapter's current account. Mirrors `apps/cli/src/account.rs`'s "new account" flow.
   */
  generateAccount(hint: string): Promise<MeridianId>;

  /**
   * Opens an existing account through whatever platform-specific secret-store descriptor the
   * concrete adapter's caller already resolved (keyfile path, OS keystore label, imported portable
   * key, ...) — deliberately opaque here (`unknown`, not a shared type): the shape of "how you
   * locate + unlock a key" is platform-specific (`apps/cli`'s `--store os|file`, browser's
   * IndexedDB-wrapped key, desktop's OS keychain via Tauri) and is exactly the kind of thing this
   * interface must NOT standardize on the wrong platform's shape. Concrete adapters document their
   * own accepted `descriptor` shape.
   */
  openAccount(descriptor: unknown): Promise<MeridianId>;

  /** The currently open account, or `null` if none is open yet (pre-onboarding / locked). */
  currentAccount(): MeridianId | null;

  /** Locks/closes the current account, discarding any in-memory key material. */
  closeAccount(): Promise<void>;

  // ---------------------------------------------------------------------
  // Sessions & messaging (core-api-contracts.md "Sessions & messaging")
  // ---------------------------------------------------------------------

  /**
   * Establishes (or resumes) a session with `peer` — `open_session`: fetch+verify bundle, X3DH,
   * dial. Idempotent: calling this for an already-open conversation is a no-op.
   */
  openConversation(peer: MeridianId): Promise<void>;

  /**
   * Sends a chat text message — `send_chat`. Enforces the same un-softenable send gate
   * `apps/cli/src/chat.rs::send_gated` does: rejects with `MeridianAdapterError` (`"send_blocked"`
   * for `SendGate::Blocked`, `"send_warn_unacknowledged"` for an un-acknowledged `SendGate::Warn`)
   * rather than silently sending or silently dropping — a screen must call
   * {@link acknowledgeKeyChange} first to clear a `"warn"` gate, exactly like the CLI's typed
   * accept prompt. Never bypassable by any other adapter method.
   */
  sendChat(peer: MeridianId, body: string): Promise<SendResult>;

  /**
   * Subscribes to verified+decrypted inbound chat messages (`on_envelope`, filtered/mapped to
   * `ChatContent::Text`). Returns an unsubscribe function.
   */
  onMessage(cb: (peer: MeridianId, msg: ChatMessage) => void): () => void;

  /** Subscribes to first-contact message requests (system-design.md §3.5). */
  onMessageRequest(cb: (req: MessageRequest) => void): () => void;

  /**
   * Accepts a pending message request: delivers the held intro and TOFU-pins the sender
   * (mirrors `apps/cli/src/chat.rs::answer_request`). `petname` is optional, user-typed only —
   * never derived from `from`/any wire field (the petname-never-from-wire invariant).
   */
  acceptMessageRequest(from: MeridianId, petname?: string): Promise<void>;

  /** Rejects a pending message request — silent, no trace left in trust state. */
  rejectMessageRequest(from: MeridianId): Promise<void>;

  /** `trust_state` — current trust state for a known contact. */
  trustState(peer: MeridianId): Promise<TrustState>;

  /** `can_send` — the send-gate state a screen should render *before* attempting {@link sendChat}. */
  sendGateState(peer: MeridianId): Promise<SendGateState>;

  /**
   * Acknowledges a live key-change warning (`TrustStore::acknowledge_key_change`), re-pinning the
   * contact's new key without a safety-number compare — clears a `SendGateState.kind === "warn"`
   * gate so a subsequently held/retried {@link sendChat} can proceed.
   */
  acknowledgeKeyChange(peer: MeridianId): Promise<void>;

  // ---------------------------------------------------------------------
  // Contacts / trust — enumeration backed by `TrustStore::contacts()` (see this file's top doc
  // comment, "Enumeration operations")
  // ---------------------------------------------------------------------

  /** Lists all known contacts — backed by `meridian_core::trust::TrustStore::contacts()`. */
  listContacts(): Promise<Contact[]>;

  /**
   * TOFU-pins `id` as a contact (`TrustStore::observe`) and, only from the caller-supplied
   * `petname`, assigns a local display name — mirrors `apps/cli/src/contact.rs::cmd_add`.
   */
  addContact(id: MeridianId, petname?: string): Promise<Contact>;

  /** `set_petname` — `null`/empty clears it. */
  renamePetname(id: MeridianId, petname: string | null): Promise<void>;

  /** `set_user_blocked(true)` — a purely local block, independent of key-change trust blocking. */
  blockContact(id: MeridianId): Promise<void>;

  /** `set_user_blocked(false)`. */
  unblockContact(id: MeridianId): Promise<void>;

  /**
   * Lists conversation threads for the conversation-list screen. `TODO: confirm` (see this file's
   * top doc comment): no `meridian-core` bulk session query backs this today — concrete adapters
   * must materialize it client-side (contacts + local history metadata), matching how
   * `apps/tui`'s own conversation list already works, and must not add a new core query to back it
   * without separate review.
   */
  listConversations(): Promise<ConversationSummary[]>;

  /**
   * Loads a page of a conversation's message history. `before` (a `ChatMessage.id`) paginates
   * backward from that message, exclusive; omitted loads the most recent page.
   */
  loadHistory(peer: MeridianId, opts?: { limit?: number; before?: string }): Promise<ChatMessage[]>;

  /**
   * Marks a conversation's unread messages as read, resetting {@link ConversationSummary.unreadCount}
   * to 0 for `peer` — the counterpart every unread badge (e.g. `ContactRow`'s `unreadCount` prop)
   * needs a way to clear. Rejects with `"unknown_contact"` if `peer` is not a known contact.
   */
  markConversationRead(peer: MeridianId): Promise<void>;

  // ---------------------------------------------------------------------
  // Verification (core-api-contracts.md "Identity": safety_number; "Sessions & messaging":
  // mark_verified)
  // ---------------------------------------------------------------------

  /** `safety_number` + `display_groups` — order-independent fingerprint for out-of-band compare. */
  safetyNumber(peer: MeridianId): Promise<SafetyNumber>;

  /**
   * Marks `peer` verified after an out-of-band safety-number compare succeeded
   * (`TrustStore::mark_verified`). The comparison itself never happens over this interface — see
   * `docs/security/verification-ux.md`.
   */
  markVerified(peer: MeridianId): Promise<void>;

  // ---------------------------------------------------------------------
  // Streams / file ops (core-api-contracts.md "Stream registry")
  // ---------------------------------------------------------------------

  /**
   * Opens a stream of registered type `streamType` (e.g. `"mrd.file/1"`) with opaque,
   * stream-type-defined `params` — `open_stream`. Generic on purpose: per `docs/api/
   * stream-types-v1.md`, additive stream types never touch this interface or `meridian-core`
   * itself, only the registry — a new stream type needs no adapter change.
   */
  openStream(peer: MeridianId, streamType: string, params: unknown): Promise<StreamOpenResult>;

  /** Subscribes to raw inbound frames for open streams. Returns an unsubscribe function. */
  onStreamFrame(cb: (streamId: StreamHandle, frame: Uint8Array) => void): () => void;

  /**
   * Convenience wrapper over `openStream(peer, "mrd.file/1", ...)` for the common case (12.7-12.9's
   * file-transfer screen) — mirrors `apps/tui/src/streams/file.rs`'s `build_open_params` +
   * `open_stream` pairing so screens do not need to know `mrd.file/1`'s param shape directly.
   */
  sendFile(peer: MeridianId, file: Blob, fileName: string): Promise<StreamOpenResult>;

  /** Lists in-progress/recent file transfers, for a transfers pane. */
  listTransfers(): Promise<FileTransferSummary[]>;

  /**
   * Accepts a pending incoming `mrd.file/1` transfer — the receive-side counterpart to
   * {@link sendFile}, added by task 12.9 for the file-transfer screen's receive prompt.
   *
   * `FileTransferSummary.state === "offered"` is the *only* state this ever legitimately applies
   * to: per `docs/api/stream-types-v1.md`'s "`on_open` policy" section (`apps/streams/src/file.rs`'s
   * `decide_file_offer`, task 10.6), a first-contact offer is rejected outright and an
   * image-under-threshold offer is auto-accepted, both before either ever reaches a UI — only the
   * remaining `AskUser` verdict surfaces here as `"offered"`, for this screen's own accept/reject
   * prompt to resolve. Rejects with `"unknown"` if `streamId` does not name a transfer currently
   * `"offered"` (already decided, or never existed).
   *
   * **Known gap, inherited as-is (task 12.9 Scope→Out; not this interface's to fix):** today's real
   * `mrd.file/1` policy hook (`FileStream::with_ask_user`, `apps/streams/src/file.rs`) is a
   * *synchronous* closure consulted inside `on_open` itself — the CLI (`apps/cli/src/send.rs`)
   * satisfies it with a real blocking terminal prompt, which a GUI event loop cannot do. Neither
   * concrete adapter today (`apps/desktop/ui/src/adapter.ts`, task 12.6) has a live round trip that
   * can produce a genuine `"offered"` transfer or honor a call to this method — see that adapter's
   * own doc comment on this method for the full gap report. This screen and
   * {@link FakeMeridianClientAdapter} are written correctly against the *intended* shape regardless,
   * so the real round trip can be wired later (a core/event-plumbing change, not a UI change) without
   * touching this screen again.
   */
  acceptTransfer(streamId: StreamHandle): Promise<void>;

  /** Rejects a pending incoming transfer — the counterpart to {@link acceptTransfer}, with the same
   * `"offered"`-only precondition and the same known gap. */
  rejectTransfer(streamId: StreamHandle): Promise<void>;
}
