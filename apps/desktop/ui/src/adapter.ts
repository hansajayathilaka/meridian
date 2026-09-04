/**
 * `TauriMeridianClientAdapter` — the concrete {@link MeridianClientAdapter} (task 12.2,
 * `shared-ui/src/lib/adapter.ts`) implementation for the Tauri desktop shell (ADR 0010). Every
 * method here is a thin marshaling wrapper: it `invoke`s one of task 12.3's
 * `apps/desktop/src/tauri_commands.rs` commands, or subscribes to one of its `domain:event`
 * events, and reshapes the result into this interface's DTOs. **No protocol/wire logic, no crypto,
 * no business/policy rules live here** — see `apps/web/CLAUDE.md`'s "the web layer only calls it"
 * rule, which this task's own Risks/notes section says applies equally to the desktop side.
 *
 * ## Reading this file
 * Every deviation from a pure 1:1 `invoke`/`listen` passthrough is called out in a comment tagged
 * **GAP** — a place where task 12.3's current command/event surface does not quite give this
 * adapter what {@link MeridianClientAdapter} needs, so a client-side workaround (or an honest
 * failure) was used instead of inventing a new Tauri command (out of this task's scope; see the
 * task file's Scope→Out list). These are summarized again in this task's own delivery report for
 * 12.3 to pick up.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import type {
  ChatMessage,
  Contact,
  ConversationSummary,
  FileTransferSummary,
  MeridianClientAdapter,
  MeridianId,
  MessageDeliveryState,
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
// Wire-shaped DTOs this file receives from `invoke`/`listen` — mirror
// `apps/desktop/src/commands.rs`'s `#[derive(Serialize)]` structs/`ChatEvent` enum field-for-field
// (plain data only, never reinterpreted/re-encoded — this file only renames/regroups fields into
// {@link MeridianClientAdapter}'s own DTOs).
// ---------------------------------------------------------------------------

interface AccountViewDto {
  id: string;
  pubkey_hex: string;
  hint: string;
}

interface ContactViewDto {
  id: string;
  pubkey_hex: string;
  petname: string | null;
  hint: string;
  state: string;
  user_blocked: boolean;
}

interface SessionViewDto {
  peer_pubkey_hex: string;
  transport: string;
  path: string;
  streams: string[];
}

interface SentMessageDto {
  id_hex: string;
}

type ChatEventDto =
  | { kind: "Message"; peer_pubkey_hex: string; id_hex: string; body: string }
  | { kind: "Receipt"; peer_pubkey_hex: string; ack_hex: string }
  | { kind: "MessageRequest"; peer_pubkey_hex: string; safety_number: string }
  | { kind: "StreamOpened"; peer_pubkey_hex: string; sid: number; stream_type: string }
  | { kind: "StreamClosed"; peer_pubkey_hex: string; sid: number }
  | { kind: "Closed"; peer_pubkey_hex: string };

interface FileSentResultDto {
  name: string;
  root_hex: string;
}

interface IncomingFileDto {
  peer_pubkey_hex: string;
  name: string;
  size: number;
}

interface FileProgressDto {
  peer_pubkey_hex: string;
  name: string;
  bytes_sent: number;
  total_bytes: number;
  bytes_per_sec: number;
}

interface FileReceivedDto {
  peer_pubkey_hex: string;
  name: string;
  root_hex: string;
  path: string;
}

interface FileFailedDto {
  peer_pubkey_hex: string;
  name: string;
  reason: string;
}

// ---------------------------------------------------------------------------
// Trust-state string mapping — mirrors `apps/desktop/src/commands.rs::trust_state_str` exactly
// (the literal strings a `ContactView.state` can hold). Kept as a table, not policy: this is a
// display-string <-> enum-tag translation, not a re-derivation of any trust decision.
// ---------------------------------------------------------------------------

const TRUST_STATE_FROM_STR: Record<string, TrustState> = {
  new: "new",
  pinned: "pinned",
  verified: "verified",
  "blocked (key change)": "blocked",
  "warn (key change)": "pinned_key_changed",
};

function trustStateFromStr(state: string): TrustState {
  const mapped = TRUST_STATE_FROM_STR[state];
  if (!mapped) {
    // TODO: confirm — `commands.rs::trust_state_str` is the only source of this string and this
    // table is kept in lockstep with it by hand; an unrecognized value means the two have drifted.
    throw new MeridianAdapterError("unknown", `unrecognized contact state from backend: "${state}"`);
  }
  return mapped;
}

function contactFromDto(dto: ContactViewDto): Contact {
  return {
    id: dto.id,
    pubkey: dto.pubkey_hex,
    hint: dto.hint,
    petname: dto.petname,
    trust: trustStateFromStr(dto.state),
    userBlocked: dto.user_blocked,
  };
}

// ---------------------------------------------------------------------------
// Error mapping — GAP: `apps/desktop/src/commands.rs` commands return `Result<T, String>`: a
// plain, human-readable message, not a structured/coded error. Tauri rejects the `invoke()`
// promise with that raw string. There is no machine-stable error *code* crossing the IPC boundary
// today, so this adapter has to pattern-match known message substrings (mirroring the exact
// wording in `apps/core/src/{trust,chat,session}.rs`'s `thiserror` messages and
// `commands.rs::chat_send`'s own hand-written wrapper text) to recover a
// {@link MeridianAdapterError} code. This is inherently fragile: any wording change on the Rust
// side silently breaks this mapping without a compile-time signal. Flagged back to 12.3 as a
// finding — a structured error (e.g. `{ code, message }` instead of `String`) would remove this
// class of bug entirely.
// ---------------------------------------------------------------------------

function mapInvokeError(err: unknown): MeridianAdapterError {
  if (err instanceof MeridianAdapterError) return err;
  const message = typeof err === "string" ? err : err instanceof Error ? err.message : String(err);

  if (message.startsWith("blocked:")) {
    return new MeridianAdapterError("send_blocked", message);
  }
  if (message.includes("call contact_acknowledge_key_change first")) {
    return new MeridianAdapterError("send_warn_unacknowledged", message);
  }
  if (message.includes("no contact recorded for this key")) {
    return new MeridianAdapterError("unknown_contact", message);
  }
  if (message.includes("no active P2P session with this peer")) {
    return new MeridianAdapterError("no_session", message);
  }
  if (message.includes("no pending message request")) {
    return new MeridianAdapterError("no_pending_request", message);
  }
  if (message.includes("the claimed new key already belongs to a different known contact")) {
    return new MeridianAdapterError("conflicting_contact", message);
  }
  if (message.includes("no account loaded")) {
    return new MeridianAdapterError("unavailable", message);
  }
  if (
    message.includes("mrd1:") ||
    message.includes("base32") ||
    message.includes("checksum mismatch") ||
    message.includes("malformed identity") ||
    message.includes("key part") ||
    message.includes("invalid hint") ||
    message.includes("not a valid ed25519") ||
    message.includes("unknown multicodec")
  ) {
    return new MeridianAdapterError("invalid_id", message);
  }
  return new MeridianAdapterError("unknown", message);
}

async function callInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (err) {
    throw mapInvokeError(err);
  }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface TauriAdapterOptions {
  /**
   * The rendezvous server URL passed to `session_connect`. GAP: `MeridianClientAdapter`'s own
   * `openConversation(peer)` takes no server argument (task 12.2 deliberately keeps this interface
   * free of any signaling-transport concept), but 12.3's `session_connect` command requires one
   * (`session_connect(peer_id, server)`). Modeled here as adapter-level *configuration* (set once,
   * at construction, like `apps/cli`'s own `--server` flag) rather than invented per-call —
   * TODO: confirm this is the right seam; a future task may want this sourced from user settings
   * instead of a constructor argument.
   */
  rendezvousServer: string;
  /** How often (ms) an open conversation is polled via `pump_once` — see this file's top doc
   * comment and the "no background pump" GAP on {@link TauriMeridianClientAdapter.openConversation}. */
  pumpIntervalMs?: number;
}

const DEFAULT_PUMP_INTERVAL_MS = 300;

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export class TauriMeridianClientAdapter implements MeridianClientAdapter {
  private readonly server: string;
  private readonly pumpIntervalMs: number;

  private currentAccountId: MeridianId | null = null;

  /** `pubkey_hex -> MeridianId` — every event/DTO this adapter receives from 12.3 identifies a
   * peer by raw hex pubkey only (`peer_pubkey_hex`), never by the canonical `mrd1:...@hint`
   * string `MeridianClientAdapter` calls a {@link MeridianId}. Reconstructing that string from
   * raw bytes is exactly the "reimplement wire/identity logic in TS" this codebase forbids
   * (`apps/identity/src/id.rs`'s encoding includes a checksum + multicodec tag, not a plain
   * base32-of-pubkey) — so this adapter never synthesizes one. Instead it opportunistically caches
   * the mapping every time a real `MeridianId` and its `pubkey_hex` cross the boundary together
   * (every `AccountView`/`ContactView`/`SessionView`, and every peer this adapter itself dialed via
   * {@link openConversation}, which is always called with the full id already known to the
   * caller). See {@link onMessage}'s doc for the one case this does not cover. */
  private readonly pubkeyToId = new Map<string, MeridianId>();

  private readonly contactsCache = new Map<MeridianId, Contact>();

  /** In-memory only — GAP: 12.3 exposes no message-history persistence/query command at all (no
   * `ChatState` session/message enumeration is wired to any Tauri command). Every `ChatMessage`
   * here was observed live (sent by this adapter, or pumped from a `chat:message`/`chat:receipt`
   * event) since this adapter instance was constructed; nothing survives an app restart even
   * though the underlying ratchet session may. Matches `adapter.ts`'s own documented expectation
   * for {@link listConversations} ("materialize client-side from local metadata, no core query"),
   * extended here to `loadHistory` for the same underlying reason. TODO: confirm — a real desktop
   * client needs its own local (likely encrypted-at-rest) message store; that is a product
   * decision out of this thin-marshaling task's scope. */
  private readonly history = new Map<MeridianId, ChatMessage[]>();
  private readonly unreadCounts = new Map<MeridianId, number>();

  /** Same "materialize from live events, no backing query" shape as `history` — GAP: no
   * `file_list`/transfers query command exists either. */
  private readonly transfers: FileTransferSummary[] = [];

  private readonly messageListeners = new Set<(peer: MeridianId, msg: ChatMessage) => void>();
  private readonly requestListeners = new Set<(req: MessageRequest) => void>();
  private readonly frameListeners = new Set<(streamId: StreamHandle, frame: Uint8Array) => void>();

  private readonly pumpTimers = new Map<MeridianId, ReturnType<typeof setInterval>>();
  private readonly unlisteners: UnlistenFn[] = [];

  private msgCounter = 0;

  /** Resolves once this adapter's base event subscriptions (`account:changed`, `contact:changed`,
   * `chat:*`, `session:closed`, `file:*`) are attached. `MeridianClientAdapter` has no `init`/
   * `ready` hook of its own (every method is independently async), so this is additive on the
   * concrete class only — screens coded against the interface never see or need it; tests use it
   * for determinism. Until it resolves there is a narrow window (inherent to `listen`'s own async
   * subscribe) where an event emitted between construction and subscription is missed — the same
   * risk any Tauri frontend has at startup. */
  readonly ready: Promise<void>;

  constructor(opts: TauriAdapterOptions) {
    this.server = opts.rendezvousServer;
    this.pumpIntervalMs = opts.pumpIntervalMs ?? DEFAULT_PUMP_INTERVAL_MS;
    this.ready = this.init();
  }

  private async init(): Promise<void> {
    const subs = await Promise.all([
      listen<AccountViewDto>("account:changed", (event) => {
        this.currentAccountId = event.payload.id;
        this.pubkeyToId.set(event.payload.pubkey_hex, event.payload.id);
      }),
      listen<ContactViewDto>("contact:changed", (event) => {
        this.cacheContact(event.payload);
      }),
      listen<ChatEventDto>("chat:message", (event) => this.handleChatEvent(event.payload)),
      listen<ChatEventDto>("chat:receipt", (event) => this.handleChatEvent(event.payload)),
      listen<ChatEventDto>("chat:message_request", (event) => this.handleChatEvent(event.payload)),
      listen<ChatEventDto>("session:closed", (event) => this.handleChatEvent(event.payload)),
      listen<IncomingFileDto>("file:incoming", (event) => this.handleFileIncoming(event.payload)),
      listen<FileProgressDto>("file:progress", (event) => this.handleFileProgress(event.payload)),
      listen<FileReceivedDto>("file:received", (event) => this.handleFileReceived(event.payload)),
      listen<FileFailedDto>("file:failed", (event) => this.handleFileFailed(event.payload)),
    ]);
    this.unlisteners.push(...subs);

    // Best-effort priming so `currentAccount()` has something to return without a screen having to
    // wait on an `account:changed` event first — mirrors `main.rs`'s own best-effort
    // `state.account_load()` call on startup.
    try {
      const view = await callInvoke<AccountViewDto | null>("account_get");
      if (view) {
        this.currentAccountId = view.id;
        this.pubkeyToId.set(view.pubkey_hex, view.id);
      }
    } catch {
      // No account yet — leave `currentAccountId` null, matching `currentAccount()`'s documented
      // "null if none is open yet" case.
    }
  }

  /** Releases every `listen` subscription and stops every `pump_once` poll loop. Not part of
   * {@link MeridianClientAdapter} (which has no lifecycle-teardown method) — additive on the
   * concrete class for callers (12.15) that need to dispose of an adapter instance cleanly. */
  dispose(): void {
    for (const unlisten of this.unlisteners) unlisten();
    this.unlisteners.length = 0;
    for (const timer of this.pumpTimers.values()) clearInterval(timer);
    this.pumpTimers.clear();
  }

  private cacheContact(dto: ContactViewDto): Contact {
    const contact = contactFromDto(dto);
    this.contactsCache.set(contact.id, contact);
    this.pubkeyToId.set(dto.pubkey_hex, dto.id);
    return contact;
  }

  private nextLocalId(prefix: string): string {
    this.msgCounter += 1;
    return `${prefix}-local-${this.msgCounter}`;
  }

  private pushHistory(peer: MeridianId, msg: ChatMessage, incrementUnread: boolean): void {
    const list = this.history.get(peer) ?? [];
    list.push(msg);
    this.history.set(peer, list);
    if (incrementUnread) {
      this.unreadCounts.set(peer, (this.unreadCounts.get(peer) ?? 0) + 1);
    }
  }

  /** Handles every `ChatEventDto` this adapter observes, whether pushed via a `listen` subscription
   * or returned directly from an `invoke` call whose command also happens to `emit` the same event
   * (`chat_send`'s own peer session, `contact_answer_request`'s accept path, `pump_once`) — see
   * `commands.rs`'s module doc: every mutating command that produces a `ChatEvent` both returns it
   * *and* emits it, so routing both through this one function keeps local state (`history`,
   * `unreadCounts`, the `pubkeyToId` cache) in sync regardless of which path delivered it. */
  private handleChatEvent(event: ChatEventDto): void {
    switch (event.kind) {
      case "Message": {
        const peer = this.pubkeyToId.get(event.peer_pubkey_hex);
        if (!peer) {
          // GAP (narrow): a `chat:message` for a pubkey this adapter never resolved to a
          // `MeridianId`. Should not happen in the normal flow — `pump_once` (the only way this
          // event fires) requires an already-open session, which requires *this adapter* to have
          // called `openConversation(peer)` with the full id first (see that method's doc) — but
          // is reachable if, e.g., a session somehow outlives this adapter instance's own cache.
          // Never invented (see `pubkeyToId`'s doc): dropped rather than surfaced with a fabricated
          // id.
          return;
        }
        const msg: ChatMessage = {
          id: event.id_hex,
          direction: "in",
          // GAP: no timestamp crosses the wire in `ChatEvent::Message` — locally observed instead
          // of core/server-sourced. Fine for the ordering this UI needs (events arrive in order),
          // not authoritative.
          timestamp: Math.floor(Date.now() / 1000),
          streamType: "mrd.chat/1",
          body: event.body,
          state: "received",
        };
        this.pushHistory(peer, msg, true);
        for (const cb of this.messageListeners) cb(peer, msg);
        return;
      }
      case "Receipt": {
        const peer = this.pubkeyToId.get(event.peer_pubkey_hex);
        if (!peer) return;
        // Best-effort: mark the matching outbound message delivered, assuming `ack` echoes the
        // original message id (TODO: confirm against `meridian_core::envelope::ChatContent::Receipt`'s
        // exact semantics — this file does not decode envelopes itself).
        const list = this.history.get(peer);
        const match = list?.find((m) => m.id === event.ack_hex);
        if (match) match.state = "delivered" as MessageDeliveryState;
        return;
      }
      case "MessageRequest": {
        const peer = this.pubkeyToId.get(event.peer_pubkey_hex) ?? event.peer_pubkey_hex;
        const req: MessageRequest = {
          from: peer,
          safetyNumber: { raw: event.safety_number, grouped: groupDigits(event.safety_number) },
          // GAP: `ChatEvent::MessageRequest` carries only `peer_pubkey_hex` + `safety_number`.
          // `meridian_core::chat::MessageRequest` (the core type) already holds the decrypted
          // `intro: ChatContent` alongside the safety number (see `apps/core/src/chat.rs`), but
          // `commands.rs` never serializes it into this DTO — so `introPreview`, which
          // `adapter.ts`'s own doc says should be "shown alongside the accept/reject prompt", can
          // never be populated pre-decision through this command surface today. Flagged back to
          // 12.3: add the intro's rendered text to `ChatEvent::MessageRequest`.
          introPreview: null,
        };
        for (const cb of this.requestListeners) cb(req);
        return;
      }
      case "StreamOpened":
      case "StreamClosed":
        // No generic-frame subscriber surface exists to route these to (see `onStreamFrame`'s
        // doc) — nothing to do with them here beyond what `file:*` events already cover for the
        // one concrete stream type (`mrd.file/1`) 12.3 wires today.
        return;
      case "Closed": {
        const peer = this.pubkeyToId.get(event.peer_pubkey_hex);
        if (peer) this.stopPump(peer);
        return;
      }
    }
  }

  private handleFileIncoming(dto: IncomingFileDto): void {
    const peer = this.pubkeyToId.get(dto.peer_pubkey_hex);
    if (!peer) return;
    this.transfers.push({
      streamId: this.nextLocalId("stream"),
      peer,
      direction: "in",
      fileName: dto.name,
      totalBytes: dto.size,
      transferredBytes: 0,
      state: "in_progress",
    });
  }

  private findTransfer(peerHex: string, name: string): FileTransferSummary | undefined {
    const peer = this.pubkeyToId.get(peerHex);
    if (!peer) return undefined;
    // Most-recent-first: a peer could in principle have re-sent the same filename.
    for (let i = this.transfers.length - 1; i >= 0; i--) {
      const t = this.transfers[i]!;
      if (t.peer === peer && t.fileName === name) return t;
    }
    return undefined;
  }

  private handleFileProgress(dto: FileProgressDto): void {
    const t = this.findTransfer(dto.peer_pubkey_hex, dto.name);
    if (t) {
      t.transferredBytes = dto.bytes_sent;
      t.totalBytes = dto.total_bytes;
      t.state = "in_progress";
    }
  }

  private handleFileReceived(dto: FileReceivedDto): void {
    const t = this.findTransfer(dto.peer_pubkey_hex, dto.name);
    if (t) {
      t.state = "complete";
      t.transferredBytes = t.totalBytes;
    }
  }

  private handleFileFailed(dto: FileFailedDto): void {
    const t = this.findTransfer(dto.peer_pubkey_hex, dto.name);
    if (t) t.state = "failed";
  }

  // ---------------------------------------------------------------------
  // Account
  // ---------------------------------------------------------------------

  async generateAccount(hint: string): Promise<MeridianId> {
    const view = await callInvoke<AccountViewDto>("account_create", { hint });
    this.currentAccountId = view.id;
    this.pubkeyToId.set(view.pubkey_hex, view.id);
    return view.id;
  }

  /**
   * GAP: `MeridianClientAdapter.openAccount(descriptor)` is meant to accept an opaque,
   * platform-specific "locate + unlock an existing account" descriptor. 12.3 has no command that
   * takes one — only `account_load()` (loads whatever account descriptor already lives at the
   * single fixed `$MERIDIAN_HOME` location; no parameters) and `account_create` (always generates
   * fresh). There is currently exactly one desktop account location, so `descriptor` is accepted
   * for interface conformance but ignored — TODO: confirm this is intended (a real "open a
   * specific/imported account" flow would need 12.3 to grow a parameterized open command).
   */
  async openAccount(_descriptor: unknown): Promise<MeridianId> {
    void _descriptor;
    const view = await callInvoke<AccountViewDto | null>("account_load");
    if (!view) {
      throw new MeridianAdapterError("unavailable", "no account found to open");
    }
    this.currentAccountId = view.id;
    this.pubkeyToId.set(view.pubkey_hex, view.id);
    return view.id;
  }

  currentAccount(): MeridianId | null {
    return this.currentAccountId;
  }

  /**
   * GAP: 12.3 has no command to lock/close an account or discard in-memory key material —
   * `DesktopState`'s `account`/`handle` fields, once set, are never cleared by anything in
   * `commands.rs`/`tauri_commands.rs`. This method can only clear *this adapter's own* local
   * cache (`currentAccountId`, `pubkeyToId`, `contactsCache`); it cannot actually instruct the
   * Rust backend to drop its loaded `KeyHandle`/`AccountDescriptor`, so key material stays resident
   * in the (already-trusted, in-process, ADR-0010) backend regardless of this call. Flagged back
   * to 12.3 as a security-relevant gap: `closeAccount`'s contract ("discarding any in-memory key
   * material") is not actually met today.
   */
  async closeAccount(): Promise<void> {
    for (const timer of this.pumpTimers.values()) clearInterval(timer);
    this.pumpTimers.clear();
    this.currentAccountId = null;
    this.contactsCache.clear();
    this.pubkeyToId.clear();
  }

  // ---------------------------------------------------------------------
  // Sessions & messaging
  // ---------------------------------------------------------------------

  private startPump(peer: MeridianId): void {
    if (this.pumpTimers.has(peer)) return;
    // GAP: `main.rs` spawns no background pump loop of its own — `pump_once` is an ordinary,
    // frontend-invoked command, meaning *this adapter* is the only thing driving inbound-event
    // delivery for an open session. Polling on an interval (rather than a real backend-push
    // subscription) is a deliberate, documented stand-in per this task's "thin marshaling, no new
    // Rust commands" scope constraint — it adds up to `pumpIntervalMs` of latency and steady IPC
    // traffic per open conversation. A future task should have `main.rs` spawn its own pump task
    // per session (as its own doc comment on `commands.rs::pump_once` already anticipates) so the
    // frontend only ever *listens*, never polls.
    const timer = setInterval(() => {
      void invoke("pump_once", { peerId: peer }).catch((err: unknown) => {
        const mapped = mapInvokeError(err);
        if (mapped.code === "no_session") this.stopPump(peer);
        // Otherwise: best-effort, matches `commands.rs`'s own "best-effort" emit philosophy —
        // a single failed pump tick is not surfaced as an adapter-level error.
      });
    }, this.pumpIntervalMs);
    this.pumpTimers.set(peer, timer);
  }

  private stopPump(peer: MeridianId): void {
    const timer = this.pumpTimers.get(peer);
    if (timer) {
      clearInterval(timer);
      this.pumpTimers.delete(peer);
    }
  }

  /**
   * `session_connect` — GAP: takes a `server` the interface itself has no place for (see
   * {@link TauriAdapterOptions.rendezvousServer}'s doc); this adapter supplies its own configured
   * server for every call. Idempotent via `session_get` first, per the interface's own contract.
   */
  async openConversation(peer: MeridianId): Promise<void> {
    const existing = await callInvoke<SessionViewDto | null>("session_get", { peerId: peer });
    if (existing) {
      this.pubkeyToId.set(existing.peer_pubkey_hex, peer);
      this.startPump(peer);
      return;
    }
    const view = await callInvoke<SessionViewDto>("session_connect", {
      peerId: peer,
      server: this.server,
    });
    this.pubkeyToId.set(view.peer_pubkey_hex, peer);
    this.startPump(peer);
  }

  /**
   * `chat_send`. GAP: `SentMessage` only returns `id_hex` — no delivered/queued distinction
   * crosses the boundary (12.3 has no offline-mailbox/queuing concept wired to any command), so
   * `delivered`/`queued` below are the best available approximation (a successful `chat_send`
   * means the frame was handed to an already-open transport, so `delivered: true, queued: false`
   * — never a store-and-forward "queued" state, unlike `apps/cli`'s three-way `sent_line` mapping
   * this interface's doc comment references).
   */
  async sendChat(peer: MeridianId, body: string): Promise<SendResult> {
    const sent = await callInvoke<SentMessageDto>("chat_send", { peerId: peer, text: body });
    const msg: ChatMessage = {
      id: sent.id_hex,
      direction: "out",
      timestamp: Math.floor(Date.now() / 1000),
      streamType: "mrd.chat/1",
      body,
      state: "sent",
    };
    this.pushHistory(peer, msg, false);
    return { id: sent.id_hex, delivered: true, queued: false };
  }

  /**
   * See {@link pubkeyToId}'s doc for how inbound events are resolved back to a {@link MeridianId}.
   */
  onMessage(cb: (peer: MeridianId, msg: ChatMessage) => void): () => void {
    this.messageListeners.add(cb);
    return () => this.messageListeners.delete(cb);
  }

  /**
   * See `handleChatEvent`'s `"MessageRequest"` case for the `introPreview: null` GAP.
   */
  onMessageRequest(cb: (req: MessageRequest) => void): () => void {
    this.requestListeners.add(cb);
    return () => this.requestListeners.delete(cb);
  }

  async acceptMessageRequest(from: MeridianId, petname?: string): Promise<void> {
    await callInvoke<ChatEventDto | null>("contact_answer_request", { id: from, accept: true });
    if (petname !== undefined) {
      // `contact_answer_request` has no petname parameter — a second call is needed. Not atomic:
      // a crash between the two leaves the contact TOFU-pinned without the requested petname.
      await this.renamePetname(from, petname);
    }
  }

  async rejectMessageRequest(from: MeridianId): Promise<void> {
    await callInvoke<ChatEventDto | null>("contact_answer_request", { id: from, accept: false });
  }

  /**
   * GAP: no single-contact `trust_state`/`contact_get` query command exists — only bulk
   * `contact_list`. Implemented as fetch-all-then-find, same as {@link markConversationRead}'s
   * existence check.
   */
  async trustState(peer: MeridianId): Promise<TrustState> {
    const contact = await this.getContactOrThrow(peer);
    return contact.trust;
  }

  /**
   * GAP: 12.3 has no `can_send`/send-gate *query* command — only `chat_send`'s own internal,
   * authoritative enforcement (`TrustStore::can_send`, `apps/core/src/trust.rs`), which is not
   * separately queryable ahead of a send. The `kind` below is re-derived client-side from
   * `ContactView.state`/`user_blocked` (a **display-string mapping**, the same category as
   * {@link trustStateFromStr}, not a re-derivation of the gate's actual precedence — the block
   * check's precedence over trust state is a real business rule that lives only in
   * `TrustStore::can_send` and is never duplicated here). `reason` is adapter-owned advisory text,
   * not sourced from core (core's own reason strings are only ever visible via `chat_send`'s error
   * message, not through any query). This is exactly the kind of duplication-risk this task's
   * Risks/notes warns about; flagged back to 12.3 as a finding — a dedicated `contact_send_gate`
   * command would let this method become a thin passthrough like every other one here. The
   * authoritative check still always happens server-side, in `chat_send`, regardless of what this
   * method returns — matching `adapter.ts`'s own "never bypassable by skipping the read" guarantee.
   */
  async sendGateState(peer: MeridianId): Promise<SendGateState> {
    const contact = await this.getContactOrThrow(peer);
    if (contact.userBlocked) {
      return { kind: "blocked", reason: "You have blocked this contact locally." };
    }
    switch (contact.trust) {
      case "blocked":
        return {
          kind: "blocked",
          reason: "This contact's safety number changed. Verify it out-of-band before sending.",
        };
      case "pinned_key_changed":
        return {
          kind: "warn",
          reason:
            "This contact's safety number changed. Acknowledge or verify before sending resumes.",
        };
      default:
        return { kind: "ok" };
    }
  }

  async acknowledgeKeyChange(peer: MeridianId): Promise<void> {
    const view = await callInvoke<ContactViewDto>("contact_acknowledge_key_change", { id: peer });
    this.cacheContact(view);
  }

  // ---------------------------------------------------------------------
  // Contacts / trust
  // ---------------------------------------------------------------------

  async listContacts(): Promise<Contact[]> {
    const views = await callInvoke<ContactViewDto[]>("contact_list");
    return views.map((v) => this.cacheContact(v));
  }

  async addContact(id: MeridianId, petname?: string): Promise<Contact> {
    const view = await callInvoke<ContactViewDto>("contact_add", { id, petname });
    return this.cacheContact(view);
  }

  async renamePetname(id: MeridianId, petname: string | null): Promise<void> {
    const view = await callInvoke<ContactViewDto>("contact_rename", {
      id,
      petname: petname ?? "",
    });
    this.cacheContact(view);
  }

  async blockContact(id: MeridianId): Promise<void> {
    const view = await callInvoke<ContactViewDto>("contact_block", { id, blocked: true });
    this.cacheContact(view);
  }

  async unblockContact(id: MeridianId): Promise<void> {
    const view = await callInvoke<ContactViewDto>("contact_block", { id, blocked: false });
    this.cacheContact(view);
  }

  /**
   * GAP (expected — see `adapter.ts`'s own top doc comment): no `meridian-core` bulk session
   * query exists; materialized client-side from contacts + this adapter's in-memory `history`
   * (see that field's own GAP doc — nothing here survives a restart).
   */
  async listConversations(): Promise<ConversationSummary[]> {
    const contacts = await this.listContacts();
    return contacts.map((contact) => {
      const msgs = this.history.get(contact.id) ?? [];
      const last = msgs[msgs.length - 1];
      return {
        contact,
        lastActivityAt: last ? last.timestamp : null,
        unreadCount: this.unreadCounts.get(contact.id) ?? 0,
        lastMessagePreview: last ? last.body : null,
      };
    });
  }

  async markConversationRead(peer: MeridianId): Promise<void> {
    await this.getContactOrThrow(peer);
    this.unreadCounts.set(peer, 0);
  }

  /** In-memory only — see `history`'s field doc GAP. */
  async loadHistory(
    peer: MeridianId,
    opts?: { limit?: number; before?: string },
  ): Promise<ChatMessage[]> {
    await this.getContactOrThrow(peer);
    let msgs = this.history.get(peer) ?? [];
    if (opts?.before) {
      const idx = msgs.findIndex((m) => m.id === opts.before);
      msgs = idx >= 0 ? msgs.slice(0, idx) : msgs;
    }
    if (opts?.limit !== undefined) {
      msgs = msgs.slice(Math.max(0, msgs.length - opts.limit));
    }
    return [...msgs];
  }

  private async getContactOrThrow(peer: MeridianId): Promise<Contact> {
    const cached = this.contactsCache.get(peer);
    if (cached) return cached;
    const contacts = await this.listContacts();
    const found = contacts.find((c) => c.id === peer);
    if (!found) {
      throw new MeridianAdapterError("unknown_contact", `no contact recorded for ${peer}`);
    }
    return found;
  }

  // ---------------------------------------------------------------------
  // Verification
  // ---------------------------------------------------------------------

  /**
   * GAP (blocking — the biggest gap this task found): 12.3 has **no command that returns a safety
   * number for an established contact on demand**. `SessionView` computes fingerprints
   * (`session.fingerprints()`) and then explicitly discards them
   * (`commands.rs::session_view`: `let _ = remote_hex; // ... display is 12.15's job`); the only
   * safety number that ever crosses the IPC boundary today is `ChatEvent::MessageRequest`'s
   * (first-contact only, pushed once, not re-fetchable afterward). There is no way to implement
   * this method against today's command surface without either inventing a new command (out of
   * this task's scope — see the task file's Scope→Out list) or reimplementing
   * `meridian_core::chat::ChatState::safety_number` in TypeScript (forbidden — bespoke crypto).
   * Fails closed. Flagged back to 12.3 as the top-priority finding: the Verification screen
   * cannot function on desktop until a `contact_safety_number`-shaped command exists.
   */
  async safetyNumber(_peer: MeridianId): Promise<SafetyNumber> {
    void _peer;
    throw new MeridianAdapterError(
      "unavailable",
      "no Tauri command exposes a safety number for an established contact yet — see this " +
        "adapter's safetyNumber() doc comment for the full gap report",
    );
  }

  async markVerified(peer: MeridianId): Promise<void> {
    const view = await callInvoke<ContactViewDto>("contact_mark_verified", { id: peer });
    this.cacheContact(view);
  }

  // ---------------------------------------------------------------------
  // Streams / file ops
  // ---------------------------------------------------------------------

  /**
   * GAP (blocking, structural): 12.3 wires exactly one concrete, hardcoded command (`file_send`,
   * `mrd.file/1`-specific, path-based) instead of a generic `open_stream(streamType, params)`
   * passthrough. `adapter.ts`'s own top doc comment is explicit that additive stream types must
   * never need an adapter change — that guarantee does not hold against today's 12.3 surface: any
   * stream type other than `mrd.file/1` has no command to call at all here. Only the one concrete
   * case is supported (and even that has its own GAP — see {@link sendFile}); everything else
   * fails closed rather than silently no-op-ing.
   */
  async openStream(peer: MeridianId, streamType: string, params: unknown): Promise<StreamOpenResult> {
    if (streamType === "mrd.file/1" && isFilePathParams(params)) {
      const result = await this.sendFileByPath(peer, params.path);
      return { streamId: result.streamId };
    }
    throw new MeridianAdapterError(
      "unavailable",
      `openStream: no Tauri command backs stream type "${streamType}" yet (only mrd.file/1, via ` +
        "file_send, is wired) — see this adapter's openStream() doc comment for the full gap report",
    );
  }

  /**
   * GAP: `onStreamFrame` is meant to be a generic raw-frame subscription for any open stream, but
   * 12.3 emits only concrete, `mrd.file/1`-specific events (`file:incoming`/`file:progress`/
   * `file:received`/`file:failed`), never a generic `(streamId, frame: Uint8Array)` event for an
   * arbitrary stream type. There is nothing to route to a subscriber here today — the callback is
   * registered (so a caller's unsubscribe function stays well-formed) but will never fire against
   * this command surface. Same root cause as {@link openStream}'s gap.
   */
  onStreamFrame(cb: (streamId: StreamHandle, frame: Uint8Array) => void): () => void {
    this.frameListeners.add(cb);
    return () => this.frameListeners.delete(cb);
  }

  /**
   * GAP (blocking): `MeridianClientAdapter.sendFile` takes a `Blob` (the browser-shaped "already
   * have the bytes in memory" file object), but 12.3's `file_send` command takes a `path: String`
   * — a native filesystem path it reads itself with `std::fs::read`. A renderer-side `Blob`/`File`
   * does not carry a filesystem path in a sandboxed WebView (Tauri's own drag-drop event payload
   * may expose one in some configurations — `TODO: confirm`, not verified here, and not something
   * this thin marshaling layer should assume). Bridging the two would mean either (a) 12.3 growing
   * a bytes-accepting command, or (b) this adapter writing the `Blob`'s bytes to a temp file itself
   * via a filesystem-write plugin — the latter is a real, security-relevant product decision
   * (where or how content briefly touches disk) that does not belong in a thin marshaling layer,
   * so it was not done here. This method only succeeds if the caller-supplied `file` object already
   * exposes a `.path` string property (as some native file-picker integrations do) — otherwise it
   * fails closed rather than silently dropping the file or reading it into a temp file unasked.
   */
  async sendFile(peer: MeridianId, file: Blob, fileName: string): Promise<StreamOpenResult> {
    const path = (file as { path?: unknown }).path;
    if (typeof path !== "string") {
      throw new MeridianAdapterError(
        "unavailable",
        "sendFile: this Blob carries no filesystem path and apps/desktop's file_send command only " +
          "accepts a path — see this adapter's sendFile() doc comment for the full gap report",
      );
    }
    void fileName; // `file_send` derives the display name from `path` itself (commands.rs).
    const result = await this.sendFileByPath(peer, path);
    return { streamId: result.streamId };
  }

  private async sendFileByPath(
    peer: MeridianId,
    path: string,
  ): Promise<{ streamId: StreamHandle; root: string }> {
    const dto = await callInvoke<FileSentResultDto>("file_send", { peerId: peer, path });
    const streamId = this.nextLocalId("stream");
    this.transfers.push({
      streamId,
      peer,
      direction: "out",
      fileName: dto.name,
      totalBytes: 0,
      transferredBytes: 0,
      state: "complete",
    });
    return { streamId, root: dto.root_hex };
  }

  /** In-memory only — see `transfers`'s field doc GAP. */
  async listTransfers(): Promise<FileTransferSummary[]> {
    return [...this.transfers];
  }

  /**
   * GAP (structural, pre-existing — task 12.9 surfaces it, does not introduce it): `acceptTransfer`/
   * `rejectTransfer` are the receive-side counterpart `shared-ui`'s file-transfer screen needs, but
   * 12.3's real `mrd.file/1` policy hook (`FileStream::with_ask_user`, `apps/streams/src/file.rs`)
   * is a *synchronous* closure consulted inside `on_open` itself, and 12.3's own `handleFileIncoming`
   * above always records an incoming transfer as `state: "in_progress"`, never `"offered"` — there
   * is no live round trip anywhere in 12.3's command/event surface that could pause on this desktop
   * shell for a human decision, let alone resolve one sent back here. `acceptTransfer`/
   * `rejectTransfer` can therefore never legitimately find an `"offered"` transfer to act on against
   * this adapter today; both fail closed rather than silently pretending to succeed. Wiring this for
   * real needs a new Tauri command/event pair backing an async `ask_user` round trip — a
   * command/event-surface change to 12.3, out of this task's scope, exactly like every other GAP in
   * this file.
   */
  async acceptTransfer(streamId: StreamHandle): Promise<void> {
    void streamId;
    throw new MeridianAdapterError(
      "unavailable",
      "acceptTransfer: no Tauri command/event round trip exists for a pending file-transfer " +
        "decision yet — see this adapter's acceptTransfer() doc comment for the full gap report",
    );
  }

  /** See {@link acceptTransfer}'s doc comment — the same gap applies symmetrically. */
  async rejectTransfer(streamId: StreamHandle): Promise<void> {
    void streamId;
    throw new MeridianAdapterError(
      "unavailable",
      "rejectTransfer: no Tauri command/event round trip exists for a pending file-transfer " +
        "decision yet — see this adapter's acceptTransfer() doc comment for the full gap report",
    );
  }
}

function isFilePathParams(params: unknown): params is { path: string } {
  return (
    typeof params === "object" &&
    params !== null &&
    "path" in params &&
    typeof (params as { path: unknown }).path === "string"
  );
}

/** Splits a digit string into 5-digit groups for display — pure text formatting (no key material,
 * no wire framing), the same trivial transform `FakeMeridianClientAdapter` uses. `adapter.ts`'s own
 * doc comment says a concrete adapter should call the real core's `display_groups` for this;
 * TODO: confirm — no Tauri command wraps `display_groups` today, so this local helper stands in
 * for it. Low risk either way: grouping-into-5s is a fixed, public display convention, not a
 * secret-dependent computation. */
function groupDigits(raw: string): string {
  return raw.match(/.{1,5}/g)?.join(" ") ?? raw;
}
