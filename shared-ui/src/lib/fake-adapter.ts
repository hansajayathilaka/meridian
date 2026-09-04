/**
 * `FakeMeridianClientAdapter` — an in-memory, deterministic {@link MeridianClientAdapter} test
 * double for screen-level component tests (12.7-12.9) and this package's own
 * {@link ./adapter.test.ts | adapter contract test}. No real crypto, no network, no WASM: every
 * "cryptographic" value below (pubkeys, safety numbers, message ids) is a deterministic, readable
 * placeholder derived from a counter or the input string — good enough to exercise UI/state logic,
 * never to be mistaken for the real thing.
 *
 * Deliberately does **not** implement any bespoke crypto or wire framing (the invariant this
 * interface itself commits to) — it fakes the *outcomes* (a contact got pinned, a message was
 * "sent") without ever deriving them from real key material.
 */

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
} from "./adapter";
import { MeridianAdapterError } from "./adapter";

/** Deterministic, non-cryptographic 32-byte-hex-shaped placeholder derived from `seed`. */
function fakePubkeyHex(seed: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x1000193 ^ seed.length;
  for (let i = 0; i < seed.length; i++) {
    const c = seed.charCodeAt(i);
    h1 = (h1 ^ c) * 0x01000193;
    h1 >>>= 0;
    h2 = (h2 + c) * 0x9e3779b1;
    h2 >>>= 0;
  }
  const hex = (n: number) => n.toString(16).padStart(8, "0");
  // 64 hex chars (32 bytes), built by repeating the two 32-bit hashes — deterministic, not secure.
  return (hex(h1) + hex(h2)).repeat(4).slice(0, 64);
}

function fakeId(hint: string, pubkeyHex: string): MeridianId {
  return `mrd1:${pubkeyHex.slice(0, 16)}@${hint}`;
}

function fakeSafetyNumber(a: string, b: string): SafetyNumber {
  // Order-independent, like the real `safety_number` — compare the two pubkeys first.
  const [first, second] = a <= b ? [a, b] : [b, a];
  const combined = (first + second).replace(/[^0-9]/g, "0");
  const digits = (combined + "0".repeat(60)).slice(0, 60);
  const grouped = digits.match(/.{1,5}/g)!.join(" ");
  return { raw: digits, grouped };
}

/**
 * Best available human-facing label for `contact` in a send-gate message — mirrors
 * `apps/core/src/trust.rs`'s `contact_label`: local petname if set, else the advisory hint, else a
 * short id-derived fallback, so a warn/block reason is never left without an identifiable subject.
 */
function contactLabel(contact: Pick<Contact, "petname" | "hint" | "id">): string {
  if (contact.petname) return contact.petname;
  if (contact.hint) return contact.hint;
  return contact.id;
}

/**
 * Derives {@link SendGateState} purely from `userBlocked`/`trust` — mirroring
 * `meridian_core::trust::TrustStore::can_send`'s exact precedence (`apps/core/src/trust.rs`,
 * ~lines 524-540): a user-initiated block is checked *first*, independently of trust state, and
 * unconditionally wins; only once that is clear does the trust state itself gate (`"blocked"` →
 * hard stop, `"pinned_key_changed"` → warn, everything else → ok).
 *
 * Deliberately a **pure function of the contact's own fields**, never separately-mutated state:
 * task 12.2's review found that an earlier version stored a `sendGate` field independently of
 * `userBlocked`/`trust`, which `blockContact`/`unblockContact`/`markVerified` never touched — so
 * the gate could silently drift out of sync (blocking a contact had zero effect on `sendChat`).
 * Recomputing on every call makes that class of bug structurally impossible.
 */
function computeSendGate(
  contact: Pick<Contact, "userBlocked" | "trust" | "petname" | "hint" | "id">,
): SendGateState {
  const label = contactLabel(contact);
  if (contact.userBlocked) {
    return {
      kind: "blocked",
      reason: `You have blocked ${label} locally. Sends stay blocked while that local block is in place.`,
    };
  }
  switch (contact.trust) {
    case "blocked":
      return {
        kind: "blocked",
        reason: `The safety number for ${label} has changed. Sends are blocked until you verify the new safety number with them.`,
      };
    case "pinned_key_changed":
      return {
        kind: "warn",
        reason: `The safety number for ${label} has changed. Sends are paused until you verify, or acknowledge this warning to re-pin without verifying.`,
      };
    case "new":
    case "pinned":
    case "verified":
      return { kind: "ok" };
  }
}

/** Monotonic counter, reset per instance — the only source of "randomness" this double uses. */
let instanceSeq = 0;

export class FakeMeridianClientAdapter implements MeridianClientAdapter {
  private readonly seq: number;
  private counter = 0;

  private account: { id: MeridianId; pubkey: string } | null = null;
  private readonly contacts = new Map<MeridianId, Contact>();
  private readonly history = new Map<MeridianId, ChatMessage[]>();
  private readonly pendingRequests = new Map<MeridianId, MessageRequest>();
  /** Per-conversation unread count — incremented whenever an inbound message is pushed to
   * `history` (see `pushHistory`), reset to 0 by {@link markConversationRead}. Keyed separately
   * from `history` itself (rather than re-deriving from `ChatMessage.state`) because every
   * simulated inbound message is created with `state: "received"` — that field tracks delivery
   * state, not read/unread, so filtering on it was dead code (task 12.2 review finding). */
  private readonly unreadCounts = new Map<MeridianId, number>();
  private readonly transfers: FileTransferSummary[] = [];

  private readonly messageListeners = new Set<(peer: MeridianId, msg: ChatMessage) => void>();
  private readonly requestListeners = new Set<(req: MessageRequest) => void>();
  private readonly frameListeners = new Set<(streamId: StreamHandle, frame: Uint8Array) => void>();

  constructor() {
    this.seq = ++instanceSeq;
  }

  private nextId(prefix: string): string {
    this.counter += 1;
    return `${prefix}-${this.seq}-${this.counter}`;
  }

  private requireAccount(): { id: MeridianId; pubkey: string } {
    if (!this.account) {
      throw new MeridianAdapterError("unavailable", "no account is open");
    }
    return this.account;
  }

  private requireContact(peer: MeridianId): Contact {
    const contact = this.contacts.get(peer);
    if (!contact) {
      throw new MeridianAdapterError("unknown_contact", `no contact recorded for ${peer}`);
    }
    return contact;
  }

  // ---------------------------------------------------------------------
  // Account
  // ---------------------------------------------------------------------

  async generateAccount(hint: string): Promise<MeridianId> {
    const pubkey = fakePubkeyHex(`account:${this.nextId("acct")}`);
    const id = fakeId(hint, pubkey);
    this.account = { id, pubkey };
    return id;
  }

  async openAccount(descriptor: unknown): Promise<MeridianId> {
    const seed = typeof descriptor === "string" ? descriptor : JSON.stringify(descriptor ?? "fake");
    const pubkey = fakePubkeyHex(`open:${seed}`);
    const id = fakeId("fake.example", pubkey);
    this.account = { id, pubkey };
    return id;
  }

  currentAccount(): MeridianId | null {
    return this.account?.id ?? null;
  }

  async closeAccount(): Promise<void> {
    this.account = null;
  }

  // ---------------------------------------------------------------------
  // Sessions & messaging
  // ---------------------------------------------------------------------

  async openConversation(peer: MeridianId): Promise<void> {
    this.requireAccount();
    if (!this.contacts.has(peer)) {
      await this.addContact(peer);
    }
    if (!this.history.has(peer)) {
      this.history.set(peer, []);
    }
  }

  async sendChat(peer: MeridianId, body: string): Promise<SendResult> {
    this.requireAccount();
    const contact = this.requireContact(peer);
    const gate = computeSendGate(contact);
    if (gate.kind === "blocked") {
      throw new MeridianAdapterError("send_blocked", gate.reason);
    }
    if (gate.kind === "warn") {
      throw new MeridianAdapterError("send_warn_unacknowledged", gate.reason);
    }

    const id = this.nextId("msg");
    const msg: ChatMessage = {
      id,
      direction: "out",
      timestamp: this.counter,
      streamType: "mrd.chat/1",
      body,
      state: "sent",
    };
    this.pushHistory(peer, msg);
    return { id, delivered: true, queued: false };
  }

  onMessage(cb: (peer: MeridianId, msg: ChatMessage) => void): () => void {
    this.messageListeners.add(cb);
    return () => this.messageListeners.delete(cb);
  }

  onMessageRequest(cb: (req: MessageRequest) => void): () => void {
    this.requestListeners.add(cb);
    return () => this.requestListeners.delete(cb);
  }

  async acceptMessageRequest(from: MeridianId, petname?: string): Promise<void> {
    const req = this.pendingRequests.get(from);
    if (!req) {
      throw new MeridianAdapterError("no_pending_request", `no pending request from ${from}`);
    }
    this.pendingRequests.delete(from);
    await this.addContact(from, petname);
    if (req.introPreview) {
      this.pushHistory(from, {
        id: this.nextId("msg"),
        direction: "in",
        timestamp: this.counter,
        streamType: "mrd.chat/1",
        body: req.introPreview,
        state: "received",
      });
    }
  }

  async rejectMessageRequest(from: MeridianId): Promise<void> {
    if (!this.pendingRequests.delete(from)) {
      throw new MeridianAdapterError("no_pending_request", `no pending request from ${from}`);
    }
    // Deliberately no trace left in `this.contacts` — mirrors the real reject-leaves-no-trace
    // guarantee this fake exists to let screen tests assert against.
  }

  async trustState(peer: MeridianId): Promise<TrustState> {
    return this.requireContact(peer).trust;
  }

  async sendGateState(peer: MeridianId): Promise<SendGateState> {
    return computeSendGate(this.requireContact(peer));
  }

  async acknowledgeKeyChange(peer: MeridianId): Promise<void> {
    const contact = this.requireContact(peer);
    if (computeSendGate(contact).kind !== "warn") {
      throw new MeridianAdapterError(
        "unknown",
        `${peer} has no live key-change warning to acknowledge`,
      );
    }
    // Mirrors `TrustStore::acknowledge_key_change`: re-pins (only reachable from
    // `pinned_key_changed`, checked above), never touches `userBlocked` — the two axes stay
    // independent. The gate is then whatever `computeSendGate` derives from the new state.
    contact.trust = "pinned";
  }

  // ---------------------------------------------------------------------
  // Contacts / trust
  // ---------------------------------------------------------------------

  async listContacts(): Promise<Contact[]> {
    return [...this.contacts.values()].map((c) => ({ ...c }));
  }

  async addContact(id: MeridianId, petname?: string): Promise<Contact> {
    const existing = this.contacts.get(id);
    if (existing) {
      if (petname !== undefined) existing.petname = petname || null;
      return { ...existing };
    }
    const pubkey = fakePubkeyHex(`contact:${id}`);
    const contact: Contact = {
      id,
      pubkey,
      hint: id.split("@")[1] ?? "",
      petname: petname ?? null,
      trust: "pinned",
      userBlocked: false,
    };
    this.contacts.set(id, contact);
    return { ...contact };
  }

  async renamePetname(id: MeridianId, petname: string | null): Promise<void> {
    const contact = this.requireContact(id);
    contact.petname = petname && petname.length > 0 ? petname : null;
  }

  async blockContact(id: MeridianId): Promise<void> {
    this.requireContact(id).userBlocked = true;
  }

  async unblockContact(id: MeridianId): Promise<void> {
    this.requireContact(id).userBlocked = false;
  }

  async listConversations(): Promise<ConversationSummary[]> {
    // TODO: confirm — materialized client-side from contacts + local history, exactly as flagged
    // in adapter.ts's top doc comment (no core-level bulk session query exists to back this).
    return [...this.contacts.values()].map((contact) => {
      const msgs = this.history.get(contact.id) ?? [];
      const last = msgs[msgs.length - 1];
      return {
        contact: { ...contact },
        lastActivityAt: last ? last.timestamp : null,
        unreadCount: this.unreadCounts.get(contact.id) ?? 0,
        lastMessagePreview: last ? last.body : null,
      };
    });
  }

  async markConversationRead(peer: MeridianId): Promise<void> {
    this.requireContact(peer);
    this.unreadCounts.set(peer, 0);
  }

  async loadHistory(
    peer: MeridianId,
    opts?: { limit?: number; before?: string },
  ): Promise<ChatMessage[]> {
    this.requireContact(peer);
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

  // ---------------------------------------------------------------------
  // Verification
  // ---------------------------------------------------------------------

  async safetyNumber(peer: MeridianId): Promise<SafetyNumber> {
    const account = this.requireAccount();
    const contact = this.requireContact(peer);
    return fakeSafetyNumber(account.pubkey, contact.pubkey);
  }

  async markVerified(peer: MeridianId): Promise<void> {
    this.requireContact(peer).trust = "verified";
  }

  // ---------------------------------------------------------------------
  // Streams / file ops
  // ---------------------------------------------------------------------

  async openStream(peer: MeridianId, streamType: string, _params: unknown): Promise<StreamOpenResult> {
    this.requireContact(peer);
    void streamType;
    return { streamId: this.nextId("stream") };
  }

  onStreamFrame(cb: (streamId: StreamHandle, frame: Uint8Array) => void): () => void {
    this.frameListeners.add(cb);
    return () => this.frameListeners.delete(cb);
  }

  async sendFile(peer: MeridianId, file: Blob, fileName: string): Promise<StreamOpenResult> {
    this.requireContact(peer);
    const streamId = this.nextId("stream");
    this.transfers.push({
      streamId,
      peer,
      direction: "out",
      fileName,
      totalBytes: file.size,
      transferredBytes: file.size,
      state: "complete",
    });
    return { streamId };
  }

  async listTransfers(): Promise<FileTransferSummary[]> {
    return [...this.transfers];
  }

  // ---------------------------------------------------------------------
  // Test-only helpers — NOT part of MeridianClientAdapter. Used by screen-level component tests to
  // drive inbound events this in-memory double otherwise has no live peer to generate.
  // ---------------------------------------------------------------------

  /** Simulates a first-contact message request arriving from `from`. */
  simulateIncomingRequest(from: MeridianId, introPreview: string | null = null): void {
    const account = this.requireAccount();
    const pubkey = fakePubkeyHex(`contact:${from}`);
    const req: MessageRequest = {
      from,
      safetyNumber: fakeSafetyNumber(account.pubkey, pubkey),
      introPreview,
    };
    this.pendingRequests.set(from, req);
    for (const cb of this.requestListeners) cb(req);
  }

  /** Simulates an inbound chat message from an already-known contact. */
  simulateIncomingMessage(from: MeridianId, body: string): void {
    this.requireContact(from);
    const msg: ChatMessage = {
      id: this.nextId("msg"),
      direction: "in",
      timestamp: this.counter,
      streamType: "mrd.chat/1",
      body,
      state: "received",
    };
    this.pushHistory(from, msg);
  }

  /** Forces `peer`'s trust state to whatever produces the requested send gate — simulates a live
   * key-change warning/block without the real TOFU/key-history machinery, so screen tests can
   * exercise the gated-send UI directly. The gate itself is never stored directly (see
   * `computeSendGate`'s doc): this only drives the underlying `trust` field, exactly like a real
   * `observe_key_change` would, and the caller-supplied `reason` string is intentionally ignored —
   * `computeSendGate` derives its own reason text from the resulting state, so it can never drift
   * out of sync with it. */
  simulateSendGate(peer: MeridianId, gate: SendGateState): void {
    const contact = this.requireContact(peer);
    if (gate.kind === "warn") contact.trust = "pinned_key_changed";
    else if (gate.kind === "blocked") contact.trust = "blocked";
    else contact.trust = "pinned";
  }

  private pushHistory(peer: MeridianId, msg: ChatMessage): void {
    const list = this.history.get(peer) ?? [];
    list.push(msg);
    this.history.set(peer, list);
    if (msg.direction === "in") {
      this.unreadCounts.set(peer, (this.unreadCounts.get(peer) ?? 0) + 1);
      for (const cb of this.messageListeners) cb(peer, msg);
    }
  }
}
