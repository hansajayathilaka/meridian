/**
 * `FakeMeridianClientAdapter` — an in-memory, deterministic test double for
 * {@link MeridianClientAdapter}, used for screen-level component tests (tasks 12.7-12.9) and by
 * the contract tests in `adapter.test.ts`.
 *
 * **This is a fake, not an implementation.** It has no crypto, no network, no persistence, and
 * its ID "validation", safety number, and fingerprints are trivial deterministic stand-ins so
 * tests are reproducible. They are NOT format-authoritative and MUST NOT be copied into a real
 * adapter — real adapters call `meridian-core` for every one of these (apps/web/CLAUDE.md: no
 * bespoke crypto or wire types in JS/TS). It models only the *observable contract* the UI relies
 * on: trust-state transitions and the send gate (mirroring `TrustStore` semantics as the CLI/TUI
 * use them), the message-request accept-then-pin order, and the error codes.
 *
 * Methods whose name starts with `simulate`/`set` are test-only controls, not part of the
 * interface.
 */
import {
  MeridianAdapterError,
  type AccountLoadResult,
  type AccountSummary,
  type ChatMessage,
  type ClientEvent,
  type ClientEventListener,
  type ConnectionState,
  type ContactSummary,
  type FileOffer,
  type FileSource,
  type KeyProtection,
  type LumaImage,
  type MeridianClientAdapter,
  type MessageRequest,
  type ParsedId,
  type PeerId,
  type RelayPolicy,
  type SafetyNumber,
  type SendGate,
  type SentMessage,
  type TransferInfo,
  type TrustState,
  type Unsubscribe
} from './adapter';

export interface FakeAdapterOptions {
  /** Injected clock (Unix seconds). Defaults to a counter starting at 1_000 that ticks per call. */
  readonly now?: () => number;
  /** Start with an existing, ready account instead of `no-account`. */
  readonly account?: AccountSummary;
  /** Start with an existing account that is locked until `unlockAccount(passphrase)` succeeds. */
  readonly lockedWithPassphrase?: string;
}

/**
 * Mirrors core's `TrustStore` record: trust, petname, user-block and pin history live here and are
 * NEVER removed by `deleteContact` (binding interface rule — delete only drops the display entry).
 */
interface TrustRecord {
  trust: TrustState;
  petname: string | null;
  userBlocked: boolean;
  pinnedKeyHistory: { fingerprint: string; firstSeen: number; lastSeen: number }[];
}

/** Mirrors the TUI-local `contacts.json` display entry: the only thing `deleteContact` removes. */
interface DisplayEntry {
  peerId: PeerId;
  id: string;
  hint: string;
  policyOverride: RelayPolicy | null;
  addedAt: number;
}

const FAKE_ID_PATTERN = /^mrd1:([^\s@]+)(?:@([^\s@]+))?$/;

/** Deterministic, order-independent, NON-cryptographic digit string. Test stand-in only. */
function fakeDigits(a: string, b: string): string {
  const [x, y] = [a, b].sort();
  const input = `${x}|${y}`;
  let h = 2166136261;
  let out = '';
  while (out.length < 60) {
    for (let i = 0; i < input.length; i += 1) {
      h = Math.imul(h ^ input.charCodeAt(i), 16777619) >>> 0;
    }
    h = Math.imul(h ^ out.length, 16777619) >>> 0;
    out += String(h % 100000).padStart(5, '0');
  }
  return out.slice(0, 60);
}

function fakeFingerprint(peerId: PeerId): string {
  let h = 5381;
  for (let i = 0; i < peerId.length; i += 1) h = (Math.imul(h, 33) ^ peerId.charCodeAt(i)) >>> 0;
  return `fp-${h.toString(16).padStart(8, '0')}`;
}

function groups(digits: string): string {
  return digits.match(/.{1,5}/g)?.join(' ') ?? digits;
}

export class FakeMeridianClientAdapter implements MeridianClientAdapter {
  private readonly now: () => number;
  private account: AccountSummary | null;
  /** Set while the account's key is passphrase-protected (modelled so lock/unlock is testable). */
  private protectionPassphrase: string | null;
  private locked: boolean;
  private readonly trustRecords = new Map<PeerId, TrustRecord>();
  private readonly displayEntries = new Map<PeerId, DisplayEntry>();
  private readonly history = new Map<PeerId, ChatMessage[]>();
  private readonly requests = new Map<PeerId, MessageRequest>();
  private readonly offers = new Map<string, FileOffer>();
  private readonly transfers = new Map<string, TransferInfo>();
  private readonly listeners = new Set<ClientEventListener>();
  private midCounter = 0;
  private transferCounter = 0;
  private routing: { delivered: boolean; queued: boolean } = { delivered: true, queued: false };

  constructor(options: FakeAdapterOptions = {}) {
    let tick = 1_000;
    this.now = options.now ?? (() => tick++);
    this.account = options.account ?? null;
    this.protectionPassphrase = options.lockedWithPassphrase ?? null;
    this.locked = this.protectionPassphrase !== null;
  }

  // ---- Account ---------------------------------------------------------------------------------

  async loadAccount(): Promise<AccountLoadResult> {
    if (this.account !== null && this.locked) return { kind: 'locked' };
    if (this.account === null) return { kind: 'no-account' };
    return { kind: 'ready', account: { ...this.account } };
  }

  async generateAccount(hint: string, protection: KeyProtection): Promise<AccountSummary> {
    const suffix = hint === '' ? '' : `@${hint}`;
    // Distinct per hint so two fake adapters model two different principals.
    this.account = { id: `mrd1:fake-${hint === '' ? 'local' : hint}${suffix}`, label: hint === '' ? 'me' : hint };
    // A freshly generated account is unlocked for this session; a passphrase-protected key
    // relocks on `simulateRestart()` and then requires `unlockAccount`. The passphrase is held
    // only in memory to model that check and is never logged or surfaced.
    this.protectionPassphrase = protection.kind === 'passphrase' ? protection.passphrase : null;
    this.locked = false;
    return { ...this.account };
  }

  async unlockAccount(passphrase: string): Promise<AccountSummary> {
    if (this.account === null) throw new MeridianAdapterError('no-account', 'no account');
    if (this.protectionPassphrase !== null && passphrase !== this.protectionPassphrase) {
      throw new MeridianAdapterError('wrong-passphrase', 'could not unlock account');
    }
    this.locked = false;
    return { ...this.account };
  }

  async registerAccount(_server: string, _invite?: string): Promise<void> {
    this.requireAccount();
  }

  async publishBundle(_server: string, otkCount: number): Promise<{ readonly otkCount: number }> {
    this.requireAccount();
    return { otkCount };
  }

  async parseId(input: string): Promise<ParsedId> {
    const match = FAKE_ID_PATTERN.exec(input.trim());
    if (match === null) throw new MeridianAdapterError('invalid-id', 'not a valid mrd1 id');
    return { id: input.trim(), hint: match[2] ?? '' };
  }

  // ---- Contacts --------------------------------------------------------------------------------

  async listContacts(): Promise<readonly ContactSummary[]> {
    return [...this.displayEntries.values()].map((d) => this.toSummary(d));
  }

  async addContact(id: string, petname?: string): Promise<ContactSummary> {
    const parsed = await this.parseId(id);
    const peerId = this.peerIdOf(parsed.id);
    let trust = this.trustRecords.get(peerId);
    if (trust === undefined) {
      const ts = this.now();
      trust = {
        trust: 'pinned',
        petname: null,
        userBlocked: false,
        pinnedKeyHistory: [{ fingerprint: fakeFingerprint(peerId), firstSeen: ts, lastSeen: ts }]
      };
      this.trustRecords.set(peerId, trust);
    } else {
      // Repeat observation (incl. re-add after delete): state untouched; last-seen refreshed
      // (TrustStore::observe contract).
      const last = trust.pinnedKeyHistory[trust.pinnedKeyHistory.length - 1];
      if (last !== undefined) last.lastSeen = this.now();
    }
    if (!this.displayEntries.has(peerId)) {
      this.displayEntries.set(peerId, {
        peerId,
        id: parsed.id,
        hint: parsed.hint,
        policyOverride: null,
        addedAt: this.now()
      });
    }
    // set_petname runs only when a petname was explicitly supplied; never clobbers otherwise.
    if (petname !== undefined && petname !== '') trust.petname = petname;
    return this.toSummary(this.requireDisplay(peerId));
  }

  async setPetname(peerId: PeerId, petname: string | null): Promise<void> {
    this.requireTrust(peerId).petname = petname === '' ? null : petname;
  }

  async setUserBlocked(peerId: PeerId, blocked: boolean): Promise<void> {
    this.requireTrust(peerId).userBlocked = blocked;
  }

  async setPolicyOverride(peerId: PeerId, policy: RelayPolicy | null): Promise<void> {
    this.requireDisplay(peerId).policyOverride = policy;
  }

  async deleteContact(peerId: PeerId): Promise<void> {
    this.requireDisplay(peerId);
    // Display entry only. Trust / block / pin state is deliberately retained.
    this.displayEntries.delete(peerId);
  }

  // ---- Trust & verification --------------------------------------------------------------------

  async getTrustState(peerId: PeerId): Promise<TrustState> {
    return this.trustRecords.get(peerId)?.trust ?? 'new';
  }

  async getSendGate(peerId: PeerId): Promise<SendGate> {
    return this.gateOf(this.trustRecords.get(peerId));
  }

  async getSafetyNumber(peerId: PeerId): Promise<SafetyNumber> {
    const own = this.requireAccount();
    this.requireTrust(peerId);
    const digits = fakeDigits(this.peerIdOf(own.id), peerId);
    return { digits, display: groups(digits) };
  }

  async markVerified(peerId: PeerId): Promise<void> {
    this.requireTrust(peerId).trust = 'verified';
    this.emit({ type: 'trust-changed', peerId });
  }

  async acknowledgeKeyChange(peerId: PeerId): Promise<void> {
    const record = this.requireTrust(peerId);
    if (record.trust !== 'pinned-key-changed') {
      throw new MeridianAdapterError('not-acknowledgeable', 'key change cannot be acknowledged');
    }
    record.trust = 'pinned';
    this.emit({ type: 'trust-changed', peerId });
  }

  async decodeQr(image: LumaImage): Promise<string> {
    // Test stand-in: the "image" carries its payload as ASCII bytes in `luma`.
    return new TextDecoder().decode(image.luma);
  }

  async renderQrText(payload: string): Promise<string> {
    return `[fake-qr:${payload}]`;
  }

  // ---- Chat ------------------------------------------------------------------------------------

  async sendMessage(peerId: PeerId, body: string): Promise<SentMessage> {
    const record = this.requireTrust(peerId);
    // Adapter-side gate re-check (binding interface rule): blocked AND warn both refuse.
    if (this.gateOf(record).kind !== 'ok') {
      throw new MeridianAdapterError('send-blocked', 'sending is blocked for this contact');
    }
    const mid = this.nextMid();
    const ts = this.now();
    const { delivered, queued } = this.routing;
    this.appendHistory(peerId, {
      mid,
      direction: 'out',
      ts,
      stream: 'mrd.chat/1',
      body,
      state: delivered ? 'sent' : queued ? 'pending' : 'failed'
    });
    return { mid, ts, delivered, queued };
  }

  async loadHistory(peerId: PeerId): Promise<readonly ChatMessage[]> {
    return [...(this.history.get(peerId) ?? [])];
  }

  // ---- Message requests ------------------------------------------------------------------------

  async listMessageRequests(): Promise<readonly MessageRequest[]> {
    return [...this.requests.values()];
  }

  async acceptMessageRequest(senderId: PeerId): Promise<ContactSummary> {
    const request = this.requests.get(senderId);
    if (request === undefined) throw new MeridianAdapterError('not-found', 'no such request');
    // Accept, then pin — never pin before the user decides. The request is only discarded once
    // the pin succeeded: a failing addContact must not silently lose the pending request.
    const contact = await this.addContact(senderId);
    this.requests.delete(senderId);
    if (request.introText !== null) {
      this.appendHistory(senderId, {
        mid: this.nextMid(),
        direction: 'in',
        ts: this.now(),
        stream: 'mrd.chat/1',
        body: request.introText,
        state: 'received'
      });
    }
    return contact;
  }

  async rejectMessageRequest(senderId: PeerId): Promise<void> {
    // Leaves no trace: no contact, no history, nothing sent.
    if (!this.requests.delete(senderId)) {
      throw new MeridianAdapterError('not-found', 'no such request');
    }
  }

  // ---- File transfer ---------------------------------------------------------------------------

  async sendFile(peerId: PeerId, file: FileSource): Promise<TransferInfo> {
    const record = this.requireTrust(peerId);
    if (this.gateOf(record).kind !== 'ok') {
      throw new MeridianAdapterError('send-blocked', 'sending is blocked for this contact');
    }
    const name = file.kind === 'blob' ? file.name : (file.path.split(/[\\/]/).pop() ?? file.path);
    const totalBytes = file.kind === 'blob' ? file.blob.size : 1024;
    const transfer: TransferInfo = {
      transferId: this.nextTransferId(),
      peerId,
      name,
      direction: 'send',
      totalBytes,
      bytesDone: 0,
      status: 'in-progress'
    };
    this.transfers.set(transfer.transferId, transfer);
    this.emit({ type: 'transfer', transfer });
    return transfer;
  }

  async listTransfers(): Promise<readonly TransferInfo[]> {
    return [...this.transfers.values()];
  }

  async answerFileOffer(transferId: string, accept: boolean): Promise<void> {
    const offer = this.offers.get(transferId);
    if (offer === undefined) throw new MeridianAdapterError('not-found', 'no such offer');
    this.offers.delete(transferId);
    if (!accept) return;
    const transfer: TransferInfo = {
      transferId,
      peerId: offer.peerId,
      name: offer.name,
      direction: 'receive',
      totalBytes: offer.size,
      bytesDone: 0,
      status: 'in-progress'
    };
    this.transfers.set(transferId, transfer);
    this.emit({ type: 'transfer', transfer });
  }

  // ---- Events ----------------------------------------------------------------------------------

  subscribe(listener: ClientEventListener): Unsubscribe {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  // ---- Test-only controls (not part of MeridianClientAdapter) ----------------------------------

  /** Make subsequent `sendMessage` calls report this routing outcome. */
  setRouting(outcome: { delivered: boolean; queued: boolean }): void {
    this.routing = { ...outcome };
  }

  /** Inject a first-contact message request, as if it arrived off the wire. */
  simulateInboundMessageRequest(senderId: PeerId, introText: string | null): MessageRequest {
    const own = this.requireAccount();
    const request: MessageRequest = {
      senderId,
      safetyNumber: fakeDigits(this.peerIdOf(own.id), senderId),
      introText
    };
    this.requests.set(senderId, request);
    this.emit({ type: 'message-request', request });
    return request;
  }

  /** Inject an ordinary inbound chat message from an already-accepted contact. */
  simulateInboundMessage(peerId: PeerId, body: string): ChatMessage {
    this.requireTrust(peerId);
    const message: ChatMessage = {
      mid: this.nextMid(),
      direction: 'in',
      ts: this.now(),
      stream: 'mrd.chat/1',
      body,
      state: 'received'
    };
    this.appendHistory(peerId, message);
    this.emit({ type: 'message', peerId, message });
    return message;
  }

  /** Inject a delivery receipt for one of our sent messages. */
  simulateReceipt(peerId: PeerId, mid: string): void {
    const messages = this.history.get(peerId) ?? [];
    const idx = messages.findIndex((m) => m.mid === mid && m.direction === 'out');
    if (idx >= 0) messages[idx] = { ...messages[idx]!, state: 'delivered' };
    this.emit({ type: 'receipt', peerId, mid });
  }

  /**
   * Model a peer key change as `TrustStore` does: a verified contact becomes `blocked` (hard
   * stop), a pinned one becomes `pinned-key-changed` (warn-until-acknowledged). Pass
   * `escalatePinned` to model org policy escalating the pinned case straight to `blocked`.
   */
  simulateKeyChange(peerId: PeerId, escalatePinned = false): void {
    const record = this.requireTrust(peerId);
    if (record.trust === 'verified' || (record.trust === 'pinned' && escalatePinned)) {
      record.trust = 'blocked';
    } else if (record.trust === 'pinned') {
      record.trust = 'pinned-key-changed';
    }
    this.emit({ type: 'trust-changed', peerId });
  }

  /** Model an app restart: a passphrase-protected account relocks until `unlockAccount`. */
  simulateRestart(): void {
    this.locked = this.protectionPassphrase !== null;
  }

  simulateConnection(state: ConnectionState): void {
    this.emit({ type: 'connection', state });
  }

  /** Inject an inbound `mrd.file/1` OPEN that needs the user's decision. */
  simulateFileOffer(peerId: PeerId, name: string, size: number): FileOffer {
    this.requireTrust(peerId);
    const offer: FileOffer = { transferId: this.nextTransferId(), peerId, name, size };
    this.offers.set(offer.transferId, offer);
    this.emit({ type: 'file-offer', offer });
    return offer;
  }

  /** Advance a transfer; reaching `totalBytes` completes it. */
  simulateTransferProgress(transferId: string, bytesDone: number): TransferInfo {
    const current = this.transfers.get(transferId);
    if (current === undefined) throw new MeridianAdapterError('not-found', 'no such transfer');
    const done = Math.min(bytesDone, current.totalBytes);
    const next: TransferInfo = {
      ...current,
      bytesDone: done,
      status: done >= current.totalBytes ? 'completed' : 'in-progress'
    };
    this.transfers.set(transferId, next);
    this.emit({ type: 'transfer', transfer: next });
    return next;
  }

  simulateTransferFailure(transferId: string, reason: string): TransferInfo {
    const current = this.transfers.get(transferId);
    if (current === undefined) throw new MeridianAdapterError('not-found', 'no such transfer');
    const next: TransferInfo = { ...current, status: 'failed', failureReason: reason };
    this.transfers.set(transferId, next);
    this.emit({ type: 'transfer', transfer: next });
    return next;
  }

  // ---- internals -------------------------------------------------------------------------------

  private requireAccount(): AccountSummary {
    if (this.account === null) throw new MeridianAdapterError('no-account', 'no account');
    if (this.locked) throw new MeridianAdapterError('locked', 'account locked');
    return this.account;
  }

  /** The TrustStore-side record; survives `deleteContact`. */
  private requireTrust(peerId: PeerId): TrustRecord {
    const record = this.trustRecords.get(peerId);
    if (record === undefined) throw new MeridianAdapterError('unknown-contact', 'unknown contact');
    return record;
  }

  /** The display-side entry; removed by `deleteContact`. */
  private requireDisplay(peerId: PeerId): DisplayEntry {
    const entry = this.displayEntries.get(peerId);
    if (entry === undefined) throw new MeridianAdapterError('unknown-contact', 'unknown contact');
    return entry;
  }

  /** Key-only identity: strip the advisory `@hint` (same_principal ignores it). */
  private peerIdOf(id: string): PeerId {
    const at = id.indexOf('@');
    return at < 0 ? id : id.slice(0, at);
  }

  private gateOf(record: TrustRecord | undefined): SendGate {
    if (record === undefined) return { kind: 'ok' };
    // user_blocked is checked before key-change state, as TrustStore::can_send does.
    if (record.userBlocked) return { kind: 'blocked', reason: 'FAKE: you blocked this contact' };
    if (record.trust === 'blocked') {
      return { kind: 'blocked', reason: 'FAKE: key changed on a verified contact; verify again' };
    }
    if (record.trust === 'pinned-key-changed') {
      return { kind: 'warn', reason: 'FAKE: key changed; acknowledge to continue' };
    }
    return { kind: 'ok' };
  }

  private toSummary(entry: DisplayEntry): ContactSummary {
    const trust = this.requireTrust(entry.peerId);
    return {
      peerId: entry.peerId,
      id: entry.id,
      petname: trust.petname,
      hint: entry.hint,
      fingerprint: fakeFingerprint(entry.peerId),
      trust: trust.trust,
      userBlocked: trust.userBlocked,
      pinnedKeyHistory: trust.pinnedKeyHistory.map((k) => ({ ...k })),
      policyOverride: entry.policyOverride,
      addedAt: entry.addedAt
    };
  }

  private appendHistory(peerId: PeerId, message: ChatMessage): void {
    const list = this.history.get(peerId) ?? [];
    if (!list.some((m) => m.mid === message.mid)) list.push(message); // dedup by mid
    this.history.set(peerId, list);
  }

  private nextMid(): string {
    this.midCounter += 1;
    return this.midCounter.toString(16).padStart(32, '0');
  }

  private nextTransferId(): string {
    this.transferCounter += 1;
    return `xfer-${this.transferCounter}`;
  }

  private emit(event: ClientEvent): void {
    for (const listener of [...this.listeners]) {
      try {
        listener(event);
      } catch {
        // A misbehaving listener must not break the adapter or other listeners.
      }
    }
  }
}
