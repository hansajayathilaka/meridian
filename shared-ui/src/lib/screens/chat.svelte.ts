/**
 * View-model for one 1:1 conversation.
 *
 * ## Trust invariant (D06 / system-design.md §4.4; core-api-contracts.md "Sessions & messaging")
 * - The send gate is **consulted per send, not reused**: every send (including a retry) first
 *   awaits a fresh `adapter.getSendGate(peerId)` and proceeds only on exactly `kind === 'ok'`. The
 *   `gate` field below exists only to *render* the composer/banner; no send decision reads it.
 * - **Fail closed:** `refreshGate()` yields `null` unless its answer is the *latest* query's and
 *   this view-model is still live. A query that was superseded (e.g. by a `trust-changed`
 *   re-query that may have returned `warn`/`blocked`) or that outlived `dispose()`, failed, or
 *   never answered therefore never authorises a send. In the UI, `gate === null` (loading,
 *   re-querying, failed) means no composer; `blocked` and `warn` remove the composer entirely.
 *   Residual window: the gate can change between the `ok` answer and `sendMessage` taking effect;
 *   that window is closed only by the adapter's own re-check in `sendMessage` (interface rule).
 * - The adapter re-checks the gate in `sendMessage` (defence in depth); a `send-blocked` rejection
 *   here just triggers a re-query.
 * - Core's gate `reason` is passed through untouched for the view to render verbatim as text.
 *
 * ## Correlation (lessons from the TUI's 4.20/4.21 review findings)
 * One view-model instance is bound to one peer (the screen re-creates it when the peer changes).
 * Inbound events are accepted only when they name that peer's id, and nothing is written after
 * `dispose()`. Messages are deduplicated by `mid`.
 *
 * Failure copy never uses the advisory `hint` (wire-populated, attacker-influenced): it names the
 * peer by petname or fingerprint only, and never says "will deliver later" for an undelivered
 * message (tui-client.md §7).
 */
import type {
  ChatMessage,
  ClientEvent,
  ContactSummary,
  MeridianClientAdapter,
  MessageState,
  PeerId,
  SendGate,
  SentMessage,
  Unsubscribe
} from '../adapter';
import { adapterErrorCode, describeError } from './copy';

export type SendNotice =
  /** Not delivered, nothing queued: retry is offered. */
  | { readonly kind: 'failed'; readonly mid: string; readonly body: string; readonly text: string }
  /** Durably queued server-side: shown as sent plus a one-time notice; never a retry. */
  | { readonly kind: 'queued'; readonly text: string }
  | { readonly kind: 'error'; readonly text: string };

function mergeByMid(
  base: readonly ChatMessage[],
  incoming: readonly ChatMessage[]
): readonly ChatMessage[] {
  // Later write wins; an overwritten entry keeps its original position before the stable sort.
  const merged: ChatMessage[] = [];
  for (const m of [...base, ...incoming]) {
    const at = merged.findIndex((x) => x.mid === m.mid);
    if (at < 0) {
      merged.push(m);
      continue;
    }
    const prev = merged[at]!;
    // A delivery receipt is never undone by a stale snapshot (e.g. a slow history load).
    merged[at] =
      prev.direction === 'out' && prev.state === 'delivered' && m.state !== 'delivered'
        ? { ...m, state: 'delivered' }
        : m;
  }
  return merged.sort((a, b) => a.ts - b.ts); // stable
}

export class ChatViewModel {
  readonly peerId: PeerId;
  contact: ContactSummary;
  messages = $state.raw<readonly ChatMessage[]>([]);
  /** Render-only snapshot of the latest gate query. NEVER consulted to authorise a send. */
  gate = $state.raw<SendGate | null>(null);
  /** The latest gate query failed: shown as "could not check", composer stays hidden. */
  gateUnavailable = $state(false);
  draft = $state('');
  sending = $state(false);
  notice = $state.raw<SendNotice | null>(null);
  loadError = $state<string | null>(null);

  private unsubscribe: Unsubscribe | null = null;
  private disposed = false;
  private gateSeq = 0;
  /** Receipts seen for mids not (yet) in `messages`, e.g. one racing `sendMessage`'s own resolve. */
  private ackedMids: string[] = [];

  constructor(
    private readonly adapter: MeridianClientAdapter,
    initialContact: ContactSummary
  ) {
    this.peerId = initialContact.peerId;
    this.contact = $state.raw(initialContact);
  }

  start(): void {
    this.unsubscribe = this.adapter.subscribe((event) => this.onEvent(event));
    void this.refreshGate();
    void this.loadHistory();
  }

  /** Adopt a fresher contact record from the parent. Ignored for any other peer. */
  syncContact(contact: ContactSummary): void {
    if (contact.peerId === this.peerId) this.contact = contact;
  }

  dispose(): void {
    this.disposed = true;
    this.unsubscribe?.();
    this.unsubscribe = null;
  }

  /** Name used in delivery-failure copy: petname or fingerprint, never the wire-supplied hint. */
  private get failureLabel(): string {
    const { petname, fingerprint } = this.contact;
    return petname !== null && petname !== '' ? petname : fingerprint;
  }

  private onEvent(event: ClientEvent): void {
    if (this.disposed) return;
    switch (event.type) {
      case 'message':
        if (event.peerId === this.peerId) this.messages = mergeByMid(this.messages, [event.message]);
        break;
      case 'receipt':
        if (event.peerId === this.peerId) this.markDelivered(event.mid);
        break;
      case 'trust-changed':
        if (event.peerId === this.peerId) {
          this.gate = null; // fail closed while the fresh answer is in flight
          void this.refreshGate();
          void this.refreshContact();
        }
        break;
      default:
        break; // other peers' / other screens' events are not ours
    }
  }

  private markDelivered(mid: string): void {
    if (!this.ackedMids.includes(mid)) this.ackedMids.push(mid);
    this.messages = this.applyAcks(this.messages);
  }

  /** Re-apply receipts to outgoing messages that do not yet show `delivered`. */
  private applyAcks(list: readonly ChatMessage[]): readonly ChatMessage[] {
    return list.map((m) =>
      m.direction === 'out' && m.state !== 'delivered' && this.ackedMids.includes(m.mid)
        ? { ...m, state: 'delivered' as const }
        : m
    );
  }

  async loadHistory(): Promise<void> {
    try {
      const history = await this.adapter.loadHistory(this.peerId);
      if (this.disposed) return;
      this.messages = this.applyAcks(mergeByMid(this.messages, history));
      this.loadError = null;
    } catch (e) {
      if (!this.disposed) this.loadError = describeError(e, 'load');
    }
  }

  private async refreshContact(): Promise<void> {
    try {
      const list = await this.adapter.listContacts();
      if (this.disposed) return;
      const fresh = list.find((c) => c.peerId === this.peerId);
      if (fresh !== undefined) this.contact = fresh;
    } catch {
      // Keep the last known header; the gate (queried separately) is what protects sends.
    }
  }

  /**
   * Ask core for the gate now. Resolves to exactly what the adapter said, but ONLY if this is still
   * the latest gate query and the view-model is live; otherwise (superseded, disposed, or the
   * query failed) it resolves to `null`, which every caller must treat as "not allowed". A
   * superseded answer is stale by definition — a newer query (e.g. after `trust-changed`) may have
   * said `warn`/`blocked` — so it must never authorise a send. Callers act on the returned value,
   * never on `this.gate`.
   */
  async refreshGate(): Promise<SendGate | null> {
    const seq = ++this.gateSeq;
    let result: SendGate | null;
    try {
      result = await this.adapter.getSendGate(this.peerId);
    } catch {
      result = null;
    }
    if (this.disposed || seq !== this.gateSeq) return null;
    this.gate = result;
    this.gateUnavailable = result === null;
    return result;
  }

  /** Send the composer draft. */
  async send(): Promise<void> {
    const body = this.draft;
    if (body.trim() === '') return;
    const sent = await this.sendBody(body, null);
    // Clear only if the user has not typed something new while the send was in flight.
    if (sent && this.draft === body) this.draft = '';
  }

  /** Retry the last undelivered message — through the same gate-checked path as any send. */
  async retry(): Promise<void> {
    const notice = this.notice;
    if (notice === null || notice.kind !== 'failed') return;
    await this.sendBody(notice.body, notice.mid);
  }

  /**
   * The single choke point for every outgoing message (composer and retry alike). Returns whether
   * the adapter accepted the send (delivered, queued, or reported undelivered) — `false` means
   * nothing was attempted or it was refused.
   */
  private async sendBody(body: string, replaceMid: string | null): Promise<boolean> {
    if (this.sending || this.disposed) return false;
    this.sending = true;
    this.notice = null;
    try {
      // Fresh consult, every time. Anything but an explicit `ok` stops here.
      const gate = await this.refreshGate();
      if (gate === null || gate.kind !== 'ok') {
        // `blocked`/`warn` are explained by the banner; "no verdict" (failed, superseded) is not.
        if (!this.disposed && gate === null) {
          this.notice = {
            kind: 'error',
            text: 'Could not confirm that sending is allowed. Please try again.'
          };
        }
        return false;
      }

      let result: SentMessage;
      try {
        result = await this.adapter.sendMessage(this.peerId, body);
      } catch (e) {
        if (adapterErrorCode(e) === 'send-blocked') {
          this.gate = null;
          void this.refreshGate();
        }
        if (!this.disposed) this.notice = { kind: 'error', text: describeError(e, 'send') };
        return false;
      }
      if (this.disposed) return true;

      // Optimistic checkmarks are never rendered for a send the transport did not confirm:
      // delivered or durably queued => `sent`; otherwise `failed`.
      const acked = this.ackedMids.includes(result.mid); // receipt beat the send's own resolve
      const state: MessageState = acked
        ? 'delivered'
        : result.delivered || result.queued
          ? 'sent'
          : 'failed';
      const entry: ChatMessage = {
        mid: result.mid,
        direction: 'out',
        ts: result.ts,
        stream: 'mrd.chat/1',
        body,
        state
      };
      const base =
        replaceMid === null ? this.messages : this.messages.filter((m) => m.mid !== replaceMid);
      this.messages = mergeByMid(base, [entry]);

      if (state === 'failed') {
        this.notice = {
          kind: 'failed',
          mid: result.mid,
          body,
          text: `Not delivered — ${this.failureLabel} is offline.`
        };
      } else if (state !== 'delivered' && !result.delivered) {
        this.notice = {
          kind: 'queued',
          text: `Queued — ${this.failureLabel} is offline; it will arrive when they reconnect.`
        };
      }
      return true;
    } finally {
      this.sending = false;
    }
  }
}
