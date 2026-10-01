/**
 * View-model for the first-contact message-request queue (system-design.md §3.5): never
 * auto-delivered, never auto-accepted, and no new signal to the sender on accept/reject. Surfaces
 * the already-existing state machine only — accept = `acceptMessageRequest` (core accepts, *then*
 * pins), reject = `rejectMessageRequest` (discards, sends nothing back).
 *
 * Each decision is a two-step (choose, then confirm), mirroring the TUI's y/n confirm, because
 * accept leads to TOFU-pinning and reject discards the session.
 *
 * Correlation (the 4.21 review finding): a decision's completion is applied to the sender it was
 * issued for — captured in the call, not read from "the currently selected row" — and results for
 * `senderId`s the user did not act on are never applied.
 */
import type {
  ClientEvent,
  ContactSummary,
  MeridianClientAdapter,
  MessageRequest,
  PeerId,
  Unsubscribe
} from '../adapter';
import { describeError } from './copy';
import { notify } from './safe-call';
import { uniqueBy } from './unique';

export type Decision = 'accept' | 'reject';

export interface PendingDecision {
  readonly senderId: PeerId;
  readonly decision: Decision;
}

export class MessageRequestsViewModel {
  requests = $state.raw<readonly MessageRequest[]>([]);
  /** The decision awaiting confirmation, if any. */
  pending = $state.raw<PendingDecision | null>(null);
  /** The sender whose accept/reject call is in flight (one at a time). */
  busySender = $state<PeerId | null>(null);
  error = $state<string | null>(null);
  loaded = $state(false);

  private unsubscribe: Unsubscribe | null = null;
  private disposed = false;
  private listSeq = 0;

  constructor(
    private readonly adapter: MeridianClientAdapter,
    private readonly hooks: {
      onaccepted?: (contact: ContactSummary) => void;
      onrejected?: (senderId: PeerId) => void;
    } = {}
  ) {}

  start(): void {
    this.unsubscribe = this.adapter.subscribe((event) => this.onEvent(event));
    void this.refresh();
  }

  dispose(): void {
    this.disposed = true;
    this.unsubscribe?.();
    this.unsubscribe = null;
  }

  private onEvent(event: ClientEvent): void {
    if (this.disposed) return;
    // Re-query rather than patch: the adapter's queue is authoritative (and dedupes by sender).
    if (event.type === 'message-request') void this.refresh();
  }

  async refresh(): Promise<void> {
    const seq = ++this.listSeq;
    try {
      const list = await this.adapter.listMessageRequests();
      if (this.disposed || seq !== this.listSeq) return;
      this.requests = uniqueBy(list, (r) => r.senderId);
      this.loaded = true;
      // A decision awaiting confirmation for a request that has since vanished is void.
      if (this.pending !== null && !list.some((r) => r.senderId === this.pending?.senderId)) {
        this.pending = null;
      }
    } catch (e) {
      if (!this.disposed && seq === this.listSeq) this.error = describeError(e, 'load');
    }
  }

  /** Step 1: ask for confirmation. Does nothing while a decision is in flight. */
  choose(senderId: PeerId, decision: Decision): void {
    if (this.busySender !== null) return;
    this.error = null;
    this.pending = { senderId, decision };
  }

  cancel(): void {
    if (this.busySender === null) this.pending = null;
  }

  /** Step 2: carry out the confirmed decision against exactly the sender it was chosen for. */
  async confirm(): Promise<void> {
    const chosen = this.pending;
    if (chosen === null || this.busySender !== null) return;
    const { senderId, decision } = chosen;
    this.busySender = senderId;
    this.error = null;
    let accepted: ContactSummary | null = null;
    let succeeded = false;
    try {
      if (decision === 'accept') {
        accepted = await this.adapter.acceptMessageRequest(senderId);
      } else {
        await this.adapter.rejectMessageRequest(senderId);
      }
      succeeded = true;
    } catch (e) {
      if (!this.disposed) this.error = describeError(e, 'request');
    } finally {
      if (!this.disposed) {
        this.busySender = null;
        if (this.pending?.senderId === senderId) this.pending = null;
        await this.refresh(); // authoritative: a successful decision removed it; a failure kept it
      }
    }
    // Outside the try: the decision already took effect, so a throwing shell callback must not
    // be shown as a failure of it.
    if (succeeded) {
      if (accepted !== null) notify(this.hooks.onaccepted, accepted);
      else notify(this.hooks.onrejected, senderId);
    }
  }
}
