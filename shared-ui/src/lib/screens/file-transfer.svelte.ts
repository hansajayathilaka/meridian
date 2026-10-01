/**
 * View-model for the file-transfer screen of one peer (`mrd.file/1`, task 12.9). It only drives
 * the adapter's already-defined operations (`sendFile`, `listTransfers`, `answerFileOffer`, the
 * `transfer`/`file-offer` events); there is no protocol, integrity, or policy logic here.
 *
 * ## What the screen may claim
 * A transfer's state and byte counts are shown exactly as the adapter reports them. Per
 * stream-types-v1.md ("Known gap", task 11.8's residual) per-chunk merkle proof delivery is not yet
 * wired into the real send path, so nothing here implies integrity beyond what the adapter says.
 *
 * ## Send gate (D06 / core-api-contracts.md "Sessions & messaging") — same discipline as Chat
 * - The gate is **consulted per file, not reused**: every send first awaits a fresh
 *   `adapter.getSendGate(peerId)` and proceeds only on exactly `kind === 'ok'`. The `gate` field
 *   exists only to *render* the controls; no send decision reads it.
 * - **Fail closed:** `refreshGate()` yields `null` unless its answer is the *latest* query's and
 *   the view-model is still live, so a superseded (e.g. overtaken by `trust-changed`), disposed, or
 *   failed query never authorises a send. The adapter re-checks the gate in `sendFile` as well.
 * - Core's gate `reason` is passed through untouched, to be rendered verbatim as text.
 *
 * ## Correlation (4.21 / 12.7 review bug class: acting on a superseded or foreign async result)
 * - One view-model is bound to one peer. Events, transfers and offers naming another peer are
 *   ignored; nothing is written after `dispose()`.
 * - An accept/reject is applied to the offer it was *chosen* for (captured, never "the first
 *   offer in the list"). Choosing is separate from confirming. If the offer is voided meanwhile
 *   (the transfer started/failed, or the adapter says it is gone) the pending choice is discarded.
 * - A decision is derived from the offer as first announced: a later event reusing a transfer id
 *   cannot change the name/size under a user who is deciding, nor resurrect an answered offer.
 * - `listTransfers` snapshots can be older than `transfer` events that arrived while they were in
 *   flight: ids touched by an event since the snapshot was requested keep the event's data, and a
 *   superseded snapshot is discarded. A terminal state is never reverted to a running one.
 *
 * Wire-supplied strings (file names, failure reasons) are never interpreted here; the view renders
 * them as text only. Nothing builds a path or URL from them.
 */
import type {
  ClientEvent,
  ContactSummary,
  FileOffer,
  FileSource,
  MeridianClientAdapter,
  PeerId,
  SendGate,
  TransferInfo,
  Unsubscribe
} from '../adapter';
import { adapterErrorCode, describeError, FILE_COPY } from './copy';
import { uniqueBy } from './unique';

export type OfferDecision = 'accept' | 'reject';

export interface PendingOfferDecision {
  readonly transferId: string;
  readonly decision: OfferDecision;
}

function isTerminal(status: TransferInfo['status']): boolean {
  return status === 'completed' || status === 'failed';
}

export class FileTransferViewModel {
  readonly peerId: PeerId;
  contact: ContactSummary;
  /** Transfers with this peer (both directions), in first-seen order. */
  transfers = $state.raw<readonly TransferInfo[]>([]);
  loaded = $state(false);
  loadError = $state<string | null>(null);
  /** Inbound offers awaiting the user's decision (core already auto-accepted/rejected the rest). */
  offers = $state.raw<readonly FileOffer[]>([]);
  /** The decision awaiting confirmation, if any. */
  pending = $state.raw<PendingOfferDecision | null>(null);
  /** The offer whose answer call is in flight (one at a time). */
  busyOffer = $state<string | null>(null);
  offerError = $state<string | null>(null);
  /** Render-only snapshot of the latest gate query. NEVER consulted to authorise a send. */
  gate = $state.raw<SendGate | null>(null);
  gateUnavailable = $state(false);
  sending = $state(false);
  /** Fixed-copy outcome of the last send attempt, or `null`. */
  sendNotice = $state<string | null>(null);

  private unsubscribe: Unsubscribe | null = null;
  private disposed = false;
  private gateSeq = 0;
  private listSeq = 0;
  /** Monotonic event counter; `touched` records the counter value of each id's latest event. */
  private clock = 0;
  private readonly touched: Record<string, number> = Object.create(null) as Record<string, number>;
  /** Offers already answered (or superseded by a transfer): never shown again. */
  private readonly settledOffers: string[] = [];

  constructor(
    private readonly adapter: MeridianClientAdapter,
    initialContact: ContactSummary
  ) {
    this.peerId = initialContact.peerId;
    this.contact = $state.raw(initialContact);
  }

  start(): void {
    if (this.unsubscribe !== null || this.disposed) return; // idempotent: never a second subscription
    this.unsubscribe = this.adapter.subscribe((event) => this.onEvent(event));
    void this.refreshGate();
    void this.refresh();
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

  // ---- events ----------------------------------------------------------------------------------

  private onEvent(event: ClientEvent): void {
    if (this.disposed) return;
    switch (event.type) {
      case 'transfer':
        if (event.transfer.peerId === this.peerId) this.onTransferEvent(event.transfer);
        break;
      case 'file-offer':
        if (event.offer.peerId === this.peerId) this.onOffer(event.offer);
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

  private onTransferEvent(transfer: TransferInfo): void {
    this.clock += 1;
    this.touched[transfer.transferId] = this.clock;
    this.upsert(transfer);
    // The offer for this transfer has been acted on (accepted here or elsewhere, auto-accepted) or
    // has failed: it is no longer a decision for the user, and a confirm for it is void.
    this.voidOffer(transfer.transferId);
  }

  private onOffer(offer: FileOffer): void {
    const id = offer.transferId;
    if (this.settledOffers.includes(id)) return;
    if (this.offers.some((o) => o.transferId === id)) return; // first announcement wins
    if (this.transfers.some((t) => t.transferId === id)) return; // already a transfer
    this.offers = [...this.offers, offer];
  }

  /** Remove an offer and any decision pending on it; remember it so it cannot be re-announced. */
  private voidOffer(transferId: string): void {
    if (!this.settledOffers.includes(transferId)) this.settledOffers.push(transferId);
    if (this.offers.some((o) => o.transferId === transferId)) {
      this.offers = this.offers.filter((o) => o.transferId !== transferId);
    }
    if (this.pending?.transferId === transferId) this.pending = null;
  }

  private upsert(transfer: TransferInfo): void {
    const at = this.transfers.findIndex((t) => t.transferId === transfer.transferId);
    if (at < 0) {
      this.transfers = [...this.transfers, transfer];
      return;
    }
    const prev = this.transfers[at]!;
    // A late/stale non-terminal snapshot never reverts a terminal state, and a failure is sticky:
    // nothing overwrites it with "complete". A transfer reported complete may still be shown as
    // failed if the adapter later says so (e.g. a whole-file check failing after all bytes arrived).
    if (isTerminal(prev.status) && !isTerminal(transfer.status)) return;
    if (prev.status === 'failed' && transfer.status !== 'failed') return;
    this.transfers = this.transfers.map((t, i) => (i === at ? transfer : t));
  }

  // ---- loading ---------------------------------------------------------------------------------

  async refresh(): Promise<void> {
    const seq = ++this.listSeq;
    const requestedAt = this.clock;
    try {
      const list = await this.adapter.listTransfers();
      if (this.disposed || seq !== this.listSeq) return;
      for (const t of uniqueBy(list, (x) => x.transferId)) {
        if (t.peerId !== this.peerId) continue;
        // An event newer than this snapshot's request is fresher than the snapshot.
        if ((this.touched[t.transferId] ?? -1) > requestedAt) continue;
        this.upsert(t);
        this.voidOffer(t.transferId);
      }
      this.loaded = true;
      this.loadError = null;
    } catch (e) {
      if (!this.disposed && seq === this.listSeq) this.loadError = describeError(e, 'load');
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
   * the latest gate query and the view-model is live; otherwise it resolves to `null`, which every
   * caller must treat as "not allowed". Callers act on the returned value, never on `this.gate`.
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

  // ---- sending ---------------------------------------------------------------------------------

  /** Send browser `File`s (drag-drop or picker): the adapter's `blob` source. */
  async sendFiles(files: readonly File[]): Promise<void> {
    await this.sendSources(files.map((f) => ({ kind: 'blob', blob: f, name: f.name })));
  }

  /** Send native paths chosen by a desktop shell: the adapter's `path` source. */
  async sendPaths(paths: readonly string[]): Promise<void> {
    await this.sendSources(paths.map((path) => ({ kind: 'path', path })));
  }

  /**
   * The single choke point for every outgoing file. Each file is gated by its own fresh query; the
   * batch stops at the first gate that is not `ok`, or at the first adapter failure.
   */
  async sendSources(sources: readonly FileSource[]): Promise<void> {
    if (this.disposed || sources.length === 0) return;
    if (this.sending) {
      // Not queued: say so, rather than letting the files vanish. Each file the user drops again
      // after the batch finishes gets its own fresh gate check like any other.
      this.sendNotice = FILE_COPY.busy;
      return;
    }
    this.sending = true;
    this.sendNotice = null;
    try {
      for (let i = 0; i < sources.length; i += 1) {
        const unsent = sources.length - i;
        // Fresh consult, every time. Anything but an explicit `ok` stops here.
        const gate = await this.refreshGate();
        if (gate === null || gate.kind !== 'ok') {
          if (!this.disposed) {
            // `blocked`/`warn` are explained by the banner; "no verdict" is not.
            this.sendNotice =
              gate === null
                ? FILE_COPY.gateUnconfirmed + FILE_COPY.notSentSuffix(unsent)
                : unsent > 1 && sources.length > 1
                  ? `Sending is not allowed.${FILE_COPY.notSentSuffix(unsent)}`
                  : null;
          }
          return;
        }

        let transfer: TransferInfo;
        try {
          transfer = await this.adapter.sendFile(this.peerId, sources[i]!);
        } catch (e) {
          if (adapterErrorCode(e) === 'send-blocked') {
            this.gate = null;
            void this.refreshGate();
          }
          if (!this.disposed) {
            this.sendNotice = describeError(e, 'file-send') + FILE_COPY.notSentSuffix(unsent - 1);
          }
          return;
        }
        if (this.disposed) return;
        // Only this peer's transfer is ever shown, and any event already received for it is newer
        // than this resolve's snapshot.
        if (
          transfer.peerId === this.peerId &&
          !this.transfers.some((t) => t.transferId === transfer.transferId)
        ) {
          this.upsert(transfer);
        }
      }
    } finally {
      this.sending = false;
    }
  }

  // ---- incoming offers -------------------------------------------------------------------------

  /** Step 1: ask for confirmation of a decision on a listed offer. */
  choose(transferId: string, decision: OfferDecision): void {
    if (this.disposed || this.busyOffer !== null) return;
    if (!this.offers.some((o) => o.transferId === transferId)) return; // not (or no longer) offered
    this.offerError = null;
    this.pending = { transferId, decision };
  }

  cancel(): void {
    if (this.busyOffer === null) this.pending = null;
  }

  /** Step 2: carry out the confirmed decision against exactly the offer it was chosen for. */
  async confirm(): Promise<void> {
    const chosen = this.pending;
    if (chosen === null || this.busyOffer !== null || this.disposed) return;
    const { transferId, decision } = chosen;
    if (!this.offers.some((o) => o.transferId === transferId)) {
      this.pending = null; // voided since it was chosen
      return;
    }
    this.busyOffer = transferId;
    this.offerError = null;
    let answered = false;
    try {
      await this.adapter.answerFileOffer(transferId, decision === 'accept');
      answered = true;
    } catch (e) {
      if (!this.disposed) {
        this.offerError = describeError(e, 'file-answer');
        if (adapterErrorCode(e) === 'not-found') this.voidOffer(transferId); // stale: gone for good
      }
    } finally {
      if (!this.disposed) {
        this.busyOffer = null;
        if (this.pending?.transferId === transferId) this.pending = null;
      }
    }
    if (answered && !this.disposed) {
      this.voidOffer(transferId);
      void this.refresh(); // authoritative: an accepted offer is now a transfer
    }
  }
}
