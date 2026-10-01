/**
 * View-model for the safety-number verification screen (task 12.8; D06, system-design.md §4.4,
 * verification-ux.md). Presentation over core's trust surface, as the terminal client's 4.22 is: no
 * new trust logic, no QR codec, no crypto, no wire types. Everything authoritative comes through
 * `MeridianClientAdapter`: the number (`getSafetyNumber`), the QR to display (`renderQrText`), QR
 * decoding of a scanned frame (`decodeQr`), the gate (`getSendGate`), and the three trust mutations
 * (`markVerified`, `acknowledgeKeyChange`, `setUserBlocked`).
 *
 * ## The one safety-critical rule
 * `adapter.markVerified` takes no proof, so THIS view-model is the only guard that the safety
 * numbers actually matched. It is called from exactly one place ({@link confirmVerified}) and only:
 *  1. on an explicit user action (a click on the confirm button; nothing here ever triggers it from
 *     a scan result, a timer, or an event), and
 *  2. while the check is in `matched` (a scanned payload that is *exactly* — `===`, no trimming, no
 *     normalisation, no prefix/partial/fuzzy comparison — the 60 digits core returned for THIS peer)
 *     or `manual` (the user explicitly said the digits read aloud were identical), and
 *  3. after a fresh `getSafetyNumber` still equals the number that was compared (a key change under
 *     the user is caught and aborts), and
 *  4. only if nothing superseded the check meanwhile (see "Staleness").
 * A mismatch is a dead end: it offers no "verify anyway", and it also disables the manual
 * "digits match" path until a later scan exactly matches (a user who scanned a different code must
 * not be one tap from verifying anyway). Decode failures, non-safety-number QR codes, partial or
 * garbled payloads, scans of another peer's code, and results that arrive after the peer changed
 * or the screen was disposed can only ever leave the check unchanged or at `mismatch`.
 *
 * ## Scope of the sticky mismatch, and self-scan symmetry
 * `mismatchSeen` lives in this view-model only: leaving and re-entering the screen builds a fresh
 * instance and reopens the manual path (consistent with the CLI, which keeps no mismatch memory
 * between runs). Note also the safety number is symmetric: scanning the QR this device displays
 * itself decodes to the exact expected digits and would reach `matched`. The explicit confirm prompt
 * ("compared out-of-band with the other person") is the mitigation; this view-model does not try
 * to detect a self-scan.
 *
 * ## Staleness (the 12.7 review's bug class: a SUPERSEDED async result must not be acted on)
 * One instance is bound to one peer (the screen is `{#key}`ed on the peer). Every async result is
 * checked after its `await` against what it was issued for, and discarded if the view-model was
 * disposed, a newer query/scan superseded it, or the state it was computed against changed:
 *  - number/QR loads: sequence-guarded; `trust-changed` for this peer drops the number to `null`
 *    (no number => no scan can match and no verify can be confirmed) until the fresh one arrives.
 *  - scan frames: tagged with the scan id; a frame decoded after the scan was stopped/restarted/
 *    superseded, or against a number that has since been replaced (identity-compared), is dropped.
 *  - `confirmVerified`: the check state object and the number object it started from must still be
 *    the current ones after its fresh `getSafetyNumber`, else it returns without calling
 *    `markVerified`.
 *  - acknowledge: acts on the freshly *returned* gate of that call only, never on `this.gate`.
 *
 * ## `warn` vs `markVerified` (mirrors 4.22)
 * `blocked` (verified-contact key change, or a local block): only `markVerified` clears a key-change
 * block; there is no acknowledge path. `warn` (pinned key changed): Verify is primary; "Acknowledge
 * without verifying" is offered only while the gate is `warn`, behind a confirm step, and is
 * re-checked against a fresh gate at confirm time. Core's `reason` text is passed through untouched.
 *
 * Failure copy is fixed UI strings (`copy.ts`); thrown values and the advisory hint are never
 * rendered.
 */
import type {
  ClientEvent,
  ContactSummary,
  LumaImage,
  MeridianClientAdapter,
  SafetyNumber,
  SendGate,
  Unsubscribe
} from '../adapter';
import type { QrScanFailure, QrScanner, QrScanSession } from '../qr-scanner';
import { QrScannerError } from '../qr-scanner';
import { VERIFY_COPY, describeError } from './copy';
import { notify } from './safe-call';

/**
 * The comparison state machine.
 *  - `idle`: nothing compared yet.
 *  - `scanning`: camera open, frames are being decoded.
 *  - `matched`: a scan decoded to exactly the expected 60 digits. Still NOT verified: the user must
 *    explicitly confirm.
 *  - `manual`: the user opened the "the digits match" confirm prompt (out-of-band comparison).
 * A mismatch is the separate `mismatchSeen` flag (see the class doc), not a state with an exit to
 * `manual`/`matched` other than a later exact scan match.
 */
export type CheckState =
  | { readonly kind: 'idle' }
  | { readonly kind: 'scanning' }
  | { readonly kind: 'matched' }
  | { readonly kind: 'manual' };

/** A pending confirm step for the two non-verify actions. */
export type ActionPrompt =
  | { readonly kind: 'acknowledge' }
  /** `blocked` is the direction that was shown to the user (true = block, false = unblock). */
  | { readonly kind: 'block'; readonly blocked: boolean };

export type VerifyNotice =
  | { readonly kind: 'success'; readonly text: string }
  | { readonly kind: 'info'; readonly text: string }
  | { readonly kind: 'error'; readonly text: string };

/** A safety number is exactly 60 ASCII digits (design §4.4). Anything else is not usable. */
const SAFETY_NUMBER_SHAPE = /^[0-9]{60}$/;

/**
 * Usable = exactly 60 digits AND a display form that is those same digits (only separating spaces
 * added). A display that disagrees with the digits would show the user one number while the QR and
 * the match logic use another, so it fails closed.
 */
function isUsableNumber(n: SafetyNumber | null | undefined): n is SafetyNumber {
  return (
    n !== null &&
    n !== undefined &&
    typeof n.digits === 'string' &&
    SAFETY_NUMBER_SHAPE.test(n.digits) &&
    typeof n.display === 'string' &&
    n.display.replace(/ /g, '') === n.digits
  );
}

/** Fixed copy for a camera failure; an unknown/hostile shell-supplied reason maps to `unavailable`. */
function scanFailureCopy(reason: unknown): string {
  const table: Record<string, string> = VERIFY_COPY.scanFailure;
  return typeof reason === 'string' && Object.hasOwn(table, reason)
    ? table[reason]!
    : VERIFY_COPY.scanFailure.unavailable;
}

/** Give up on a single frame's decode after this long (a hung decoder must not starve the scan). */
const DEFAULT_DECODE_TIMEOUT_MS = 5000;

export class VerificationViewModel {
  readonly peerId: string;
  contact: ContactSummary;

  /** The number core computed for (us, this peer); `null` while loading/failed/after a key change. */
  numbers = $state.raw<SafetyNumber | null>(null);
  numbersFailed = $state(false);
  /** `renderQrText` of the digits (text QR only: no pixel/SVG render exists in the adapter). */
  qrText = $state<string | null>(null);
  qrFailed = $state(false);

  /** Render-only snapshot of the latest gate query; no decision reads it (see acknowledge). */
  gate = $state.raw<SendGate | null>(null);
  gateUnavailable = $state(false);

  check = $state.raw<CheckState>({ kind: 'idle' });
  /** A scan decoded to a full 60-digit number that is NOT this peer's. Sticky; see class doc. */
  mismatchSeen = $state(false);
  /** Transient scan hint (non-safety-number QR in view) or camera failure copy. */
  scanNote = $state<string | null>(null);
  prompt = $state.raw<ActionPrompt | null>(null);
  busy = $state(false);
  notice = $state.raw<VerifyNotice | null>(null);

  private unsubscribe: Unsubscribe | null = null;
  private session: QrScanSession | null = null;
  private disposed = false;
  private numbersSeq = 0;
  private gateSeq = 0;
  private contactSeq = 0;
  private scanId = 0;
  /** The id of the scan whose decode is in flight (one at a time per scan), else `null`. */
  private decodingScan: number | null = null;

  constructor(
    private readonly adapter: MeridianClientAdapter,
    initialContact: ContactSummary,
    private readonly scanner: QrScanner | null = null,
    private readonly hooks: {
      onverified?: (contact: ContactSummary) => void;
      /** Per-frame decode timeout (ms); a test seam, default 5000. */
      decodeTimeoutMs?: number;
    } = {}
  ) {
    this.peerId = initialContact.peerId;
    this.contact = $state.raw(initialContact);
  }

  /** Whether a camera scanner was injected (the shell decides; absent => manual compare only). */
  get canScan(): boolean {
    return this.scanner !== null;
  }

  /** Whether the manual "digits match" path may be opened (never after a mismatch). */
  get canCompareManually(): boolean {
    return this.numbers !== null && !this.mismatchSeen && !this.busy;
  }

  start(): void {
    this.unsubscribe = this.adapter.subscribe((event) => this.onEvent(event));
    void this.loadNumbers();
    void this.refreshGate();
    void this.refreshContact();
  }

  /** Adopt a fresher contact record from the parent. Ignored for any other peer. */
  syncContact(contact: ContactSummary): void {
    if (contact.peerId === this.peerId) this.contact = contact;
  }

  dispose(): void {
    this.disposed = true;
    this.endScan();
    this.unsubscribe?.();
    this.unsubscribe = null;
  }

  private onEvent(event: ClientEvent): void {
    if (this.disposed) return;
    if (event.type !== 'trust-changed' || event.peerId !== this.peerId) return;
    // The peer's key/trust changed: whatever was being compared (a scan, a matched result, an open
    // prompt) was computed against a number that may no longer exist. Drop it all and re-query.
    const wasComparing = this.check.kind !== 'idle';
    this.endScan();
    this.check = { kind: 'idle' };
    this.prompt = null;
    if (wasComparing) this.notice = { kind: 'info', text: VERIFY_COPY.staleNumber };
    this.mismatchSeen = false;
    this.scanNote = null;
    this.numbers = null; // fail closed: no number, nothing can match or be confirmed
    this.qrText = null;
    this.gate = null;
    void this.loadNumbers();
    void this.refreshGate();
    void this.refreshContact();
  }

  // ---- queries (each sequence-guarded: a superseded/disposed answer is discarded) ----------------

  async loadNumbers(): Promise<void> {
    const seq = ++this.numbersSeq;
    this.numbersFailed = false;
    this.qrFailed = false;
    let fetched: SafetyNumber | null;
    try {
      fetched = await this.adapter.getSafetyNumber(this.peerId);
    } catch {
      fetched = null;
    }
    if (this.disposed || seq !== this.numbersSeq) return;
    if (!isUsableNumber(fetched)) {
      // A missing or malformed number (e.g. empty) must never become the thing scans are compared
      // against: an empty/garbled "expected" value could equal an empty/garbled decode.
      this.numbers = null;
      this.numbersFailed = true;
      return;
    }
    const numbers = fetched;
    this.numbers = numbers;
    try {
      const qr = await this.adapter.renderQrText(numbers.digits);
      if (this.disposed || seq !== this.numbersSeq) return;
      this.qrText = typeof qr === 'string' ? qr : null;
      this.qrFailed = typeof qr !== 'string';
    } catch {
      if (this.disposed || seq !== this.numbersSeq) return;
      this.qrText = null;
      this.qrFailed = true; // digits remain usable for the manual compare
    }
  }

  /**
   * Ask core for the gate now. Resolves to exactly what the adapter said ONLY if this is still the
   * latest gate query and the view-model is live; otherwise (superseded, disposed, failed) `null`,
   * which every caller must treat as "not allowed / unknown". Callers act on the returned value,
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

  private async refreshContact(): Promise<void> {
    const seq = ++this.contactSeq;
    try {
      const list = await this.adapter.listContacts();
      if (this.disposed || seq !== this.contactSeq) return;
      const fresh = list.find((c) => c.peerId === this.peerId);
      if (fresh !== undefined) this.contact = fresh;
    } catch {
      // Keep the last known header; the gate is queried separately and is what protects sends.
    }
  }

  // ---- camera scan ---------------------------------------------------------------------------------

  /** Open the camera (via the injected scanner) and start decoding frames. */
  async startScan(): Promise<void> {
    if (this.scanner === null || this.disposed || this.busy || this.numbers === null) return;
    this.endScan(); // a restart supersedes any earlier scan (and its in-flight decode)
    const id = this.scanId;
    this.check = { kind: 'scanning' };
    this.prompt = null;
    this.scanNote = null;
    this.notice = null;
    let session: QrScanSession;
    try {
      session = await this.scanner.start({
        onFrame: (frame) => void this.onFrame(id, frame),
        onError: (reason) => this.onScanError(id, reason)
      });
    } catch (e) {
      if (this.disposed || id !== this.scanId) return;
      this.check = { kind: 'idle' };
      this.scanNote = scanFailureCopy(e instanceof QrScannerError ? e.reason : 'unavailable');
      return;
    }
    if (this.disposed || id !== this.scanId) {
      session.stop(); // superseded/disposed while the camera was opening: release it at once
      return;
    }
    this.session = session;
  }

  /** Stop scanning without a verdict. */
  stopScan(): void {
    if (this.check.kind !== 'scanning') return;
    this.endScan();
    this.check = { kind: 'idle' };
  }

  /** Invalidate the current scan: drops in-flight decodes/frames and releases the camera. */
  private endScan(): void {
    this.scanId += 1;
    const session = this.session;
    this.session = null;
    try {
      session?.stop();
    } catch {
      // A shell scanner that throws on stop() must not abort teardown (unsubscribe, state reset).
      // The thrown value is dropped, not logged.
    }
  }

  private onScanError(id: number, reason: QrScanFailure): void {
    if (this.disposed || id !== this.scanId || this.check.kind !== 'scanning') return;
    this.endScan();
    this.check = { kind: 'idle' };
    this.scanNote = scanFailureCopy(reason);
  }

  private async onFrame(id: number, frame: LumaImage): Promise<void> {
    if (this.disposed || id !== this.scanId || this.check.kind !== 'scanning') return;
    if (this.decodingScan === id) return; // drop frames while THIS scan has a decode in flight
    const expected = this.numbers;
    if (expected === null) return;
    this.decodingScan = id;
    let decoded: unknown;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      decoded = await Promise.race([
        this.adapter.decodeQr(frame),
        new Promise<null>((resolve) => {
          timer = setTimeout(() => resolve(null), this.hooks.decodeTimeoutMs ?? DEFAULT_DECODE_TIMEOUT_MS);
        })
      ]);
    } catch {
      decoded = null; // no QR in this frame / undecodable: keep scanning, never a verdict
    } finally {
      clearTimeout(timer);
      // Only release the slot if it is still this scan's: an older scan's late finish must not
      // clear a newer scan's in-flight marker.
      if (this.decodingScan === id) this.decodingScan = null;
    }
    // Superseded (stopped, restarted, trust changed, disposed) or the number was replaced while
    // decoding: this result is about a comparison that no longer exists. Discard it.
    if (this.disposed || id !== this.scanId || this.check.kind !== 'scanning') return;
    if (this.numbers !== expected) return;
    if (typeof decoded !== 'string') return;

    if (!SAFETY_NUMBER_SHAPE.test(decoded)) {
      // Not a complete safety number (an ID QR, partial/garbled payload, someone else's poster).
      // Not evidence of an attack, and never a match: say so and keep scanning.
      this.scanNote = VERIFY_COPY.notSafetyNumber;
      return;
    }
    this.endScan(); // stop the camera on any verdict
    if (decoded === expected.digits) {
      // Exact, full, strict equality with the number core returned for THIS peer.
      this.mismatchSeen = false;
      this.scanNote = null;
      this.check = { kind: 'matched' };
    } else {
      this.mismatchSeen = true;
      this.scanNote = null;
      this.check = { kind: 'idle' };
    }
  }

  // ---- verify --------------------------------------------------------------------------------------

  /**
   * The user states the digits were compared out-of-band and are identical. Opens the confirm
   * prompt only; it never verifies by itself. Unavailable after a mismatch.
   */
  beginManualCompare(): void {
    if (!this.canCompareManually) return;
    this.endScan();
    this.prompt = null;
    this.notice = null;
    this.scanNote = null;
    this.check = { kind: 'manual' };
  }

  /** Back out of `matched`/`manual` without verifying. */
  cancelCompare(): void {
    if (this.busy) return;
    if (this.check.kind === 'matched' || this.check.kind === 'manual') {
      this.check = { kind: 'idle' };
    }
  }

  /**
   * THE only call site of `adapter.markVerified`. Must be invoked by an explicit user action; see
   * the class doc for every precondition.
   */
  async confirmVerified(): Promise<void> {
    if (this.busy || this.disposed) return;
    const startCheck = this.check;
    if (startCheck.kind !== 'matched' && startCheck.kind !== 'manual') return;
    if (startCheck.kind === 'manual' && this.mismatchSeen) return;
    const shown = this.numbers;
    if (shown === null) return;

    this.busy = true;
    this.notice = null;
    try {
      let fresh: SafetyNumber | null;
      try {
        fresh = await this.adapter.getSafetyNumber(this.peerId);
      } catch {
        fresh = null;
      }
      // Superseded while we asked (trust changed, restarted, cancelled, disposed): not ours to act on.
      if (this.disposed || this.check !== startCheck || this.numbers !== shown) return;
      if (!isUsableNumber(fresh)) {
        this.notice = { kind: 'error', text: describeError(null, 'verify') };
        return;
      }
      if (fresh.digits !== shown.digits) {
        // The number moved under the user (key change): what they compared is not this peer's
        // current number. Nothing is verified; they must compare the new number from scratch.
        this.check = { kind: 'idle' };
        this.notice = { kind: 'error', text: VERIFY_COPY.staleNumber };
        void this.loadNumbers();
        return;
      }
      try {
        await this.adapter.markVerified(this.peerId);
      } catch (e) {
        if (!this.disposed) this.notice = { kind: 'error', text: describeError(e, 'verify') };
        return;
      }
      if (this.disposed) return;
      this.check = { kind: 'idle' };
      this.mismatchSeen = false;
      this.notice = { kind: 'success', text: VERIFY_COPY.verified };
      void this.refreshGate();
      void this.refreshContact();
      notify(this.hooks.onverified, this.contact);
    } finally {
      this.busy = false;
    }
  }

  // ---- acknowledge (warn only) & block ---------------------------------------------------------------

  /** Offer acknowledge-without-verifying: only while the gate is currently `warn`. */
  beginAcknowledge(): void {
    if (this.busy || this.gate === null || this.gate.kind !== 'warn') return;
    this.prompt = { kind: 'acknowledge' };
    this.notice = null;
  }

  async confirmAcknowledge(): Promise<void> {
    if (this.busy || this.disposed || this.prompt?.kind !== 'acknowledge') return;
    this.busy = true;
    try {
      // Fresh consult; act only on what THIS call's query returned and only if it says `warn`.
      const gate = await this.refreshGate();
      if (this.disposed) return;
      if (gate === null || gate.kind !== 'warn' || this.prompt?.kind !== 'acknowledge') {
        this.prompt = null; // no longer a pinned-key-changed warning (or unknown): do not acknowledge
        return;
      }
      try {
        await this.adapter.acknowledgeKeyChange(this.peerId);
      } catch (e) {
        if (!this.disposed) {
          this.prompt = null;
          this.notice = { kind: 'error', text: describeError(e, 'acknowledge') };
        }
        return;
      }
      if (this.disposed) return;
      this.prompt = null;
      this.notice = { kind: 'info', text: VERIFY_COPY.acknowledged };
      void this.refreshGate();
      void this.refreshContact();
    } finally {
      this.busy = false;
    }
  }

  beginBlock(): void {
    if (this.busy) return;
    this.prompt = { kind: 'block', blocked: !this.contact.userBlocked };
    this.notice = null;
  }

  async confirmBlock(): Promise<void> {
    const prompt = this.prompt;
    if (this.busy || this.disposed || prompt?.kind !== 'block') return;
    this.busy = true;
    try {
      try {
        await this.adapter.setUserBlocked(this.peerId, prompt.blocked);
      } catch (e) {
        if (!this.disposed) {
          this.prompt = null;
          this.notice = { kind: 'error', text: describeError(e, 'block') };
        }
        return;
      }
      if (this.disposed) return;
      this.prompt = null;
      void this.refreshGate();
      void this.refreshContact();
    } finally {
      this.busy = false;
    }
  }

  cancelPrompt(): void {
    if (!this.busy) this.prompt = null;
  }
}
