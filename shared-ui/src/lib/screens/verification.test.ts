import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import {
  MeridianAdapterError,
  QrScannerError,
  Verification,
  VerificationViewModel,
  type ContactSummary,
  type LumaImage,
  type QrScanHandlers,
  type QrScanner,
  type SafetyNumber,
  type SendGate
} from '../index';
import type { FakeMeridianClientAdapter } from '../fake-adapter';
import vectors from '../../../../test-vectors/safety-numbers-v1.json';
import {
  ALICE_ID,
  ALICE_PEER,
  BOB_ID,
  BOB_PEER,
  XSS_IMG,
  XSS_SCRIPT,
  readyAdapter,
  settle,
  withContact
} from './test-support';

// ---- helpers ------------------------------------------------------------------------------------

/** The fake adapter's `decodeQr` reads the payload from the frame's bytes (test stand-in only). */
function frameOf(text: string): LumaImage {
  const luma = new TextEncoder().encode(text);
  return { width: Math.max(luma.length, 1), height: 1, luma };
}

/** A mock camera: the real MediaDevices scanner is the shell's job and is never run in tests. */
class MockScanner implements QrScanner {
  handlers: QrScanHandlers | null = null;
  starts = 0;
  stops = 0;
  startError: unknown = null;
  gate: Promise<void> | null = null;

  async start(handlers: QrScanHandlers): Promise<{ stop(): void }> {
    this.starts += 1;
    if (this.gate !== null) await this.gate;
    if (this.startError !== null) throw this.startError;
    this.handlers = handlers;
    return {
      stop: () => {
        this.stops += 1;
      }
    };
  }

  /** Deliver a frame carrying `text` through the handlers captured at start (even a dead one). */
  emit(text: string): void {
    this.handlers?.onFrame(frameOf(text));
  }
}

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void } {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

interface Setup {
  adapter: FakeMeridianClientAdapter;
  alice: ContactSummary;
  expected: SafetyNumber;
}

async function setup(petname = 'Alice'): Promise<Setup> {
  const adapter = await readyAdapter();
  const alice = await withContact(adapter, ALICE_ID, petname);
  const expected = await adapter.getSafetyNumber(ALICE_PEER);
  return { adapter, alice, expected };
}

/** Flip the last digit: a full-length, plausible, WRONG safety number. */
function oneDigitOff(digits: string): string {
  const last = digits.charAt(digits.length - 1);
  return digits.slice(0, -1) + (last === '0' ? '1' : '0');
}

const startScanButton = () => screen.getByRole('button', { name: /Scan (their QR code|again)/ });
const markVerifiedButton = () => screen.queryByRole('button', { name: 'Mark as verified' });
const manualButton = () => screen.queryByRole('button', { name: 'The digits match' });
const anyVerifyControl = () =>
  screen.queryAllByRole('button', { name: /verified|digits match|verify anyway|trust/i });

async function beginScan(scanner: MockScanner): Promise<void> {
  await fireEvent.click(await screen.findByRole('button', { name: /Scan their QR code/ }));
  await waitFor(() => expect(scanner.handlers).not.toBeNull());
}

// ---- display ------------------------------------------------------------------------------------

describe('Verification: display', () => {
  it('shows the adapter-supplied number verbatim and the text QR of the digits', async () => {
    const { adapter, alice, expected } = await setup();
    const renderQr = vi.spyOn(adapter, 'renderQrText');
    render(Verification, { adapter, contact: alice });

    const number = await screen.findByTestId('safety-number');
    expect(number.textContent).toBe(expected.display);
    expect(renderQr).toHaveBeenCalledWith(expected.digits);
    const qr = await screen.findByRole('img', { name: 'QR code of the safety number' });
    expect(qr.textContent).toBe(`[fake-qr:${expected.digits}]`);
    // Peer is named by petname with the fingerprint alongside; unverified reads "unverified".
    expect(screen.getByText('Verify Alice')).toBeTruthy();
    expect(screen.getByText(alice.fingerprint)).toBeTruthy();
    expect(screen.getByText('unverified')).toBeTruthy();
  });

  it('falls back to the digits when the QR cannot be drawn', async () => {
    const { adapter, alice, expected } = await setup();
    vi.spyOn(adapter, 'renderQrText').mockRejectedValue(new Error('boom'));
    render(Verification, { adapter, contact: alice });
    expect((await screen.findByTestId('safety-number')).textContent).toBe(expected.display);
    expect(await screen.findByText(/QR code could not be drawn/)).toBeTruthy();
    expect(manualButton()).toBeTruthy();
  });

  it('offers no camera control without an injected scanner, but still the manual compare', async () => {
    const { adapter, alice } = await setup();
    render(Verification, { adapter, contact: alice });
    await screen.findByTestId('safety-number');
    expect(screen.queryByRole('button', { name: /Scan/ })).toBeNull();
    expect(manualButton()).toBeTruthy();
  });

  it.each([
    ['empty', ''],
    ['59 digits', '1'.repeat(59)],
    ['61 digits', '1'.repeat(61)],
    ['non-digits', 'a'.repeat(60)]
  ])('fails closed on a malformed number from the adapter (%s): no compare/verify controls', async (_n, digits) => {
    const { adapter, alice } = await setup();
    vi.spyOn(adapter, 'getSafetyNumber').mockResolvedValue({ digits, display: digits });
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    render(Verification, { adapter, contact: alice, scanner });
    expect(await screen.findByText(/Could not get the safety number/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Scan|digits match|verified/ })).toBeNull();
    expect(markVerified).not.toHaveBeenCalled();
  });

  it('shows no passphrase or key material anywhere in the DOM', async () => {
    const adapter = await readyAdapter();
    await adapter.generateAccount('org-b.test', { kind: 'passphrase', passphrase: 'hunter2-SECRET-pass' });
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    render(Verification, { adapter, contact: alice, scanner: new MockScanner() });
    await screen.findByTestId('safety-number');
    expect(document.body.textContent).not.toContain('hunter2-SECRET-pass');
  });

  it('renders hostile strings as text, never markup', async () => {
    const { adapter } = await setup();
    const hostile = await withContact(adapter, 'mrd1:mallory@org-a.test', XSS_IMG);
    vi.spyOn(adapter, 'getSafetyNumber').mockResolvedValue({
      digits: '1'.repeat(60),
      display: '1'.repeat(60)
    });
    vi.spyOn(adapter, 'renderQrText').mockResolvedValue(XSS_IMG);
    adapter.simulateKeyChange('mrd1:mallory'); // pinned -> warn
    vi.spyOn(adapter, 'getSendGate').mockResolvedValue({ kind: 'warn', reason: XSS_SCRIPT });
    const { container } = render(Verification, { adapter, contact: hostile });

    expect((await screen.findByTestId('safety-number')).textContent).toBe('1'.repeat(60));
    await screen.findByRole('img', { name: 'QR code of the safety number' });
    await waitFor(() => expect(container.querySelector('[data-gate="warn"]')).not.toBeNull());
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
    expect(container.textContent).toContain(XSS_IMG);
    expect(container.textContent).toContain(XSS_SCRIPT); // the gate reason, as text
  });

  it('fails closed when the display form disagrees with the digits (e.g. hostile markup)', async () => {
    const { adapter, alice } = await setup();
    vi.spyOn(adapter, 'getSafetyNumber').mockResolvedValue({
      digits: '1'.repeat(60),
      display: XSS_SCRIPT
    });
    const { container } = render(Verification, { adapter, contact: alice, scanner: new MockScanner() });
    expect(await screen.findByText(/Could not get the safety number/)).toBeTruthy();
    expect(container.querySelector('script')).toBeNull();
    expect(container.textContent).not.toContain(XSS_SCRIPT);
    expect(screen.queryByRole('button', { name: /Scan|digits match|verified/ })).toBeNull();
  });

  it('keeps the KEY CHANGE header for a contact that is both key-changed and locally blocked', async () => {
    const { adapter } = await setup();
    await adapter.markVerified(ALICE_PEER);
    adapter.simulateKeyChange(ALICE_PEER); // verified -> blocked (key change)
    await adapter.setUserBlocked(ALICE_PEER, true);
    const [contact] = await adapter.listContacts();
    const { container } = render(Verification, { adapter, contact: contact! });
    const banner = await waitFor(() => {
      const el = container.querySelector('[data-gate="blocked"]');
      expect(el).not.toBeNull();
      return el!;
    });
    expect(banner.textContent).toContain('KEY CHANGE — SENDS BLOCKED');
    expect(banner.textContent).not.toContain('CONTACT BLOCKED');
    expect(banner.textContent).toContain('You have also blocked this contact.');
  });
});

// ---- the safety-critical rule: markVerified -------------------------------------------------------

describe('Verification: exact match then explicit confirmation', () => {
  it('exact scan match -> matched (NOT verified yet) -> explicit confirm -> markVerified once', async () => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const decodeQr = vi.spyOn(adapter, 'decodeQr');
    const onverified = vi.fn();
    const scanner = new MockScanner();
    render(Verification, { adapter, contact: alice, scanner, onverified });
    await screen.findByTestId('safety-number');
    await beginScan(scanner);

    scanner.emit(expected.digits);
    expect(await screen.findByText(/^MATCH/)).toBeTruthy();
    // The scanned frame went to the adapter's decoder (no QR logic in TS).
    expect(decodeQr).toHaveBeenCalledTimes(1);
    expect(decodeQr.mock.calls[0]?.[0].luma).toEqual(frameOf(expected.digits).luma);
    // Camera released on the verdict, and a match alone never verifies.
    expect(scanner.stops).toBe(1);
    await settle();
    expect(markVerified).not.toHaveBeenCalled();
    expect(await adapter.getTrustState(ALICE_PEER)).toBe('pinned');

    await fireEvent.click(markVerifiedButton()!);
    await waitFor(() => expect(markVerified).toHaveBeenCalledTimes(1));
    expect(markVerified).toHaveBeenCalledWith(ALICE_PEER);
    expect(await adapter.getTrustState(ALICE_PEER)).toBe('verified');
    expect(await screen.findByText(/Safety number confirmed/)).toBeTruthy();
    await waitFor(() => expect(onverified).toHaveBeenCalledTimes(1));
    expect(screen.getByText('verified')).toBeTruthy();
  });

  it('manual path: "digits match" only opens a prompt; verification needs the explicit confirm', async () => {
    const { adapter, alice } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    render(Verification, { adapter, contact: alice });
    await screen.findByTestId('safety-number');
    await settle();
    expect(markVerified).not.toHaveBeenCalled(); // never auto-triggered on load

    await fireEvent.click(manualButton()!);
    expect(screen.getByRole('group', { name: 'Confirm verification' }).textContent).toContain(
      'compared out-of-band'
    );
    await settle();
    expect(markVerified).not.toHaveBeenCalled();

    await fireEvent.click(screen.getByRole('button', { name: /Yes, the numbers matched/ }));
    await waitFor(() => expect(markVerified).toHaveBeenCalledTimes(1));
    expect(markVerified).toHaveBeenCalledWith(ALICE_PEER);
  });

  it.each(['manual', 'matched'] as const)('cancelling the %s confirm never verifies', async (path) => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    render(Verification, { adapter, contact: alice, scanner });
    await screen.findByTestId('safety-number');
    if (path === 'manual') {
      await fireEvent.click(manualButton()!);
    } else {
      await beginScan(scanner);
      scanner.emit(expected.digits);
      await screen.findByText(/^MATCH/);
    }
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await settle();
    expect(markVerified).not.toHaveBeenCalled();
    expect(markVerifiedButton()).toBeNull();
    expect(manualButton()).toBeTruthy(); // back to idle, nothing verified
    expect(await adapter.getTrustState(ALICE_PEER)).toBe('pinned');
  });

  it('a double-clicked confirm calls markVerified once', async () => {
    const { adapter, alice, expected } = await setup();
    const gate = deferred<void>();
    const markVerified = vi.spyOn(adapter, 'markVerified').mockImplementation(async () => gate.promise);
    const scanner = new MockScanner();
    render(Verification, { adapter, contact: alice, scanner });
    await screen.findByTestId('safety-number');
    await beginScan(scanner);
    scanner.emit(expected.digits);
    const button = await screen.findByRole('button', { name: 'Mark as verified' });
    await fireEvent.click(button);
    await fireEvent.click(button);
    await settle();
    expect(markVerified).toHaveBeenCalledTimes(1);
    gate.resolve();
    await settle();
    expect(markVerified).toHaveBeenCalledTimes(1);
  });

  it('a failing markVerified shows fixed copy (never the thrown text) and does not report success', async () => {
    const { adapter, alice } = await setup();
    vi.spyOn(adapter, 'markVerified').mockRejectedValue(
      new MeridianAdapterError('internal', `leaky ${XSS_IMG} mrd1:secret`)
    );
    const onverified = vi.fn();
    render(Verification, { adapter, contact: alice, onverified });
    await screen.findByTestId('safety-number');
    await fireEvent.click(manualButton()!);
    await fireEvent.click(screen.getByRole('button', { name: /Yes, the numbers matched/ }));
    expect(await screen.findByText(/Could not mark this contact as verified/)).toBeTruthy();
    expect(document.body.textContent).not.toContain('leaky');
    expect(onverified).not.toHaveBeenCalled();
    expect(screen.queryByText(/Safety number confirmed/)).toBeNull();
  });

  it('a throwing onverified callback is isolated and does not read as a failure', async () => {
    const { adapter, alice } = await setup();
    const onverified = vi.fn(() => {
      throw new Error('shell bug');
    });
    render(Verification, { adapter, contact: alice, onverified });
    await screen.findByTestId('safety-number');
    await fireEvent.click(manualButton()!);
    await fireEvent.click(screen.getByRole('button', { name: /Yes, the numbers matched/ }));
    expect(await screen.findByText(/Safety number confirmed/)).toBeTruthy();
    expect(onverified).toHaveBeenCalledTimes(1);
  });
});

describe('Verification: ambiguous / failed / wrong scans never verify', () => {
  const digitsOf = (n: SafetyNumber) => n.digits;

  it.each<[string, (n: SafetyNumber) => string]>([
    ['empty payload', () => ''],
    ['59 digits (truncated)', (n) => digitsOf(n).slice(0, 59)],
    ['30 digits (partial)', (n) => digitsOf(n).slice(0, 30)],
    ['61 digits (extra digit)', (n) => digitsOf(n) + '0'],
    ['leading space', (n) => ` ${digitsOf(n)}`],
    ['trailing newline', (n) => `${digitsOf(n)}\n`],
    ['grouped display form', (n) => n.display],
    ['an mrd1 id QR', () => ALICE_ID],
    ['garbled non-digit noise', () => '\u0000\u0001garbage�'],
    ['digits with one letter', (n) => `${digitsOf(n).slice(0, 59)}x`],
    ['fullwidth digits', (n) => digitsOf(n).replace(/[0-9]/g, (d) => String.fromCharCode(0xff10 + Number(d)))],
    ['hostile markup', () => XSS_IMG]
  ])('%s: no match, no verify control, markVerified never called', async (_name, payloadOf) => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    const { container } = render(Verification, { adapter, contact: alice, scanner });
    await screen.findByTestId('safety-number');
    await beginScan(scanner);

    scanner.emit(payloadOf(expected));
    await settle();

    // Not a complete safety number: not evidence of an attack either (no MISMATCH alarm), and the
    // camera keeps looking for the real code.
    expect(container.querySelector('[data-state="mismatch"]')).toBeNull();
    expect(screen.getByTestId('scan-note').textContent).toContain('not a complete safety number');
    expect(screen.getByText(/^Scanning/)).toBeTruthy();
    expect(screen.queryByText(/^MATCH/)).toBeNull();
    expect(markVerifiedButton()).toBeNull();
    expect(markVerified).not.toHaveBeenCalled();
    expect(await adapter.getTrustState(ALICE_PEER)).toBe('pinned');
  });

  it('a full-length wrong number is a strong MISMATCH, with no verify-anyway of any kind', async () => {
    const { adapter, alice, expected } = await setup();
    const bob = await withContact(adapter, BOB_ID, 'Bob');
    const bobsNumber = (await adapter.getSafetyNumber(bob.peerId)).digits;
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    render(Verification, { adapter, contact: alice, scanner });
    await screen.findByTestId('safety-number');
    await beginScan(scanner);

    // A different peer's (valid, 60-digit) safety number.
    expect(bobsNumber).not.toBe(expected.digits);
    scanner.emit(bobsNumber);
    const alert = await screen.findByText(/^MISMATCH: the scanned code does not match/);
    expect(alert.textContent).toContain('someone is intercepting your messages');
    expect(alert.textContent).toContain('Do not mark this contact verified');
    expect(scanner.stops).toBe(1);
    expect(screen.queryByText(/^MATCH/)).toBeNull();
    expect(markVerifiedButton()).toBeNull();
    expect(manualButton()).toBeNull(); // the manual path is not a back door past a mismatch
    expect(anyVerifyControl()).toHaveLength(0);
    expect(markVerified).not.toHaveBeenCalled();
  });

  it.each<[string, (n: SafetyNumber) => string]>([
    ['one digit off', (n) => oneDigitOff(n.digits)],
    ['all zeros', () => '0'.repeat(60)]
  ])('mismatch (%s) shows the strong state and nothing can then verify', async (_n, payloadOf) => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    const { container } = render(Verification, { adapter, contact: alice, scanner });
    await screen.findByTestId('safety-number');
    await beginScan(scanner);
    scanner.emit(payloadOf(expected));
    await waitFor(() => expect(container.querySelector('[data-state="mismatch"]')).not.toBeNull());
    expect(markVerifiedButton()).toBeNull();
    expect(manualButton()).toBeNull();
    expect(markVerified).not.toHaveBeenCalled();
  });

  it('after a mismatch only a later EXACT scan can lead to verification', async () => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    const { container } = render(Verification, { adapter, contact: alice, scanner });
    await screen.findByTestId('safety-number');
    await beginScan(scanner);
    scanner.emit(oneDigitOff(expected.digits));
    await waitFor(() => expect(container.querySelector('[data-state="mismatch"]')).not.toBeNull());

    // Rescan: another wrong code keeps the mismatch, and the manual path stays closed.
    await fireEvent.click(startScanButton());
    await waitFor(() => expect(scanner.starts).toBe(2));
    scanner.emit(oneDigitOff(expected.digits));
    await settle();
    expect(manualButton()).toBeNull();
    expect(markVerified).not.toHaveBeenCalled();

    // Rescan: the exact number clears the mismatch and offers the (still explicit) confirm.
    await fireEvent.click(startScanButton());
    await waitFor(() => expect(scanner.starts).toBe(3));
    scanner.emit(expected.digits);
    expect(await screen.findByText(/^MATCH/)).toBeTruthy();
    expect(container.querySelector('[data-state="mismatch"]')).toBeNull();
    expect(markVerified).not.toHaveBeenCalled();
    await fireEvent.click(markVerifiedButton()!);
    await waitFor(() => expect(markVerified).toHaveBeenCalledTimes(1));
  });

  it('decode failures keep scanning without a verdict, and a later exact frame still matches', async () => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const decodeQr = vi.spyOn(adapter, 'decodeQr');
    const scanner = new MockScanner();
    render(Verification, { adapter, contact: alice, scanner });
    await screen.findByTestId('safety-number');
    await beginScan(scanner);

    decodeQr.mockRejectedValueOnce(new MeridianAdapterError('internal', 'no qr found'));
    scanner.emit('noise');
    await settle();
    expect(screen.queryByText(/^MATCH/)).toBeNull();
    expect(screen.queryByText(/^MISMATCH/)).toBeNull();
    expect(screen.getByText(/^Scanning/)).toBeTruthy();
    expect(markVerified).not.toHaveBeenCalled();

    scanner.emit(expected.digits);
    expect(await screen.findByText(/^MATCH/)).toBeTruthy();
    expect(markVerified).not.toHaveBeenCalled();
  });

  it('an empty number can never be "matched" by an empty decode (guard against empty === empty)', async () => {
    const { adapter, alice } = await setup();
    vi.spyOn(adapter, 'getSafetyNumber').mockResolvedValue({ digits: '', display: '' });
    vi.spyOn(adapter, 'decodeQr').mockResolvedValue('');
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    const vm = new VerificationViewModel(adapter, alice, scanner);
    vm.start();
    await settle();
    await vm.startScan(); // no usable number: refuses to open the camera
    scanner.emit('');
    await settle();
    expect(scanner.starts).toBe(0);
    expect(vm.check.kind).toBe('idle');
    await vm.confirmVerified();
    expect(markVerified).not.toHaveBeenCalled();
    vm.dispose();
  });

  it('the view-model refuses to verify from idle / scanning / mismatch (not just a hidden button)', async () => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    const vm = new VerificationViewModel(adapter, alice, scanner);
    vm.start();
    await settle();

    await vm.confirmVerified(); // idle
    await vm.startScan();
    await vm.confirmVerified(); // scanning
    scanner.emit(oneDigitOff(expected.digits));
    await settle();
    expect(vm.mismatchSeen).toBe(true);
    await vm.confirmVerified(); // after mismatch
    vm.beginManualCompare(); // closed after a mismatch
    expect(vm.check.kind).toBe('idle');
    await vm.confirmVerified();
    expect(markVerified).not.toHaveBeenCalled();
    vm.dispose();
  });
});

// ---- staleness: superseded / disposed / other peer ---------------------------------------------------

describe('Verification: stale results are discarded', () => {
  it('a decode that resolves after the screen was disposed never matches or verifies', async () => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const pending = deferred<string>();
    vi.spyOn(adapter, 'decodeQr').mockImplementation(() => pending.promise);
    const scanner = new MockScanner();
    const vm = new VerificationViewModel(adapter, alice, scanner);
    vm.start();
    await settle();
    await vm.startScan();
    scanner.emit('frame');
    await settle();

    vm.dispose();
    expect(scanner.stops).toBe(1);
    pending.resolve(expected.digits);
    await settle();
    expect(vm.check.kind).not.toBe('matched');
    await vm.confirmVerified();
    expect(markVerified).not.toHaveBeenCalled();
  });

  it('a scan result for the previous peer is dropped after the screen switches peer', async () => {
    const { adapter, alice, expected } = await setup();
    const bob = await withContact(adapter, BOB_ID, 'Bob');
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const pending = deferred<string>();
    vi.spyOn(adapter, 'decodeQr').mockImplementationOnce(() => pending.promise);
    const scanner = new MockScanner();
    const { rerender } = render(Verification, { adapter, contact: alice, scanner });
    await screen.findByTestId('safety-number');
    await beginScan(scanner);
    scanner.emit('frame');
    await settle();

    await rerender({ adapter, contact: bob, scanner }); // {#key}: Alice's screen is torn down
    await waitFor(() => expect(screen.getByText('Verify Bob')).toBeTruthy());
    expect(scanner.stops).toBe(1); // Alice's camera session was released
    pending.resolve(expected.digits); // Alice's exact number arrives late
    await settle();

    expect(screen.queryByText(/^MATCH/)).toBeNull();
    expect(markVerifiedButton()).toBeNull();
    expect(markVerified).not.toHaveBeenCalled();
    // Bob's screen shows Bob's own number, not Alice's.
    const bobsNumber = await adapter.getSafetyNumber(BOB_PEER);
    expect((await screen.findByTestId('safety-number')).textContent).toBe(bobsNumber.display);
  });

  it('scanning another contact\'s number on this contact\'s screen is a mismatch, never a match', async () => {
    const { adapter, alice } = await setup();
    const bob = await withContact(adapter, BOB_ID, 'Bob');
    const bobsNumber = await adapter.getSafetyNumber(bob.peerId);
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    const { container } = render(Verification, { adapter, contact: alice, scanner });
    await screen.findByTestId('safety-number');
    await beginScan(scanner);
    scanner.emit(bobsNumber.digits);
    await waitFor(() => expect(container.querySelector('[data-state="mismatch"]')).not.toBeNull());
    expect(markVerified).not.toHaveBeenCalled();
  });

  it('a decode from a superseded (restarted) scan is discarded', async () => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const first = deferred<string>();
    vi.spyOn(adapter, 'decodeQr').mockImplementationOnce(() => first.promise);
    const scanner = new MockScanner();
    const vm = new VerificationViewModel(adapter, alice, scanner);
    vm.start();
    await settle();
    await vm.startScan();
    scanner.emit('frame-1');
    await settle();
    vm.stopScan();
    await vm.startScan(); // scan #2 is now the live one
    expect(vm.check.kind).toBe('scanning');

    first.resolve(expected.digits); // scan #1's late, exact result
    await settle();
    expect(vm.check.kind).toBe('scanning'); // not matched by a superseded scan
    await vm.confirmVerified();
    expect(markVerified).not.toHaveBeenCalled();
    vm.dispose();
  });

  it('frames a buggy scanner delivers after stop are ignored', async () => {
    const { adapter, alice, expected } = await setup();
    const decodeQr = vi.spyOn(adapter, 'decodeQr');
    const scanner = new MockScanner();
    const vm = new VerificationViewModel(adapter, alice, scanner);
    vm.start();
    await settle();
    await vm.startScan();
    vm.stopScan();
    scanner.emit(expected.digits);
    await settle();
    expect(decodeQr).not.toHaveBeenCalled();
    expect(vm.check.kind).toBe('idle');
    vm.dispose();
  });

  it('a camera that finishes opening after dispose is released immediately', async () => {
    const { adapter, alice } = await setup();
    const scanner = new MockScanner();
    const open = deferred<void>();
    scanner.gate = open.promise;
    const vm = new VerificationViewModel(adapter, alice, scanner);
    vm.start();
    await settle();
    const started = vm.startScan();
    vm.dispose();
    open.resolve();
    await started;
    expect(scanner.stops).toBe(1);
  });

  it('a key change while a match is awaiting confirmation resets it and clears the number', async () => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    render(Verification, { adapter, contact: alice, scanner });
    await screen.findByTestId('safety-number');
    await beginScan(scanner);
    scanner.emit(expected.digits);
    await screen.findByText(/^MATCH/);

    adapter.simulateKeyChange(ALICE_PEER); // pinned -> pinned-key-changed
    await waitFor(() => expect(screen.queryByText(/^MATCH/)).toBeNull());
    expect(markVerifiedButton()).toBeNull();
    expect(await screen.findByText(/safety number changed while you were comparing/)).toBeTruthy();
    expect(markVerified).not.toHaveBeenCalled();
  });

  it('a trust change DURING the confirm pre-check aborts: markVerified is never called', async () => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    const vm = new VerificationViewModel(adapter, alice, scanner);
    vm.start();
    await settle();
    await vm.startScan();
    scanner.emit(expected.digits);
    await settle();
    expect(vm.check.kind).toBe('matched');

    const fresh = deferred<SafetyNumber>();
    vi.spyOn(adapter, 'getSafetyNumber').mockImplementationOnce(() => fresh.promise);
    const confirming = vm.confirmVerified();
    adapter.simulateKeyChange(ALICE_PEER); // supersedes the comparison while we wait
    fresh.resolve(expected); // an `ok`-looking, identical number: still superseded
    await confirming;
    expect(markVerified).not.toHaveBeenCalled();
    vm.dispose();
  });

  it('the screen disposed DURING the confirm pre-check aborts too', async () => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const vm = new VerificationViewModel(adapter, alice, null);
    vm.start();
    await settle();
    vm.beginManualCompare();
    const fresh = deferred<SafetyNumber>();
    vi.spyOn(adapter, 'getSafetyNumber').mockImplementationOnce(() => fresh.promise);
    const confirming = vm.confirmVerified();
    vm.dispose();
    fresh.resolve(expected);
    await confirming;
    expect(markVerified).not.toHaveBeenCalled();
  });

  it('a number that changed without an event is caught at confirm time: nothing is verified', async () => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    render(Verification, { adapter, contact: alice });
    await screen.findByTestId('safety-number');
    await fireEvent.click(manualButton()!);

    vi.spyOn(adapter, 'getSafetyNumber').mockResolvedValue({
      digits: oneDigitOff(expected.digits),
      display: oneDigitOff(expected.digits)
    });
    await fireEvent.click(screen.getByRole('button', { name: /Yes, the numbers matched/ }));
    expect(await screen.findByText(/safety number changed while you were comparing/)).toBeTruthy();
    expect(markVerified).not.toHaveBeenCalled();
    // The screen reloads and shows the NEW number, back at idle: the old comparison is void.
    await waitFor(() =>
      expect(screen.getByTestId('safety-number').textContent).toBe(oneDigitOff(expected.digits))
    );
    expect(screen.queryByRole('group', { name: 'Confirm verification' })).toBeNull();
  });

  it('a stale number load (superseded by a trust change) is not what scans are compared to', async () => {
    const { adapter, alice, expected } = await setup();
    const stale = deferred<SafetyNumber>();
    const getSafetyNumber = vi.spyOn(adapter, 'getSafetyNumber');
    getSafetyNumber.mockImplementationOnce(() => stale.promise); // initial load, held in flight
    const vm = new VerificationViewModel(adapter, alice, null);
    vm.start();
    adapter.simulateKeyChange(ALICE_PEER); // triggers a second, newer load (real adapter call)
    await settle();
    const newer = vm.numbers;
    expect(newer?.digits).toBe(expected.digits);
    stale.resolve({ digits: '9'.repeat(60), display: '9'.repeat(60) }); // late stale answer
    await settle();
    expect(vm.numbers).toBe(newer);
    vm.dispose();
  });
});

// ---- camera failure --------------------------------------------------------------------------------

describe('Verification: camera failure', () => {
  it.each<[unknown, RegExp]>([
    [new QrScannerError('permission-denied'), /Camera access was denied/],
    [new QrScannerError('no-camera'), /No camera was found/],
    [new Error('NotReadableError: secret device id 1234'), /camera is not available/]
  ])('start failure %# shows fixed copy and the manual compare still works', async (error, text) => {
    const { adapter, alice } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    scanner.startError = error;
    render(Verification, { adapter, contact: alice, scanner });
    await screen.findByTestId('safety-number');
    await fireEvent.click(screen.getByRole('button', { name: /Scan their QR code/ }));
    expect(await screen.findByText(text)).toBeTruthy();
    expect(document.body.textContent).not.toContain('secret device id');
    expect(markVerified).not.toHaveBeenCalled();

    await fireEvent.click(manualButton()!);
    await fireEvent.click(screen.getByRole('button', { name: /Yes, the numbers matched/ }));
    await waitFor(() => expect(markVerified).toHaveBeenCalledTimes(1));
  });

  it('a stream error mid-scan stops the scan without a verdict', async () => {
    const { adapter, alice } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    render(Verification, { adapter, contact: alice, scanner });
    await screen.findByTestId('safety-number');
    await beginScan(scanner);
    scanner.handlers!.onError('permission-denied');
    expect(await screen.findByText(/Camera access was denied/)).toBeTruthy();
    expect(scanner.stops).toBe(1);
    expect(screen.queryByText(/^Scanning/)).toBeNull();
    expect(markVerified).not.toHaveBeenCalled();
  });
});

// ---- gate: blocked / warn --------------------------------------------------------------------------------

describe('Verification: blocked / warn gate', () => {
  it('blocked after a key change on a verified contact: core reason verbatim, no acknowledge, Verify clears it', async () => {
    const { adapter, alice, expected } = await setup();
    await adapter.markVerified(ALICE_PEER);
    adapter.simulateKeyChange(ALICE_PEER); // verified -> blocked
    const gate = (await adapter.getSendGate(ALICE_PEER)) as Extract<SendGate, { kind: 'blocked' }>;
    const scanner = new MockScanner();
    const { container } = render(Verification, { adapter, contact: alice, scanner });

    const banner = await waitFor(() => {
      const el = container.querySelector('[data-gate="blocked"]');
      expect(el).not.toBeNull();
      return el!;
    });
    expect(banner.textContent).toContain('KEY CHANGE — SENDS BLOCKED');
    expect(banner.querySelector('.reason')?.textContent).toBe(gate.reason);
    // Hard stop: no acknowledge / "trust anyway" path exists for a blocked contact.
    expect(screen.queryByRole('button', { name: /Acknowledge/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /trust|anyway|dismiss/i })).toBeNull();

    // Re-verification (exact match + explicit confirm) is what clears it.
    await beginScan(scanner);
    scanner.emit((await adapter.getSafetyNumber(ALICE_PEER)).digits);
    await fireEvent.click(await screen.findByRole('button', { name: 'Mark as verified' }));
    await waitFor(() => expect(container.querySelector('[data-gate="blocked"]')).toBeNull());
    expect(await adapter.getSendGate(ALICE_PEER)).toEqual({ kind: 'ok' });
    expect(expected.digits).toHaveLength(60);
  });

  it('a purely local block is not framed as a key change', async () => {
    const { adapter } = await setup();
    await adapter.setUserBlocked(ALICE_PEER, true);
    const [contact] = await adapter.listContacts();
    const { container } = render(Verification, { adapter, contact: contact! });
    const banner = await waitFor(() => {
      const el = container.querySelector('[data-gate="blocked"]');
      expect(el).not.toBeNull();
      return el!;
    });
    expect(banner.textContent).toContain('CONTACT BLOCKED — SENDS BLOCKED');
    expect(banner.textContent).not.toContain('KEY CHANGE');
    expect(screen.getByRole('button', { name: 'Unblock contact' })).toBeTruthy();
  });

  it('warn (pinned key changed): reason verbatim, Verify primary, acknowledge behind a confirm and not a verify', async () => {
    const { adapter, alice } = await setup();
    adapter.simulateKeyChange(ALICE_PEER); // pinned -> pinned-key-changed (warn)
    const gate = (await adapter.getSendGate(ALICE_PEER)) as Extract<SendGate, { kind: 'warn' }>;
    const ack = vi.spyOn(adapter, 'acknowledgeKeyChange');
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const { container } = render(Verification, { adapter, contact: alice });

    await waitFor(() => expect(container.querySelector('[data-gate="warn"]')).not.toBeNull());
    expect(container.querySelector('[data-gate="warn"] .reason')?.textContent).toBe(gate.reason);
    expect(manualButton()).toBeTruthy(); // Verify is available

    await fireEvent.click(screen.getByRole('button', { name: 'Acknowledge without verifying' }));
    expect(screen.getByRole('group', { name: 'Confirm acknowledge' }).textContent).toContain(
      'does not confirm it is genuinely theirs'
    );
    await settle();
    expect(ack).not.toHaveBeenCalled();

    await fireEvent.click(
      screen.getAllByRole('button', { name: 'Acknowledge without verifying' }).at(-1)!
    );
    await waitFor(() => expect(ack).toHaveBeenCalledTimes(1));
    expect(ack).toHaveBeenCalledWith(ALICE_PEER);
    expect(markVerified).not.toHaveBeenCalled(); // acknowledging never verifies
    expect(await adapter.getTrustState(ALICE_PEER)).toBe('pinned');
    expect(await screen.findByText(/NOT verified/)).toBeTruthy();
    await waitFor(() => expect(container.querySelector('[data-gate="warn"]')).toBeNull());
  });

  it('cancelling the acknowledge confirm acknowledges nothing', async () => {
    const { adapter, alice } = await setup();
    adapter.simulateKeyChange(ALICE_PEER);
    const ack = vi.spyOn(adapter, 'acknowledgeKeyChange');
    render(Verification, { adapter, contact: alice });
    await fireEvent.click(await screen.findByRole('button', { name: 'Acknowledge without verifying' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await settle();
    expect(ack).not.toHaveBeenCalled();
    expect(screen.queryByRole('group', { name: 'Confirm acknowledge' })).toBeNull();
  });

  it('acknowledge is re-checked against a FRESH gate: a warn that escalated to blocked is not acknowledged', async () => {
    const { adapter, alice } = await setup();
    adapter.simulateKeyChange(ALICE_PEER);
    const ack = vi.spyOn(adapter, 'acknowledgeKeyChange');
    const vm = new VerificationViewModel(adapter, alice, null);
    vm.start();
    await settle();
    expect(vm.gate?.kind).toBe('warn');
    vm.beginAcknowledge();
    expect(vm.prompt?.kind).toBe('acknowledge');

    vi.spyOn(adapter, 'getSendGate').mockResolvedValue({ kind: 'blocked', reason: 'escalated' });
    await vm.confirmAcknowledge();
    expect(ack).not.toHaveBeenCalled();
    expect(vm.prompt).toBeNull();
    vm.dispose();
  });

  it('acknowledge is not offered unless the gate is warn', async () => {
    const { adapter, alice } = await setup(); // pinned, gate ok
    const ack = vi.spyOn(adapter, 'acknowledgeKeyChange');
    const vm = new VerificationViewModel(adapter, alice, null);
    vm.start();
    await settle();
    vm.beginAcknowledge();
    expect(vm.prompt).toBeNull();
    await vm.confirmAcknowledge();
    expect(ack).not.toHaveBeenCalled();
    vm.dispose();
  });

  it('shows hostile gate reasons as text and fails closed when the gate query fails', async () => {
    const { adapter, alice } = await setup();
    vi.spyOn(adapter, 'getSendGate').mockRejectedValue(new Error('down'));
    render(Verification, { adapter, contact: alice });
    expect(await screen.findByText('Could not check whether sending is allowed.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Acknowledge/ })).toBeNull();
  });
});

// ---- block ---------------------------------------------------------------------------------------------

describe('Verification: block', () => {
  it('block needs a confirm; cancelling does nothing', async () => {
    const { adapter, alice } = await setup();
    const setBlocked = vi.spyOn(adapter, 'setUserBlocked');
    render(Verification, { adapter, contact: alice });
    await fireEvent.click(await screen.findByRole('button', { name: 'Block contact' }));
    await settle();
    expect(setBlocked).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(setBlocked).not.toHaveBeenCalled();

    await fireEvent.click(screen.getByRole('button', { name: 'Block contact' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Yes, block' }));
    await waitFor(() => expect(setBlocked).toHaveBeenCalledWith(ALICE_PEER, true));
    expect(setBlocked).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole('button', { name: 'Unblock contact' })).toBeTruthy();
  });
});

// ---- authoritative fixtures (T08 safety-number vectors) ---------------------------------------------------

describe('Verification: T08 safety-number fixture values', () => {
  // The fake adapter's safety number is a NON-authoritative stand-in (fake-adapter.ts); it cannot
  // compute core's values. So the authoritative T08 vectors are supplied to the screen AS the
  // adapter's answer, which proves the screen's own contract with real values: shown verbatim, the
  // QR payload is exactly the digits, an exact scan matches, one digit off does not. It does NOT
  // prove cross-platform equality of the computation: that is core's conformance suite (and the
  // wasm adapter's own vector test, 12.13).
  type Vector = { name: string; safety_number: string; display: string };
  const list = (vectors as { vectors: Vector[] }).vectors;

  it('has the vectors this suite expects', () => {
    expect(list.length).toBeGreaterThanOrEqual(5);
  });

  it.each(list.map((v) => [v.name, v] as const))('%s', async (_name, v) => {
    const { adapter, alice } = await setup();
    vi.spyOn(adapter, 'getSafetyNumber').mockResolvedValue({
      digits: v.safety_number,
      display: v.display
    });
    const renderQr = vi.spyOn(adapter, 'renderQrText');
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const scanner = new MockScanner();
    render(Verification, { adapter, contact: alice, scanner });

    // Shown exactly as the adapter grouped it; the grouping is the digits and nothing else.
    expect((await screen.findByTestId('safety-number')).textContent).toBe(v.display);
    expect(v.display.replace(/ /g, '')).toBe(v.safety_number);
    await waitFor(() => expect(renderQr).toHaveBeenCalledWith(v.safety_number));

    await beginScan(scanner);
    scanner.emit(v.display); // the grouped form is not the QR payload: never a match
    await settle();
    expect(screen.queryByText(/^MATCH/)).toBeNull();
    scanner.emit(oneDigitOff(v.safety_number));
    await settle();
    expect(screen.queryByText(/^MATCH/)).toBeNull();
    expect(markVerified).not.toHaveBeenCalled();
    await fireEvent.click(startScanButton());
    await waitFor(() => expect(scanner.starts).toBe(2));
    scanner.emit(v.safety_number);
    expect(await screen.findByText(/^MATCH/)).toBeTruthy();
    expect(markVerified).not.toHaveBeenCalled();
  });
});

// ---- hardening (review follow-ups) ----------------------------------------------------------------

describe('Verification: teardown, decode slot, rebuild', () => {
  it('a scanner whose stop() throws cannot skip dispose()\'s unsubscribe', async () => {
    const { adapter, alice } = await setup();
    const unsubscribe = vi.fn();
    vi.spyOn(adapter, 'subscribe').mockReturnValue(unsubscribe);
    const stop = vi.fn(() => {
      throw new Error('device busy');
    });
    const scanner = new MockScanner();
    scanner.start = async (h) => {
      scanner.handlers = h;
      return { stop };
    };
    const vm = new VerificationViewModel(adapter, alice, scanner);
    vm.start();
    await settle();
    await vm.startScan();
    expect(() => vm.dispose()).not.toThrow();
    expect(stop).toHaveBeenCalled();
    expect(unsubscribe).toHaveBeenCalledTimes(1);
  });

  it('a throwing stop() cannot leave stale scanning state or a number after trust-changed', async () => {
    const { adapter, alice, expected } = await setup();
    const scanner = new MockScanner();
    scanner.start = async (h) => {
      scanner.handlers = h;
      return {
        stop: () => {
          throw new Error('device busy');
        }
      };
    };
    const vm = new VerificationViewModel(adapter, alice, scanner);
    vm.start();
    await settle();
    await vm.startScan();
    expect(vm.check.kind).toBe('scanning');
    expect(vm.numbers?.digits).toBe(expected.digits);

    adapter.simulateKeyChange(ALICE_PEER);
    expect(vm.check.kind).toBe('idle'); // synchronously reset despite the throw
    expect(vm.numbers).toBeNull(); // fail closed until the fresh number arrives
    vm.dispose();
  });

  it('a never-resolving decode does not starve the scan: it times out and later frames are decoded', async () => {
    const { adapter, alice, expected } = await setup();
    const decodeQr = vi.spyOn(adapter, 'decodeQr');
    decodeQr.mockImplementationOnce(() => new Promise<string>(() => {}));
    const scanner = new MockScanner();
    const vm = new VerificationViewModel(adapter, alice, scanner, { decodeTimeoutMs: 20 });
    vm.start();
    await settle();
    await vm.startScan();
    scanner.emit('hung');
    await new Promise((r) => setTimeout(r, 60));
    scanner.emit(expected.digits);
    await settle();
    expect(decodeQr).toHaveBeenCalledTimes(2);
    expect(vm.check.kind).toBe('matched');
    vm.dispose();
  });

  it('a hung decode from an earlier scan does not block a restarted scan', async () => {
    const { adapter, alice, expected } = await setup();
    const decodeQr = vi.spyOn(adapter, 'decodeQr');
    decodeQr.mockImplementationOnce(() => new Promise<string>(() => {}));
    const scanner = new MockScanner();
    const vm = new VerificationViewModel(adapter, alice, scanner, { decodeTimeoutMs: 60_000 });
    vm.start();
    await settle();
    await vm.startScan();
    scanner.emit('hung');
    await settle();
    vm.stopScan();
    await vm.startScan();
    scanner.emit(expected.digits);
    await settle();
    expect(vm.check.kind).toBe('matched');
    vm.dispose();
  });

  it('an old scan\'s late decode finishing does not clear the new scan\'s in-flight marker', async () => {
    const { adapter, alice } = await setup();
    const first = deferred<string>();
    const second = deferred<string>();
    const decodeQr = vi.spyOn(adapter, 'decodeQr');
    decodeQr.mockImplementationOnce(() => first.promise).mockImplementationOnce(() => second.promise);
    const scanner = new MockScanner();
    const vm = new VerificationViewModel(adapter, alice, scanner, { decodeTimeoutMs: 60_000 });
    vm.start();
    await settle();
    await vm.startScan();
    scanner.emit('a');
    await settle();
    vm.stopScan();
    await vm.startScan(); // scan #2
    scanner.emit('b'); // decode #2 in flight
    await settle();
    expect(decodeQr).toHaveBeenCalledTimes(2);

    first.resolve('x'); // scan #1's decode finishes late
    await settle();
    scanner.emit('c'); // scan #2 still has a decode in flight: this frame must be dropped
    await settle();
    expect(decodeQr).toHaveBeenCalledTimes(2);
    second.resolve('y');
    vm.dispose();
  });

  it.each<[string, (digits: string) => string]>([
    ['a partial scan', (d) => d.slice(0, 30)],
    ['an mrd1 id QR', () => ALICE_ID],
    ['garbage', () => '\u0000garbage\ufffd'],
    ['an empty payload', () => '']
  ])('after a MISMATCH, %s on the rescan keeps the mismatch, the manual path closed, and verifies/acknowledges nothing', async (_n, payloadOf) => {
    const { adapter, alice, expected } = await setup();
    const markVerified = vi.spyOn(adapter, 'markVerified');
    const acknowledge = vi.spyOn(adapter, 'acknowledgeKeyChange');
    const scanner = new MockScanner();
    const vm = new VerificationViewModel(adapter, alice, scanner);
    vm.start();
    await settle();
    await vm.startScan();
    scanner.emit(oneDigitOff(expected.digits));
    await settle();
    expect(vm.mismatchSeen).toBe(true);

    await vm.startScan(); // rescan
    scanner.emit(payloadOf(expected.digits));
    await settle();

    expect(vm.mismatchSeen).toBe(true);
    expect(vm.check.kind).toBe('scanning');
    expect(vm.canCompareManually).toBe(false);
    vm.beginManualCompare();
    expect(vm.check.kind).toBe('scanning');
    await vm.confirmVerified();
    await vm.confirmAcknowledge();
    expect(markVerified).not.toHaveBeenCalled();
    expect(acknowledge).not.toHaveBeenCalled();
    vm.dispose();
  });

  it('a swapped adapter (same peer) rebuilds the view-model on the new adapter and releases the old', async () => {
    const first = await setup();
    const second = await setup();
    // Make the two adapters disagree on the number so the rebuild is observable.
    vi.spyOn(second.adapter, 'getSafetyNumber').mockResolvedValue({
      digits: '7'.repeat(60),
      display: '7'.repeat(60)
    });
    const unsubscribe = vi.fn();
    vi.spyOn(first.adapter, 'subscribe').mockReturnValue(unsubscribe);
    const { rerender } = render(Verification, { adapter: first.adapter, contact: first.alice });
    expect((await screen.findByTestId('safety-number')).textContent).toBe(first.expected.display);

    await rerender({ adapter: second.adapter, contact: first.alice });
    await waitFor(() => expect(screen.getByTestId('safety-number').textContent).toBe('7'.repeat(60)));
    expect(unsubscribe).toHaveBeenCalledTimes(1);
  });

  it('a swapped scanner (same peer) rebuilds the view-model on the new scanner', async () => {
    const { adapter, alice } = await setup();
    const a = new MockScanner();
    const b = new MockScanner();
    const { rerender } = render(Verification, { adapter, contact: alice, scanner: a });
    await beginScan(a);
    await rerender({ adapter, contact: alice, scanner: b });
    expect(a.stops).toBe(1); // the old screen (and its camera) was torn down
    await beginScan(b);
    expect(b.starts).toBe(1);
  });

  it.each(['constructor', '__proto__', 'toString', 'hasOwnProperty'])(
    'a shell-supplied camera failure reason %j maps to the generic unavailable copy',
    async (reason) => {
      const { adapter, alice } = await setup();
      const scanner = new MockScanner();
      render(Verification, { adapter, contact: alice, scanner });
      await screen.findByTestId('safety-number');
      await beginScan(scanner);
      scanner.handlers!.onError(reason as never);
      expect(await screen.findByText(/camera is not available/)).toBeTruthy();
    }
  );
});
