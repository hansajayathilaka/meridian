import { describe, expect, it, vi } from 'vitest';
import { createEvent, render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import {
  FileTransfer,
  FileTransferViewModel,
  MeridianAdapterError,
  type ClientEvent,
  type ClientEventListener,
  type FileOffer,
  type SendGate,
  type TransferInfo
} from '../index';
import type { FakeMeridianClientAdapter } from '../fake-adapter';
import { displayText, formatBytes } from './transfer-view';
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

const makeFile = (name: string, size = 10): File => new File(['x'.repeat(size)], name);
const zone = () => screen.queryByRole('group', { name: 'Send files' });
const picker = () => screen.queryByLabelText('Choose files to send') as HTMLInputElement | null;

async function dropFiles(files: File[], types: string[] = ['Files']): Promise<void> {
  await fireEvent.drop(screen.getByRole('group', { name: 'Send files' }), {
    dataTransfer: { files, types }
  });
}

/** Dispatch a drag event with a non-empty file list; resolves to whether the app swallowed it. */
async function drag(
  target: Element,
  type: 'dragOver' | 'drop',
  types: string[],
  files: File[] = [makeFile('dragged.txt')]
): Promise<boolean> {
  const event = createEvent[type](target, { dataTransfer: { files, types } });
  await fireEvent(target, event);
  return event.defaultPrevented;
}

async function pickFiles(files: File[]): Promise<void> {
  await fireEvent.change(picker()!, { target: { files } });
}

/** Capture the screen's subscription so a test can inject arbitrary (e.g. hostile/duplicate) events. */
function captureEvents(adapter: FakeMeridianClientAdapter): { emit: ClientEventListener } {
  let listener: ClientEventListener | null = null;
  const real = adapter.subscribe.bind(adapter);
  vi.spyOn(adapter, 'subscribe').mockImplementation((l) => {
    listener = l;
    return real(l);
  });
  return { emit: (event: ClientEvent) => listener?.(event) };
}

const transferOf = (over: Partial<TransferInfo> & { transferId: string }): TransferInfo => ({
  peerId: ALICE_PEER,
  name: 'a.txt',
  direction: 'receive',
  totalBytes: 100,
  bytesDone: 0,
  status: 'in-progress',
  ...over
});

async function setup(petname = 'Alice') {
  const adapter = await readyAdapter();
  const alice = await withContact(adapter, ALICE_ID, petname);
  return { adapter, alice };
}

describe('FileTransfer: send', () => {
  it('sends a file chosen with the picker as a blob source and shows it as outgoing, in progress', async () => {
    const { adapter, alice } = await setup();
    const sendFile = vi.spyOn(adapter, 'sendFile');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });

    const file = makeFile('report.pdf', 2048);
    await pickFiles([file]);

    await waitFor(() => expect(sendFile).toHaveBeenCalledTimes(1));
    const [peer, source] = sendFile.mock.calls[0]!;
    expect(peer).toBe(ALICE_PEER);
    expect(source).toEqual({ kind: 'blob', blob: file, name: 'report.pdf' });
    const row = await screen.findByText('report.pdf');
    const li = row.closest('li')!;
    expect(li.textContent).toContain('Outgoing');
    expect(li.textContent).toContain('Sending');
    expect(li.textContent).toContain('0 B of 2.0 KiB');
  });

  it('sends files dropped on the zone, one adapter call each', async () => {
    const { adapter, alice } = await setup();
    const sendFile = vi.spyOn(adapter, 'sendFile');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });

    await dropFiles([makeFile('one.txt'), makeFile('two.txt')]);
    await waitFor(() => expect(sendFile).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('one.txt')).toBeTruthy();
    expect(await screen.findByText('two.txt')).toBeTruthy();
  });

  it('ignores a drop whose payload is not a file drag, even if it carries a file list', async () => {
    const { adapter, alice } = await setup();
    const sendFile = vi.spyOn(adapter, 'sendFile');
    render(FileTransfer, { adapter, contact: alice });
    const area = await screen.findByRole('group', { name: 'Send files' });
    expect(await drag(area, 'dragOver', ['text/plain'])).toBe(false);
    expect(await drag(area, 'drop', ['text/plain'])).toBe(false);
    await settle();
    expect(sendFile).not.toHaveBeenCalled();
    // A real file drag on the zone is accepted and sent.
    expect(await drag(area, 'dragOver', ['Files'])).toBe(true);
    expect(await drag(area, 'drop', ['Files'])).toBe(true);
    await waitFor(() => expect(sendFile).toHaveBeenCalledTimes(1));
  });

  it('swallows file drags/drops elsewhere in the section (so the browser does not open the file), not text drags', async () => {
    const { adapter, alice } = await setup();
    const sendFile = vi.spyOn(adapter, 'sendFile');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    const outside = screen.getByRole('heading', { name: 'File transfers' });
    expect(await drag(outside, 'dragOver', ['Files'])).toBe(true);
    expect(await drag(outside, 'drop', ['Files'])).toBe(true);
    expect(await drag(outside, 'dragOver', ['text/plain'])).toBe(false);
    expect(await drag(outside, 'drop', ['text/plain'])).toBe(false);
    await settle();
    expect(sendFile).not.toHaveBeenCalled(); // only the zone ever sends
  });

  it('while the gate is blocked, a file drop on the section is swallowed but nothing is sent', async () => {
    const { adapter, alice } = await setup();
    adapter.simulateKeyChange(ALICE_PEER, true);
    const sendFile = vi.spyOn(adapter, 'sendFile');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('alert');
    expect(zone()).toBeNull();
    const outside = screen.getByRole('heading', { name: 'File transfers' });
    expect(await drag(outside, 'drop', ['Files'])).toBe(true);
    expect(await drag(outside, 'drop', ['text/plain'])).toBe(false);
    await settle();
    expect(sendFile).not.toHaveBeenCalled();
  });

  it('files dropped while a batch is sending are not silently lost: a fixed notice says so, nothing extra is sent', async () => {
    const { adapter, alice } = await setup();
    let release!: (t: TransferInfo) => void;
    const real = adapter.sendFile.bind(adapter);
    const sendFile = vi.spyOn(adapter, 'sendFile').mockImplementationOnce(
      () => new Promise<TransferInfo>((r) => (release = r))
    );
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    await dropFiles([makeFile('first.txt')]);
    await waitFor(() => expect(sendFile).toHaveBeenCalledTimes(1));

    await dropFiles([makeFile('second.txt')]);
    expect((await screen.findByRole('alert')).textContent).toBe(
      'Files were not added while another batch is sending; drop them again after it finishes.'
    );
    expect(sendFile).toHaveBeenCalledTimes(1);

    release(await real(ALICE_PEER, { kind: 'blob', blob: makeFile('first.txt'), name: 'first.txt' }));
    await screen.findByText('first.txt');
    expect(screen.queryByText('second.txt')).toBeNull();
    // After it finishes, dropping again works (and is gated afresh).
    await dropFiles([makeFile('second.txt')]);
    await waitFor(() => expect(sendFile).toHaveBeenCalledTimes(2));
  });

  it('shows progress exactly as reported: bytes of total, a bar only from real numbers, completion only when reported', async () => {
    const { adapter, alice } = await setup();
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    await pickFiles([makeFile('clip.bin', 1000)]);
    const li = (await screen.findByText('clip.bin')).closest('li')!;
    const id = li.getAttribute('data-transfer')!;

    adapter.simulateTransferProgress(id, 400);
    await waitFor(() => expect(li.textContent).toContain('400 B of 1000 B'));
    const bar = li.querySelector('progress')!;
    expect(bar.value).toBe(400);
    expect(bar.max).toBe(1000);
    expect(li.textContent).not.toContain('Transfer complete');
    expect(li.textContent).not.toContain('%'); // never a (fake) percentage

    adapter.simulateTransferProgress(id, 1000);
    await waitFor(() => expect(li.textContent).toContain('Transfer complete'));
    expect(li.querySelector('progress')).toBeNull();
    expect(li.textContent).toContain('1000 B of 1000 B');
  });

  it('shows a failed transfer as failed, with the adapter-reported reason as text, and offers no resume/cancel', async () => {
    const { adapter, alice } = await setup();
    const { container } = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    await pickFiles([makeFile('x.bin', 500)]);
    const li = (await screen.findByText('x.bin')).closest('li')!;
    adapter.simulateTransferProgress(li.getAttribute('data-transfer')!, 100);
    adapter.simulateTransferFailure(li.getAttribute('data-transfer')!, XSS_IMG);

    await waitFor(() => expect(li.textContent).toContain('Failed'));
    expect(li.querySelector('.failure')?.textContent).toBe(XSS_IMG);
    expect(container.querySelector('img')).toBeNull();
    expect(li.textContent).not.toContain('Transfer complete');
    expect(screen.queryByRole('button', { name: /resume|cancel|retry/i })).toBeNull();
  });

  it('a stalled transfer is shown as stalled (not progressing, not complete) with no resume control', async () => {
    const { adapter, alice } = await setup();
    const { emit } = captureEvents(adapter);
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    emit({
      type: 'transfer',
      transfer: transferOf({ transferId: 't-stall', status: 'stalled', bytesDone: 50 })
    });
    const li = (await screen.findByText('a.txt')).closest('li')!;
    expect(li.textContent).toContain('Stalled');
    expect(li.textContent).not.toContain('Transfer complete');
    expect(screen.queryByRole('button', { name: /resume/i })).toBeNull();
  });

  it('states what progress means and never claims integrity, security or anonymity', async () => {
    const { adapter, alice } = await setup();
    const { container } = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    await pickFiles([makeFile('done.bin', 10)]);
    const id = (await screen.findByText('done.bin')).closest('li')!.getAttribute('data-transfer')!;
    adapter.simulateTransferProgress(id, 10);
    await screen.findByText('Transfer complete');
    expect(container.textContent).toContain('It is not an integrity check');
    expect(container.textContent).not.toMatch(
      /verified|intact|uncorrupt|tamper|authentic|secure|anonymous|safe/i
    );
  });

  it('ignores a snapshot that is older than an event received while it was in flight', async () => {
    const { adapter, alice } = await setup();
    const { emit } = captureEvents(adapter);
    let release!: (list: readonly TransferInfo[]) => void;
    vi.spyOn(adapter, 'listTransfers').mockImplementation(
      () => new Promise<readonly TransferInfo[]>((r) => (release = r))
    );
    render(FileTransfer, { adapter, contact: alice });
    await settle();

    const old = transferOf({ transferId: 't1', bytesDone: 10 });
    emit({ type: 'transfer', transfer: transferOf({ transferId: 't1', bytesDone: 80 }) });
    release([old]); // the stale snapshot lands after the newer event
    await settle();
    const li = screen.getByText('a.txt').closest('li')!;
    expect(li.textContent).toContain('80 B of 100 B');
    expect(li.textContent).not.toContain('10 B of 100 B');
  });

  it('never reverts a terminal state to a running one', async () => {
    const { adapter, alice } = await setup();
    const { emit } = captureEvents(adapter);
    render(FileTransfer, { adapter, contact: alice });
    await settle();
    emit({ type: 'transfer', transfer: transferOf({ transferId: 't1', status: 'failed', failureReason: 'peer gone' }) });
    emit({ type: 'transfer', transfer: transferOf({ transferId: 't1', status: 'in-progress', bytesDone: 5 }) });
    await settle();
    const li = screen.getByText('a.txt').closest('li')!;
    expect(li.textContent).toContain('Failed');
    // ...but a later terminal report (e.g. whole-file check failing after "complete") is shown.
    emit({ type: 'transfer', transfer: transferOf({ transferId: 't2', status: 'completed', bytesDone: 100 }) });
    emit({ type: 'transfer', transfer: transferOf({ transferId: 't2', status: 'failed', bytesDone: 100, failureReason: 'check failed' }) });
    await settle();
    expect(screen.getAllByText('a.txt')[1]!.closest('li')!.textContent).toContain('Failed');
  });

  it('a failure is sticky: a later "complete" report never overwrites it', async () => {
    const { adapter, alice } = await setup();
    const { emit } = captureEvents(adapter);
    render(FileTransfer, { adapter, contact: alice });
    await settle();
    emit({ type: 'transfer', transfer: transferOf({ transferId: 't3', status: 'failed', failureReason: 'peer gone' }) });
    emit({ type: 'transfer', transfer: transferOf({ transferId: 't3', status: 'completed', bytesDone: 100 }) });
    await settle();
    const li = screen.getByText('a.txt').closest('li')!;
    expect(li.textContent).toContain('Failed');
    expect(li.textContent).not.toContain('Transfer complete');
    expect(li.querySelector('.failure')?.textContent).toBe('peer gone');
  });

  it('an unknown direction is shown neutrally, not as incoming; the note says a transfer can fail after all bytes arrive', async () => {
    const { adapter, alice } = await setup();
    const { emit } = captureEvents(adapter);
    const { container } = render(FileTransfer, { adapter, contact: alice });
    await settle();
    emit({
      type: 'transfer',
      transfer: transferOf({ transferId: 't4', direction: 'sideways' as unknown as 'send' })
    });
    const li = (await screen.findByText('a.txt')).closest('li')!;
    expect(li.querySelector('.direction')!.textContent).toBe('Unknown direction');
    expect(li.textContent).not.toMatch(/Incoming|Outgoing|Receiving|Sending/);
    expect(container.textContent).toContain('can still fail after all bytes have arrived');
  });

  it('only shows this peer\'s transfers and offers', async () => {
    const { adapter, alice } = await setup();
    await withContact(adapter, BOB_ID, 'Bob');
    const { emit } = captureEvents(adapter);
    render(FileTransfer, { adapter, contact: alice });
    await settle();
    emit({ type: 'transfer', transfer: transferOf({ transferId: 'tb', peerId: BOB_PEER, name: 'bob.txt' }) });
    emit({ type: 'file-offer', offer: { transferId: 'ob', peerId: BOB_PEER, name: 'bob-offer.txt', size: 5 } });
    await settle();
    expect(screen.queryByText('bob.txt')).toBeNull();
    expect(screen.queryByText('bob-offer.txt')).toBeNull();
  });

  it('a sendFile result naming another peer is not shown', async () => {
    const { adapter, alice } = await setup();
    vi.spyOn(adapter, 'sendFile').mockResolvedValue(
      transferOf({ transferId: 'tx', peerId: BOB_PEER, name: 'for-bob.txt', direction: 'send' })
    );
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    await pickFiles([makeFile('f.txt')]);
    await settle();
    expect(screen.queryByText('for-bob.txt')).toBeNull();
  });

  it('an adapter send-blocked rejection shows fixed file copy (not the raw error) and re-queries the gate', async () => {
    const { adapter, alice } = await setup();
    vi.spyOn(adapter, 'sendFile').mockRejectedValue(new MeridianAdapterError('send-blocked', `raw ${XSS_IMG}`));
    const gate = vi.spyOn(adapter, 'getSendGate');
    const { container } = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    const before = gate.mock.calls.length;
    await pickFiles([makeFile('f.txt')]);
    const alert = await screen.findByText(/File not sent: sending to this contact is blocked/);
    expect(alert.textContent).not.toContain('raw');
    expect(container.querySelector('img')).toBeNull();
    await waitFor(() => expect(gate.mock.calls.length).toBeGreaterThan(before + 1));
  });

  it('any other adapter failure shows fixed copy and stops the batch', async () => {
    const { adapter, alice } = await setup();
    const sendFile = vi.spyOn(adapter, 'sendFile').mockRejectedValue(new Error(`secret ${XSS_SCRIPT}`));
    const { container } = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    await pickFiles([makeFile('a'), makeFile('b'), makeFile('c')]);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe('The file was not sent. Please try again. 2 files were not sent.');
    expect(sendFile).toHaveBeenCalledTimes(1);
    expect(container.textContent).not.toContain('secret');
  });

  it('desktop shell: chosen native paths are sent as path sources through the same gated path', async () => {
    const { adapter, alice } = await setup();
    const sendFile = vi.spyOn(adapter, 'sendFile');
    const pickPaths = vi.fn(async () => ['/home/u/notes.txt']);
    render(FileTransfer, { adapter, contact: alice, pickPaths });
    await fireEvent.click(await screen.findByRole('button', { name: 'Choose files…' }));
    await waitFor(() => expect(sendFile).toHaveBeenCalledTimes(1));
    expect(sendFile.mock.calls[0]![1]).toEqual({ kind: 'path', path: '/home/u/notes.txt' });
  });

  it('no native chooser button without a shell-supplied pickPaths; a failing/cancelled chooser sends nothing', async () => {
    const { adapter, alice } = await setup();
    const sendFile = vi.spyOn(adapter, 'sendFile');
    const first = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    expect(screen.queryByRole('button', { name: 'Choose files…' })).toBeNull();
    first.unmount();

    const pickPaths = vi.fn<() => Promise<readonly string[] | null>>().mockRejectedValueOnce(new Error('x')).mockResolvedValueOnce(null);
    render(FileTransfer, { adapter, contact: alice, pickPaths });
    const button = await screen.findByRole('button', { name: 'Choose files…' });
    await fireEvent.click(button);
    await fireEvent.click(button);
    await settle();
    expect(pickPaths).toHaveBeenCalledTimes(2);
    expect(sendFile).not.toHaveBeenCalled();
  });
});

describe('FileTransfer: send gate', () => {
  it.each([
    ['blocked', () => ({ kind: 'blocked', reason: 'core: key changed' }) as SendGate],
    ['warn', () => ({ kind: 'warn', reason: 'core: acknowledge first' }) as SendGate]
  ])('%s gate: no send controls, core\'s reason verbatim as text', async (_n, gate) => {
    const { adapter, alice } = await setup();
    const reason = `${XSS_IMG} ${XSS_SCRIPT}   keep spacing`;
    vi.spyOn(adapter, 'getSendGate').mockResolvedValue({ ...gate(), reason } as SendGate);
    const sendFile = vi.spyOn(adapter, 'sendFile');
    const { container } = render(FileTransfer, { adapter, contact: alice });
    const banner = await screen.findByRole('alert');
    expect(banner.querySelector('.reason')?.textContent).toBe(reason);
    expect(zone()).toBeNull();
    expect(picker()).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(sendFile).not.toHaveBeenCalled();
  });

  it('no verdict yet, a failing query, or an unknown gate kind: no send controls (fail closed)', async () => {
    const { adapter, alice } = await setup();
    const spy = vi.spyOn(adapter, 'getSendGate').mockReturnValue(new Promise<SendGate>(() => {}));
    const a = render(FileTransfer, { adapter, contact: alice });
    expect(await screen.findByText(/Checking whether sending is allowed/)).toBeTruthy();
    expect(zone()).toBeNull();
    a.unmount();

    spy.mockRejectedValue(new Error('boom'));
    const b = render(FileTransfer, { adapter, contact: alice });
    expect(await screen.findByText(/Could not check whether sending is allowed/)).toBeTruthy();
    expect(zone()).toBeNull();
    b.unmount();

    spy.mockResolvedValue({ kind: 'mystery' } as unknown as SendGate);
    render(FileTransfer, { adapter, contact: alice });
    await settle();
    expect(zone()).toBeNull();
    expect(picker()).toBeNull();
  });

  it('re-queries the gate at send time: a gate that went blocked behind the UI\'s back sends nothing', async () => {
    const { adapter, alice } = await setup();
    const sendFile = vi.spyOn(adapter, 'sendFile');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    // Blocked WITHOUT a trust-changed event: the rendered gate is stale ("ok").
    await adapter.setUserBlocked(ALICE_PEER, true);
    await dropFiles([makeFile('late.txt')]);
    await settle();
    expect(sendFile).not.toHaveBeenCalled();
    expect((await screen.findByRole('alert')).textContent).toContain('FAKE: you blocked this contact');
    expect(zone()).toBeNull();
    expect(screen.queryByText('late.txt')).toBeNull();
  });

  it('a gate query superseded by a newer (warn) answer cannot authorise the send when it resolves ok', async () => {
    const { adapter, alice } = await setup();
    const sendFile = vi.spyOn(adapter, 'sendFile');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });

    let release!: (g: SendGate) => void;
    let calls = 0;
    vi.spyOn(adapter, 'getSendGate').mockImplementation(() => {
      calls += 1;
      return calls === 1
        ? new Promise<SendGate>((r) => (release = r))
        : Promise.resolve({ kind: 'warn', reason: 'newer answer: warn' });
    });
    await dropFiles([makeFile('raced.txt')]);
    adapter.simulateKeyChange(ALICE_PEER); // trust-changed => newer query => warn
    expect((await screen.findByRole('alert')).textContent).toContain('newer answer: warn');

    release({ kind: 'ok' }); // the stale answer finally arrives
    await settle();
    expect(sendFile).not.toHaveBeenCalled();
    expect(zone()).toBeNull();
  });

  it.each([
    ['rejects', () => Promise.reject(new Error('boom'))],
    ['returns an unknown kind', () => Promise.resolve({ kind: 'mystery' } as unknown as SendGate)],
    ['never answers', () => new Promise<SendGate>(() => {})]
  ])('a gate query that %s at send time never reaches sendFile', async (_n, behave) => {
    const { adapter, alice } = await setup();
    const sendFile = vi.spyOn(adapter, 'sendFile');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    vi.spyOn(adapter, 'getSendGate').mockImplementation(behave);
    await dropFiles([makeFile('nope.txt')]);
    await settle();
    expect(sendFile).not.toHaveBeenCalled();
    expect(screen.queryByText('nope.txt')).toBeNull();
  });

  it('every file of a batch is gated by its own query; the batch stops when the gate stops being ok', async () => {
    const { adapter, alice } = await setup();
    const sendFile = vi.spyOn(adapter, 'sendFile');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    const gate = vi.spyOn(adapter, 'getSendGate');
    gate.mockResolvedValueOnce({ kind: 'ok' }).mockResolvedValue({ kind: 'blocked', reason: 'now blocked' });
    await dropFiles([makeFile('first.txt'), makeFile('second.txt'), makeFile('third.txt')]);
    await waitFor(() => expect(screen.getByText(/2 files were not sent/)).toBeTruthy());
    expect(gate.mock.calls.length).toBeGreaterThanOrEqual(2);
    expect(sendFile).toHaveBeenCalledTimes(1);
    expect(sendFile.mock.calls[0]![1]).toMatchObject({ name: 'first.txt' });
  });

  it('offers a Verify hand-off only when the shell wires one', async () => {
    const { adapter, alice } = await setup();
    adapter.simulateKeyChange(ALICE_PEER);
    const onverify = vi.fn();
    const first = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('alert');
    expect(screen.queryByRole('button', { name: 'Verify' })).toBeNull();
    first.unmount();
    render(FileTransfer, { adapter, contact: alice, onverify });
    await fireEvent.click(await screen.findByRole('button', { name: 'Verify' }));
    expect(onverify).toHaveBeenCalledTimes(1);
  });
});

describe('FileTransfer: receive', () => {
  it('shows an incoming offer with the sender-supplied name and size flagged as unverified; nothing is answered yet', async () => {
    const { adapter, alice } = await setup();
    const answer = vi.spyOn(adapter, 'answerFileOffer');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    adapter.simulateFileOffer(ALICE_PEER, 'holiday.zip', 3 * 1024 * 1024);

    expect(await screen.findByText('holiday.zip')).toBeTruthy();
    expect(screen.getByText('3.0 MiB')).toBeTruthy();
    expect(screen.getByText(/supplied by the sender and are not verified/)).toBeTruthy();
    expect(answer).not.toHaveBeenCalled();
  });

  it('accept needs a confirm step; confirming answers the offer and a receive transfer appears', async () => {
    const { adapter, alice } = await setup();
    const answer = vi.spyOn(adapter, 'answerFileOffer');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    const offer = adapter.simulateFileOffer(ALICE_PEER, 'photo.png', 2000);
    await fireEvent.click(await screen.findByRole('button', { name: 'Accept' }));
    expect(answer).not.toHaveBeenCalled(); // choosing alone does nothing adapter-side
    expect(screen.getByRole('group', { name: 'Confirm decision' }).textContent).toContain('not verified');

    await fireEvent.click(screen.getByRole('button', { name: 'Confirm accept' }));
    await waitFor(() => expect(answer).toHaveBeenCalledWith(offer.transferId, true));
    await waitFor(() => expect(screen.queryByRole('group', { name: 'Confirm decision' })).toBeNull());
    expect(screen.queryByText('Incoming file offers')).toBeNull();
    const li = screen.getByText('photo.png').closest('li')!;
    expect(li.textContent).toContain('Incoming');
    expect(li.textContent).toContain('Receiving');
    expect(li.textContent).toContain('0 B of 2.0 KiB');

    adapter.simulateTransferProgress(offer.transferId, 2000);
    await waitFor(() => expect(li.textContent).toContain('Transfer complete'));
  });

  it('reject needs a confirm step; confirming declines the offer and no transfer appears', async () => {
    const { adapter, alice } = await setup();
    const answer = vi.spyOn(adapter, 'answerFileOffer');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    const offer = adapter.simulateFileOffer(ALICE_PEER, 'nope.exe', 99);
    await fireEvent.click(await screen.findByRole('button', { name: 'Reject' }));
    expect(answer).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm reject' }));
    await waitFor(() => expect(answer).toHaveBeenCalledWith(offer.transferId, false));
    await waitFor(() => expect(screen.queryByText('nope.exe')).toBeNull());
    expect(await adapter.listTransfers()).toEqual([]);
    expect(await screen.findByText('No transfers yet.')).toBeTruthy();
  });

  it('cancel abandons the decision without touching the adapter', async () => {
    const { adapter, alice } = await setup();
    const answer = vi.spyOn(adapter, 'answerFileOffer');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    adapter.simulateFileOffer(ALICE_PEER, 'maybe.txt', 1);
    await fireEvent.click(await screen.findByRole('button', { name: 'Accept' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('group', { name: 'Confirm decision' })).toBeNull();
    expect(answer).not.toHaveBeenCalled();
    expect(screen.getByText('maybe.txt')).toBeTruthy();
  });

  it('applies the answer to the offer it was chosen for, not to the first or newest offer', async () => {
    const { adapter, alice } = await setup();
    const answer = vi.spyOn(adapter, 'answerFileOffer');
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    const a = adapter.simulateFileOffer(ALICE_PEER, 'first.txt', 1);
    const b = adapter.simulateFileOffer(ALICE_PEER, 'second.txt', 2);
    await screen.findByText('second.txt');

    const secondRow = screen.getByText('second.txt').closest('li')!;
    await fireEvent.click(secondRow.querySelector<HTMLButtonElement>('.actions button')!); // Accept (second)
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm accept' }));
    await waitFor(() => expect(answer).toHaveBeenCalledTimes(1));
    expect(answer).toHaveBeenCalledWith(b.transferId, true);
    await waitFor(() => expect(screen.queryByText('second.txt', { selector: '.offer .name bdi' })).toBeNull());
    expect(a.transferId).not.toBe(b.transferId);
    // The first offer is untouched and still pending.
    expect(screen.getByText('first.txt')).toBeTruthy();
    expect(await adapter.listTransfers()).toHaveLength(1);
  });

  it('a decision in flight is applied to its own offer even if another offer arrives meanwhile', async () => {
    const { adapter, alice } = await setup();
    const a = adapter.simulateFileOffer(ALICE_PEER, 'a.txt', 1);
    const b = adapter.simulateFileOffer(ALICE_PEER, 'b.txt', 2);
    let release!: () => void;
    const realAnswer = adapter.answerFileOffer.bind(adapter);
    const answer = vi.spyOn(adapter, 'answerFileOffer').mockImplementation(async (id, accept) => {
      await new Promise<void>((r) => (release = r));
      return realAnswer(id, accept);
    });
    const { emit } = captureEvents(adapter);
    render(FileTransfer, { adapter, contact: alice });
    emit({ type: 'file-offer', offer: a });
    emit({ type: 'file-offer', offer: b });
    await screen.findByText('b.txt');

    const bRow = screen.getByText('b.txt').closest('li')!;
    await fireEvent.click(bRow.querySelector<HTMLButtonElement>('.actions button')!);
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm accept' }));
    const c = adapter.simulateFileOffer(ALICE_PEER, 'c.txt', 3);
    emit({ type: 'file-offer', offer: c });
    await screen.findByText('c.txt');
    // Decision controls are locked while one is in flight.
    for (const btn of screen.getAllByRole('button', { name: /^(Accept|Reject)$/ })) {
      expect((btn as HTMLButtonElement).disabled).toBe(true);
    }
    release();
    await waitFor(() => expect(screen.queryByText('b.txt', { selector: '.offer .name bdi' })).toBeNull());
    expect(answer).toHaveBeenCalledTimes(1);
    expect(answer).toHaveBeenCalledWith(b.transferId, true);
    expect(screen.getByText('a.txt', { selector: '.offer .name bdi' })).toBeTruthy();
    expect(screen.getByText('c.txt')).toBeTruthy();
  });

  it('an offer that goes stale while awaiting confirmation is voided and never answered', async () => {
    const { adapter, alice } = await setup();
    const answer = vi.spyOn(adapter, 'answerFileOffer');
    const { emit } = captureEvents(adapter);
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    emit({ type: 'file-offer', offer: { transferId: 'o1', peerId: ALICE_PEER, name: 'gone.txt', size: 5 } });
    await fireEvent.click(await screen.findByRole('button', { name: 'Accept' }));
    expect(screen.getByRole('button', { name: 'Confirm accept' })).toBeTruthy();

    // The sender gives up: the transfer for that id fails.
    emit({ type: 'transfer', transfer: transferOf({ transferId: 'o1', name: 'gone.txt', status: 'failed', failureReason: 'peer cancelled' }) });
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Confirm accept' })).toBeNull());
    expect(screen.queryByText('Incoming file offers')).toBeNull();
    expect(answer).not.toHaveBeenCalled();
    // ...and a replayed announcement cannot resurrect it.
    emit({ type: 'file-offer', offer: { transferId: 'o1', peerId: ALICE_PEER, name: 'gone.txt', size: 5 } });
    await settle();
    expect(screen.queryByRole('button', { name: 'Accept' })).toBeNull();
  });

  it('a rejected offer re-announced later is not resurrected (no transfer exists for it)', async () => {
    const { adapter, alice } = await setup();
    const answer = vi.spyOn(adapter, 'answerFileOffer');
    const { emit } = captureEvents(adapter);
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    const offer: FileOffer = { transferId: 'o9', peerId: ALICE_PEER, name: 'rejected.txt', size: 5 };
    emit({ type: 'file-offer', offer });
    await fireEvent.click(await screen.findByRole('button', { name: 'Reject' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm reject' }));
    await waitFor(() => expect(screen.queryByText('rejected.txt')).toBeNull());
    expect(answer).toHaveBeenCalledTimes(1);
    expect(await adapter.listTransfers()).toEqual([]);

    emit({ type: 'file-offer', offer });
    await settle();
    expect(screen.queryByText('rejected.txt')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Accept' })).toBeNull();
  });

  it('a later announcement reusing a transfer id cannot change the name or size under the user', async () => {
    const { adapter, alice } = await setup();
    const { emit } = captureEvents(adapter);
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    emit({ type: 'file-offer', offer: { transferId: 'o1', peerId: ALICE_PEER, name: 'small.txt', size: 10 } });
    await screen.findByText('small.txt');
    emit({ type: 'file-offer', offer: { transferId: 'o1', peerId: ALICE_PEER, name: 'huge.exe', size: 9e9 } });
    await settle();
    expect(screen.queryByText('huge.exe')).toBeNull();
    expect(screen.getAllByText('small.txt')).toHaveLength(1);
    expect(screen.getByText('10 B')).toBeTruthy();
  });

  it('answering an offer the adapter no longer knows shows fixed copy and removes it', async () => {
    const { adapter, alice } = await setup();
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    const offer = adapter.simulateFileOffer(ALICE_PEER, 'stale.txt', 1);
    await fireEvent.click(await screen.findByRole('button', { name: 'Accept' }));
    await adapter.answerFileOffer(offer.transferId, false); // answered behind the UI's back
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm accept' }));
    expect((await screen.findByText('That file offer is no longer available.')).getAttribute('role')).toBe('alert');
    await waitFor(() => expect(screen.queryByText('stale.txt')).toBeNull());
  });

  it('any other answer failure shows fixed copy (not the raw error) and keeps the offer', async () => {
    const { adapter, alice } = await setup();
    vi.spyOn(adapter, 'answerFileOffer').mockRejectedValue(new Error(`raw ${XSS_IMG}`));
    const { container } = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    adapter.simulateFileOffer(ALICE_PEER, 'keep.txt', 1);
    await fireEvent.click(await screen.findByRole('button', { name: 'Accept' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm accept' }));
    expect((await screen.findByRole('alert')).textContent).toBe('Could not answer the file offer. Please try again.');
    expect(container.textContent).not.toContain('raw');
    expect(screen.getByText('keep.txt')).toBeTruthy();
  });

  it('receiving is not blocked by the send gate (it gates sending only)', async () => {
    const { adapter, alice } = await setup();
    adapter.simulateKeyChange(ALICE_PEER, true); // blocked
    render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('alert');
    adapter.simulateFileOffer(ALICE_PEER, 'inbound.txt', 1);
    expect(await screen.findByText('inbound.txt')).toBeTruthy();
    expect(zone()).toBeNull();
  });
});

describe('FileTransfer: hostile wire strings are text only', () => {
  const HOSTILE_NAMES: [string, string][] = [
    ['html', XSS_IMG],
    ['script', XSS_SCRIPT],
    ['path traversal', '../../etc/passwd'],
    ['windows path', '..\\..\\Windows\\System32\\x.exe'],
    ['url-like', 'javascript:alert(1)']
  ];

  it.each(HOSTILE_NAMES)('%s name renders as text in offers and transfers; no element, link, or download attribute', async (_n, name) => {
    const { adapter, alice } = await setup();
    const { container } = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    adapter.simulateFileOffer(ALICE_PEER, name, 7);
    await waitFor(() => expect(container.querySelector('.offer .name bdi')?.textContent).toBe(name));
    await fireEvent.click(screen.getByRole('button', { name: 'Accept' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm accept' }));
    await waitFor(() => expect(container.querySelector('.transfer .name bdi')?.textContent).toBe(name));
    await pickFiles([makeFile(name)]);
    await waitFor(() => expect(container.querySelectorAll('.transfer')).toHaveLength(2));

    for (const bdi of container.querySelectorAll('.name bdi')) expect(bdi.textContent).toBe(name);
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
    expect(container.querySelector('a')).toBeNull();
    expect(container.querySelector('[href]')).toBeNull();
    expect(container.querySelector('[download]')).toBeNull();
    expect(container.querySelector('[src]')).toBeNull();
  });

  it('RTL-override and other invisible characters in a name are made visible, never rendered raw', async () => {
    const { adapter, alice } = await setup();
    const { container } = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    adapter.simulateFileOffer(ALICE_PEER, 'invoice\u202Egpj.exe\u200B\u0000', 7);
    const name = await waitFor(() => {
      const el = container.querySelector('.offer .name');
      if (!el) throw new Error('not yet');
      return el.textContent!;
    });
    for (const raw of ['\u202E', '\u200B', '\u0000']) expect(name.includes(raw)).toBe(false);
    expect(name).toContain('invoice[U+202E]gpj.exe[U+200B][U+0000]');
  });

  it('a very long name is capped for display and a long failure reason too', async () => {
    const { adapter, alice } = await setup();
    const { emit } = captureEvents(adapter);
    const { container } = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    emit({ type: 'file-offer', offer: { transferId: 'o', peerId: ALICE_PEER, name: 'n'.repeat(100_000), size: 1 } });
    emit({ type: 'transfer', transfer: transferOf({ transferId: 't', name: 'm'.repeat(100_000), status: 'failed', failureReason: 'r'.repeat(100_000) }) });
    await waitFor(() => expect(container.querySelector('.transfer')).toBeTruthy());
    expect(container.querySelector('.offer .name')!.textContent!.length).toBeLessThanOrEqual(260);
    expect(container.querySelector('.transfer .name')!.textContent!.length).toBeLessThanOrEqual(260);
    expect(container.querySelector('.failure')!.textContent!.length).toBeLessThanOrEqual(210);
  });

  it('hostile sizes and counts from the wire never render as numbers that look real', async () => {
    const { adapter, alice } = await setup();
    const { emit } = captureEvents(adapter);
    const { container } = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    emit({ type: 'file-offer', offer: { transferId: 'o', peerId: ALICE_PEER, name: 'f', size: Number.NaN } });
    emit({ type: 'transfer', transfer: transferOf({ transferId: 't', totalBytes: -5, bytesDone: Number.POSITIVE_INFINITY }) });
    await waitFor(() => expect(container.querySelector('.transfer')).toBeTruthy());
    expect(container.querySelector('.offer .size')!.textContent).toBe('unknown size');
    expect(container.querySelector('.transfer .bytes')!.textContent).toBe('unknown size of unknown size');
    expect(container.querySelector('progress')).toBeNull();
  });

  it('the peer label is shown as text (hostile hint), never as markup', async () => {
    const adapter = await readyAdapter();
    const hostile = await adapter.addContact(`mrd1:mallory@${XSS_IMG.replace(/\s/g, '/')}`);
    const { container } = render(FileTransfer, { adapter, contact: hostile });
    await screen.findByRole('group', { name: 'Send files' });
    expect(container.querySelector('img')).toBeNull();
  });
});

describe('FileTransfer: lifecycle', () => {
  it('switching peers opens an isolated screen (no transfers, offers or pending decisions carry over)', async () => {
    const { adapter, alice } = await setup();
    const bob = await withContact(adapter, BOB_ID, 'Bob');
    const { emit } = captureEvents(adapter);
    const { rerender } = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    emit({ type: 'file-offer', offer: { transferId: 'o1', peerId: ALICE_PEER, name: 'alice-offer.txt', size: 1 } });
    emit({ type: 'transfer', transfer: transferOf({ transferId: 't1', name: 'alice-xfer.txt' }) });
    await fireEvent.click(await screen.findByRole('button', { name: 'Accept' }));

    await rerender({ adapter, contact: bob });
    await settle();
    expect(screen.queryByText('alice-offer.txt')).toBeNull();
    expect(screen.queryByText('alice-xfer.txt')).toBeNull();
    expect(screen.queryByRole('group', { name: 'Confirm decision' })).toBeNull();
    // A late event for the old peer is not rendered here.
    emit({ type: 'transfer', transfer: transferOf({ transferId: 't2', name: 'late-alice.txt' }) });
    await settle();
    expect(screen.queryByText('late-alice.txt')).toBeNull();
  });

  it('start() is idempotent: a second call does not leak a second subscription', async () => {
    const { adapter, alice } = await setup();
    const unsub = vi.fn();
    const subscribe = vi.spyOn(adapter, 'subscribe').mockImplementation(() => unsub);
    const vm = new FileTransferViewModel(adapter, alice);
    vm.start();
    vm.start();
    expect(subscribe).toHaveBeenCalledTimes(1);
    vm.dispose();
    expect(unsub).toHaveBeenCalledTimes(1);
    vm.start(); // never restarts after dispose
    expect(subscribe).toHaveBeenCalledTimes(1);
  });

  it('stops listening to the adapter when unmounted', async () => {
    const { adapter, alice } = await setup();
    const unsub = vi.fn();
    vi.spyOn(adapter, 'subscribe').mockImplementation(() => unsub);
    const { unmount } = render(FileTransfer, { adapter, contact: alice });
    await screen.findByRole('group', { name: 'Send files' });
    unmount();
    expect(unsub).toHaveBeenCalledTimes(1);
  });

  it('a send, answer or gate result that resolves after dispose writes nothing and sends nothing', async () => {
    const { adapter, alice } = await setup();
    const vm = new FileTransferViewModel(adapter, alice);
    vm.start();
    await settle();
    let release!: (g: SendGate) => void;
    vi.spyOn(adapter, 'getSendGate').mockImplementation(() => new Promise<SendGate>((r) => (release = r)));
    const sendFile = vi.spyOn(adapter, 'sendFile');
    const sending = vm.sendFiles([makeFile('x.txt')]);
    vm.dispose();
    release({ kind: 'ok' });
    await sending;
    expect(sendFile).not.toHaveBeenCalled();
    expect(vm.transfers).toEqual([]);
  });

  it('shows the empty state, and a load failure as fixed copy', async () => {
    const { adapter, alice } = await setup();
    const a = render(FileTransfer, { adapter, contact: alice });
    expect(await screen.findByText('No transfers yet.')).toBeTruthy();
    a.unmount();
    vi.spyOn(adapter, 'listTransfers').mockRejectedValue(new Error(`raw ${XSS_IMG}`));
    const b = render(FileTransfer, { adapter, contact: alice });
    expect((await screen.findByText('Could not load this view. Please try again.')).getAttribute('role')).toBe('alert');
    expect(b.container.textContent).not.toContain('raw');
  });

  it('lists transfers that already exist when the screen opens (this peer only)', async () => {
    const { adapter, alice } = await setup();
    await withContact(adapter, BOB_ID, 'Bob');
    await adapter.sendFile(ALICE_PEER, { kind: 'blob', blob: makeFile('earlier.txt'), name: 'earlier.txt' });
    await adapter.sendFile(BOB_PEER, { kind: 'blob', blob: makeFile('bobs.txt'), name: 'bobs.txt' });
    render(FileTransfer, { adapter, contact: alice });
    expect(await screen.findByText('earlier.txt')).toBeTruthy();
    expect(screen.queryByText('bobs.txt')).toBeNull();
  });
});

describe('transfer-view helpers', () => {
  it('formatBytes', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1023)).toBe('1023 B');
    expect(formatBytes(1536)).toBe('1.5 KiB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MiB');
    for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY, '5' as unknown as number]) {
      expect(formatBytes(bad)).toBe('unknown size');
    }
  });

  it('displayText marks invisible/reordering characters', () => {
    expect(displayText('a\u202Eb')).toBe('a[U+202E]b');
    expect(displayText('a\nb\tc')).toBe('a[U+000A]b[U+0009]c');
    expect(displayText('..\\..\\x/../y')).toBe('..\\..\\x/../y'); // path text is left as text
  });

  it.each([
    ['soft hyphen', '\u00AD', 'U+00AD'],
    ['combining grapheme joiner', '\u034F', 'U+034F'],
    ['hangul choseong filler', '\u115F', 'U+115F'],
    ['hangul jungseong filler', '\u1160', 'U+1160'],
    ['khmer inherent vowel', '\u17B4', 'U+17B4'],
    ['khmer inherent vowel aa', '\u17B5', 'U+17B5'],
    ['hangul filler', '\u3164', 'U+3164'],
    ['halfwidth hangul filler', '\uFFA0', 'U+FFA0'],
    ['variation selector', '\uFE0F', 'U+FE0F'],
    ['variation selector low', '\uFE00', 'U+FE00'],
    ['interlinear annotation', '\uFFF9', 'U+FFF9'],
    ['interlinear terminator', '\uFFFB', 'U+FFFB'],
    ['braille blank', '\u2800', 'U+2800'],
    ['tag character', '\u{E0041}', 'U+E0041'],
    ['tag cancel', '\u{E007F}', 'U+E007F'],
    ['variation selector supplement', '\u{E0100}', 'U+E0100'],
    ['lone surrogate', '\uD800', 'U+D800']
  ])('displayText makes %s visible', (_n, ch, label) => {
    const out = displayText(`a${ch}b`);
    expect(out).toBe(`a[${label}]b`);
    expect(out.includes(ch)).toBe(false);
  });

  it('displayText keeps the head and the tail (extension) when truncating, by code point', () => {
    const name = `${'n'.repeat(500)}.tar.gz`;
    const out = displayText(name);
    expect(Array.from(out).length).toBeLessThanOrEqual(256 + 1);
    expect(out.endsWith('.tar.gz')).toBe(true);
    expect(out.startsWith('nnnn')).toBe(true);
    expect(out).toContain('…');
    expect(displayText('x'.repeat(10), 4)).toBe('xx…x');
    expect(displayText('\u{1F600}'.repeat(20), 8)).toBe(`${'\u{1F600}'.repeat(5)}…${'\u{1F600}'.repeat(2)}`);
    expect(displayText('short.txt')).toBe('short.txt'); // under the cap: unchanged
  });

  it('displayText truncates before scanning: a 100 MB name is cheap and still shows its tail', () => {
    const huge = `${'a'.repeat(100_000_000)}.exe`;
    const started = performance.now();
    const out = displayText(huge);
    expect(performance.now() - started).toBeLessThan(500);
    expect(out.endsWith('.exe')).toBe(true);
    expect(out.length).toBeLessThanOrEqual(260);
  });

  it('displayText still marks hostile characters in the kept head and tail of a truncated name', () => {
    const out = displayText(`\u202E${'z'.repeat(1000)}exe.\u202Egpj`);
    expect(out.includes('\u202E')).toBe(false);
    expect(out.startsWith('[U+202E]')).toBe(true);
    expect(out.endsWith('exe.[U+202E]gpj')).toBe(true);
  });
});
