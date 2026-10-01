import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { Chat, ChatViewModel, MeridianAdapterError, type SendGate } from '../index';
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

const typeInto = (el: HTMLElement, value: string) => fireEvent.input(el, { target: { value } });
const composer = () => screen.queryByRole('textbox', { name: 'Message' });
const sendButton = () => screen.queryByRole('button', { name: 'Send' });

async function send(text: string): Promise<void> {
  await typeInto(screen.getByRole('textbox', { name: 'Message' }), text);
  await fireEvent.click(screen.getByRole('button', { name: 'Send' }));
}

describe('Chat: send / receive', () => {
  it('sends a message: it lands in the transcript and the adapter, and the draft clears', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    const sendMessage = vi.spyOn(adapter, 'sendMessage');
    render(Chat, { adapter, contact: alice });

    await screen.findByRole('textbox', { name: 'Message' });
    await send('hello alice');

    expect(await screen.findByText('hello alice')).toBeTruthy();
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage).toHaveBeenCalledWith(ALICE_PEER, 'hello alice');
    const history = await adapter.loadHistory(ALICE_PEER);
    expect(history.map((m) => m.body)).toEqual(['hello alice']);
    // Delivered live => a single "sent" marker, shown once (deduped by mid against history).
    expect(screen.getAllByText('hello alice')).toHaveLength(1);
    expect(screen.getByText('sent')).toBeTruthy();
    await waitFor(() =>
      expect((screen.getByRole('textbox', { name: 'Message' }) as HTMLTextAreaElement).value).toBe('')
    );
  });

  it('does not send an empty / whitespace-only draft', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter);
    const sendMessage = vi.spyOn(adapter, 'sendMessage');
    render(Chat, { adapter, contact: alice });
    await screen.findByRole('textbox', { name: 'Message' });
    await typeInto(screen.getByRole('textbox', { name: 'Message' }), '   ');
    expect((sendButton() as HTMLButtonElement).disabled).toBe(true);
    await fireEvent.keyDown(screen.getByRole('textbox', { name: 'Message' }), { key: 'Enter' });
    await settle();
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('Enter sends; Shift+Enter does not', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter);
    const sendMessage = vi.spyOn(adapter, 'sendMessage');
    render(Chat, { adapter, contact: alice });
    const box = await screen.findByRole('textbox', { name: 'Message' });
    await typeInto(box, 'line');
    await fireEvent.keyDown(box, { key: 'Enter', shiftKey: true });
    await settle();
    expect(sendMessage).not.toHaveBeenCalled();
    await fireEvent.keyDown(box, { key: 'Enter' });
    await waitFor(() => expect(sendMessage).toHaveBeenCalledTimes(1));
  });

  it('shows persisted history and receives inbound messages and receipts live', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    await adapter.sendMessage(ALICE_PEER, 'earlier');
    render(Chat, { adapter, contact: alice });
    expect(await screen.findByText('earlier')).toBeTruthy();

    adapter.simulateInboundMessage(ALICE_PEER, 'hi from alice');
    expect(await screen.findByText('hi from alice')).toBeTruthy();

    const [sent] = await adapter.loadHistory(ALICE_PEER);
    adapter.simulateReceipt(ALICE_PEER, sent!.mid);
    expect(await screen.findByText('delivered')).toBeTruthy();
  });

  it('ignores events that belong to a different peer', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    await withContact(adapter, BOB_ID, 'Bob');
    render(Chat, { adapter, contact: alice });
    await screen.findByRole('textbox', { name: 'Message' });

    adapter.simulateInboundMessage(BOB_PEER, 'for the bob conversation');
    adapter.simulateKeyChange(BOB_PEER);
    await settle();
    expect(screen.queryByText('for the bob conversation')).toBeNull();
    // Bob's key change must not disturb Alice's (still-ok) composer.
    expect(composer()).toBeTruthy();
  });

  it('switching peers opens an isolated conversation (no history or state carries over)', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    const bob = await withContact(adapter, BOB_ID, 'Bob');
    await adapter.sendMessage(ALICE_PEER, 'alice-only');
    const { rerender } = render(Chat, { adapter, contact: alice });
    expect(await screen.findByText('alice-only')).toBeTruthy();

    await rerender({ adapter, contact: bob });
    expect(await screen.findByRole('heading', { name: 'Bob' })).toBeTruthy();
    await settle();
    expect(screen.queryByText('alice-only')).toBeNull();
    // A late inbound for the old peer is not rendered in the new conversation.
    adapter.simulateInboundMessage(ALICE_PEER, 'late alice message');
    await settle();
    expect(screen.queryByText('late alice message')).toBeNull();
  });

  it('stops listening to the adapter when unmounted', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter);
    const unsub = vi.fn();
    vi.spyOn(adapter, 'subscribe').mockImplementation(() => unsub);
    const { unmount } = render(Chat, { adapter, contact: alice });
    await screen.findByRole('textbox', { name: 'Message' });
    unmount();
    expect(unsub).toHaveBeenCalledTimes(1);
  });

  it('shows the trust label for the contact; pinned reads unverified, never trusted', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    render(Chat, { adapter, contact: alice });
    expect(await screen.findByText('unverified')).toBeTruthy();
    expect(screen.getByText(alice.fingerprint)).toBeTruthy();
  });
});

describe('Chat: delivery failure copy', () => {
  it('undelivered: says "not delivered", offers retry, never promises later delivery; retry replaces it', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    adapter.setRouting({ delivered: false, queued: false });
    const { container } = render(Chat, { adapter, contact: alice });
    await screen.findByRole('textbox', { name: 'Message' });
    await send('are you there');

    const notice = await screen.findByText(/Not delivered/);
    expect(notice.textContent).toContain('Alice is offline');
    expect(container.textContent).not.toMatch(/deliver(ed)? later|will deliver|when they come online/i);
    expect(screen.getByText('failed')).toBeTruthy();

    adapter.setRouting({ delivered: true, queued: false });
    await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(screen.queryByText('failed')).toBeNull());
    expect(screen.getAllByText('are you there')).toHaveLength(1);
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
  });

  it('queued server-side: shows sent plus a queued notice and no retry', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    adapter.setRouting({ delivered: false, queued: true });
    render(Chat, { adapter, contact: alice });
    await screen.findByRole('textbox', { name: 'Message' });
    await send('later');
    expect((await screen.findByText(/Queued/)).textContent).toContain('will arrive when they reconnect');
    expect(screen.getByText('sent')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
  });

  it('failure copy names the peer by petname or fingerprint, never by the wire-supplied hint', async () => {
    const adapter = await readyAdapter();
    const hostile = await adapter.addContact(`mrd1:mallory@will-deliver-later-${XSS_IMG.replace(/\s/g, '/')}`);
    adapter.setRouting({ delivered: false, queued: false });
    render(Chat, { adapter, contact: hostile });
    await screen.findByRole('textbox', { name: 'Message' });
    await send('hi');
    const notice = await screen.findByText(/Not delivered/);
    expect(notice.textContent).toContain(hostile.fingerprint);
    expect(notice.textContent).not.toContain('will-deliver-later');
    expect(notice.querySelector('img')).toBeNull();
  });

  it('an adapter send-blocked rejection shows fixed copy, not the raw error, and re-queries the gate', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    vi.spyOn(adapter, 'sendMessage').mockRejectedValue(
      new MeridianAdapterError('send-blocked', `raw ${XSS_IMG}`)
    );
    const gate = vi.spyOn(adapter, 'getSendGate');
    const { container } = render(Chat, { adapter, contact: alice });
    await screen.findByRole('textbox', { name: 'Message' });
    const before = gate.mock.calls.length;
    await send('hi');
    const alert = await screen.findByText(/Message not sent: sending to this contact is blocked/);
    expect(alert).toBeTruthy();
    expect(container.querySelector('img')).toBeNull();
    await waitFor(() => expect(gate.mock.calls.length).toBeGreaterThan(before + 1));
  });
});

describe('Chat: trust invariant (D06) — the send gate is consulted, never cached', () => {
  it('user-blocked contact: no composer, no Send, core reason shown', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    await adapter.setUserBlocked(ALICE_PEER, true);
    render(Chat, { adapter, contact: alice });

    const banner = await screen.findByRole('alert');
    expect(banner.getAttribute('data-gate')).toBe('blocked');
    expect(banner.textContent).toContain('FAKE: you blocked this contact');
    expect(composer()).toBeNull();
    expect(sendButton()).toBeNull();
    expect(document.querySelector('textarea')).toBeNull();
  });

  it('verified contact whose key changed (blocked): hard stop, no composer, no way to send', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    await adapter.markVerified(ALICE_PEER);
    adapter.simulateKeyChange(ALICE_PEER);
    const sendMessage = vi.spyOn(adapter, 'sendMessage');
    render(Chat, { adapter, contact: alice });

    const banner = await screen.findByRole('alert');
    expect(banner.getAttribute('data-gate')).toBe('blocked');
    expect(banner.textContent).toContain('FAKE: key changed on a verified contact; verify again');
    expect(composer()).toBeNull();
    expect(sendButton()).toBeNull();
    expect(sendMessage).not.toHaveBeenCalled();
    // The header shows the key-change state; it never reads as reassurance.
    expect(screen.getAllByText(/key changed/).length).toBeGreaterThan(0);
  });

  it('pinned contact whose key changed (warn): no composer until core says ok again', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    adapter.simulateKeyChange(ALICE_PEER);
    render(Chat, { adapter, contact: alice });

    const banner = await screen.findByRole('alert');
    expect(banner.getAttribute('data-gate')).toBe('warn');
    expect(banner.textContent).toContain('FAKE: key changed; acknowledge to continue');
    expect(composer()).toBeNull();
    expect(sendButton()).toBeNull();

    // Core clears the gate (acknowledge) and pushes trust-changed => the composer returns.
    await adapter.acknowledgeKeyChange(ALICE_PEER);
    expect(await screen.findByRole('textbox', { name: 'Message' })).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('a live key change removes the composer immediately and a stale draft cannot be sent', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    await adapter.markVerified(ALICE_PEER);
    const sendMessage = vi.spyOn(adapter, 'sendMessage');
    render(Chat, { adapter, contact: alice });
    const box = await screen.findByRole('textbox', { name: 'Message' });
    await typeInto(box, 'draft typed before the key change');

    adapter.simulateKeyChange(ALICE_PEER);
    await waitFor(() => expect(composer()).toBeNull());
    expect(sendButton()).toBeNull();
    expect((await screen.findByRole('alert')).getAttribute('data-gate')).toBe('blocked');
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('consults getSendGate afresh on every send: a gate that turns blocked with NO event still stops the send', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    const sendMessage = vi.spyOn(adapter, 'sendMessage');
    const getSendGate = vi.spyOn(adapter, 'getSendGate');
    render(Chat, { adapter, contact: alice });
    await screen.findByRole('textbox', { name: 'Message' });

    // First send: ok => goes through, and the gate was queried for it.
    const callsBeforeFirst = getSendGate.mock.calls.length;
    await send('first');
    await screen.findByText('first');
    expect(getSendGate.mock.calls.length).toBeGreaterThan(callsBeforeFirst);
    expect(sendMessage).toHaveBeenCalledTimes(1);

    // The gate flips behind the UI's back (no trust-changed event). The UI still shows a composer.
    getSendGate.mockResolvedValue({ kind: 'blocked', reason: 'blocked behind the UI back' });
    const callsBeforeSecond = getSendGate.mock.calls.length;
    await send('second');

    await waitFor(() => expect(composer()).toBeNull());
    expect(getSendGate.mock.calls.length).toBeGreaterThan(callsBeforeSecond);
    expect(sendMessage).toHaveBeenCalledTimes(1); // the second send never reached the adapter
    expect(screen.queryByText('second')).toBeNull();
    expect((await screen.findByRole('alert')).textContent).toContain('blocked behind the UI back');
  });

  it('retry goes through the same fresh gate check', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    adapter.setRouting({ delivered: false, queued: false });
    const sendMessage = vi.spyOn(adapter, 'sendMessage');
    render(Chat, { adapter, contact: alice });
    await screen.findByRole('textbox', { name: 'Message' });
    await send('x');
    const retry = await screen.findByRole('button', { name: 'Retry' });

    vi.spyOn(adapter, 'getSendGate').mockResolvedValue({ kind: 'warn', reason: 'warn now' });
    await fireEvent.click(retry);
    await waitFor(() => expect(composer()).toBeNull());
    expect(sendMessage).toHaveBeenCalledTimes(1);
  });

  it('fails closed when the gate query fails: no composer', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter);
    vi.spyOn(adapter, 'getSendGate').mockRejectedValue(new Error('boom'));
    render(Chat, { adapter, contact: alice });
    expect((await screen.findByText(/Sending is paused/)).textContent).toContain('Sending is paused');
    expect(composer()).toBeNull();
    expect(sendButton()).toBeNull();
  });

  it('fails closed while the gate has not answered yet: no composer', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter);
    vi.spyOn(adapter, 'getSendGate').mockReturnValue(new Promise<SendGate>(() => {}));
    render(Chat, { adapter, contact: alice });
    expect(await screen.findByText(/Checking whether sending is allowed/)).toBeTruthy();
    expect(composer()).toBeNull();
    expect(sendButton()).toBeNull();
  });

  it('only an explicit "ok" enables sending: an unrecognised gate kind is treated as blocked', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter);
    vi.spyOn(adapter, 'getSendGate').mockResolvedValue({ kind: 'mystery' } as unknown as SendGate);
    render(Chat, { adapter, contact: alice });
    await settle();
    expect(composer()).toBeNull();
    expect(sendButton()).toBeNull();
  });

  it('renders core\'s gate reason verbatim, as text (never HTML)', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter);
    const reason = `${XSS_IMG} ${XSS_SCRIPT} keep   spacing & <em>markup</em>`;
    vi.spyOn(adapter, 'getSendGate').mockResolvedValue({ kind: 'blocked', reason });
    const { container } = render(Chat, { adapter, contact: alice });
    const banner = await screen.findByRole('alert');
    expect(banner.querySelector('.reason')?.textContent).toBe(reason);
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('em')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
  });

  it('offers a Verify hand-off only when the shell wires one, in blocked and warn states', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter);
    adapter.simulateKeyChange(ALICE_PEER);
    const onverify = vi.fn();
    const first = render(Chat, { adapter, contact: alice });
    await screen.findByRole('alert');
    expect(screen.queryByRole('button', { name: 'Verify' })).toBeNull();
    first.unmount();

    render(Chat, { adapter, contact: alice, onverify });
    await fireEvent.click(await screen.findByRole('button', { name: 'Verify' }));
    expect(onverify).toHaveBeenCalledTimes(1);
  });
});

describe('Chat: send-time gate races fail closed', () => {
  it('a gate query superseded by a newer (warn) answer cannot authorise the send when it resolves ok', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    const sendMessage = vi.spyOn(adapter, 'sendMessage');
    render(Chat, { adapter, contact: alice });
    await screen.findByRole('textbox', { name: 'Message' });

    // The send's own query is held in flight; the newer (trust-changed) query returns `warn`.
    let release!: (g: SendGate) => void;
    let calls = 0;
    vi.spyOn(adapter, 'getSendGate').mockImplementation(() => {
      calls += 1;
      return calls === 1
        ? new Promise<SendGate>((r) => (release = r))
        : Promise.resolve({ kind: 'warn', reason: 'newer answer: warn' });
    });
    await send('raced');
    adapter.simulateKeyChange(ALICE_PEER); // emits trust-changed => newer query => warn
    expect((await screen.findByRole('alert')).textContent).toContain('newer answer: warn');

    release({ kind: 'ok' }); // the stale, superseded answer finally arrives
    await settle();
    expect(sendMessage).not.toHaveBeenCalled();
    expect(composer()).toBeNull();
    expect(screen.queryByText('raced')).toBeNull();
  });

  it.each([
    ['rejects', () => Promise.reject(new Error('boom'))],
    ['returns an unknown kind', () => Promise.resolve({ kind: 'mystery' } as unknown as SendGate)],
    ['never answers', () => new Promise<SendGate>(() => {})]
  ])('a gate query that %s at send time never reaches sendMessage', async (_name, behave) => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    const sendMessage = vi.spyOn(adapter, 'sendMessage');
    render(Chat, { adapter, contact: alice });
    await screen.findByRole('textbox', { name: 'Message' });

    vi.spyOn(adapter, 'getSendGate').mockImplementation(behave);
    await send('should not go');
    await settle();
    expect(sendMessage).not.toHaveBeenCalled();
    expect(screen.queryByText('should not go')).toBeNull();
  });

  it('a gate query that resolves ok after the screen was unmounted cannot send', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    const sendMessage = vi.spyOn(adapter, 'sendMessage');
    const vm = new ChatViewModel(adapter, alice);
    vm.start();
    await settle();
    let release!: (g: SendGate) => void;
    vi.spyOn(adapter, 'getSendGate').mockImplementation(
      () => new Promise<SendGate>((r) => (release = r))
    );
    vm.draft = 'late';
    const pending = vm.send();
    vm.dispose();
    release({ kind: 'ok' });
    await pending;
    expect(sendMessage).not.toHaveBeenCalled();
  });
});

describe('Chat: receipts and history ordering', () => {
  it('a receipt arriving before sendMessage resolves still shows delivered', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    const real = adapter.sendMessage.bind(adapter);
    vi.spyOn(adapter, 'sendMessage').mockImplementation(async (peer, body) => {
      const sent = await real(peer, body);
      adapter.simulateReceipt(peer, sent.mid); // receipt event beats the send's own resolve
      await settle();
      return sent;
    });
    render(Chat, { adapter, contact: alice });
    await screen.findByRole('textbox', { name: 'Message' });
    await send('quick ack');
    expect(await screen.findByText('delivered')).toBeTruthy();
    expect(screen.queryByText('sent')).toBeNull();
  });

  it('a stale history snapshot cannot downgrade a delivered message, nor lose an early receipt', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    const stale = {
      mid: 'abc',
      direction: 'out' as const,
      ts: 5,
      stream: 'mrd.chat/1',
      body: 'old out',
      state: 'sent' as const
    };
    let release!: () => void;
    const loadHistory = vi.spyOn(adapter, 'loadHistory');
    loadHistory.mockImplementation(
      () => new Promise((r) => (release = () => r([stale])))
    );
    const vm = new ChatViewModel(adapter, alice);
    vm.start();
    await settle();
    adapter.simulateReceipt(ALICE_PEER, 'abc'); // receipt first; message not in the transcript yet
    release(); // ...then the stale snapshot lands
    await settle();
    expect(vm.messages.find((m) => m.mid === 'abc')?.state).toBe('delivered');

    // And a second stale load after it is already delivered still does not downgrade it.
    loadHistory.mockResolvedValue([stale]);
    await vm.loadHistory();
    expect(vm.messages.find((m) => m.mid === 'abc')?.state).toBe('delivered');
    vm.dispose();
  });
});

describe('Chat: header follows the contact prop', () => {
  it('a refreshed contact for the same peer (petname, user-block) updates header and label without remounting', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    const { rerender } = render(Chat, { adapter, contact: alice });
    expect(await screen.findByRole('heading', { name: 'Alice' })).toBeTruthy();
    const box = screen.getByRole('textbox', { name: 'Message' });
    await typeInto(box, 'draft survives');

    await rerender({ adapter, contact: { ...alice, petname: 'Alicia', userBlocked: true } });
    expect(await screen.findByRole('heading', { name: 'Alicia' })).toBeTruthy();
    expect(screen.getByText('blocked by you')).toBeTruthy();
    // Same conversation instance (no remount): the unsent draft is still in the composer.
    expect((screen.getByRole('textbox', { name: 'Message' }) as HTMLTextAreaElement).value).toBe(
      'draft survives'
    );
  });
});

describe('Chat: peer-controlled strings render as text only', () => {
  it('message bodies, petname, hint and fingerprint-adjacent labels cannot inject markup', async () => {
    const adapter = await readyAdapter();
    const eve = await adapter.addContact(`mrd1:eve@${XSS_IMG.replace(/\s/g, '/')}`, XSS_SCRIPT);
    await adapter.sendMessage(eve.peerId, XSS_IMG);
    adapter.simulateInboundMessage(eve.peerId, XSS_SCRIPT);
    const { container } = render(Chat, { adapter, contact: eve });
    await screen.findByRole('heading', { name: XSS_SCRIPT });
    await screen.findByText(XSS_IMG);
    await waitFor(() => expect(container.textContent).toContain(XSS_SCRIPT));
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
  });

  it('a hostile hint used as the header label is text only', async () => {
    const adapter = await readyAdapter();
    const eve = await adapter.addContact(`mrd1:eve@${XSS_IMG.replace(/\s/g, '/')}`);
    const { container } = render(Chat, { adapter, contact: eve });
    await screen.findByRole('textbox', { name: 'Message' });
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('h2')?.textContent).toBe(eve.hint);
  });
});
