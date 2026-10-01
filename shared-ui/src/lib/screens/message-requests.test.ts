import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { MessageRequests, type ContactSummary } from '../index';
import { BOB_PEER, XSS_IMG, XSS_SCRIPT, readyAdapter, settle } from './test-support';

const CAROL_PEER = 'mrd1:carol';

describe('MessageRequests', () => {
  it('shows sender, safety number, and intro for a pending request, and nothing is actioned yet', async () => {
    const adapter = await readyAdapter();
    const req = adapter.simulateInboundMessageRequest(BOB_PEER, 'hello, it is bob');
    render(MessageRequests, { adapter });

    expect(await screen.findByText(BOB_PEER)).toBeTruthy();
    expect(screen.getByText(req.safetyNumber)).toBeTruthy();
    expect(screen.getByText('hello, it is bob')).toBeTruthy();
    expect(await adapter.listContacts()).toEqual([]);
  });

  it('shows an explicit marker when the first envelope carried no text', async () => {
    const adapter = await readyAdapter();
    adapter.simulateInboundMessageRequest(BOB_PEER, null);
    render(MessageRequests, { adapter });
    expect(await screen.findByText('(no text)')).toBeTruthy();
  });

  it('shows the empty state', async () => {
    const adapter = await readyAdapter();
    render(MessageRequests, { adapter });
    expect(await screen.findByText('No message requests.')).toBeTruthy();
  });

  it('accept needs a confirm step; confirming pins the sender and delivers the intro to the chat', async () => {
    const adapter = await readyAdapter();
    adapter.simulateInboundMessageRequest(BOB_PEER, 'hello, it is bob');
    const accept = vi.spyOn(adapter, 'acceptMessageRequest');
    const onaccepted = vi.fn<(c: ContactSummary) => void>();
    render(MessageRequests, { adapter, onaccepted });

    await fireEvent.click(await screen.findByRole('button', { name: 'Accept' }));
    // Choosing alone does nothing adapter-side (never pin before the user decides).
    expect(accept).not.toHaveBeenCalled();
    expect(await adapter.listContacts()).toEqual([]);
    expect(screen.getByRole('group', { name: 'Confirm decision' }).textContent).toContain('unverified');

    await fireEvent.click(screen.getByRole('button', { name: 'Confirm accept' }));
    await waitFor(() => expect(onaccepted).toHaveBeenCalledTimes(1));
    expect(accept).toHaveBeenCalledWith(BOB_PEER);
    const [contact] = await adapter.listContacts();
    expect(contact?.peerId).toBe(BOB_PEER);
    expect(contact?.trust).toBe('pinned'); // pinned, NOT verified
    expect((await adapter.loadHistory(BOB_PEER)).map((m) => m.body)).toEqual(['hello, it is bob']);
    expect(await screen.findByText('No message requests.')).toBeTruthy();
  });

  it('reject needs a confirm step; confirming discards it and leaves no trace', async () => {
    const adapter = await readyAdapter();
    adapter.simulateInboundMessageRequest(BOB_PEER, 'hello');
    const reject = vi.spyOn(adapter, 'rejectMessageRequest');
    const send = vi.spyOn(adapter, 'sendMessage');
    const onrejected = vi.fn();
    render(MessageRequests, { adapter, onrejected });

    await fireEvent.click(await screen.findByRole('button', { name: 'Reject' }));
    expect(reject).not.toHaveBeenCalled();
    expect(screen.getByRole('group', { name: 'Confirm decision' }).textContent).toContain(
      'nothing is sent back'
    );
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm reject' }));

    await waitFor(() => expect(onrejected).toHaveBeenCalledWith(BOB_PEER));
    expect(await screen.findByText('No message requests.')).toBeTruthy();
    // Indistinguishable from a sender who was never queued: no contact, no history, nothing sent.
    expect(await adapter.listContacts()).toEqual([]);
    expect(await adapter.loadHistory(BOB_PEER)).toEqual([]);
    expect(await adapter.listMessageRequests()).toEqual([]);
    expect(send).not.toHaveBeenCalled();
  });

  it('cancel abandons the decision without touching the adapter', async () => {
    const adapter = await readyAdapter();
    adapter.simulateInboundMessageRequest(BOB_PEER, 'hello');
    const accept = vi.spyOn(adapter, 'acceptMessageRequest');
    const reject = vi.spyOn(adapter, 'rejectMessageRequest');
    render(MessageRequests, { adapter });
    await fireEvent.click(await screen.findByRole('button', { name: 'Accept' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('group', { name: 'Confirm decision' })).toBeNull();
    expect(accept).not.toHaveBeenCalled();
    expect(reject).not.toHaveBeenCalled();
    expect(screen.getByText(BOB_PEER)).toBeTruthy();
  });

  it('picks up requests that arrive while open, once per sender', async () => {
    const adapter = await readyAdapter();
    render(MessageRequests, { adapter });
    await screen.findByText('No message requests.');
    adapter.simulateInboundMessageRequest(BOB_PEER, 'one');
    adapter.simulateInboundMessageRequest(BOB_PEER, 'one again');
    await screen.findByText('one again');
    expect(screen.getAllByText(BOB_PEER)).toHaveLength(1);
  });

  it('applies a decision to the sender it was issued for, not to another row (4.21 correlation bug)', async () => {
    const adapter = await readyAdapter();
    adapter.simulateInboundMessageRequest(BOB_PEER, 'from bob');
    adapter.simulateInboundMessageRequest(CAROL_PEER, 'from carol');

    // Hold bob's accept in flight so a refresh/event for carol can land mid-decision.
    let release!: () => void;
    const realAccept = adapter.acceptMessageRequest.bind(adapter);
    vi.spyOn(adapter, 'acceptMessageRequest').mockImplementation(async (id) => {
      await new Promise<void>((r) => (release = r));
      return realAccept(id);
    });
    render(MessageRequests, { adapter });
    await screen.findByText('from carol');

    const bobRow = screen.getByText(BOB_PEER).closest('li')!;
    await fireEvent.click(bobRow.querySelector<HTMLButtonElement>('button')!); // Accept (bob)
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm accept' }));

    // While in flight: a new request arrives; every other decision control is locked.
    adapter.simulateInboundMessageRequest('mrd1:dave', 'from dave');
    await screen.findByText('from dave');
    for (const b of screen.getAllByRole('button', { name: /^(Accept|Reject)$/ })) {
      expect((b as HTMLButtonElement).disabled).toBe(true);
    }
    release();

    await waitFor(() => expect(screen.queryByText('from bob')).toBeNull());
    expect(screen.getByText('from carol')).toBeTruthy();
    expect(screen.getByText('from dave')).toBeTruthy();
    expect((await adapter.listContacts()).map((c) => c.peerId)).toEqual([BOB_PEER]);
  });

  it('a stale accept for a request that no longer exists shows fixed copy and refreshes the queue', async () => {
    const adapter = await readyAdapter();
    adapter.simulateInboundMessageRequest(BOB_PEER, 'hello');
    render(MessageRequests, { adapter });
    await fireEvent.click(await screen.findByRole('button', { name: 'Accept' }));
    // The request vanishes behind the UI's back (not via an event the screen listens to).
    await adapter.rejectMessageRequest(BOB_PEER);
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm accept' }));
    expect((await screen.findByRole('alert')).textContent).toBe('That request is no longer pending.');
    expect(await screen.findByText('No message requests.')).toBeTruthy();
    expect(await adapter.listContacts()).toEqual([]);
  });

  it('renders sender, safety number and intro as text only (XSS-hostile strings)', async () => {
    const adapter = await readyAdapter();
    adapter.simulateInboundMessageRequest(`mrd1:${XSS_IMG.replace(/\s/g, '/')}`, XSS_SCRIPT);
    const { container } = render(MessageRequests, { adapter });
    await screen.findByText(XSS_SCRIPT);
    await settle();
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
    expect(container.querySelector('.intro')?.textContent?.trim()).toBe(XSS_SCRIPT);
  });

  it('stops listening to the adapter when unmounted', async () => {
    const adapter = await readyAdapter();
    const unsub = vi.fn();
    vi.spyOn(adapter, 'subscribe').mockImplementation(() => unsub);
    const { unmount } = render(MessageRequests, { adapter });
    await screen.findByText('No message requests.');
    unmount();
    expect(unsub).toHaveBeenCalledTimes(1);
  });

  it('a throwing shell callback is not shown as a failed decision', async () => {
    const adapter = await readyAdapter();
    adapter.simulateInboundMessageRequest(BOB_PEER, 'hello');
    adapter.simulateInboundMessageRequest(CAROL_PEER, 'hello too');
    const boom = vi.fn(() => {
      throw new Error('shell bug');
    });
    render(MessageRequests, { adapter, onaccepted: boom, onrejected: boom });

    const bobRow = (await screen.findByText(BOB_PEER)).closest('li')!;
    await fireEvent.click(bobRow.querySelector<HTMLButtonElement>('button')!); // Accept bob
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm accept' }));
    await waitFor(() => expect(boom).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByText(BOB_PEER)).toBeNull());
    expect(screen.queryByRole('alert')).toBeNull();

    await fireEvent.click(screen.getByRole('button', { name: 'Reject' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm reject' }));
    await waitFor(() => expect(boom).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByText('No message requests.')).toBeTruthy());
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('tolerates an adapter queue containing the same sender twice (keyed each)', async () => {
    const adapter = await readyAdapter();
    const req = adapter.simulateInboundMessageRequest(BOB_PEER, 'dup');
    vi.spyOn(adapter, 'listMessageRequests').mockResolvedValue([req, req]);
    render(MessageRequests, { adapter });
    expect(await screen.findByText('dup')).toBeTruthy();
    expect(screen.getAllByText(BOB_PEER)).toHaveLength(1);
  });
});
