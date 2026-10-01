import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { Contacts } from '../index';
import { ALICE_ID, ALICE_PEER, BOB_ID, BOB_PEER, XSS_IMG, readyAdapter, withContact } from './test-support';

const typeInto = (el: HTMLElement, value: string) => fireEvent.input(el, { target: { value } });
const idInput = () => screen.getByLabelText('Meridian ID');
const petnameInput = () => screen.getByLabelText(/Petname/);
const addButton = () => screen.getByRole('button', { name: 'Add contact' });

describe('Contacts', () => {
  it('shows the empty state, then a contact added through the form (with petname)', async () => {
    const adapter = await readyAdapter();
    const onadded = vi.fn();
    render(Contacts, { adapter, onadded });
    expect(await screen.findByText('No contacts yet.')).toBeTruthy();

    await typeInto(idInput(), ` ${ALICE_ID} `);
    await typeInto(petnameInput(), 'Al');
    await fireEvent.click(addButton());

    expect(await screen.findByText('Al')).toBeTruthy();
    expect(onadded).toHaveBeenCalledTimes(1);
    const [contact] = await adapter.listContacts();
    expect(contact?.petname).toBe('Al');
    expect(contact?.trust).toBe('pinned');
    // Fingerprint is shown alongside the petname; pinned reads "unverified", never "trusted".
    expect(screen.getByText(contact!.fingerprint)).toBeTruthy();
    expect(screen.getByText('unverified')).toBeTruthy();
    // The form is cleared after a successful add.
    expect((idInput() as HTMLInputElement).value).toBe('');
    expect((petnameInput() as HTMLInputElement).value).toBe('');
  });

  it('never invents a petname: without one the contact is labelled by hint, petname stays null', async () => {
    const adapter = await readyAdapter();
    render(Contacts, { adapter });
    await typeInto(idInput(), ALICE_ID);
    await fireEvent.click(addButton());
    expect(await screen.findByText('org-a.test')).toBeTruthy();
    expect((await adapter.listContacts())[0]?.petname).toBeNull();
  });

  it('asks core to validate the id and shows fixed copy for an invalid one', async () => {
    const adapter = await readyAdapter();
    const parse = vi.spyOn(adapter, 'parseId');
    const add = vi.spyOn(adapter, 'addContact');
    render(Contacts, { adapter });

    await typeInto(idInput(), 'not an id');
    await fireEvent.click(addButton());

    expect((await screen.findByRole('alert')).textContent).toContain('not a valid Meridian ID');
    expect(parse).toHaveBeenCalledWith('not an id');
    expect(add).not.toHaveBeenCalled();
  });

  it('asks for an id when the field is empty', async () => {
    const adapter = await readyAdapter();
    const parse = vi.spyOn(adapter, 'parseId');
    render(Contacts, { adapter });
    await fireEvent.click(addButton());
    expect((await screen.findByRole('alert')).textContent).toContain('Paste a Meridian ID');
    expect(parse).not.toHaveBeenCalled();
  });

  it('fires onselect and marks the open conversation', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Al');
    const onselect = vi.fn();
    render(Contacts, { adapter, onselect, selectedPeerId: ALICE_PEER });
    const row = await screen.findByRole('button', { name: /Al/ });
    expect(row.getAttribute('aria-pressed')).toBe('true');
    await fireEvent.click(row);
    expect(onselect).toHaveBeenCalledWith(alice);
  });

  it('filters by label, id, and fingerprint', async () => {
    const adapter = await readyAdapter();
    await withContact(adapter, ALICE_ID, 'Alice');
    await withContact(adapter, BOB_ID, 'Bob');
    render(Contacts, { adapter });
    await screen.findByText('Alice');
    await typeInto(screen.getByLabelText('Filter contacts'), 'bob');
    expect(screen.queryByText('Alice')).toBeNull();
    expect(screen.getByText('Bob')).toBeTruthy();
    await typeInto(screen.getByLabelText('Filter contacts'), 'zzz');
    expect(screen.getByText('No matching contacts.')).toBeTruthy();
  });

  it('reflects a core trust change pushed as an event (key change on a pinned contact)', async () => {
    const adapter = await readyAdapter();
    await withContact(adapter, ALICE_ID, 'Alice');
    render(Contacts, { adapter });
    expect(await screen.findByText('unverified')).toBeTruthy();
    adapter.simulateKeyChange(ALICE_PEER);
    expect(await screen.findByText('key changed: warning')).toBeTruthy();
  });

  it('delete + re-add cannot launder a key-change incident: the re-added row still shows it', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    adapter.simulateKeyChange(ALICE_PEER);
    await adapter.deleteContact(alice.peerId);
    render(Contacts, { adapter });
    await typeInto(idInput(), ALICE_ID);
    await fireEvent.click(addButton());
    expect(await screen.findByText('key changed: warning')).toBeTruthy();
    expect(screen.queryByText('unverified')).toBeNull();
  });

  it('shows the pending-request badge and opens the queue; updates when a request arrives', async () => {
    const adapter = await readyAdapter();
    const onopenrequests = vi.fn();
    render(Contacts, { adapter, onopenrequests });
    await screen.findByText('No contacts yet.');
    expect(screen.queryByRole('button', { name: /Message requests/ })).toBeNull();

    adapter.simulateInboundMessageRequest(BOB_PEER, 'hi');
    const link = await screen.findByRole('button', { name: 'Message requests (1)' });
    await fireEvent.click(link);
    expect(onopenrequests).toHaveBeenCalledTimes(1);
  });

  it('renders petnames, hints and ids as text only (XSS-hostile strings)', async () => {
    const adapter = await readyAdapter();
    await adapter.addContact(`mrd1:eve@${XSS_IMG.replace(/\s/g, '/')}`, XSS_IMG);
    const { container } = render(Contacts, { adapter });
    await screen.findByText(XSS_IMG);
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(container.textContent).toContain(XSS_IMG);
    await waitFor(() => expect(container.querySelectorAll('[onerror]').length).toBe(0));
  });

  it('stops listening to the adapter when unmounted', async () => {
    const adapter = await readyAdapter();
    const unsub = vi.fn();
    vi.spyOn(adapter, 'subscribe').mockImplementation(() => unsub);
    const { unmount } = render(Contacts, { adapter });
    await screen.findByText('No contacts yet.');
    unmount();
    expect(unsub).toHaveBeenCalledTimes(1);
  });

  it('a throwing onadded callback is isolated: no error shown, contact still listed', async () => {
    const adapter = await readyAdapter();
    const onadded = vi.fn(() => {
      throw new Error('shell bug');
    });
    render(Contacts, { adapter, onadded });
    await typeInto(idInput(), ALICE_ID);
    await typeInto(petnameInput(), 'Al');
    await fireEvent.click(addButton());
    expect(await screen.findByText('Al')).toBeTruthy();
    expect(onadded).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('tolerates an adapter list containing duplicate peers (keyed each)', async () => {
    const adapter = await readyAdapter();
    const alice = await withContact(adapter, ALICE_ID, 'Alice');
    vi.spyOn(adapter, 'listContacts').mockResolvedValue([alice, alice]);
    render(Contacts, { adapter });
    expect(await screen.findByText('Alice')).toBeTruthy();
    expect(screen.getAllByText('Alice')).toHaveLength(1);
  });
});
