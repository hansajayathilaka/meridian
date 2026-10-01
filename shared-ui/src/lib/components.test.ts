import { describe, expect, it, vi } from 'vitest';
import { createRawSnippet } from 'svelte';
import { render, screen, fireEvent } from '@testing-library/svelte';
import { AppShell, ContactRow, MessageList, type ChatMessage, type ContactSummary } from './index';
import { contactDisplayLabel, trustLabel } from './view';

const contact = (over: Partial<ContactSummary> = {}): ContactSummary => ({
  peerId: 'mrd1:alice',
  id: 'mrd1:alice@org-a.test',
  petname: null,
  hint: 'org-a.test',
  fingerprint: 'fp-deadbeef',
  trust: 'pinned',
  userBlocked: false,
  pinnedKeyHistory: [],
  policyOverride: null,
  addedAt: 1,
  ...over
});

describe('view helpers', () => {
  it('label falls back petname -> hint -> fingerprint; never derives a petname', () => {
    expect(contactDisplayLabel(contact({ petname: 'Al' }))).toBe('Al');
    expect(contactDisplayLabel(contact())).toBe('org-a.test');
    expect(contactDisplayLabel(contact({ hint: '' }))).toBe('fp-deadbeef');
  });

  it('pinned reads as unverified, never as trusted', () => {
    expect(trustLabel('pinned')).toBe('unverified');
    expect(trustLabel('verified', true)).toBe('blocked by you');
  });

  it('key-change states are labelled distinctly and never read as reassurance', () => {
    expect(trustLabel('blocked')).toBe('key changed: sending blocked');
    expect(trustLabel('pinned-key-changed')).toBe('key changed: warning');
  });
});

describe('MessageList', () => {
  const messages: ChatMessage[] = [
    { mid: '1', direction: 'in', ts: 1, stream: 'mrd.chat/1', body: 'hi', state: 'received' },
    { mid: '2', direction: 'out', ts: 2, stream: 'mrd.chat/1', body: 'yo', state: 'sent' }
  ];

  it('renders bodies and a state marker for outgoing messages only', () => {
    render(MessageList, { messages });
    const items = screen.getAllByRole('listitem');
    expect(items).toHaveLength(2);
    expect(items[0]?.textContent?.trim()).toBe('hi');
    expect(items[1]?.textContent).toContain('sent');
  });

  it('renders peer-controlled bodies as text, never as HTML', () => {
    const hostile: ChatMessage = {
      ...messages[0]!,
      mid: '3',
      body: '<img src=x onerror=alert(1)>'
    };
    const { container } = render(MessageList, { messages: [hostile] });
    expect(container.querySelector('img')).toBeNull();
    expect(container.textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('shows the empty text when there are no messages', () => {
    render(MessageList, { messages: [], emptyText: 'Nothing here' });
    expect(screen.getByText('Nothing here')).toBeTruthy();
  });
});

describe('ContactRow', () => {
  it('shows label, fingerprint alongside the petname, and trust; fires onselect', async () => {
    const onselect = vi.fn();
    const c = contact({ petname: 'Al' });
    render(ContactRow, { contact: c, onselect });
    expect(screen.getByText('Al')).toBeTruthy();
    expect(screen.getByText('fp-deadbeef')).toBeTruthy();
    expect(screen.getByText('unverified')).toBeTruthy();
    await fireEvent.click(screen.getByRole('button'));
    expect(onselect).toHaveBeenCalledWith(c);
  });

  it('reflects selection via aria-pressed', () => {
    render(ContactRow, { contact: contact(), selected: true });
    expect(screen.getByRole('button').getAttribute('aria-pressed')).toBe('true');
  });
});

describe('AppShell', () => {
  it('renders title, connection status, and slots', () => {
    const children = createRawSnippet(() => ({ render: () => '<p>content</p>' }));
    const sidebar = createRawSnippet(() => ({ render: () => '<p>side</p>' }));
    render(AppShell, {
      title: 'Meridian',
      connection: { kind: 'reconnecting', attempt: 2, max: 5 },
      children,
      sidebar
    });
    expect(screen.getByRole('heading').textContent).toBe('Meridian');
    expect(screen.getByRole('status').textContent).toBe('reconnecting (2/5)');
    expect(screen.getByText('content')).toBeTruthy();
    expect(screen.getByText('side')).toBeTruthy();
    expect(screen.getByRole('navigation', { name: 'Contacts' })).toBeTruthy();
  });

  it('sidebar label is overridable', () => {
    const sidebar = createRawSnippet(() => ({ render: () => '<p>side</p>' }));
    render(AppShell, { title: 'Meridian', sidebar, sidebarLabel: 'Conversations' });
    expect(screen.getByRole('navigation', { name: 'Conversations' })).toBeTruthy();
  });
});
