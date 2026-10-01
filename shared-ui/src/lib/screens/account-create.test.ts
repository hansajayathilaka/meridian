import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { AccountCreate, FakeMeridianClientAdapter, MeridianAdapterError } from '../index';

const typeInto = (el: HTMLElement, value: string) => fireEvent.input(el, { target: { value } });
const input = (name: string) => document.querySelector<HTMLInputElement>(`input[name="${name}"]`)!;

describe('AccountCreate', () => {
  it('creates an account with device protection and reports it', async () => {
    const adapter = new FakeMeridianClientAdapter();
    const oncreated = vi.fn();
    render(AccountCreate, { adapter, oncreated });

    await typeInto(input('hint'), 'org-b.test');
    await fireEvent.click(screen.getByRole('button', { name: 'Create account' }));

    await waitFor(() => expect(oncreated).toHaveBeenCalledTimes(1));
    const loaded = await adapter.loadAccount();
    expect(loaded.kind).toBe('ready');
    expect(oncreated).toHaveBeenCalledWith(loaded.kind === 'ready' ? loaded.account : null);
  });

  it('hands a passphrase to the adapter, never renders it, and clears the fields afterwards', async () => {
    const adapter = new FakeMeridianClientAdapter();
    const generate = vi.spyOn(adapter, 'generateAccount');
    const { container } = render(AccountCreate, { adapter });

    await fireEvent.click(screen.getByLabelText('Protect with a passphrase'));
    await typeInto(input('passphrase'), 'correct horse battery');
    await typeInto(input('passphrase-confirm'), 'correct horse battery');
    expect(input('passphrase').type).toBe('password'); // masked
    expect(input('passphrase-confirm').type).toBe('password');
    await fireEvent.click(screen.getByRole('button', { name: 'Create account' }));

    await waitFor(() => expect(generate).toHaveBeenCalledTimes(1));
    expect(generate).toHaveBeenCalledWith('', { kind: 'passphrase', passphrase: 'correct horse battery' });
    await waitFor(() => expect(input('passphrase').value).toBe(''));
    expect(input('passphrase-confirm').value).toBe('');
    expect(container.textContent).not.toContain('correct horse battery');
    expect(container.innerHTML).not.toContain('correct horse battery');
  });

  it('clears the passphrase fields when creation fails, and shows fixed copy not the raw error', async () => {
    const adapter = new FakeMeridianClientAdapter();
    vi.spyOn(adapter, 'generateAccount').mockRejectedValue(
      new MeridianAdapterError('internal', `boom ${'hunter2'} <img src=x onerror=alert(1)>`)
    );
    const { container } = render(AccountCreate, { adapter });

    await fireEvent.click(screen.getByLabelText('Protect with a passphrase'));
    await typeInto(input('passphrase'), 'hunter2');
    await typeInto(input('passphrase-confirm'), 'hunter2');
    await fireEvent.click(screen.getByRole('button', { name: 'Create account' }));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe('Could not create the account. Please try again.');
    expect(container.textContent).not.toContain('hunter2');
    expect(container.querySelector('img')).toBeNull();
    expect(input('passphrase').value).toBe('');
    expect(input('passphrase-confirm').value).toBe('');
  });

  it('refuses mismatched or empty passphrases without calling the adapter, and clears the fields', async () => {
    const adapter = new FakeMeridianClientAdapter();
    const generate = vi.spyOn(adapter, 'generateAccount');
    render(AccountCreate, { adapter });

    await fireEvent.click(screen.getByLabelText('Protect with a passphrase'));
    await fireEvent.click(screen.getByRole('button', { name: 'Create account' }));
    expect((await screen.findByRole('alert')).textContent).toContain('Enter a passphrase');

    await typeInto(input('passphrase'), 'one');
    await typeInto(input('passphrase-confirm'), 'two');
    await fireEvent.click(screen.getByRole('button', { name: 'Create account' }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('do not match'));
    expect(generate).not.toHaveBeenCalled();
    expect(input('passphrase').value).toBe('');
    expect(input('passphrase-confirm').value).toBe('');
  });

  it('does not offer the passphrase option when the shell disables it', () => {
    render(AccountCreate, { adapter: new FakeMeridianClientAdapter(), allowPassphrase: false });
    expect(screen.queryByLabelText('Protect with a passphrase')).toBeNull();
  });

  it('never claims to be anonymous', () => {
    const { container } = render(AccountCreate, { adapter: new FakeMeridianClientAdapter() });
    expect(container.textContent?.toLowerCase()).not.toContain('anonymous');
  });

  it('a throwing shell callback is not reported as a creation failure', async () => {
    const adapter = new FakeMeridianClientAdapter();
    const oncreated = vi.fn(() => {
      throw new Error('shell bug');
    });
    render(AccountCreate, { adapter, oncreated });
    await fireEvent.click(screen.getByRole('button', { name: 'Create account' }));
    await waitFor(() => expect(oncreated).toHaveBeenCalledTimes(1));
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.queryByRole('alert')).toBeNull();
    expect((await adapter.loadAccount()).kind).toBe('ready');
  });

  it('switching back to device protection discards the typed passphrase', async () => {
    const adapter = new FakeMeridianClientAdapter();
    const generate = vi.spyOn(adapter, 'generateAccount');
    render(AccountCreate, { adapter });
    await fireEvent.click(screen.getByLabelText('Protect with a passphrase'));
    await typeInto(input('passphrase'), 'left behind');
    await typeInto(input('passphrase-confirm'), 'left behind');
    await fireEvent.click(screen.getByLabelText('Use device storage'));
    expect(document.querySelector('input[name="passphrase"]')).toBeNull();
    await fireEvent.click(screen.getByLabelText('Protect with a passphrase'));
    expect(input('passphrase').value).toBe('');
    expect(input('passphrase-confirm').value).toBe('');
    await fireEvent.click(screen.getByLabelText('Use device storage'));
    await fireEvent.click(screen.getByRole('button', { name: 'Create account' }));
    await waitFor(() => expect(generate).toHaveBeenCalledWith('', { kind: 'platform' }));
  });
});
