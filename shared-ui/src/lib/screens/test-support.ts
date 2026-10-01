/** Shared fixtures for the screen component tests. Test-only; not exported from the package. */
import { FakeMeridianClientAdapter } from '../fake-adapter';
import type { ContactSummary } from '../adapter';

export const XSS_IMG = '<img src=x onerror=alert(1)>';
export const XSS_SCRIPT = '<script>alert(1)</script><b>bold</b>';

export const ALICE_ID = 'mrd1:alice@org-a.test';
export const ALICE_PEER = 'mrd1:alice';
export const BOB_ID = 'mrd1:bob@org-a.test';
export const BOB_PEER = 'mrd1:bob';

export async function readyAdapter(): Promise<FakeMeridianClientAdapter> {
  const adapter = new FakeMeridianClientAdapter();
  await adapter.generateAccount('org-b.test', { kind: 'platform' });
  return adapter;
}

export async function withContact(
  adapter: FakeMeridianClientAdapter,
  id = ALICE_ID,
  petname?: string
): Promise<ContactSummary> {
  return adapter.addContact(id, petname);
}

/** Let queued microtasks (adapter promises, store updates) settle. */
export async function settle(): Promise<void> {
  for (let i = 0; i < 5; i += 1) await Promise.resolve();
  await new Promise((r) => setTimeout(r, 0));
}
