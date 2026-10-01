/**
 * View-model for the contacts list + add-contact form. Pure orchestration over the adapter:
 * ID validation/canonicalisation is core's (`parseId`), trust state is core's (read back from
 * `listContacts`), and a petname is only ever the user's own typed input (system-design.md §3.1) —
 * never derived from the ID, the hint, or anything off the wire.
 */
import type { ClientEvent, ContactSummary, MeridianClientAdapter, Unsubscribe } from '../adapter';
import { contactDisplayLabel } from '../view';
import { describeError } from './copy';
import { uniqueBy } from './unique';

export class ContactsViewModel {
  contacts = $state.raw<readonly ContactSummary[]>([]);
  /** Number of pending first-contact requests (the queue itself lives in `MessageRequests`). */
  requestCount = $state(0);
  filter = $state('');
  addId = $state('');
  addPetname = $state('');
  adding = $state(false);
  addError = $state<string | null>(null);
  loadError = $state<string | null>(null);

  /** Contacts matching `filter` (case-insensitive substring over label, id, hint, fingerprint). */
  visible = $derived.by(() => {
    const needle = this.filter.trim().toLowerCase();
    if (needle === '') return this.contacts;
    return this.contacts.filter((c) =>
      [contactDisplayLabel(c), c.id, c.hint, c.fingerprint].some((s) =>
        s.toLowerCase().includes(needle)
      )
    );
  });

  private unsubscribe: Unsubscribe | null = null;
  private disposed = false;
  private listSeq = 0;
  private requestSeq = 0;

  constructor(private readonly adapter: MeridianClientAdapter) {}

  start(): void {
    // Subscribe before the first load so nothing is missed between the two.
    this.unsubscribe = this.adapter.subscribe((event) => this.onEvent(event));
    void this.refresh();
  }

  dispose(): void {
    this.disposed = true;
    this.unsubscribe?.();
    this.unsubscribe = null;
  }

  private onEvent(event: ClientEvent): void {
    if (this.disposed) return;
    // Both are re-queried rather than patched: the adapter's answer is authoritative.
    if (event.type === 'trust-changed') void this.refreshContacts();
    else if (event.type === 'message-request') void this.refreshRequestCount();
  }

  async refresh(): Promise<void> {
    await Promise.all([this.refreshContacts(), this.refreshRequestCount()]);
  }

  async refreshContacts(): Promise<void> {
    const seq = ++this.listSeq;
    try {
      const list = await this.adapter.listContacts();
      if (this.disposed || seq !== this.listSeq) return; // a newer refresh supersedes this one
      this.contacts = uniqueBy(list, (c) => c.peerId);
      this.loadError = null;
    } catch (e) {
      if (!this.disposed && seq === this.listSeq) this.loadError = describeError(e, 'load');
    }
  }

  async refreshRequestCount(): Promise<void> {
    const seq = ++this.requestSeq;
    try {
      const requests = await this.adapter.listMessageRequests();
      if (this.disposed || seq !== this.requestSeq) return;
      this.requestCount = requests.length;
    } catch {
      // The badge is advisory; the Requests screen reports its own load failures.
    }
  }

  /** Validate via core, then TOFU-pin. Resolves to the contact record on success. */
  async add(): Promise<ContactSummary | null> {
    if (this.adding) return null;
    const id = this.addId.trim();
    if (id === '') {
      this.addError = 'Paste a Meridian ID to add a contact.';
      return null;
    }
    const petname = this.addPetname.trim();
    this.adding = true;
    this.addError = null;
    try {
      const parsed = await this.adapter.parseId(id); // core validates; the UI never does
      // petname: only the user's explicit input, and only when non-empty (no clobbering on re-add).
      const contact = await this.adapter.addContact(parsed.id, petname === '' ? undefined : petname);
      this.addId = '';
      this.addPetname = '';
      await this.refreshContacts();
      return contact;
    } catch (e) {
      this.addError = describeError(e, 'add-contact');
      return null;
    } finally {
      this.adding = false;
    }
  }
}
