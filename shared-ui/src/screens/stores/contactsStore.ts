/**
 * View-model store backing {@link ../Contacts.svelte}. Materializes the conversation list from
 * `MeridianClientAdapter.listConversations()` (itself client-materialized per `adapter.ts`'s own
 * "Enumeration operations" doc — no `meridian-core` bulk session query exists yet) and wraps
 * `addContact`. No trust/send-gate decisions live here — that is `chatStore`'s job once a
 * conversation is opened; this store only ever surfaces `Contact.trust` as already reported by
 * the adapter, unmodified, exactly like `ContactRow` does.
 */

import { writable, type Readable } from "svelte/store";

import type { ConversationSummary, MeridianClientAdapter, MeridianId } from "../../lib/adapter";
import { errorMessage } from "./errors";

export interface ContactsState {
  conversations: ConversationSummary[];
  loading: boolean;
  error: string | null;
  addError: string | null;
}

export interface ContactsStore extends Readable<ContactsState> {
  /** (Re)loads the conversation list from the adapter. */
  refresh(): Promise<void>;
  /** TOFU-pins `id` as a contact and refreshes the list. */
  addContact(id: MeridianId, petname?: string): Promise<void>;
}

const initialState: ContactsState = {
  conversations: [],
  loading: false,
  error: null,
  addError: null,
};

function byLastActivityDesc(a: ConversationSummary, b: ConversationSummary): number {
  return (b.lastActivityAt ?? 0) - (a.lastActivityAt ?? 0);
}

export function createContactsStore(adapter: MeridianClientAdapter): ContactsStore {
  const { subscribe, update } = writable<ContactsState>({ ...initialState });

  async function refresh(): Promise<void> {
    update((s) => ({ ...s, loading: true, error: null }));
    try {
      const conversations = (await adapter.listConversations()).slice().sort(byLastActivityDesc);
      update((s) => ({ ...s, conversations, loading: false }));
    } catch (err) {
      update((s) => ({ ...s, loading: false, error: errorMessage(err) }));
    }
  }

  async function addContact(id: MeridianId, petname?: string): Promise<void> {
    update((s) => ({ ...s, addError: null }));
    try {
      await adapter.addContact(id, petname);
      await refresh();
    } catch (err) {
      update((s) => ({ ...s, addError: errorMessage(err) }));
      throw err;
    }
  }

  return { subscribe, refresh, addContact };
}
