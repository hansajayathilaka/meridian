/**
 * View-model store backing {@link ../MessageRequests.svelte} — the first-contact request queue
 * (system-design.md §3.5).
 *
 * **Known interface gap (flagged, not worked around by extending `adapter.ts`/`fake-adapter.ts` —
 * those are task 12.2's owned, already-reviewed files; out of this task's scope per its own
 * "Out" list):** `MeridianClientAdapter` exposes only `onMessageRequest` (a live subscription for
 * *newly arriving* requests) and `acceptMessageRequest`/`rejectMessageRequest` (peer-keyed
 * actions) — there is no bulk `listMessageRequests()` query, even though `adapter.ts`'s own doc
 * comment notes `meridian_core::chat::ChatState::pending_requests()` already exists as real core
 * precedent for exactly this enumeration (it names it while discussing why `listConversations`
 * has *no* such precedent). Practical effect: this store only ever reflects requests that arrive
 * *while a `MessageRequests` screen instance is mounted and subscribed* — a request that was
 * already pending before mount (e.g. arrived while the queue screen was closed, or across an app
 * restart) will not appear until the sender's next envelope, if any. A future task should add a
 * `listMessageRequests(): Promise<MessageRequest[]>` to `MeridianClientAdapter`, backed by
 * `ChatState::pending_requests()`, mirroring `listContacts()`'s precedent-backed shape — see
 * `adapter.ts`'s own "Enumeration operations" doc comment for the pattern to follow.
 */

import { writable, type Readable } from "svelte/store";

import type { MeridianClientAdapter, MeridianId, MessageRequest } from "../../lib/adapter";
import { errorMessage } from "./errors";

export interface MessageRequestsState {
  requests: MessageRequest[];
  /** The `from` id of the request currently being accepted/rejected, if any — lets the UI disable
   * just that row's actions rather than the whole list while an accept/reject is in flight. */
  busy: MeridianId | null;
  error: string | null;
}

export interface MessageRequestsStore extends Readable<MessageRequestsState> {
  accept(from: MeridianId, petname?: string): Promise<void>;
  /** Rejects the request from `from` — leaves no trace in the contact list (mirrors
   * `apps/tui/src/screens/requests.rs`'s own "leaves no trace" property, task 4.21). */
  reject(from: MeridianId): Promise<void>;
  /** Unsubscribes from `onMessageRequest`. Call from the component's `onDestroy`. */
  destroy(): void;
}

export function createMessageRequestsStore(adapter: MeridianClientAdapter): MessageRequestsStore {
  const { subscribe, update } = writable<MessageRequestsState>({
    requests: [],
    busy: null,
    error: null,
  });

  const unsubscribe = adapter.onMessageRequest((req) => {
    update((s) =>
      s.requests.some((r) => r.from === req.from) ? s : { ...s, requests: [...s.requests, req] },
    );
  });

  async function accept(from: MeridianId, petname?: string): Promise<void> {
    update((s) => ({ ...s, busy: from, error: null }));
    try {
      await adapter.acceptMessageRequest(from, petname);
      update((s) => ({ ...s, busy: null, requests: s.requests.filter((r) => r.from !== from) }));
    } catch (err) {
      update((s) => ({ ...s, busy: null, error: errorMessage(err) }));
      throw err;
    }
  }

  async function reject(from: MeridianId): Promise<void> {
    update((s) => ({ ...s, busy: from, error: null }));
    try {
      await adapter.rejectMessageRequest(from);
      update((s) => ({ ...s, busy: null, requests: s.requests.filter((r) => r.from !== from) }));
    } catch (err) {
      update((s) => ({ ...s, busy: null, error: errorMessage(err) }));
      throw err;
    }
  }

  function destroy(): void {
    unsubscribe();
  }

  return { subscribe, accept, reject, destroy };
}
