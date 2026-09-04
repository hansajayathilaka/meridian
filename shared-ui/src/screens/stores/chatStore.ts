/**
 * View-model store backing {@link ../Chat.svelte} — the 1:1 conversation view. This is the
 * task's own named highest-risk area (block-on-verified / D06, system-design.md §4.4): a
 * `blocked` `SendGateState` must never be soft-bypassable from this UI.
 *
 * Two independent layers enforce that, deliberately redundant:
 *   1. `Chat.svelte` reads `$store.sendGate` and disables the composer's submit control whenever
 *      `sendGate.kind !== "ok"` — the UI-level gate this task's own review specifically wants a
 *      test for (mirrors `apps/tui/src/screens/chat.rs`'s "composer refuses to enqueue a send").
 *   2. `send()` below *re-reads* `adapter.sendGateState(peer)` immediately before ever calling
 *      `adapter.sendChat`, rather than trusting whatever gate value the UI last rendered — closing
 *      the window where a contact could be blocked (e.g. from another tab/screen sharing the same
 *      adapter) between paint and click. `adapter.sendChat` itself enforces the gate a third time
 *      (its own doc comment: "never bypassable by any other adapter method") — this store never
 *      relies on that alone, but never tries to duplicate its logic either, only to fail the same
 *      way at the UI layer first.
 */

import { writable, type Readable } from "svelte/store";

import type { ChatMessage, MeridianClientAdapter, MeridianId, SendGateState } from "../../lib/adapter";
import { MeridianAdapterError } from "../../lib/adapter";
import { errorMessage } from "./errors";

export interface ChatState {
  peer: MeridianId | null;
  messages: ChatMessage[];
  loading: boolean;
  sendGate: SendGateState;
  sending: boolean;
  error: string | null;
}

export interface ChatStore extends Readable<ChatState> {
  /** Opens (or resumes) the conversation with `peer`, loads history + the current send gate, and
   * marks it read. Safe to call again with a different `peer` to switch conversations. */
  open(peer: MeridianId): Promise<void>;
  /** Sends `body` to the currently open peer, re-checking the send gate first (see module doc). */
  send(body: string): Promise<void>;
  /** Clears a live `"warn"` gate for the currently open peer. */
  acknowledgeKeyChange(): Promise<void>;
  /** Unsubscribes from inbound-message events. Call from the component's `onDestroy`. */
  destroy(): void;
}

const initialState: ChatState = {
  peer: null,
  messages: [],
  loading: false,
  sendGate: { kind: "ok" },
  sending: false,
  error: null,
};

export function createChatStore(adapter: MeridianClientAdapter): ChatStore {
  const { subscribe, update, set } = writable<ChatState>({ ...initialState });
  let currentPeer: MeridianId | null = null;

  const unsubscribeMessages = adapter.onMessage((from, msg) => {
    if (from !== currentPeer) return;
    update((s) => (s.peer === from ? { ...s, messages: [...s.messages, msg] } : s));
    void adapter.markConversationRead(from).catch(() => {
      // Best-effort — an unread badge staying stale is not a correctness/security issue.
    });
  });

  async function open(peer: MeridianId): Promise<void> {
    currentPeer = peer;
    set({ ...initialState, peer, loading: true });
    try {
      await adapter.openConversation(peer);
      const [messages, sendGate] = await Promise.all([
        adapter.loadHistory(peer),
        adapter.sendGateState(peer),
      ]);
      await adapter.markConversationRead(peer);
      if (currentPeer === peer) {
        update((s) => (s.peer === peer ? { ...s, messages, sendGate, loading: false } : s));
      }
    } catch (err) {
      if (currentPeer === peer) {
        update((s) => (s.peer === peer ? { ...s, loading: false, error: errorMessage(err) } : s));
      }
    }
  }

  async function send(body: string): Promise<void> {
    const peer = currentPeer;
    if (!peer) {
      throw new MeridianAdapterError("unknown_conversation", "no conversation is open");
    }

    // Re-check the gate right before sending — see module doc. Never trust a stale render.
    const gate = await adapter.sendGateState(peer);
    if (currentPeer === peer) {
      update((s) => (s.peer === peer ? { ...s, sendGate: gate } : s));
    }
    if (gate.kind === "blocked") {
      throw new MeridianAdapterError("send_blocked", gate.reason);
    }
    if (gate.kind === "warn") {
      throw new MeridianAdapterError("send_warn_unacknowledged", gate.reason);
    }

    update((s) => (s.peer === peer ? { ...s, sending: true, error: null } : s));
    try {
      await adapter.sendChat(peer, body);
      const messages = await adapter.loadHistory(peer);
      if (currentPeer === peer) {
        update((s) => (s.peer === peer ? { ...s, messages, sending: false } : s));
      }
    } catch (err) {
      if (currentPeer === peer) {
        update((s) => (s.peer === peer ? { ...s, sending: false, error: errorMessage(err) } : s));
      }
      throw err;
    }
  }

  async function acknowledgeKeyChange(): Promise<void> {
    const peer = currentPeer;
    if (!peer) return;
    await adapter.acknowledgeKeyChange(peer);
    const gate = await adapter.sendGateState(peer);
    if (currentPeer === peer) {
      update((s) => (s.peer === peer ? { ...s, sendGate: gate } : s));
    }
  }

  function destroy(): void {
    unsubscribeMessages();
  }

  return { subscribe, open, send, acknowledgeKeyChange, destroy };
}
