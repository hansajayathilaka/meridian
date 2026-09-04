<!--
  MessageRequests — the first-contact request queue (task 4.21's browser/desktop equivalent).
  Shows only what `MessageRequest` already exposes (sender id, safety number, held intro) and
  wraps `acceptMessageRequest`/`rejectMessageRequest` — no new trust decision made here, mirroring
  4.21's own "no new trust decision made here" scope note. Reject requires an explicit confirm
  step (mirrors `apps/tui/src/screens/requests.rs`'s y/n confirm — accept/reject are both
  consequential enough not to be a single click) and, once confirmed, leaves no trace: the request
  simply disappears from `$store.requests`, and (per `fake-adapter.ts`'s own guarantee)
  `listContacts()` never gains an entry for it.

  Known interface-coverage note: this screen only ever shows requests received *after* it mounts
  (see `messageRequestsStore.ts`'s module doc for the full explanation and the flagged gap).
-->
<script lang="ts">
  import { onDestroy } from "svelte";

  import type { MeridianClientAdapter, MeridianId } from "../lib/adapter";
  import { createMessageRequestsStore } from "./stores/messageRequestsStore";

  export let adapter: MeridianClientAdapter;
  /** Fired once a request is accepted, with the sender's id — a shell wires this to opening
   * `Chat.svelte` for the newly-pinned contact. */
  export let onAccepted: ((peer: MeridianId) => void) | undefined = undefined;

  const store = createMessageRequestsStore(adapter);
  onDestroy(() => store.destroy());

  let petnameDrafts: Record<string, string> = {};
  let confirmingReject: MeridianId | null = null;

  async function handleAccept(from: MeridianId): Promise<void> {
    const petname = petnameDrafts[from]?.trim();
    try {
      await store.accept(from, petname || undefined);
      onAccepted?.(from);
    } catch {
      // Surfaced via $store.error below.
    }
  }

  function requestReject(from: MeridianId): void {
    confirmingReject = from;
  }

  function cancelReject(): void {
    confirmingReject = null;
  }

  async function confirmReject(from: MeridianId): Promise<void> {
    confirmingReject = null;
    try {
      await store.reject(from);
    } catch {
      // Surfaced via $store.error below.
    }
  }
</script>

<div class="message-requests-screen">
  <h2>Message requests</h2>
  {#if $store.error}
    <p class="error" role="alert">{$store.error}</p>
  {/if}
  {#if $store.requests.length === 0}
    <p class="empty">No pending requests.</p>
  {:else}
    <ul class="request-list">
      {#each $store.requests as req (req.from)}
        <li class="request">
          <p class="from">{req.from}</p>
          <p class="safety-number">{req.safetyNumber.grouped}</p>
          {#if req.introPreview}
            <p class="intro">{req.introPreview}</p>
          {/if}
          <input
            aria-label="Petname for {req.from} (optional)"
            bind:value={petnameDrafts[req.from]}
            placeholder="Petname (optional)"
          />
          <div class="actions">
            <button
              type="button"
              disabled={$store.busy === req.from}
              on:click={() => handleAccept(req.from)}
            >
              Accept
            </button>
            {#if confirmingReject === req.from}
              <span class="confirm">Reject and discard this request?</span>
              <button
                type="button"
                disabled={$store.busy === req.from}
                on:click={() => confirmReject(req.from)}
              >
                Confirm reject
              </button>
              <button type="button" on:click={cancelReject}>Cancel</button>
            {:else}
              <button
                type="button"
                disabled={$store.busy === req.from}
                on:click={() => requestReject(req.from)}
              >
                Reject
              </button>
            {/if}
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .message-requests-screen {
    padding: 0.75rem;
  }
  .error {
    color: var(--meridian-error-fg, #b91c1c);
  }
  .empty {
    color: var(--meridian-muted-fg, #666);
  }
  .request-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .request {
    border: 1px solid var(--meridian-border, #ddd);
    border-radius: 0.5rem;
    padding: 0.6rem;
  }
  .from {
    font-weight: 600;
    word-break: break-all;
    margin: 0;
  }
  .safety-number {
    font-family: var(--meridian-mono, monospace);
    font-size: 0.85em;
  }
  .intro {
    color: var(--meridian-muted-fg, #666);
    font-style: italic;
  }
  .actions {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-top: 0.5rem;
  }
  .confirm {
    font-size: 0.85em;
    color: var(--meridian-warn-fg, #92400e);
  }
</style>
