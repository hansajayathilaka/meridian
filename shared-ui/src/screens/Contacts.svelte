<!--
  Contacts — the contact list + add-contact screen (task 4.19's browser/desktop equivalent).
  Renders `ConversationSummary[]` (contact + last-activity/unread/preview) via the existing
  `ContactRow` primitive, so trust state always renders as the same glyph+label `ContactRow`
  already uses — no color-alone trust signal reintroduced here. No send-gate logic of its own:
  that only matters once a conversation is open, which is `Chat.svelte`'s job.
-->
<script lang="ts">
  import { onMount } from "svelte";

  import type { MeridianClientAdapter, MeridianId } from "../lib/adapter";
  import ContactRow from "../lib/components/ContactRow.svelte";
  import { createContactsStore } from "./stores/contactsStore";

  export let adapter: MeridianClientAdapter;
  export let selectedPeer: MeridianId | null = null;
  /** Fired when a row is selected — a shell wires this to opening `Chat.svelte` for that peer. */
  export let onSelect: ((peer: MeridianId) => void) | undefined = undefined;

  const store = createContactsStore(adapter);

  onMount(() => {
    void store.refresh();
  });

  let newId = "";
  let newPetname = "";

  async function handleAdd(): Promise<void> {
    const id = newId.trim();
    if (!id) return;
    try {
      await store.addContact(id, newPetname.trim() || undefined);
      newId = "";
      newPetname = "";
    } catch {
      // Surfaced via $store.addError below.
    }
  }

  function handleSelect(peer: MeridianId): void {
    onSelect?.(peer);
  }
</script>

<div class="contacts-screen">
  <form class="add-contact" on:submit|preventDefault={handleAdd}>
    <input aria-label="Contact id" bind:value={newId} placeholder="mrd1:...@domain" />
    <input aria-label="Petname (optional)" bind:value={newPetname} placeholder="Petname (optional)" />
    <button type="submit" disabled={!newId.trim()}>Add contact</button>
  </form>
  {#if $store.addError}
    <p class="error" role="alert">{$store.addError}</p>
  {/if}

  {#if $store.loading}
    <p class="loading">Loading…</p>
  {:else if $store.conversations.length === 0}
    <p class="empty">No contacts yet.</p>
  {:else}
    <ul class="conversation-list">
      {#each $store.conversations as conv (conv.contact.id)}
        <li>
          <ContactRow
            contact={conv.contact}
            selected={conv.contact.id === selectedPeer}
            unreadCount={conv.unreadCount}
            preview={conv.lastMessagePreview}
            on:click={() => handleSelect(conv.contact.id)}
          />
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .contacts-screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }
  .add-contact {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    padding: 0.75rem;
    border-bottom: 1px solid var(--meridian-border, #ddd);
  }
  .error {
    color: var(--meridian-error-fg, #b91c1c);
    padding: 0 0.75rem;
  }
  .loading,
  .empty {
    color: var(--meridian-muted-fg, #666);
    padding: 0.75rem;
  }
  .conversation-list {
    list-style: none;
    margin: 0;
    padding: 0;
    overflow-y: auto;
  }
</style>
