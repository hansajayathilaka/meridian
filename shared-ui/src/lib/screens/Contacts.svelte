<script lang="ts">
  import { onMount } from 'svelte';
  import type { ContactSummary, MeridianClientAdapter, PeerId } from '../adapter';
  import ContactRow from '../components/ContactRow.svelte';
  import { ContactsViewModel } from './contacts.svelte';
  import { notify } from './safe-call';

  interface Props {
    adapter: MeridianClientAdapter;
    /** The currently open conversation, for highlighting. */
    selectedPeerId?: PeerId | null;
    /** A contact row was chosen (the shell opens the chat). */
    onselect?: (contact: ContactSummary) => void;
    /** A contact was added (or re-added) through the form. */
    onadded?: (contact: ContactSummary) => void;
    /** The user asked to open the message-request queue. */
    onopenrequests?: () => void;
  }

  let { adapter, selectedPeerId = null, onselect, onadded, onopenrequests }: Props = $props();

  // The adapter is fixed for this screen's lifetime (a shell remounts to change it).
  // svelte-ignore state_referenced_locally
  const vm = new ContactsViewModel(adapter);

  onMount(() => {
    vm.start();
    return () => vm.dispose();
  });

  async function add(): Promise<void> {
    const contact = await vm.add();
    if (contact !== null) notify(onadded, contact); // a throwing shell callback is isolated
  }
</script>

<!--
  Everything shown here that a peer or the wire can influence (hint, id) is rendered as text only
  (never `{@html}`); the petname is the user's own. The fingerprint is shown alongside every
  label by ContactRow (tui-client.md §6 rule 2). Trust comes from core, via the adapter.
-->
<section class="contacts" aria-label="Contacts">
  <form
    class="add"
    onsubmit={(e) => {
      e.preventDefault();
      void add();
    }}
  >
    <label>
      Meridian ID
      <input
        type="text"
        name="contact-id"
        autocomplete="off"
        spellcheck="false"
        placeholder="mrd1:…"
        bind:value={vm.addId}
        disabled={vm.adding}
      />
    </label>
    <label>
      Petname (optional, only you see it)
      <input
        type="text"
        name="petname"
        autocomplete="off"
        bind:value={vm.addPetname}
        disabled={vm.adding}
      />
    </label>
    <button type="submit" disabled={vm.adding}>Add contact</button>
    {#if vm.addError}
      <p role="alert" class="error">{vm.addError}</p>
    {/if}
  </form>

  {#if vm.requestCount > 0}
    <button type="button" class="requests-link" onclick={() => onopenrequests?.()}>
      Message requests ({vm.requestCount})
    </button>
  {/if}

  <input
    type="search"
    aria-label="Filter contacts"
    placeholder="Filter"
    autocomplete="off"
    bind:value={vm.filter}
  />

  {#if vm.loadError}
    <p role="alert" class="error">{vm.loadError}</p>
  {/if}

  <ul class="list">
    {#each vm.visible as contact (contact.peerId)}
      <li>
        <ContactRow
          {contact}
          selected={selectedPeerId !== null && selectedPeerId === contact.peerId}
          onselect={(c) => onselect?.(c)}
        />
      </li>
    {:else}
      <li class="empty">{vm.contacts.length === 0 ? 'No contacts yet.' : 'No matching contacts.'}</li>
    {/each}
  </ul>
</section>

<style>
  .add {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    padding: 0.5rem;
  }
  .add label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .empty {
    padding: 0.5rem;
    opacity: 0.7;
  }
</style>
