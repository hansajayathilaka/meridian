<!--
  Protected app chrome — every route under `(app)/` (contacts/requests/chat/verify/files) needs a
  signed-in account; this layout is the one place that guard lives (route groups let it apply to
  all of them without adding a path segment, and without repeating the guard in each `+page.svelte`).

  Reuses `shared-ui`'s `LayoutShell` (12.7) unmodified for the sidebar/main frame, and `Contacts`
  (12.7) itself as the permanent sidebar contents — clicking a contact routes to `/chat/[peer]`.
  `Contacts.svelte` (and everything it calls — `listConversations`/`addContact`) is one of the
  ~30 GAP'd `MeridianClientAdapter` methods today (see `src/lib/adapter.ts`'s top doc comment): this
  sidebar will render its own `$store.error`/`$store.addError` banners from `contactsStore.ts`
  rather than a contact list, until a future task adds the missing `meridian-wasm` session/chat
  bindings. That is the correct, honest behavior for this shell to wire up — not something to route
  around.
-->
<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";

  import { Contacts, LayoutShell } from "shared-ui";
  import type { MeridianId } from "shared-ui";
  import { adapter, currentAccountId, signOut } from "$lib/session";

  onMount(() => {
    if (!$currentAccountId) void goto("/");
  });

  function handleSelectContact(peer: MeridianId): void {
    void goto(`/chat/${encodeURIComponent(peer)}`);
  }

  async function handleSignOut(): Promise<void> {
    await signOut();
    void goto("/");
  }
</script>

{#if $currentAccountId}
  <LayoutShell>
    <svelte:fragment slot="sidebar">
      <Contacts {adapter} onSelect={handleSelectContact} />
    </svelte:fragment>
    <svelte:fragment slot="header">
      <header class="app-header">
        <span class="account" data-testid="current-account" title={$currentAccountId}
          >{$currentAccountId}</span
        >
        <nav>
          <a href="/requests">Requests</a>
          <button type="button" on:click={handleSignOut}>Sign out</button>
        </nav>
      </header>
    </svelte:fragment>
    <slot />
  </LayoutShell>
{/if}

<style>
  .app-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--meridian-border, #ddd);
  }
  .account {
    font-family: var(--meridian-mono, monospace);
    font-size: 0.8em;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 60%;
  }
  .app-header nav {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
</style>
