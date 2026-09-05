<!--
  App — the whole desktop shell (task 12.15's Deliverable 1). Plays the same role
  `apps/web/src/routes/**` (task 12.14) plays for the browser: wires `../src/adapter.ts`'s real
  `TauriMeridianClientAdapter` (task 12.6) to `shared-ui`'s screens (12.7-12.9), unmodified, per
  ADR 0012 ("screens are written once ... reused by both shells unmodified") and this task's own
  Risks/notes.

  **Why one component with view-state instead of SvelteKit routing (`apps/web`'s shape):** this
  shell has no server, and — unlike the browser — no shareable/bookmarkable URL for a Tauri window
  to navigate to; the whole app is a single always-in-process WebView over the Tauri IPC boundary.
  `view`/`selectedPeer` below stand in for what `apps/web`'s route params + `$app/navigation.goto`
  do there: which screen is showing, and which peer it's scoped to. Every screen reached this way is
  the exact same `shared-ui` component the browser route renders, just selected by an `{#if}`
  instead of a file-system route.

  Account-creation-first (mirrors `apps/web/src/routes/+page.svelte`): before an account exists,
  this is the *only* thing rendered — `CreateAccount` (12.7), unmodified.
-->
<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";

  import {
    Chat,
    Contacts,
    CreateAccount,
    FileTransfer,
    LayoutShell,
    MessageRequests,
    Verification,
  } from "shared-ui";
  import type { MeridianId } from "shared-ui";

  import { adapter, currentAccountId, noteAccountCreated, signOut } from "./session";
  import PeerNav from "./PeerNav.svelte";

  type View = "contacts" | "chat" | "verify" | "files" | "requests";

  let view: View = "contacts";
  let selectedPeer: MeridianId | null = null;

  function openConversation(peer: MeridianId, next: "chat" | "verify" | "files" = "chat"): void {
    selectedPeer = peer;
    view = next;
  }

  function handleSelectContact(peer: MeridianId): void {
    openConversation(peer);
  }

  function handleRequestAccepted(peer: MeridianId): void {
    openConversation(peer);
  }

  function handleAccountCreated(id: MeridianId): void {
    noteAccountCreated(id);
    view = "contacts";
    selectedPeer = null;
  }

  async function handleSignOut(): Promise<void> {
    await signOut();
    view = "contacts";
    selectedPeer = null;
  }

  // Native menu wiring (`../src/main.rs::build_app_menu`/`handle_menu_event`) — the "menus" half of
  // this task's window chrome deliverable. Both events are additive conveniences over controls this
  // screen already exposes some other way (the header's own "Requests"/"Sign out" — see below); a
  // user who never touches the menu bar loses nothing.
  let unlistenNavigate: UnlistenFn | undefined;
  let unlistenSignOut: UnlistenFn | undefined;

  onMount(() => {
    void listen<string>("menu:navigate", (event) => {
      if (event.payload === "requests") {
        view = "requests";
      } else if (event.payload === "contacts") {
        view = "contacts";
        selectedPeer = null;
      }
    }).then((fn) => (unlistenNavigate = fn));

    void listen("menu:sign-out", () => {
      void handleSignOut();
    }).then((fn) => (unlistenSignOut = fn));
  });

  onDestroy(() => {
    unlistenNavigate?.();
    unlistenSignOut?.();
  });
</script>

{#if !$currentAccountId}
  <CreateAccount {adapter} onCreated={handleAccountCreated} />
{:else}
  <LayoutShell>
    <svelte:fragment slot="sidebar">
      <Contacts {adapter} {selectedPeer} onSelect={handleSelectContact} />
    </svelte:fragment>
    <svelte:fragment slot="header">
      <header class="app-header">
        <span class="account" title={$currentAccountId}>{$currentAccountId}</span>
        <nav>
          <button
            type="button"
            class:current={view === "requests"}
            on:click={() => {
              view = "requests";
            }}
          >
            Requests
          </button>
          <button type="button" on:click={handleSignOut}>Sign out</button>
        </nav>
      </header>
    </svelte:fragment>

    {#if view === "requests"}
      <MessageRequests {adapter} onAccepted={handleRequestAccepted} />
    {:else if selectedPeer && (view === "chat" || view === "verify" || view === "files")}
      <PeerNav peer={selectedPeer} active={view} onNavigate={(v) => openConversation(selectedPeer ?? "", v)} />
      {#if view === "chat"}
        <Chat {adapter} peer={selectedPeer} />
      {:else if view === "verify"}
        <Verification {adapter} peer={selectedPeer} />
      {:else}
        <FileTransfer {adapter} peer={selectedPeer} />
      {/if}
    {:else}
      <div class="contacts-landing">
        <p>Select a contact from the sidebar to open a conversation, or add a new one above the list.</p>
      </div>
    {/if}
  </LayoutShell>
{/if}

<style>
  :global(html, body) {
    margin: 0;
    height: 100%;
    font-family:
      system-ui,
      -apple-system,
      "Segoe UI",
      sans-serif;
  }
  :global(#app) {
    height: 100%;
    min-height: 100vh;
  }
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
  .app-header nav button {
    background: none;
    border: 1px solid transparent;
    color: inherit;
    cursor: pointer;
    padding: 0.25rem 0.5rem;
    border-radius: 0.3rem;
  }
  .app-header nav button.current {
    border-color: var(--meridian-accent, #2563eb);
    color: var(--meridian-accent, #2563eb);
  }
  .contacts-landing {
    padding: 1rem;
    color: var(--meridian-muted-fg, #666);
  }
</style>
