<!--
  PeerNav — desktop-local chrome (not a `shared-ui` screen; this shell's own view-switching glue),
  mirroring `apps/web/src/lib/PeerNav.svelte` (task 12.14) one-for-one in purpose and markup, with
  one necessary difference: the browser shell switches views by navigating to a URL
  (`<a href="/chat/...">`, SvelteKit's router); this shell has no router (`App.svelte`'s own doc
  comment) — a peer-scoped "view" is plain component state here, so the same three tabs are plain
  buttons that call the `onNavigate` callback prop instead of anchors. No adapter calls of its own
  — pure navigation, exactly like its browser sibling.
-->
<script lang="ts">
  export let peer: string;
  export let active: "chat" | "verify" | "files";
  export let onNavigate: (view: "chat" | "verify" | "files") => void;

  const tabs: Array<{ label: string; view: "chat" | "verify" | "files" }> = [
    { label: "Chat", view: "chat" },
    { label: "Verify", view: "verify" },
    { label: "Files", view: "files" },
  ];
</script>

<nav class="peer-nav" aria-label="Conversation views">
  {#each tabs as tab (tab.view)}
    <button
      type="button"
      class:current={active === tab.view}
      aria-current={active === tab.view ? "page" : undefined}
      on:click={() => onNavigate(tab.view)}
    >
      {tab.label}
    </button>
  {/each}
  <span class="peer" title={peer}>{peer}</span>
</nav>

<style>
  .peer-nav {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--meridian-border, #ddd);
  }
  .peer-nav button {
    background: none;
    border: none;
    padding: 0;
    color: var(--meridian-muted-fg, #666);
    text-decoration: none;
    font-size: 0.85em;
    cursor: pointer;
  }
  .peer-nav button.current {
    color: var(--meridian-accent, #2563eb);
    font-weight: 600;
  }
  .peer-nav .peer {
    margin-left: auto;
    font-family: var(--meridian-mono, monospace);
    font-size: 0.75em;
    color: var(--meridian-muted-fg, #666);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 40%;
  }
</style>
