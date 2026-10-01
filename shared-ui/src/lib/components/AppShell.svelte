<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { ConnectionState } from '../adapter';
  import { connectionLabel } from '../view';

  interface Props {
    title: string;
    connection?: ConnectionState;
    sidebar?: Snippet;
    /** Accessible name for the sidebar landmark. */
    sidebarLabel?: string;
    children?: Snippet;
  }

  let { title, connection, sidebar, sidebarLabel = 'Contacts', children }: Props = $props();
</script>

<!-- Layout only: no routing, no data access. Screens (12.7-12.9) fill the slots. -->
<div class="shell">
  <header>
    <h1>{title}</h1>
    {#if connection}
      <span class="connection" role="status">{connectionLabel(connection)}</span>
    {/if}
  </header>
  <div class="body">
    {#if sidebar}
      <nav class="sidebar" aria-label={sidebarLabel}>{@render sidebar()}</nav>
    {/if}
    <main>{@render children?.()}</main>
  </div>
</div>

<style>
  .shell {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    padding: 0.5rem 1rem;
  }
  h1 {
    margin: 0;
    font-size: 1.1rem;
  }
  .body {
    display: flex;
    flex: 1;
    min-height: 0;
  }
  .sidebar {
    width: 16rem;
    overflow-y: auto;
  }
  main {
    flex: 1;
    overflow-y: auto;
    padding: 0.5rem 1rem;
  }
</style>
