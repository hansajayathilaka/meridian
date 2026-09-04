<!--
  LayoutShell — the generic two-pane (sidebar + main) frame both the browser and desktop shells
  reuse verbatim (ADR 0012: "screens are written once ... reused by both shells unmodified"). No
  routing, no adapter wiring, no chat-specific content — purely a layout primitive with three named
  slots.
-->
<script lang="ts">
  export let sidebarLabel = "Conversations";
</script>

<div class="layout-shell">
  <nav class="sidebar" aria-label={sidebarLabel}>
    <slot name="sidebar" />
  </nav>
  <main class="content">
    <slot name="header" />
    <div class="body">
      <slot />
    </div>
  </main>
</div>

<style>
  .layout-shell {
    display: grid;
    grid-template-columns: minmax(220px, 320px) 1fr;
    height: 100%;
    min-height: 0;
  }
  .sidebar {
    overflow-y: auto;
    border-right: 1px solid var(--meridian-border, #ddd);
  }
  .content {
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
  .body {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
  }
</style>
