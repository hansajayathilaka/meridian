<!--
  PeerNav — app-shell-local chrome (not a `shared-ui` screen; this task's own routing glue) linking
  the three per-peer screens (Chat/Verify/Files) for whichever conversation is currently open, so a
  user can move between them without going back through the contact list each time. No adapter
  calls of its own — pure navigation, mirrors `LayoutShell`'s own "layout primitive, no protocol
  logic" scoping.
-->
<script lang="ts">
  import { page } from "$app/stores";

  export let peer: string;

  $: encodedPeer = encodeURIComponent(peer);
  $: tabs = [
    { label: "Chat", href: `/chat/${encodedPeer}` },
    { label: "Verify", href: `/verify/${encodedPeer}` },
    { label: "Files", href: `/files/${encodedPeer}` },
  ];
</script>

<nav class="peer-nav" aria-label="Conversation views">
  {#each tabs as tab (tab.href)}
    <a href={tab.href} aria-current={$page.url.pathname === tab.href ? "page" : undefined}>
      {tab.label}
    </a>
  {/each}
</nav>

<style>
  .peer-nav {
    display: flex;
    gap: 0.75rem;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--meridian-border, #ddd);
  }
  .peer-nav a {
    color: var(--meridian-muted-fg, #666);
    text-decoration: none;
    font-size: 0.85em;
  }
  .peer-nav a[aria-current="page"] {
    color: var(--meridian-accent, #2563eb);
    font-weight: 600;
  }
</style>
