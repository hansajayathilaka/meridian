<!--
  `/contacts` — the app's default landing route once signed in (`(app)/+layout.svelte`'s sidebar
  already shows the contact list on every route in this group; this page is what renders in the
  main pane before a specific conversation is selected).
-->
<svelte:head>
  <title>Meridian — Contacts</title>
</svelte:head>

<div class="contacts-landing">
  <p>Select a contact from the sidebar to open a conversation, or add a new one above the list.</p>
</div>

<style>
  .contacts-landing {
    padding: 1rem;
    color: var(--meridian-muted-fg, #666);
  }
</style>
