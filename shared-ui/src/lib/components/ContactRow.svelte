<!--
  ContactRow — one row in a contact/conversation list. Deliberately generic: it renders whatever
  `Contact` (from `../adapter`) it's given plus optional list-row extras (unread count, preview,
  timestamp) a conversation-list screen (12.7) layers on — it has no chat-specific business logic
  (no send-gate handling, no message decoding) of its own. `on:select` is the only interaction it
  exposes; a screen decides what selecting a row actually does.
-->
<script lang="ts">
  import type { Contact } from "../adapter";

  export let contact: Contact;
  export let selected = false;
  export let unreadCount = 0;
  export let preview: string | null = null;

  function displayName(c: Contact): string {
    return c.petname ?? c.id;
  }
</script>

<button
  type="button"
  class="contact-row"
  class:selected
  on:click
  aria-pressed={selected}
>
  <span class="name">{displayName(contact)}</span>
  {#if preview}
    <span class="preview">{preview}</span>
  {/if}
  <span class="trust trust-{contact.trust}">{contact.trust}</span>
  {#if unreadCount > 0}
    <span class="unread" aria-label="{unreadCount} unread">{unreadCount}</span>
  {/if}
</button>

<style>
  .contact-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    width: 100%;
    padding: 0.5rem 0.75rem;
    background: none;
    border: none;
    text-align: left;
    cursor: pointer;
    font: inherit;
  }
  .contact-row.selected {
    background: var(--meridian-selected-bg, #e6e6e6);
  }
  .name {
    font-weight: 600;
    flex: 1 1 auto;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .preview {
    flex: 2 1 auto;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--meridian-muted-fg, #666);
    font-size: 0.85em;
  }
  .trust {
    font-size: 0.75em;
    text-transform: uppercase;
    color: var(--meridian-muted-fg, #666);
  }
  .unread {
    display: inline-block;
    min-width: 1.25em;
    padding: 0 0.35em;
    border-radius: 999px;
    background: var(--meridian-accent, #2b6cb0);
    color: white;
    font-size: 0.75em;
    text-align: center;
  }
</style>
