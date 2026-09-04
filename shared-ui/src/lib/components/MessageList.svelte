<!--
  MessageList — a generic, direction-aware transcript renderer over `ChatMessage[]` (`../adapter`).
  No chat-specific business logic: it does not send-gate, does not decrypt, does not know about
  message requests — it only lays out whatever messages a screen (12.7-12.9) already loaded via
  `MeridianClientAdapter.loadHistory`/`onMessage`. Deliberately renders `msg.body` as plain text
  (never `{@html}`) so no message content is ever interpreted as markup, regardless of source.
-->
<script lang="ts">
  import type { ChatMessage } from "../adapter";

  export let messages: ChatMessage[] = [];
  /** Optional empty-state copy; a screen may override for context (e.g. "no messages yet"). */
  export let emptyLabel = "No messages yet.";
</script>

<div class="message-list" role="log" aria-live="polite">
  {#if messages.length === 0}
    <p class="empty">{emptyLabel}</p>
  {:else}
    {#each messages as msg (msg.id)}
      <div class="message message-{msg.direction}" data-state={msg.state}>
        <p class="body">{msg.body}</p>
        <span class="meta">{msg.state}</span>
      </div>
    {/each}
  {/if}
</div>

<style>
  .message-list {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    padding: 0.75rem;
    overflow-y: auto;
  }
  .empty {
    color: var(--meridian-muted-fg, #666);
    text-align: center;
    margin: 1rem 0;
  }
  .message {
    max-width: 75%;
    padding: 0.4rem 0.6rem;
    border-radius: 0.6rem;
    word-break: break-word;
  }
  .message-out {
    align-self: flex-end;
    background: var(--meridian-accent, #2b6cb0);
    color: white;
  }
  .message-in {
    align-self: flex-start;
    background: var(--meridian-bubble-in-bg, #eee);
  }
  .body {
    margin: 0;
    white-space: pre-wrap;
  }
  .meta {
    display: block;
    font-size: 0.7em;
    opacity: 0.7;
    margin-top: 0.15rem;
  }
</style>
