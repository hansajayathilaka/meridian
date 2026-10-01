<script lang="ts">
  import type { ChatMessage } from '../adapter';
  import { messageStateLabel } from '../view';

  interface Props {
    messages: readonly ChatMessage[];
    /** Shown when `messages` is empty. */
    emptyText?: string;
  }

  let { messages, emptyText = 'No messages yet.' }: Props = $props();
</script>

<!--
  Message bodies are rendered as text nodes only (never `{@html}`): bodies are peer-controlled.
  A delivery marker is shown for outgoing messages only, and only what the adapter reported.
-->
<ol class="message-list" role="log" aria-label="Messages">
  {#each messages as message (message.mid)}
    <li class="message" data-direction={message.direction} data-state={message.state}>
      <span class="body">{message.body}</span>
      {#if message.direction === 'out'}
        <span class="state">{messageStateLabel(message.state)}</span>
      {/if}
    </li>
  {:else}
    <li class="empty">{emptyText}</li>
  {/each}
</ol>

<style>
  .message-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .message[data-direction='out'] {
    align-self: flex-end;
  }
  .message[data-direction='in'] {
    align-self: flex-start;
  }
  .state {
    margin-inline-start: 0.5rem;
    font-size: 0.75em;
    opacity: 0.7;
  }
  .empty {
    opacity: 0.7;
  }
</style>
