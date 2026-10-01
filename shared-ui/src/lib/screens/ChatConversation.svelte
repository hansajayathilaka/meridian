<script lang="ts">
  import { onMount } from 'svelte';
  import type { ContactSummary, MeridianClientAdapter } from '../adapter';
  import MessageList from '../components/MessageList.svelte';
  import { contactDisplayLabel, trustLabel } from '../view';
  import { ChatViewModel } from './chat.svelte';

  interface Props {
    adapter: MeridianClientAdapter;
    contact: ContactSummary;
    onverify?: (contact: ContactSummary) => void;
  }

  let { adapter, contact, onverify }: Props = $props();

  // One view-model per peer: `Chat.svelte` re-creates this component when the peer changes, so a
  // stale completion for another conversation can never land here.
  // svelte-ignore state_referenced_locally
  const vm = new ChatViewModel(adapter, contact);

  // The parent may refresh the contact (petname / block changes) without changing the peer; keep
  // the header in step. Only for the same peer: a different peer remounts via `Chat.svelte`.
  $effect(() => {
    vm.syncContact(contact);
  });

  onMount(() => {
    vm.start();
    return () => vm.dispose();
  });

  function onKeydown(event: KeyboardEvent): void {
    // Enter sends, Shift+Enter inserts a newline (multi-line composer). Never mid-IME-composition.
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      void vm.send();
    }
  }
</script>

<!--
  Trust-state UI. The composer exists ONLY while core's freshly-queried gate is `ok`. For `warn`
  and `blocked` it is replaced by a banner carrying core's `reason` verbatim — as a text node
  (never `{@html}`), and never paraphrased or softened. With no verdict yet (loading, re-querying,
  or the query failed) there is no composer either: fail closed.

  Every peer-influenced string here (petname, hint, bodies, reason) is rendered as text.
-->
<section class="chat" aria-label="Conversation">
  <header class="peer">
    <h2>{contactDisplayLabel(vm.contact)}</h2>
    <span class="fingerprint">{vm.contact.fingerprint}</span>
    <span class="trust">{trustLabel(vm.contact.trust, vm.contact.userBlocked)}</span>
  </header>

  <MessageList messages={vm.messages} emptyText="No messages yet." />

  {#if vm.loadError}
    <p role="alert" class="error">{vm.loadError}</p>
  {/if}

  {#if vm.notice}
    {#if vm.notice.kind === 'error'}
      <p role="alert" class="notice error">{vm.notice.text}</p>
    {:else}
      <p role="status" class="notice" data-notice={vm.notice.kind}>
        {vm.notice.text}
        {#if vm.notice.kind === 'failed'}
          <button type="button" onclick={() => void vm.retry()} disabled={vm.sending}>Retry</button>
        {/if}
      </p>
    {/if}
  {/if}

  {#if vm.gate === null}
    <p class="gate-pending" role="status">
      {vm.gateUnavailable
        ? 'Could not check whether sending is allowed. Sending is paused.'
        : 'Checking whether sending is allowed…'}
    </p>
  {:else if vm.gate.kind === 'ok'}
    <form
      class="composer"
      onsubmit={(e) => {
        e.preventDefault();
        void vm.send();
      }}
    >
      <textarea
        aria-label="Message"
        rows="2"
        bind:value={vm.draft}
        onkeydown={onKeydown}
        disabled={vm.sending}
      ></textarea>
      <button type="submit" disabled={vm.sending || vm.draft.trim() === ''}>Send</button>
    </form>
  {:else}
    <div class="gate-banner" role="alert" data-gate={vm.gate.kind}>
      <strong>{vm.gate.kind === 'blocked' ? 'Sending is blocked' : 'Sending is paused'}</strong>
      <p class="reason">{vm.gate.reason}</p>
      {#if onverify}
        <button type="button" onclick={() => onverify?.(vm.contact)}>Verify</button>
      {/if}
    </div>
  {/if}
</section>

<style>
  .peer {
    display: flex;
    align-items: baseline;
    gap: 0.75rem;
  }
  .peer h2 {
    margin: 0;
    font-size: 1rem;
  }
  .fingerprint,
  .trust {
    font-size: 0.75em;
    opacity: 0.7;
  }
  .composer {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.5rem;
  }
  .composer textarea {
    flex: 1;
  }
  .gate-banner {
    margin-top: 0.5rem;
    padding: 0.5rem;
    border: 2px solid currentColor;
  }
  .reason {
    margin: 0.25rem 0;
    white-space: pre-wrap;
  }
  .notice {
    font-size: 0.85em;
  }
</style>
