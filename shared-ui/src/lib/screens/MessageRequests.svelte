<script lang="ts">
  import { onMount } from 'svelte';
  import type { ContactSummary, MeridianClientAdapter, PeerId } from '../adapter';
  import { MessageRequestsViewModel } from './message-requests.svelte';

  interface Props {
    adapter: MeridianClientAdapter;
    /** A request was accepted; the sender is now a (pinned, unverified) contact. */
    onaccepted?: (contact: ContactSummary) => void;
    /** A request was rejected and discarded. */
    onrejected?: (senderId: PeerId) => void;
  }

  let { adapter, onaccepted, onrejected }: Props = $props();

  // The adapter is fixed for this screen's lifetime (a shell remounts to change it).
  // svelte-ignore state_referenced_locally
  const vm = new MessageRequestsViewModel(adapter, {
    onaccepted: (contact) => onaccepted?.(contact),
    onrejected: (senderId) => onrejected?.(senderId)
  });

  onMount(() => {
    vm.start();
    return () => vm.dispose();
  });
</script>

<!--
  Shows only what the message-request gate already exposes: the sender's key id, the safety number,
  and the short intro. All of it is peer-controlled, so it is rendered as text only (never
  `{@html}`). Nothing here is sent to the sender; nothing is accepted automatically.
-->
<section class="requests" aria-label="Message requests">
  <h2>Message requests</h2>
  <p class="note">
    These people are not your contacts. Nothing is sent to them whichever you choose. Accepting adds
    them as an unverified contact.
  </p>

  {#if vm.error}
    <p role="alert" class="error">{vm.error}</p>
  {/if}

  <ul class="list">
    {#each vm.requests as request (request.senderId)}
      {@const confirming = vm.pending?.senderId === request.senderId ? vm.pending : null}
      {@const busy = vm.busySender === request.senderId}
      <li class="request" data-sender={request.senderId}>
        <dl>
          <dt>Sender</dt>
          <dd class="sender">{request.senderId}</dd>
          <dt>Safety number</dt>
          <dd class="safety-number">{request.safetyNumber}</dd>
          <dt>Intro</dt>
          <dd class="intro">
            {#if request.introText !== null}{request.introText}{:else}<em>(no text)</em>{/if}
          </dd>
        </dl>

        {#if confirming}
          <div class="confirm" role="group" aria-label="Confirm decision">
            <p>
              {#if confirming.decision === 'accept'}
                Accept this request? They will be added as an unverified contact. Compare the
                safety number with them before you trust them.
              {:else}
                Reject this request? It is discarded and nothing is sent back to the sender.
              {/if}
            </p>
            <button type="button" onclick={() => void vm.confirm()} disabled={busy}>
              Confirm {confirming.decision === 'accept' ? 'accept' : 'reject'}
            </button>
            <button type="button" onclick={() => vm.cancel()} disabled={busy}>Cancel</button>
          </div>
        {:else}
          <div class="actions">
            <button
              type="button"
              onclick={() => vm.choose(request.senderId, 'accept')}
              disabled={vm.busySender !== null}>Accept</button
            >
            <button
              type="button"
              onclick={() => vm.choose(request.senderId, 'reject')}
              disabled={vm.busySender !== null}>Reject</button
            >
          </div>
        {/if}
      </li>
    {:else}
      <li class="empty">{vm.loaded ? 'No message requests.' : 'Loading…'}</li>
    {/each}
  </ul>
</section>

<style>
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .request {
    border: 1px solid rgba(127, 127, 127, 0.5);
    padding: 0.5rem;
  }
  dl {
    margin: 0;
  }
  dt {
    font-size: 0.75em;
    opacity: 0.7;
  }
  dd {
    margin: 0 0 0.25rem;
    overflow-wrap: anywhere;
    white-space: pre-wrap;
  }
  .note {
    font-size: 0.85em;
    opacity: 0.85;
  }
  .empty {
    opacity: 0.7;
  }
</style>
