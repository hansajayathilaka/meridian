<script lang="ts">
  import { onMount } from 'svelte';
  import type { ContactSummary, MeridianClientAdapter } from '../adapter';
  import { contactDisplayLabel } from '../view';
  import { FILE_COPY } from './copy';
  import { FileTransferViewModel } from './file-transfer.svelte';
  import {
    MAX_REASON_DISPLAY,
    displayText,
    formatBytes,
    progressBar,
    transferBytesLabel,
    transferDirectionLabel,
    transferStatusLabel
  } from './transfer-view';

  interface Props {
    adapter: MeridianClientAdapter;
    contact: ContactSummary;
    onverify?: (contact: ContactSummary) => void;
    pickPaths?: () => Promise<readonly string[] | null>;
  }

  let { adapter, contact, onverify, pickPaths }: Props = $props();

  // One view-model per (adapter, peer): `FileTransfer.svelte` re-creates this component when either
  // changes, so a stale completion for another peer can never land here.
  // svelte-ignore state_referenced_locally
  const vm = new FileTransferViewModel(adapter, contact);

  // The parent may refresh the contact (petname / block changes) without changing the peer.
  $effect(() => {
    vm.syncContact(contact);
  });

  onMount(() => {
    vm.start();
    return () => vm.dispose();
  });

  let dragging = $state(false);

  function hasFiles(event: DragEvent): boolean {
    return Array.from(event.dataTransfer?.types ?? []).includes('Files');
  }

  // Swallow file drags/drops anywhere within this section: a drop that is not handled would make
  // the browser navigate to (open) the dropped file. This cannot cover drops outside the section:
  // the host app must also swallow those at its own root. Only the drop zone below ever sends.
  function swallowDragOver(event: DragEvent): void {
    if (hasFiles(event)) event.preventDefault();
  }
  function swallowDrop(event: DragEvent): void {
    if (hasFiles(event)) event.preventDefault();
    dragging = false;
  }

  function onZoneDragOver(event: DragEvent): void {
    if (!hasFiles(event)) return;
    event.preventDefault();
    dragging = true;
  }

  function onZoneDrop(event: DragEvent): void {
    if (!hasFiles(event)) return;
    event.preventDefault();
    dragging = false;
    const files = Array.from(event.dataTransfer?.files ?? []);
    // The gate is re-queried inside the view-model for every file; nothing is decided here.
    void vm.sendFiles(files);
  }

  function onPick(event: Event): void {
    const input = event.currentTarget as HTMLInputElement;
    const files = Array.from(input.files ?? []);
    input.value = ''; // allow choosing the same file again
    void vm.sendFiles(files);
  }

  async function onPickNative(): Promise<void> {
    let paths: readonly string[] | null;
    try {
      paths = (await pickPaths?.()) ?? null;
    } catch {
      return; // a failing shell chooser is a cancelled pick; nothing is sent
    }
    if (paths !== null && paths.length > 0) void vm.sendPaths(paths);
  }
</script>

<!--
  Trust-state UI. The drop zone / picker exist ONLY while core's freshly-queried gate is `ok`. For
  `warn` and `blocked` they are replaced by a banner carrying core's `reason` verbatim — as a text
  node (never `{@html}`), never paraphrased. With no verdict yet (loading, re-querying, failed)
  there are no send controls either: fail closed.

  Every wire-supplied string (file names, failure reasons, the peer label) is shown as text only,
  through `displayText` (bidi/control characters made visible, length capped). No name is ever used
  to build a path, URL, `href` or `download` attribute.
-->
<section
  class="file-transfer"
  aria-label="File transfers"
  ondragover={swallowDragOver}
  ondrop={swallowDrop}
>
  <header class="peer">
    <h2>{FILE_COPY.heading}</h2>
    <span class="with">{displayText(contactDisplayLabel(vm.contact))}</span>
  </header>

  {#if vm.gate === null}
    <p class="gate-pending" role="status">
      {vm.gateUnavailable ? FILE_COPY.gateUnavailable : FILE_COPY.gatePending}
    </p>
  {:else if vm.gate.kind === 'ok'}
    <div
      class="dropzone"
      class:dragging
      role="group"
      aria-label={FILE_COPY.dropZoneLabel}
      ondragover={onZoneDragOver}
      ondragleave={() => (dragging = false)}
      ondrop={onZoneDrop}
    >
      <p>{FILE_COPY.dropHint}</p>
      <input
        type="file"
        multiple
        aria-label={FILE_COPY.chooseFilesLabel}
        onchange={onPick}
        disabled={vm.sending}
      />
      {#if pickPaths}
        <button type="button" onclick={() => void onPickNative()} disabled={vm.sending}>
          {FILE_COPY.chooseNative}
        </button>
      {/if}
    </div>
  {:else}
    <div class="gate-banner" role="alert" data-gate={vm.gate.kind}>
      <strong>
        {vm.gate.kind === 'blocked' ? FILE_COPY.gateBlockedHeading : FILE_COPY.gatePausedHeading}
      </strong>
      <p class="reason">{vm.gate.reason}</p>
      {#if onverify}
        <button type="button" onclick={() => onverify?.(vm.contact)}>Verify</button>
      {/if}
    </div>
  {/if}

  {#if vm.sendNotice}
    <p role="alert" class="notice error">{vm.sendNotice}</p>
  {/if}

  {#if vm.offerError}
    <p role="alert" class="error">{vm.offerError}</p>
  {/if}

  {#if vm.offers.length > 0}
    <h3>{FILE_COPY.offersHeading}</h3>
    <p class="note">{FILE_COPY.offerNameNote}</p>
    <ul class="offers">
      {#each vm.offers as offer (offer.transferId)}
        {@const confirming = vm.pending?.transferId === offer.transferId ? vm.pending : null}
        {@const busy = vm.busyOffer === offer.transferId}
        <li class="offer" data-offer={offer.transferId}>
          <dl>
            <dt>File name (from sender)</dt>
            <dd class="name"><bdi>{displayText(offer.name)}</bdi></dd>
            <dt>Size (from sender)</dt>
            <dd class="size">{formatBytes(offer.size)}</dd>
          </dl>
          {#if confirming}
            <div class="confirm" role="group" aria-label="Confirm decision">
              <p>
                {confirming.decision === 'accept' ? FILE_COPY.acceptPrompt : FILE_COPY.rejectPrompt}
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
                onclick={() => vm.choose(offer.transferId, 'accept')}
                disabled={vm.busyOffer !== null}>Accept</button
              >
              <button
                type="button"
                onclick={() => vm.choose(offer.transferId, 'reject')}
                disabled={vm.busyOffer !== null}>Reject</button
              >
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}

  <h3>Transfers</h3>
  <p class="note">{FILE_COPY.progressNote}</p>
  {#if vm.loadError}
    <p role="alert" class="error">{vm.loadError}</p>
  {/if}
  <ul class="transfers">
    {#each vm.transfers as transfer (transfer.transferId)}
      {@const bar = transfer.status === 'in-progress' ? progressBar(transfer) : null}
      <li class="transfer" data-transfer={transfer.transferId} data-status={transfer.status}>
        <span class="name"><bdi>{displayText(transfer.name)}</bdi></span>
        <span class="direction">{transferDirectionLabel(transfer.direction)}</span>
        <span class="status">{transferStatusLabel(transfer)}</span>
        {#if bar}
          <progress value={bar.value} max={bar.max} aria-label="Bytes transferred"></progress>
        {/if}
        <span class="bytes">{transferBytesLabel(transfer)}</span>
        {#if transfer.status === 'stalled'}
          <span class="note">{FILE_COPY.noResume}</span>
        {/if}
        {#if transfer.status === 'failed' && transfer.failureReason}
          <span class="failure">{displayText(transfer.failureReason, MAX_REASON_DISPLAY)}</span>
        {/if}
      </li>
    {:else}
      <li class="empty">{vm.loaded ? FILE_COPY.noTransfers : FILE_COPY.loadingTransfers}</li>
    {/each}
  </ul>
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
  .with {
    font-size: 0.75em;
    opacity: 0.7;
  }
  .dropzone {
    margin-top: 0.5rem;
    padding: 0.75rem;
    border: 2px dashed rgba(127, 127, 127, 0.6);
  }
  .dropzone.dragging {
    border-style: solid;
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
  .note {
    font-size: 0.85em;
    opacity: 0.85;
  }
  .offers,
  .transfers {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .offer,
  .transfer {
    border: 1px solid rgba(127, 127, 127, 0.5);
    padding: 0.5rem;
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: baseline;
  }
  .offer {
    display: block;
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
  }
  .name,
  .failure {
    overflow-wrap: anywhere;
    white-space: pre-wrap;
    max-width: 100%;
  }
  .empty {
    opacity: 0.7;
  }
</style>
