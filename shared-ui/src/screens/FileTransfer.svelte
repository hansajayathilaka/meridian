<!--
  FileTransfer — drag-drop/file-picker send, a per-transfer progress display, and the receive
  prompt for `mrd.file/1` (task 12.9), the browser/desktop equivalent of the terminal client's
  existing transfers pane (`apps/tui/src/streams/file.rs::TransfersPane`, task 10.11). Wired purely
  through `MeridianClientAdapter.sendFile`/`listTransfers`/`acceptTransfer`/`rejectTransfer` — no
  protocol logic lives here, see `fileTransferStore.ts`'s own doc comment for the full contract
  (including its "known interface-coverage note" on why progress is refresh-driven, not live-push).

  Only ever shows transfers with `peer` — the same per-conversation scoping `Chat.svelte` and
  `Verification.svelte` already use.

  **Never overclaims corruption-detection**: every state is rendered via `transferStateLabel`, which
  says no more than `FileTransferSummary.state` itself reports (never "verified" or
  "corruption-free" — the inherited 11.8 residual, `adapter.ts`'s own doc comment on that type).
-->
<script lang="ts">
  import type { FileTransferSummary, MeridianClientAdapter, MeridianId, StreamHandle } from "../lib/adapter";
  import { createFileTransferStore, transferPercent, transferStateLabel } from "./stores/fileTransferStore";

  export let adapter: MeridianClientAdapter;
  export let peer: MeridianId;

  const store = createFileTransferStore(adapter);
  void store.refresh();

  let fileInputEl: HTMLInputElement | undefined;
  let dragOver = false;
  let sendError: string | null = null;

  $: peerTransfers = $store.transfers.filter((t) => t.peer === peer);

  async function sendFile(file: File): Promise<void> {
    sendError = null;
    try {
      await store.send(peer, file, file.name);
    } catch (err) {
      sendError = err instanceof Error ? err.message : "Failed to send file.";
    }
  }

  function handleDragOver(event: DragEvent): void {
    event.preventDefault();
    dragOver = true;
  }

  function handleDragLeave(): void {
    dragOver = false;
  }

  async function handleDrop(event: DragEvent): Promise<void> {
    event.preventDefault();
    dragOver = false;
    const file = event.dataTransfer?.files?.[0];
    if (file) await sendFile(file);
  }

  async function handleFileInputChange(event: Event): Promise<void> {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (file) await sendFile(file);
    input.value = "";
  }

  function openFilePicker(): void {
    fileInputEl?.click();
  }

  async function handleAccept(streamId: StreamHandle): Promise<void> {
    try {
      await store.accept(streamId);
    } catch {
      // Surfaced via $store.error below.
    }
  }

  async function handleReject(streamId: StreamHandle): Promise<void> {
    try {
      await store.reject(streamId);
    } catch {
      // Surfaced via $store.error below.
    }
  }

  function rowKind(t: FileTransferSummary): "offer" | "outbound" | "inbound" {
    if (t.direction === "in" && t.state === "offered") return "offer";
    return t.direction === "out" ? "outbound" : "inbound";
  }
</script>

<div class="file-transfer-screen">
  <h2>File transfers</h2>
  <p class="peer">{peer}</p>

  {#if $store.error}
    <p class="error" role="alert">{$store.error}</p>
  {/if}
  {#if sendError}
    <p class="error" role="alert">{sendError}</p>
  {/if}

  <!-- svelte-ignore a11y-no-static-element-interactions -->
  <div
    class="dropzone"
    class:drag-over={dragOver}
    data-testid="dropzone"
    on:dragover={handleDragOver}
    on:dragleave={handleDragLeave}
    on:drop={handleDrop}
  >
    <p>Drag a file here to send it{$store.sending ? " (sending…)" : ""}</p>
    <button type="button" on:click={openFilePicker} disabled={$store.sending}>Choose file…</button>
    <input
      bind:this={fileInputEl}
      type="file"
      class="visually-hidden"
      data-testid="file-input"
      aria-label="Choose file to send"
      on:change={handleFileInputChange}
    />
  </div>

  <div class="transfers-header">
    <h3>Transfers</h3>
    <button type="button" data-testid="refresh" on:click={() => store.refresh()}>Refresh</button>
  </div>

  {#if peerTransfers.length === 0}
    <p class="empty">No transfers with this contact yet.</p>
  {:else}
    <ul class="transfer-list">
      {#each peerTransfers as t (t.streamId)}
        <li class="transfer" data-testid="transfer-row" data-stream-id={t.streamId}>
          <div class="transfer-main">
            <span class="direction" aria-hidden="true">{t.direction === "out" ? "↑" : "↓"}</span>
            <span class="file-name">{t.fileName}</span>
            <span class="state" data-testid="transfer-state">{transferStateLabel(t.state)}</span>
          </div>
          <div class="progress-track" role="progressbar" aria-valuenow={transferPercent(t)} aria-valuemin={0} aria-valuemax={100}>
            <div class="progress-fill" style="width: {transferPercent(t)}%"></div>
          </div>
          <span class="percent" data-testid="transfer-percent">{transferPercent(t)}%</span>

          {#if rowKind(t) === "offer"}
            <div class="offer-actions">
              <span class="offer-prompt" role="alert" data-testid="offer-prompt">
                Incoming file from {t.peer}: {t.fileName} ({t.totalBytes} bytes). Accept?
              </span>
              <button
                type="button"
                data-testid="accept-transfer"
                disabled={$store.busy === t.streamId}
                on:click={() => handleAccept(t.streamId)}
              >
                Accept
              </button>
              <button
                type="button"
                data-testid="reject-transfer"
                disabled={$store.busy === t.streamId}
                on:click={() => handleReject(t.streamId)}
              >
                Reject
              </button>
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .file-transfer-screen {
    padding: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .peer {
    word-break: break-all;
    color: var(--meridian-muted-fg, #666);
    margin: 0;
  }
  .error {
    color: var(--meridian-error-fg, #b91c1c);
  }
  .empty {
    color: var(--meridian-muted-fg, #666);
  }
  .dropzone {
    border: 2px dashed var(--meridian-border, #ddd);
    border-radius: 0.5rem;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.5rem;
  }
  .dropzone.drag-over {
    border-color: var(--meridian-accent, #2563eb);
    background: var(--meridian-accent-bg, #eff6ff);
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }
  .transfers-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .transfers-header h3 {
    margin: 0;
    font-size: 0.9rem;
  }
  .transfer-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .transfer {
    border: 1px solid var(--meridian-border, #ddd);
    border-radius: 0.5rem;
    padding: 0.6rem;
  }
  .transfer-main {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .file-name {
    flex: 1 1 auto;
    word-break: break-all;
  }
  .state {
    font-size: 0.85em;
    color: var(--meridian-muted-fg, #666);
  }
  .progress-track {
    margin-top: 0.35rem;
    height: 0.4rem;
    border-radius: 0.2rem;
    background: var(--meridian-border, #ddd);
    overflow: hidden;
  }
  .progress-fill {
    height: 100%;
    background: var(--meridian-accent, #2563eb);
  }
  .percent {
    font-size: 0.8em;
    color: var(--meridian-muted-fg, #666);
  }
  .offer-actions {
    margin-top: 0.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .offer-prompt {
    font-size: 0.85em;
    color: var(--meridian-warn-fg, #92400e);
  }
</style>
