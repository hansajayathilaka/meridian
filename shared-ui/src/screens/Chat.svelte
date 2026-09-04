<!--
  Chat — the 1:1 conversation screen (task 4.20's browser/desktop equivalent). Loads history via
  `MeridianClientAdapter.openConversation`/`loadHistory`, renders it with the existing
  `MessageList` primitive, and gates the composer on `chatStore`'s `sendGate` — the task's own
  named highest-risk area (block-on-verified / D06, system-design.md §4.4).

  **The invariant this file itself is responsible for, at the UI layer:** the composer's submit
  control is disabled whenever `$store.sendGate.kind !== "ok"` (see the single `sendDisabled`
  expression below) — a blocked or unacknowledged-key-change contact cannot be messaged from this
  screen, full stop. There is deliberately no "send anyway" affordance for a `"blocked"` gate here
  (that requires the real verification flow, task 12.8); a `"warn"` gate's only way out is the
  explicit "Acknowledge and re-pin" action, mirroring the CLI's typed accept prompt
  (`adapter.ts`'s own `sendChat`/`acknowledgeKeyChange` doc comments). `chatStore.send` itself
  re-checks the gate a second time immediately before calling `sendChat` (see that module's doc)
  — this component's disabled-button check is the first, not the only, line of defense.
-->
<script lang="ts">
  import { onDestroy } from "svelte";

  import type { MeridianClientAdapter, MeridianId } from "../lib/adapter";
  import MessageList from "../lib/components/MessageList.svelte";
  import { createChatStore } from "./stores/chatStore";

  export let adapter: MeridianClientAdapter;
  export let peer: MeridianId;

  const store = createChatStore(adapter);
  onDestroy(() => store.destroy());

  // Re-opens whenever the `peer` prop changes (including on first mount).
  $: void store.open(peer);

  let composerText = "";
  let sendError: string | null = null;

  $: sendDisabled = $store.sendGate.kind !== "ok" || $store.sending || !composerText.trim();

  async function handleSend(): Promise<void> {
    const body = composerText.trim();
    if (!body) return;
    sendError = null;
    try {
      await store.send(body);
      composerText = "";
    } catch (err) {
      sendError = err instanceof Error ? err.message : "Failed to send.";
    }
  }

  async function handleAcknowledge(): Promise<void> {
    try {
      await store.acknowledgeKeyChange();
    } catch (err) {
      sendError = err instanceof Error ? err.message : "Failed to acknowledge.";
    }
  }
</script>

<div class="chat-screen">
  <header>
    <h2>{peer}</h2>
    {#if $store.sendGate.kind === "blocked"}
      <p class="gate-banner gate-blocked" role="alert" data-testid="send-gate-blocked">
        {$store.sendGate.reason}
      </p>
    {:else if $store.sendGate.kind === "warn"}
      <p class="gate-banner gate-warn" role="alert" data-testid="send-gate-warn">
        {$store.sendGate.reason}
        <button type="button" on:click={handleAcknowledge}>Acknowledge and re-pin</button>
      </p>
    {/if}
  </header>

  <MessageList messages={$store.messages} emptyLabel="No messages yet." />

  {#if sendError}
    <p class="send-error" role="alert">{sendError}</p>
  {/if}

  <form class="composer" on:submit|preventDefault={handleSend}>
    <textarea
      bind:value={composerText}
      disabled={$store.sendGate.kind === "blocked"}
      placeholder={$store.sendGate.kind === "blocked"
        ? "Sending is blocked for this contact"
        : "Type a message"}
      aria-label="Message"
    ></textarea>
    <button type="submit" disabled={sendDisabled}>Send</button>
  </form>
</div>

<style>
  .chat-screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }
  header {
    padding: 0.75rem;
    border-bottom: 1px solid var(--meridian-border, #ddd);
  }
  header h2 {
    margin: 0;
    font-size: 1rem;
    word-break: break-all;
  }
  .gate-banner {
    margin: 0.5rem 0 0;
    padding: 0.5rem;
    border-radius: 0.4rem;
    font-size: 0.85em;
  }
  .gate-blocked {
    background: var(--meridian-error-bg, #fee2e2);
    color: var(--meridian-error-fg, #b91c1c);
  }
  .gate-warn {
    background: var(--meridian-warn-bg, #fef3c7);
    color: var(--meridian-warn-fg, #92400e);
  }
  .send-error {
    color: var(--meridian-error-fg, #b91c1c);
    padding: 0 0.75rem;
  }
  .composer {
    display: flex;
    gap: 0.5rem;
    padding: 0.75rem;
    border-top: 1px solid var(--meridian-border, #ddd);
  }
  .composer textarea {
    flex: 1 1 auto;
    resize: vertical;
    min-height: 2.5rem;
  }
</style>
