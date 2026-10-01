<script lang="ts">
  import { onMount } from 'svelte';
  import type { ContactSummary, MeridianClientAdapter } from '../adapter';
  import type { QrScanner } from '../qr-scanner';
  import { contactDisplayLabel, trustLabel } from '../view';
  import { VERIFY_COPY } from './copy';
  import { notify } from './safe-call';
  import { VerificationViewModel } from './verification.svelte';

  interface Props {
    adapter: MeridianClientAdapter;
    contact: ContactSummary;
    scanner?: QrScanner;
    onverified?: (contact: ContactSummary) => void;
    onclose?: () => void;
  }

  let { adapter, contact, scanner, onverified, onclose }: Props = $props();

  // One view-model per peer: `Verification.svelte` re-creates this component when the peer
  // changes, so a stale scan/query completion for another peer can never land here.
  // svelte-ignore state_referenced_locally
  const vm = new VerificationViewModel(adapter, contact, scanner ?? null, {
    onverified: (c) => onverified?.(c)
  });

  $effect(() => {
    vm.syncContact(contact);
  });

  onMount(() => {
    vm.start();
    return () => vm.dispose();
  });

  // A key change always keeps the KEY CHANGE header, even when the contact is ALSO locally blocked
  // (the local block is shown as an extra line, never in place of the key-change message). Only a
  // purely local block gets the "CONTACT BLOCKED" header.
  const keyChanged = $derived(
    vm.contact.trust === 'blocked' || vm.contact.trust === 'pinned-key-changed'
  );
  const blockHeader = $derived(
    vm.contact.userBlocked && !keyChanged
      ? 'CONTACT BLOCKED — SENDS BLOCKED'
      : 'KEY CHANGE — SENDS BLOCKED'
  );
</script>

<!--
  Verification screen (D06). Mirrors the terminal client's 4.22 and verification-ux.md.

  - Core's gate `reason` is rendered verbatim as a text node (never `{@html}`), never paraphrased.
  - The safety number is rendered exactly as the adapter supplied it; the QR is the adapter's text
    render (a text QR: no pixel/SVG render exists in the adapter).
  - There is NO "verify anyway" / "trust anyway" control. After a mismatch no verify control of any
    kind is shown. `Mark as verified` exists only after an exact scan match, and the manual
    "digits match" control only before any mismatch; each leads to an explicit confirm.
  - Every peer-influenced string (petname, hint, reason, number display) is rendered as text only.
-->
<section class="verification" aria-label="Verify safety number">
  <header class="peer">
    <h2>Verify {contactDisplayLabel(vm.contact)}</h2>
    <span class="fingerprint">{vm.contact.fingerprint}</span>
    <span class="trust">{trustLabel(vm.contact.trust, vm.contact.userBlocked)}</span>
    {#if onclose}
      <button type="button" onclick={() => notify(onclose)}>Back</button>
    {/if}
  </header>

  {#if vm.gate === null}
    {#if vm.gateUnavailable}
      <p class="gate-pending" role="status">{VERIFY_COPY.gateUnavailable}</p>
    {/if}
  {:else if vm.gate.kind === 'blocked'}
    <div class="gate-banner" role="alert" data-gate="blocked">
      <strong>{blockHeader}</strong>
      <p class="reason">{vm.gate.reason}</p>
      {#if vm.contact.userBlocked && keyChanged}
        <p class="reason">You have also blocked this contact.</p>
      {/if}
    </div>
  {:else if vm.gate.kind === 'warn'}
    <div class="gate-banner" role="alert" data-gate="warn">
      <strong>KEY CHANGE WARNING</strong>
      <p class="reason">{vm.gate.reason}</p>
    </div>
  {/if}

  {#if vm.numbers !== null}
    <div class="number-pane">
      <h3>Safety number</h3>
      <p class="safety-number" data-testid="safety-number">{vm.numbers.display}</p>
      {#if vm.qrText !== null}
        <pre class="qr" role="img" aria-label="QR code of the safety number">{vm.qrText}</pre>
      {:else if vm.qrFailed}
        <p class="note">{VERIFY_COPY.qrUnavailable}</p>
      {/if}
      <p class="note">{VERIFY_COPY.compareHint}</p>
    </div>
  {:else if vm.numbersFailed}
    <p role="alert" class="error">{VERIFY_COPY.numberUnavailable}</p>
  {:else}
    <p role="status">Loading safety number…</p>
  {/if}

  {#if vm.notice}
    <p
      class="notice"
      role={vm.notice.kind === 'error' ? 'alert' : 'status'}
      data-notice={vm.notice.kind}
    >
      {vm.notice.text}
    </p>
  {/if}

  {#if vm.mismatchSeen}
    <div class="mismatch" role="alert" data-state="mismatch">
      <strong>MISMATCH</strong>
      <p>{VERIFY_COPY.mismatch}</p>
    </div>
  {/if}

  {#if vm.scanNote}
    <p class="note" role="status" data-testid="scan-note">{vm.scanNote}</p>
  {/if}

  {#if vm.numbers !== null}
    <div class="compare">
      {#if vm.check.kind === 'scanning'}
        <p role="status">Scanning… hold their safety number QR code in front of the camera.</p>
        <button type="button" onclick={() => vm.stopScan()}>Stop scanning</button>
      {:else if vm.check.kind === 'matched'}
        <div role="group" aria-label="Confirm verification" data-state="matched">
          <p role="status">{VERIFY_COPY.matched}</p>
          <p>{VERIFY_COPY.confirmPrompt}</p>
          <button type="button" onclick={() => void vm.confirmVerified()} disabled={vm.busy}>
            Mark as verified
          </button>
          <button type="button" onclick={() => vm.cancelCompare()} disabled={vm.busy}>Cancel</button>
        </div>
      {:else if vm.check.kind === 'manual'}
        <div role="group" aria-label="Confirm verification" data-state="manual">
          <p>{VERIFY_COPY.confirmPrompt}</p>
          <button type="button" onclick={() => void vm.confirmVerified()} disabled={vm.busy}>
            Yes, the numbers matched: mark as verified
          </button>
          <button type="button" onclick={() => vm.cancelCompare()} disabled={vm.busy}>Cancel</button>
        </div>
      {:else}
        {#if vm.canScan}
          <button type="button" onclick={() => void vm.startScan()} disabled={vm.busy}>
            {vm.mismatchSeen ? 'Scan again' : 'Scan their QR code'}
          </button>
        {/if}
        {#if !vm.mismatchSeen}
          <button type="button" onclick={() => vm.beginManualCompare()} disabled={vm.busy}>
            The digits match
          </button>
        {/if}
      {/if}
    </div>
  {/if}

  <div class="actions">
    {#if vm.gate?.kind === 'warn' && vm.prompt?.kind !== 'acknowledge'}
      <button type="button" onclick={() => vm.beginAcknowledge()} disabled={vm.busy}>
        Acknowledge without verifying
      </button>
    {/if}
    {#if vm.prompt === null}
      <button type="button" onclick={() => vm.beginBlock()} disabled={vm.busy}>
        {vm.contact.userBlocked ? 'Unblock contact' : 'Block contact'}
      </button>
    {/if}
  </div>

  {#if vm.prompt?.kind === 'acknowledge'}
    <div role="group" aria-label="Confirm acknowledge">
      <p>{VERIFY_COPY.acknowledgePrompt}</p>
      <button type="button" onclick={() => void vm.confirmAcknowledge()} disabled={vm.busy}>
        Acknowledge without verifying
      </button>
      <button type="button" onclick={() => vm.cancelPrompt()} disabled={vm.busy}>Cancel</button>
    </div>
  {:else if vm.prompt?.kind === 'block'}
    <div role="group" aria-label="Confirm block">
      <p>{vm.prompt.blocked ? 'Block' : 'Unblock'} this contact?</p>
      <button type="button" onclick={() => void vm.confirmBlock()} disabled={vm.busy}>
        {vm.prompt.blocked ? 'Yes, block' : 'Yes, unblock'}
      </button>
      <button type="button" onclick={() => vm.cancelPrompt()} disabled={vm.busy}>Cancel</button>
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
  .gate-banner,
  .mismatch {
    margin: 0.5rem 0;
    padding: 0.5rem;
    border: 2px solid currentColor;
  }
  .reason {
    margin: 0.25rem 0;
    white-space: pre-wrap;
  }
  .safety-number {
    font-family: monospace;
    font-size: 1.1em;
    word-break: break-word;
  }
  .qr {
    font-family: monospace;
    line-height: 1;
    margin: 0.5rem 0;
    overflow-x: auto;
  }
  .note {
    font-size: 0.85em;
  }
  .actions,
  .compare {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0.5rem;
  }
</style>
