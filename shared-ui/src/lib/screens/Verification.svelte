<script lang="ts">
  import type { ContactSummary, MeridianClientAdapter } from '../adapter';
  import type { QrScanner } from '../qr-scanner';
  import VerificationPanel from './VerificationPanel.svelte';

  interface Props {
    adapter: MeridianClientAdapter;
    /** The contact being verified. Switching `contact.peerId` opens a fresh, isolated screen. */
    contact: ContactSummary;
    /**
     * Camera scanner supplied by the shell (browser `MediaDevices` / desktop). Optional: without
     * one the screen offers the out-of-band "digits match" comparison only.
     */
    scanner?: QrScanner;
    /** The user confirmed and the contact was marked verified (e.g. return to the chat). */
    onverified?: (contact: ContactSummary) => void;
    /** The user asked to leave the screen (Chat's `onverify` hand-off navigates here; this returns). */
    onclose?: () => void;
  }

  let { adapter, contact, scanner, onverified, onclose }: Props = $props();
</script>

<!--
  Keyed on the peer, the adapter AND the scanner: each combination gets its own view-model (which
  captures all three at construction), so a scan result, a pending confirm, or an in-flight query
  for one peer can never be applied to another's screen, and a swapped adapter/scanner for the same
  peer rebuilds it instead of leaving it bound to the old one.
-->
{#key adapter}
  {#key scanner}
    {#key contact.peerId}
      <VerificationPanel {adapter} {contact} {scanner} {onverified} {onclose} />
    {/key}
  {/key}
{/key}
