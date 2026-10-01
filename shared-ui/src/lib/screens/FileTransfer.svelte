<script lang="ts">
  import type { ContactSummary, MeridianClientAdapter } from '../adapter';
  import FileTransferPanel from './FileTransferPanel.svelte';

  interface Props {
    adapter: MeridianClientAdapter;
    /** The peer files are sent to and received from. Switching `contact.peerId` opens a fresh screen. */
    contact: ContactSummary;
    /** Hand-off to the verification screen (12.8); the button is shown only when provided. */
    onverify?: (contact: ContactSummary) => void;
    /**
     * Native file chooser supplied by a desktop shell (resolves to the chosen filesystem paths, or
     * `null`/empty when cancelled). Optional: without it only the browser drop zone and file
     * picker are offered. Chosen paths go through the same gate-checked send as dropped files.
     */
    pickPaths?: () => Promise<readonly string[] | null>;
  }

  let { adapter, contact, onverify, pickPaths }: Props = $props();
</script>

<!--
  Keyed on the adapter AND the peer: each combination gets its own view-model (which captures both
  at construction), so a transfer event, a pending accept/reject, a gate answer or an in-flight send
  for one peer can never be applied to another's screen.
-->
{#key adapter}
  {#key contact.peerId}
    <FileTransferPanel {adapter} {contact} {onverify} {pickPaths} />
  {/key}
{/key}
