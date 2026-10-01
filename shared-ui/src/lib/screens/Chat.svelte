<script lang="ts">
  import type { ContactSummary, MeridianClientAdapter } from '../adapter';
  import ChatConversation from './ChatConversation.svelte';

  interface Props {
    adapter: MeridianClientAdapter;
    /** The conversation partner. Switching `contact.peerId` opens a fresh, isolated conversation. */
    contact: ContactSummary;
    /** Hand-off to the verification screen (12.8); the button is shown only when provided. */
    onverify?: (contact: ContactSummary) => void;
  }

  let { adapter, contact, onverify }: Props = $props();
</script>

<!--
  Keyed on the peer: each conversation gets its own view-model (events, in-flight sends, gate
  state), so nothing from one peer's conversation can be applied to another's.
-->
{#key contact.peerId}
  <ChatConversation {adapter} {contact} {onverify} />
{/key}
