<script lang="ts">
  import type { ContactSummary } from '../adapter';
  import { contactDisplayLabel, trustLabel } from '../view';

  interface Props {
    contact: ContactSummary;
    selected?: boolean;
    onselect?: (contact: ContactSummary) => void;
  }

  let { contact, selected = false, onselect }: Props = $props();
</script>

<!--
  The fingerprint is always shown alongside the petname (tui-client.md §6 rule 2): a petname is
  user-editable, so it must never be the only identity cue. The trust label never reads as
  reassurance for an unverified contact.
-->
<button
  type="button"
  class="contact-row"
  aria-pressed={selected}
  data-trust={contact.trust}
  onclick={() => onselect?.(contact)}
>
  <span class="label">{contactDisplayLabel(contact)}</span>
  <span class="fingerprint">{contact.fingerprint}</span>
  <span class="trust">{trustLabel(contact.trust, contact.userBlocked)}</span>
</button>

<style>
  .contact-row {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    width: 100%;
    text-align: start;
    background: none;
    border: 0;
    padding: 0.5rem;
    cursor: pointer;
  }
  .contact-row[aria-pressed='true'] {
    background: rgba(127, 127, 127, 0.2);
  }
  .fingerprint,
  .trust {
    font-size: 0.75em;
    opacity: 0.7;
  }
</style>
