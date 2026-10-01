<script lang="ts">
  import { onDestroy } from 'svelte';
  import type { AccountSummary, MeridianClientAdapter } from '../adapter';
  import { AccountCreateViewModel } from './account-create.svelte';

  interface Props {
    adapter: MeridianClientAdapter;
    /** Called with the new account once core has generated it. */
    oncreated?: (account: AccountSummary) => void;
    /**
     * Offer the passphrase-wrapped keyfile option. `TODO: confirm` whether the browser backend
     * (12.5) offers it at all (adapter.ts `KeyProtection`); a shell that does not support it
     * passes `false`.
     */
    allowPassphrase?: boolean;
  }

  let { adapter, oncreated, allowPassphrase = true }: Props = $props();

  // The adapter and callback are fixed for this screen's lifetime (a shell remounts to change them).
  // svelte-ignore state_referenced_locally
  const vm = new AccountCreateViewModel(adapter, (account) => oncreated?.(account));

  onDestroy(() => vm.clearSecrets());
</script>

<!--
  Account creation. The key never crosses the adapter boundary and is never shown. The passphrase
  input is masked, is never echoed into the DOM as text, and is cleared once the request settles.
  Copy is deliberately modest: Meridian is end-to-end encrypted with pseudonymous IDs; it is not
  anonymous in the Tor sense, so that word does not appear here.
-->
<section class="account-create" aria-label="Create account">
  <h2>Create your Meridian account</h2>
  <form
    onsubmit={(e) => {
      e.preventDefault();
      void vm.submit();
    }}
  >
    <label>
      Server domain hint (advisory)
      <input
        type="text"
        name="hint"
        autocomplete="off"
        spellcheck="false"
        placeholder="org.example"
        bind:value={vm.hint}
        disabled={vm.busy}
      />
    </label>

    <fieldset disabled={vm.busy}>
      <legend>Protect your key</legend>
      <label>
        <input
          type="radio"
          name="protection"
          value="platform"
          bind:group={vm.protection}
          onchange={() => vm.clearSecrets()}
        />
        Use device storage
      </label>
      {#if allowPassphrase}
        <label>
          <input type="radio" name="protection" value="passphrase" bind:group={vm.protection} />
          Protect with a passphrase
        </label>
      {/if}
    </fieldset>

    {#if allowPassphrase && vm.protection === 'passphrase'}
      <label>
        Passphrase
        <input
          type="password"
          name="passphrase"
          autocomplete="new-password"
          bind:value={vm.passphrase}
          disabled={vm.busy}
        />
      </label>
      <label>
        Confirm passphrase
        <input
          type="password"
          name="passphrase-confirm"
          autocomplete="new-password"
          bind:value={vm.confirm}
          disabled={vm.busy}
        />
      </label>
      <p class="note">
        There is no passphrase recovery. If you lose it, your identity cannot be restored.
      </p>
    {/if}

    {#if vm.error}
      <p role="alert" class="error">{vm.error}</p>
    {/if}

    <button type="submit" disabled={vm.busy}>Create account</button>
  </form>
</section>

<style>
  form {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    max-width: 24rem;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  fieldset label {
    flex-direction: row;
    align-items: center;
  }
  .note {
    font-size: 0.8em;
    opacity: 0.8;
    margin: 0;
  }
</style>
