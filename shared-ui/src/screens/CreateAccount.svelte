<!--
  CreateAccount — the account-creation flow named in this task's Scope→In list. A small,
  dedicated screen rather than folded into `Contacts.svelte`: it is a distinct pre-onboarding
  step (there is no contact list or chat to show until an account exists — `MeridianClientAdapter
  .currentAccount()` is `null`), and every other screen in this file assumes an already-open
  account, exactly like `apps/tui`'s own `Screen::Unlock`-before-`Screen::Contacts` ordering.

  Only wires `generateAccount` (a fresh account) — `openAccount`'s `descriptor` is deliberately
  platform-opaque (keyfile path, OS keystore label, ...; see `adapter.ts`'s own doc comment) and
  is not this task's to standardize a form around; a concrete shell (12.14/12.15) wires its own
  "open existing account" entry point using whatever descriptor shape it accepts.
  TODO: confirm — no design doc specifies an "open existing account" browser/desktop UI; left out
  rather than invented.
-->
<script lang="ts">
  import type { MeridianClientAdapter, MeridianId } from "../lib/adapter";
  import { createAccountStore } from "./stores/accountStore";

  export let adapter: MeridianClientAdapter;
  /** Called once account creation succeeds, with the new account id — a shell wires this to
   * navigation into the main contacts/chat view. */
  export let onCreated: ((id: MeridianId) => void) | undefined = undefined;

  const store = createAccountStore(adapter);
  let hint = "";

  async function handleSubmit(): Promise<void> {
    if (!hint.trim()) return;
    try {
      const id = await store.createAccount(hint);
      onCreated?.(id);
    } catch {
      // Surfaced via $store.error below — no further action needed here.
    }
  }
</script>

<div class="create-account-screen">
  <h1>Create your Meridian account</h1>
  <p class="copy">
    Choose a routing hint — usually your organization's domain. It is advisory only: an initial
    lookup aid, never part of your identity itself (system-design.md §3.1).
  </p>
  <form on:submit|preventDefault={handleSubmit}>
    <label for="account-hint">Routing hint</label>
    <input
      id="account-hint"
      type="text"
      bind:value={hint}
      placeholder="example.org"
      autocomplete="off"
      disabled={$store.status === "creating"}
    />
    <button type="submit" disabled={$store.status === "creating" || !hint.trim()}>
      {$store.status === "creating" ? "Creating…" : "Create account"}
    </button>
  </form>

  {#if $store.status === "error" && $store.error}
    <p class="error" role="alert">{$store.error}</p>
  {/if}

  {#if $store.status === "done" && $store.accountId}
    <p class="success" role="status">
      Account created: <code>{$store.accountId}</code>
    </p>
  {/if}
</div>

<style>
  .create-account-screen {
    max-width: 28rem;
    margin: 0 auto;
    padding: 1.5rem;
  }
  .copy {
    color: var(--meridian-muted-fg, #666);
    font-size: 0.9em;
  }
  form {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .error {
    color: var(--meridian-error-fg, #b91c1c);
  }
  .success code {
    word-break: break-all;
  }
</style>
