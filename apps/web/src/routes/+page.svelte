<!--
  Onboarding / account creation — the one route this task's adapter (12.13) makes genuinely work
  end to end (`generateAccount`, real `crypto.subtle`). Reuses `shared-ui`'s `CreateAccount` screen
  (12.7) unmodified, per ADR 0012 ("screens are written once ... reused by both shells unmodified").

  `openAccount` (an existing session surviving a reload) is not wired here — `adapter.ts`'s own top
  doc comment ("Account persistence across a reload") documents this as a real, structural gap in
  `WebCryptoSecretStore`'s non-extractable `CryptoKey`s, not something this route can paper over; a
  fresh page load always lands back here with no account, by design, until that gap is closed.
-->
<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";

  import { CreateAccount } from "shared-ui";
  import type { MeridianId } from "shared-ui";
  import { adapter, currentAccountId, noteAccountCreated } from "$lib/session";

  onMount(() => {
    // Already signed in this session (e.g. navigated back here manually) — go straight to the app.
    if ($currentAccountId) void goto("/contacts");
  });

  function handleCreated(id: MeridianId): void {
    noteAccountCreated(id);
    void goto("/contacts");
  }
</script>

<svelte:head>
  <title>Meridian — Create account</title>
</svelte:head>

<CreateAccount {adapter} onCreated={handleCreated} />
