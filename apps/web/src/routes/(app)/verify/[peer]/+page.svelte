<!--
  `/verify/[peer]` — safety-number verification. Reuses `shared-ui`'s `Verification` screen (12.8)
  unmodified. `adapter.safetyNumber` is GAP'd against today's real adapter (`src/lib/adapter.ts`'s
  top doc comment: no trust-store binding to resolve a peer's raw pubkey) — `verificationStore.ts`
  catches that and surfaces `$store.error`; this route renders the real camera-scan UI shell (the
  default `MediaDevicesQrScanner` prop) correctly reporting that failure rather than fabricating a
  safety number.
-->
<script lang="ts">
  import { page } from "$app/stores";

  import { Verification } from "shared-ui";
  import { adapter } from "$lib/session";
  import PeerNav from "$lib/PeerNav.svelte";

  $: peer = $page.params.peer ?? "";
</script>

<svelte:head>
  <title>Meridian — Verify — {peer}</title>
</svelte:head>

{#if peer}
  <PeerNav {peer} />
  <Verification {adapter} {peer} />
{/if}
