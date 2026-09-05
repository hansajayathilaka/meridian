<!--
  `/files/[peer]` — file transfers for one conversation. Reuses `shared-ui`'s `FileTransfer` screen
  (12.9) unmodified. `sendFile`/`listTransfers`/`acceptTransfer`/`rejectTransfer` are all GAP'd
  against today's real adapter (`src/lib/adapter.ts`'s top doc comment: no stream-registry binding
  exists yet) — `fileTransferStore.ts` catches every one of those and surfaces `$store.error`; this
  route renders the real drag-drop/file-picker UI correctly reporting "can't send/list" rather than
  crashing or silently accepting a drop that goes nowhere.
-->
<script lang="ts">
  import { page } from "$app/stores";

  import { FileTransfer } from "shared-ui";
  import { adapter } from "$lib/session";
  import PeerNav from "$lib/PeerNav.svelte";

  $: peer = $page.params.peer ?? "";
</script>

<svelte:head>
  <title>Meridian — Files — {peer}</title>
</svelte:head>

{#if peer}
  <PeerNav {peer} />
  <FileTransfer {adapter} {peer} />
{/if}
