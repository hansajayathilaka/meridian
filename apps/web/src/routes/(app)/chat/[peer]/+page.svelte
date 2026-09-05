<!--
  `/chat/[peer]` — 1:1 conversation. Reuses `shared-ui`'s `Chat` screen (12.7) unmodified.
  `openConversation`/`sendChat`/`loadHistory`/`onMessage`/... are all GAP'd against today's real
  adapter (`src/lib/adapter.ts`'s top doc comment: no session/chat orchestration binding exists
  yet) — `chatStore.ts` already catches every one of those and surfaces `$store.error`, so this
  route renders a real composer that correctly reports "can't load/send" rather than crashing or
  silently doing nothing. `peer` is taken verbatim from the URL param (already
  `decodeURIComponent`d by SvelteKit) — never re-parsed/re-derived here; `Chat.svelte` itself is
  the only place that touches it further.
-->
<script lang="ts">
  import { page } from "$app/stores";

  import { Chat } from "shared-ui";
  import { adapter } from "$lib/session";
  import PeerNav from "$lib/PeerNav.svelte";

  $: peer = $page.params.peer ?? "";
</script>

<svelte:head>
  <title>Meridian — Chat — {peer}</title>
</svelte:head>

{#if peer}
  <PeerNav {peer} />
  <Chat {adapter} {peer} />
{/if}
