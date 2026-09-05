<!--
  `/requests` — first-contact message request queue. Reuses `shared-ui`'s `MessageRequests` (12.7)
  unmodified. `onMessageRequest`/`acceptMessageRequest`/`rejectMessageRequest` are all GAP'd against
  today's real adapter (`src/lib/adapter.ts`'s top doc comment: no trust-store binding exists yet)
  — this route renders the screen's own `$store.error` banner and an always-empty request list
  rather than crashing or fabricating requests, exactly as `messageRequestsStore.ts` already
  guarantees for a real adapter error.
-->
<script lang="ts">
  import { goto } from "$app/navigation";

  import { MessageRequests } from "shared-ui";
  import type { MeridianId } from "shared-ui";
  import { adapter } from "$lib/session";

  function handleAccepted(peer: MeridianId): void {
    void goto(`/chat/${encodeURIComponent(peer)}`);
  }
</script>

<svelte:head>
  <title>Meridian — Message requests</title>
</svelte:head>

<MessageRequests {adapter} onAccepted={handleAccepted} />
