<!--
  Verification — camera-scan safety-number compare (task 12.8), the browser/desktop equivalent of
  the terminal client's verification screen (task 4.22, `apps/tui/src/screens/verify.rs`). Shows this
  device's own safety number as text + QR (via `meridian_core::crypto::safety_number`/
  `display_groups`, through `adapter.safetyNumber`), scans the peer's device for the same code, and
  calls `markVerified` — but ONLY once `verificationStore`'s own `compareSafetyNumbers` has reported
  an exact `"match"`. See that module's doc comment for the full state-machine argument for why a
  partial/garbled/ambiguous scan can never reach `markVerified`; this component adds nothing to that
  argument, it only renders `$store.scanResult.kind` and disables the "Mark verified" button for
  every value except `"match"` (mirrors `Chat.svelte`'s own "render, never re-derive" pattern for
  `sendGate`).

  Camera capture goes through the injectable `scanner` prop (default: the real
  `MediaDevicesQrScanner`, `../lib/qrScanner.ts`) so component tests can supply a deterministic fake
  instead of touching `navigator.mediaDevices`/jsQR — no real camera exists in this task's headless
  test environment (task 12.8 Deliverables).
-->
<script lang="ts">
  import { onDestroy, tick } from "svelte";
  import QRCode from "qrcode";

  import type { MeridianClientAdapter, MeridianId } from "../lib/adapter";
  import { MediaDevicesQrScanner, type QrScanner } from "../lib/qrScanner";
  import { createVerificationStore } from "./stores/verificationStore";

  export let adapter: MeridianClientAdapter;
  export let peer: MeridianId;
  /** Injectable for tests — defaults to the real camera-backed scanner in production. */
  export let scanner: QrScanner = new MediaDevicesQrScanner();

  const store = createVerificationStore(adapter);
  onDestroy(() => scanner.stop());

  $: void store.load(peer);

  let videoEl: HTMLVideoElement | undefined;
  let qrSvgMarkup: string | null = null;
  let confirmError: string | null = null;

  // Renders this device's own safety number as a QR code whenever it (re)loads. The QR payload is
  // exactly the 60-digit raw safety number string — nothing else — mirroring
  // `apps/identity/src/qr.rs`'s own doc comment that "a QR is a transport, not a trust anchor": the
  // real trust decision is `compareSafetyNumbers`'s exact-match check, not the QR mechanism itself.
  //
  // Rendered as SVG markup (`QRCode.toString(..., { type: "svg" })`) rather than a canvas-backed
  // `toDataURL()` PNG: the SVG path is pure string generation with no `<canvas>`/2D-context
  // dependency, so it works identically in every real target (browser, desktop webview) AND in this
  // package's jsdom component tests, which have no native canvas backing. `{@html}` is safe here —
  // the markup is entirely library-generated from a validated numeric-digits-only payload, never
  // interpolated from unsanitized input.
  $: if ($store.localSafetyNumber) {
    void QRCode.toString($store.localSafetyNumber.raw, { type: "svg", margin: 1 }).then((svg) => {
      qrSvgMarkup = svg;
    });
  } else {
    qrSvgMarkup = null;
  }

  async function handleStartScan(): Promise<void> {
    confirmError = null;
    store.beginScan();
    // `beginScan()` flips `$store.scanning`, which is what conditionally mounts `<video
    // bind:this={videoEl}>` below — wait one tick for Svelte's own DOM update to land before
    // reading `videoEl`, or it would still be `undefined` from the pre-scan render.
    await tick();
    if (!videoEl) {
      store.reportCameraError("Camera preview is not ready.");
      return;
    }
    try {
      await scanner.start(videoEl, (text) => {
        store.handleScan(text);
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Could not access the camera.";
      store.reportCameraError(message);
    }
  }

  function handleStopScan(): void {
    scanner.stop();
    store.reportCameraError("Scan cancelled.");
  }

  async function handleConfirmVerified(): Promise<void> {
    confirmError = null;
    try {
      await store.confirmVerified();
      scanner.stop();
    } catch (err) {
      confirmError = err instanceof Error ? err.message : "Could not mark as verified.";
    }
  }

  async function handleRescan(): Promise<void> {
    await handleStartScan();
  }
</script>

<div class="verification-screen">
  <h2>Verify safety number</h2>
  <p class="peer">{peer}</p>

  {#if $store.error}
    <p class="error" role="alert">{$store.error}</p>
  {/if}

  {#if $store.alreadyVerified && !$store.verified}
    <p class="already-verified" role="status">This contact is already marked verified.</p>
  {/if}

  {#if $store.loading}
    <p>Loading safety number…</p>
  {:else if $store.localSafetyNumber}
    <section class="local-number">
      <p class="grouped" data-testid="local-safety-number">{$store.localSafetyNumber.grouped}</p>
      {#if qrSvgMarkup}
        <div class="qr" data-testid="qr-code" role="img" aria-label="QR code of this device's safety number">
          {@html qrSvgMarkup}
        </div>
      {/if}
    </section>

    {#if $store.verified}
      <p class="verified-banner" role="status" data-testid="verified-banner">
        Verified. This contact's safety number is confirmed to match.
      </p>
    {:else}
      <section class="scan">
        {#if !$store.scanning && !$store.scanResult}
          <button type="button" data-testid="start-scan" on:click={handleStartScan}>
            Scan peer's code
          </button>
        {:else if $store.scanning}
          <!-- svelte-ignore a11y-media-has-caption -->
          <video bind:this={videoEl} class="camera-preview" playsinline muted></video>
          <button type="button" data-testid="stop-scan" on:click={handleStopScan}>Cancel scan</button>
        {/if}

        {#if $store.cameraError}
          <p class="camera-error" role="alert" data-testid="camera-error">{$store.cameraError}</p>
        {/if}

        {#if $store.scanResult}
          {#if $store.scanResult.kind === "match"}
            <p class="result-match" role="status" data-testid="scan-result-match">
              Safety numbers match.
            </p>
            <button
              type="button"
              data-testid="mark-verified"
              disabled={$store.verifying}
              on:click={handleConfirmVerified}
            >
              {$store.verifying ? "Marking verified…" : "Mark verified"}
            </button>
          {:else if $store.scanResult.kind === "mismatch"}
            <p class="result-mismatch" role="alert" data-testid="scan-result-mismatch">
              Safety numbers do NOT match. Do not trust this contact until this is resolved — this
              can mean interception. Verification was NOT recorded.
            </p>
            <button type="button" data-testid="rescan" on:click={handleRescan}>Scan again</button>
          {:else}
            <p class="result-invalid" role="alert" data-testid="scan-result-invalid">
              Could not read a valid safety number from that scan ({$store.scanResult.reason}). Try
              again with the code fully in frame.
            </p>
            <button type="button" data-testid="rescan" on:click={handleRescan}>Scan again</button>
          {/if}
        {/if}

        {#if confirmError}
          <p class="confirm-error" role="alert">{confirmError}</p>
        {/if}
      </section>
    {/if}
  {/if}
</div>

<style>
  .verification-screen {
    padding: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .peer {
    word-break: break-all;
    color: var(--meridian-muted-fg, #666);
    margin: 0;
  }
  .error,
  .camera-error,
  .result-mismatch,
  .result-invalid,
  .confirm-error {
    color: var(--meridian-error-fg, #b91c1c);
  }
  .already-verified,
  .verified-banner,
  .result-match {
    color: var(--meridian-ok-fg, #15803d);
  }
  .local-number {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.5rem;
  }
  .grouped {
    font-family: var(--meridian-mono, monospace);
    font-size: 1rem;
    letter-spacing: 0.05em;
  }
  .qr {
    width: 200px;
    height: 200px;
  }
  .qr :global(svg) {
    width: 100%;
    height: 100%;
  }
  .camera-preview {
    width: 100%;
    max-width: 320px;
  }
  .scan {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    align-items: flex-start;
  }
</style>
