/**
 * `QrScanner` — the thin MediaDevices-camera + jsQR abstraction {@link ../screens/Verification.svelte}
 * drives. Deliberately its own tiny interface (not called directly from the screen's markup) so a
 * component test can inject a fully deterministic fake instead of the real one — task 12.8's own
 * Deliverables note: "camera access itself MOCKED, not exercised live in this task's test suite (no
 * real browser camera in a headless test environment)". `MediaDevicesQrScanner` below is the real
 * implementation used in production; it is intentionally NOT unit-tested here (there is no camera to
 * test against in jsdom/CI), only type-checked.
 *
 * `qrcode` (encode) and `jsqr` (decode) are the two QR dependencies this task adds to `shared-ui` —
 * see that package's `package.json`. Neither existed anywhere else in the monorepo (`meridian-identity`'s
 * own `apps/identity/src/qr.rs` uses the Rust `qrcode`/`rqrr` crates for the terminal client, which
 * this web/TS layer cannot call into — the WASM boundary carries `safety_number` string data, never
 * pixels). Chosen because both are small, dependency-free (`jsqr`), widely used, and — critically —
 * this task performs no cryptographic operation with either: both only encode/decode a plain ASCII
 * string. All identity/trust logic stays in `meridian-core`; see this file's and `Verification.svelte`'s
 * own doc comments for where the actual match/mismatch decision is made (never here).
 */

import jsQR from "jsqr";

/** One decode attempt's raw outcome — camera frames rarely contain a well-formed code, so "no code
 * found in the current frame" is a normal, non-error outcome the scanner keeps polling through. */
export type QrScanOutcome =
  | { kind: "decoded"; text: string }
  | { kind: "no-code" };

export interface QrScanner {
  /**
   * Starts scanning `video` for QR codes, invoking `onDecode` once per *successfully decoded* frame
   * (never for a `"no-code"` outcome — that's internal polling noise the caller should not need to
   * filter). Never invoked with a partial/truncated string: jsQR/the underlying decoder either
   * recovers the full encoded payload from a frame or reports nothing at all for that frame — there
   * is no jsQR API surface for a "partial decode". Continues scanning after a decode (the caller
   * decides whether to {@link stop} once it has what it needs) so a rejected/mismatched scan can be
   * retried without the user re-opening the camera.
   */
  start(video: HTMLVideoElement, onDecode: (text: string) => void): Promise<void>;
  /** Stops scanning and releases the camera stream/track. Idempotent — safe to call when not started
   * (e.g. from a component's `onDestroy` regardless of whether scanning was ever begun). */
  stop(): void;
}

/**
 * Real implementation: `getUserMedia` → `<video>` → per-frame `<canvas>` capture → `jsQR`. Never
 * touched by this task's own test suite (see module doc) — component tests inject a fake
 * {@link QrScanner} instead.
 */
export class MediaDevicesQrScanner implements QrScanner {
  private stream: MediaStream | null = null;
  private rafHandle: number | null = null;
  private canvas: HTMLCanvasElement | null = null;
  private stopped = false;

  async start(video: HTMLVideoElement, onDecode: (text: string) => void): Promise<void> {
    this.stopped = false;
    this.stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment" },
      audio: false,
    });
    video.srcObject = this.stream;
    await video.play();

    this.canvas = document.createElement("canvas");
    const ctx = this.canvas.getContext("2d", { willReadFrequently: true });

    const tick = (): void => {
      if (this.stopped || !this.stream || !ctx || !this.canvas) return;
      if (video.readyState >= video.HAVE_ENOUGH_DATA && video.videoWidth > 0) {
        this.canvas.width = video.videoWidth;
        this.canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, this.canvas.width, this.canvas.height);
        const frame = ctx.getImageData(0, 0, this.canvas.width, this.canvas.height);
        const result = decodeFrame(frame.data, frame.width, frame.height);
        if (result.kind === "decoded") {
          onDecode(result.text);
        }
      }
      this.rafHandle = requestAnimationFrame(tick);
    };
    this.rafHandle = requestAnimationFrame(tick);
  }

  stop(): void {
    this.stopped = true;
    if (this.rafHandle !== null) {
      cancelAnimationFrame(this.rafHandle);
      this.rafHandle = null;
    }
    if (this.stream) {
      for (const track of this.stream.getTracks()) track.stop();
      this.stream = null;
    }
  }
}

/** Isolated so a future test could exercise it against a synthetic `ImageData` without a real camera
 * — not exercised by this task (no synthetic-frame fixture exists yet), but kept as a pure,
 * side-effect-free function rather than inlined so that remains possible later. */
export function decodeFrame(data: Uint8ClampedArray, width: number, height: number): QrScanOutcome {
  const code = jsQR(data, width, height);
  if (!code || !code.data) return { kind: "no-code" };
  return { kind: "decoded", text: code.data };
}
