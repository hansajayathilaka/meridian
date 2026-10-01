/**
 * `QrScanner` — the injectable camera-capture seam for the verification screen (task 12.8).
 *
 * The shared UI never touches `navigator.mediaDevices` itself: the shell (apps/web 12.14, desktop
 * 12.15) supplies a concrete scanner that opens the camera and hands back **grayscale frames**.
 * Tests supply a mock; the camera is never exercised in the shared-ui suite.
 *
 * ## What a scanner is NOT
 * - **No QR decoding.** A scanner only captures pixels (RGBA -> luma). Every frame is passed to
 *   `MeridianClientAdapter.decodeQr` (core's `decode_luma`); there is no QR or crypto logic in TS.
 * - **No verdicts.** A scanner never says "matched". Whether a decoded payload equals the safety
 *   number is decided by the view-model against the number the adapter returned for the peer.
 * - **No retention.** Frames are camera pixels of a screen/QR; the scanner must not persist, log, or
 *   transmit them, and must release the camera on `stop()`.
 */
import type { LumaImage } from './adapter';

/** Why the camera could not be used. Fixed vocabulary: the UI maps each to its own copy. */
export type QrScanFailure = 'permission-denied' | 'no-camera' | 'unavailable';

/** A scanner's `start` rejects with this to say why; any other rejection means `unavailable`. */
export class QrScannerError extends Error {
  readonly reason: QrScanFailure;

  constructor(reason: QrScanFailure) {
    super(reason);
    this.name = 'QrScannerError';
    this.reason = reason;
  }
}

export interface QrScanHandlers {
  /**
   * One captured frame. May be called at any rate; the screen drops frames while a decode is in
   * flight. Must not be called after the session's `stop()`.
   */
  onFrame(frame: LumaImage): void;
  /** The camera stream failed after it had started (device unplugged, permission revoked). */
  onError(reason: QrScanFailure): void;
}

export interface QrScanSession {
  /** Stop capturing and release the camera. Idempotent. */
  stop(): void;
}

export interface QrScanner {
  /**
   * Open the camera and begin delivering frames. Rejects (ideally with a {@link QrScannerError})
   * when the camera cannot be opened.
   */
  start(handlers: QrScanHandlers): Promise<QrScanSession>;
}
