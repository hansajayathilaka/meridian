/**
 * View-model store backing {@link ../Verification.svelte} — the browser/desktop equivalent of the
 * terminal client's safety-number verification screen (task 4.22, `apps/tui/src/screens/verify.rs`).
 * This is the phase's own safety-critical D06 surface: a false-positive {@link MeridianClientAdapter.markVerified}
 * call here is exactly the failure the terminal client's own screen was built to make structurally
 * hard, and is this task's own explicitly named risk.
 *
 * ## The state machine, and why it can never produce a false-positive `markVerified`
 * `compareSafetyNumbers` (below) is the ONLY function in this file allowed to decide whether a scan
 * "matches" — it is a pure function of two strings, exported and independently unit-tested against
 * the real T08 safety-number conformance fixtures (`test-vectors/safety-numbers-v1.json`) rather than
 * invented values, per this task's Deliverables. Its contract:
 *   - Anything that is not *exactly* 60 ASCII digits (wrong length, non-digit characters, empty
 *     string, whitespace-mangled, ...) is `"invalid"` — never coerced, truncated, or padded into a
 *     comparable shape. A partial/garbled QR frame decoding to e.g. `"123"` or `"88446863420591404"`
 *     (a truncated read) is `"invalid"`, not a candidate mismatch or a lucky prefix match.
 *   - Only two full, well-formed 60-digit strings are ever compared, and only with `===` (exact
 *     string equality — no fuzzy/edit-distance/prefix logic anywhere in this file or its caller).
 *   - `"match"` is the only outcome from which {@link VerificationStore.confirmVerified} is callable
 *     at all — {@link confirmVerified} throws for every other state (`"mismatch"`, `"invalid"`, or no
 *     scan yet), so there is no code path from a decode error to a `markVerified` call. See that
 *     function's own guard.
 * `Verification.svelte` never re-derives or bypasses this comparison — it only renders whatever
 * `$store.scanResult.kind` already says, exactly like `chatStore`'s send-gate rendering never
 * re-derives `SendGateState`.
 */

import { writable, type Readable } from "svelte/store";

import type { MeridianClientAdapter, MeridianId, SafetyNumber } from "../../lib/adapter";
import { errorMessage } from "./errors";

/** A 60-digit safety number, per `meridian_core::crypto::safety_number` (see `SafetyNumber.raw`'s
 * own doc comment in `adapter.ts`) — never any other length, ever coerced to fit. */
const SAFETY_NUMBER_LENGTH = 60;
const SAFETY_NUMBER_PATTERN = /^[0-9]{60}$/;

export type ScanComparison =
  | { kind: "match" }
  | { kind: "mismatch" }
  | { kind: "invalid"; reason: string };

/**
 * Pure, exact-match-or-nothing comparison between the locally computed safety number and whatever a
 * QR decode produced. See this module's own doc comment for the full "no false positive" contract.
 * Exported (and the primary thing this task's own component tests exercise) precisely so it can be
 * unit-tested in complete isolation from any camera/DOM/adapter concern.
 */
export function compareSafetyNumbers(local: string, scanned: string): ScanComparison {
  // Defensive: `local` always comes from `adapter.safetyNumber(peer).raw`, which should always be
  // well-formed — but a malformed local value must never be silently treated as a valid comparison
  // basis (that would risk an accidental match against equally-malformed scanned data).
  if (!SAFETY_NUMBER_PATTERN.test(local)) {
    return { kind: "invalid", reason: "local safety number is not a well-formed 60-digit number" };
  }

  // Deliberately only `.trim()` (whitespace a QR/camera pipeline can incidentally introduce, e.g. a
  // trailing newline some encoders add) — never any transformation that could turn a malformed scan
  // into a well-formed one (no stripping of interior characters, no truncation, no padding).
  const scannedTrimmed = scanned.trim();

  if (scannedTrimmed.length !== SAFETY_NUMBER_LENGTH) {
    return {
      kind: "invalid",
      reason: `scanned code is ${scannedTrimmed.length} characters, expected exactly ${SAFETY_NUMBER_LENGTH} digits — a partial or garbled scan is never treated as a match`,
    };
  }
  if (!SAFETY_NUMBER_PATTERN.test(scannedTrimmed)) {
    return {
      kind: "invalid",
      reason: "scanned code is not purely numeric — this does not look like a safety number",
    };
  }

  return scannedTrimmed === local ? { kind: "match" } : { kind: "mismatch" };
}

export interface VerificationState {
  peer: MeridianId | null;
  loading: boolean;
  /** This device's own view of the (order-independent) safety number for `peer`. Rendered as both
   * text and a QR code for the peer to scan; never itself the thing compared against a scan without
   * going through {@link compareSafetyNumbers}. */
  localSafetyNumber: SafetyNumber | null;
  /** Whether `peer` is already `trust === "verified"` (loaded once up front, purely informational —
   * this screen never trusts a cached value over a fresh {@link confirmVerified} outcome). */
  alreadyVerified: boolean;
  scanning: boolean;
  cameraError: string | null;
  /** The most recent scan's outcome, or `null` before any scan/decode has happened. Cleared by
   * {@link startScan} so a new scan attempt never shows a stale prior result. */
  scanResult: ScanComparison | null;
  verifying: boolean;
  /** Set only after {@link MeridianClientAdapter.markVerified} has actually resolved — never
   * optimistically set on a mere `"match"` scan result. */
  verified: boolean;
  error: string | null;
}

export interface VerificationStore extends Readable<VerificationState> {
  /** Loads `peer`'s current safety number + trust state. */
  load(peer: MeridianId): Promise<void>;
  /** Marks scanning as in progress and clears any prior scan result — call before starting the
   * camera. */
  beginScan(): void;
  /** Records a camera/permission error, ending the scanning state. */
  reportCameraError(message: string): void;
  /**
   * Handles one decoded QR payload: runs it through {@link compareSafetyNumbers} against the
   * currently loaded local safety number and records the outcome. This is the ONLY place a scanned
   * string enters this store's state — there is no other setter for `scanResult`.
   */
  handleScan(decodedText: string): void;
  /**
   * Calls `markVerified` for the currently loaded peer. Throws (and never calls the adapter) unless
   * `scanResult.kind === "match"` right now — the safety-critical guard this whole module exists
   * for. Re-checked against the store's own current state at call time, not a value the caller
   * cached earlier, so a state change between render and click can't slip through.
   */
  confirmVerified(): Promise<void>;
}

const initialState: VerificationState = {
  peer: null,
  loading: false,
  localSafetyNumber: null,
  alreadyVerified: false,
  scanning: false,
  cameraError: null,
  scanResult: null,
  verifying: false,
  verified: false,
  error: null,
};

export function createVerificationStore(adapter: MeridianClientAdapter): VerificationStore {
  const { subscribe, update, set } = writable<VerificationState>({ ...initialState });
  let currentPeer: MeridianId | null = null;

  async function load(peer: MeridianId): Promise<void> {
    currentPeer = peer;
    set({ ...initialState, peer, loading: true });
    try {
      const [localSafetyNumber, trust] = await Promise.all([
        adapter.safetyNumber(peer),
        adapter.trustState(peer),
      ]);
      if (currentPeer === peer) {
        update((s) =>
          s.peer === peer
            ? { ...s, localSafetyNumber, alreadyVerified: trust === "verified", loading: false }
            : s,
        );
      }
    } catch (err) {
      if (currentPeer === peer) {
        update((s) => (s.peer === peer ? { ...s, loading: false, error: errorMessage(err) } : s));
      }
    }
  }

  function beginScan(): void {
    update((s) => ({ ...s, scanning: true, cameraError: null, scanResult: null }));
  }

  function reportCameraError(message: string): void {
    update((s) => ({ ...s, scanning: false, cameraError: message }));
  }

  function handleScan(decodedText: string): void {
    update((s) => {
      if (!s.localSafetyNumber) return s;
      const result = compareSafetyNumbers(s.localSafetyNumber.raw, decodedText);
      return { ...s, scanning: false, scanResult: result };
    });
  }

  async function confirmVerified(): Promise<void> {
    const peer = currentPeer;
    if (!peer) {
      throw new Error("no verification is in progress");
    }

    // Re-read the store's own live state at call time (never a value the caller captured earlier —
    // same defense-in-depth pattern as `chatStore.send`'s pre-send gate re-check) and hard-fail
    // unless it is exactly `"match"`. This is the single guard that makes a false-positive
    // `markVerified` call structurally unreachable from this store. `!s.verifying` additionally
    // makes this reentrancy-safe: two synchronous confirmVerified() calls before Svelte's reactive
    // DOM update disables the button can't both pass the guard and double-fire adapter.markVerified.
    let isMatch = false;
    update((s) => {
      isMatch = s.peer === peer && s.scanResult?.kind === "match" && !s.verifying;
      return isMatch ? { ...s, verifying: true, error: null } : s;
    });
    if (!isMatch) {
      throw new Error("cannot mark verified without a confirmed matching safety-number scan");
    }

    try {
      await adapter.markVerified(peer);
      if (currentPeer === peer) {
        update((s) => (s.peer === peer ? { ...s, verifying: false, verified: true } : s));
      }
    } catch (err) {
      if (currentPeer === peer) {
        update((s) => (s.peer === peer ? { ...s, verifying: false, error: errorMessage(err) } : s));
      }
      throw err;
    }
  }

  return { subscribe, load, beginScan, reportCameraError, handleScan, confirmVerified };
}
