/**
 * Fixed, UI-authored copy for adapter failures. Screens never render `MeridianAdapterError.message`
 * (or any other thrown value): the code is mapped to a fixed string here, so an adapter bug or a
 * hostile peer-influenced error string can never reach the DOM. Core's *send-gate reason* is the one
 * piece of core-authored text the UI shows, and it is rendered verbatim by `Chat.svelte`, not here.
 *
 * Honest scope: no copy in this module says "anonymous" or promises delivery (anonymity model).
 */
import { MeridianAdapterError, type AdapterErrorCode } from '../adapter';

export type ErrorContext =
  | 'create-account'
  | 'add-contact'
  | 'send'
  | 'load'
  | 'request'
  | 'verify'
  | 'acknowledge'
  | 'block';

export function adapterErrorCode(error: unknown): AdapterErrorCode | null {
  return error instanceof MeridianAdapterError ? error.code : null;
}

const GENERIC: Record<ErrorContext, string> = {
  'create-account': 'Could not create the account. Please try again.',
  'add-contact': 'Could not add that contact. Please try again.',
  send: 'Message not sent. Please try again.',
  load: 'Could not load this view. Please try again.',
  request: 'Could not complete that action. Please try again.',
  verify: 'Could not mark this contact as verified. Nothing was changed. Please try again.',
  acknowledge: 'Could not acknowledge the key change. Nothing was changed. Please try again.',
  block: 'Could not update the block. Nothing was changed. Please try again.'
};

export function describeError(error: unknown, context: ErrorContext): string {
  switch (adapterErrorCode(error)) {
    case 'invalid-id':
      return 'That is not a valid Meridian ID. Check it and try again.';
    case 'send-blocked':
      return 'Message not sent: sending to this contact is blocked.';
    case 'not-found':
      return 'That request is no longer pending.';
    case 'unknown-contact':
      return 'That contact no longer exists.';
    case 'not-acknowledgeable':
      return 'This key change cannot be acknowledged. Verify the safety number instead.';
    case 'locked':
      return 'The account is locked. Unlock it and try again.';
    case 'no-account':
      return 'There is no account yet. Create one first.';
    default:
      return GENERIC[context];
  }
}

/**
 * Fixed copy for the verification screen (task 12.8). Wording mirrors the terminal client's
 * verification flow (apps/cli/src/verify.rs, apps/tui/src/screens/verify.rs) and preserves
 * verification-ux.md's canonical intent: never reassurance, never "verify anyway". Core's send-gate
 * `reason` is NOT here; it is rendered verbatim from the adapter.
 */
export const VERIFY_COPY = {
  compareHint:
    'Compare this number and QR code with the other person out-of-band: in person, over an ' +
    'existing trusted channel, or on a video call. Never confirm over the channel you are trying ' +
    'to verify.',
  matched: 'MATCH: the scanned code is identical to this safety number.',
  /** CLI `scan_and_compare` MISMATCH wording, minus the peer id. */
  mismatch:
    'MISMATCH: the scanned code does not match the safety number computed locally for this ' +
    'contact. This can mean a stale/wrong scan, or that someone is intercepting your messages. ' +
    'Do not mark this contact verified; re-check the code with them directly through a channel ' +
    'you trust.',
  notSafetyNumber:
    'That QR code is not a complete safety number. Keep scanning, or ask them to show their ' +
    'safety number QR code.',
  /** TUI `Confirm(Verify)` prompt. */
  confirmPrompt:
    'Did both sides see the identical safety number/QR, compared out-of-band? Only confirm if ' +
    'they genuinely matched.',
  /** TUI `Confirm(Acknowledge)` prompt. */
  acknowledgePrompt:
    'Acknowledge without verifying? This re-pins the new key but does not confirm it is ' +
    'genuinely theirs. Verify instead if anything you are about to send is sensitive.',
  verified: 'Safety number confirmed. This contact is marked as verified.',
  acknowledged: 'Key change acknowledged. The contact is NOT verified.',
  numberUnavailable:
    'Could not get the safety number for this contact. Verification is unavailable until it loads.',
  qrUnavailable: 'The QR code could not be drawn. Compare the digits instead.',
  staleNumber:
    'The safety number changed while you were comparing. Nothing was marked verified. Compare the ' +
    'new number again.',
  gateUnavailable: 'Could not check whether sending is allowed.',
  scanFailure: {
    'permission-denied':
      'Camera access was denied. You can still compare the digits by reading them aloud.',
    'no-camera': 'No camera was found. You can still compare the digits by reading them aloud.',
    unavailable: 'The camera is not available. You can still compare the digits by reading them aloud.'
  }
} as const;
