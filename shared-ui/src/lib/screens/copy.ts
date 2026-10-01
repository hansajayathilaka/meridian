/**
 * Fixed, UI-authored copy for adapter failures. Screens never render `MeridianAdapterError.message`
 * (or any other thrown value): the code is mapped to a fixed string here, so an adapter bug or a
 * hostile peer-influenced error string can never reach the DOM. Core's *send-gate reason* is the one
 * piece of core-authored text the UI shows, and it is rendered verbatim by `Chat.svelte`, not here.
 *
 * Honest scope: no copy in this module says "anonymous" or promises delivery (anonymity model).
 */
import { MeridianAdapterError, type AdapterErrorCode } from '../adapter';

export type ErrorContext = 'create-account' | 'add-contact' | 'send' | 'load' | 'request';

export function adapterErrorCode(error: unknown): AdapterErrorCode | null {
  return error instanceof MeridianAdapterError ? error.code : null;
}

const GENERIC: Record<ErrorContext, string> = {
  'create-account': 'Could not create the account. Please try again.',
  'add-contact': 'Could not add that contact. Please try again.',
  send: 'Message not sent. Please try again.',
  load: 'Could not load this view. Please try again.',
  request: 'Could not complete that action. Please try again.'
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
    case 'locked':
      return 'The account is locked. Unlock it and try again.';
    case 'no-account':
      return 'There is no account yet. Create one first.';
    default:
      return GENERIC[context];
  }
}
