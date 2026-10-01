/**
 * Pure, framework-free view helpers shared by the Svelte primitives (and any future React view
 * layer — ADR 0012). Presentation only: nothing here computes trust, identity, or protocol values;
 * it only maps values core already produced onto display strings.
 */
import type { ConnectionState, ContactSummary, MessageState, TrustState } from './adapter';

/**
 * The label to show for a contact: explicit petname, else the advisory hint, else the short
 * fingerprint. Mirrors the TUI's `ContactEntry::display_label`. The petname is user-entered only;
 * this function never derives one from an ID.
 */
export function contactDisplayLabel(
  contact: Pick<ContactSummary, 'petname' | 'hint' | 'fingerprint'>
): string {
  if (contact.petname !== null && contact.petname !== '') return contact.petname;
  if (contact.hint !== '') return contact.hint;
  return contact.fingerprint;
}

/**
 * Plain-language trust label. Deliberately never reads as reassurance for an unverified contact:
 * `pinned` is "unverified", not "trusted" (verification-ux.md; "anonymity" is scoped — we never
 * overclaim). Full canonical key-change warning text comes from core's send gate, not from here.
 */
export function trustLabel(state: TrustState, userBlocked = false): string {
  if (userBlocked) return 'blocked by you';
  switch (state) {
    case 'new':
      return 'new';
    case 'pinned':
      return 'unverified';
    case 'verified':
      return 'verified';
    case 'blocked':
      return 'key changed: sending blocked';
    case 'pinned-key-changed':
      return 'key changed: warning';
  }
}

/** Delivery-state marker for a message row. Never renders a "delivered" tick for anything else. */
export function messageStateLabel(state: MessageState): string {
  switch (state) {
    case 'composing':
      return 'preparing';
    case 'pending':
      return 'pending';
    case 'sent':
      return 'sent';
    case 'delivered':
      return 'delivered';
    case 'failed':
      return 'failed';
    case 'received':
      return '';
  }
}

/** Status-bar wording for the persistent connection (tui-client.md §7 `reconnecting (n/m)`). */
export function connectionLabel(state: ConnectionState): string {
  switch (state.kind) {
    case 'disconnected':
      return 'disconnected';
    case 'connecting':
      return 'connecting';
    case 'connected':
      return 'connected';
    case 'reconnecting':
      return `reconnecting (${state.attempt}/${state.max})`;
  }
}
