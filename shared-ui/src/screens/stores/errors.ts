/**
 * Shared error-to-display-text helper for every screen store in this directory. Deliberately
 * narrow: only ever surfaces `Error#message` (which `MeridianAdapterError`'s own doc comment
 * guarantees is "human-readable and safe to display" — never plaintext content or a raw
 * identifier the anonymity model forbids) — never a raw thrown value verbatim, so an accidental
 * non-`Error` throw can't leak an unreviewed object shape into the DOM.
 */

import { MeridianAdapterError } from "../../lib/adapter";

export function errorMessage(err: unknown): string {
  if (err instanceof MeridianAdapterError) return err.message;
  if (err instanceof Error) return err.message;
  return "Something went wrong.";
}
