/**
 * Pure presentation helpers for the file-transfer screen (task 12.9). Everything here maps
 * adapter-reported values onto display strings; nothing computes integrity, trust, or protocol
 * values, and nothing builds a path, URL, or href from a wire-supplied string.
 */
import type { TransferInfo } from '../adapter';
import { FILE_COPY } from './copy';

/** Default display cap for wire-supplied names (file systems cap a name at 255 bytes). */
export const MAX_NAME_DISPLAY = 256;
export const MAX_REASON_DISPLAY = 200;

/**
 * Characters that must never reach the DOM raw in a wire-supplied string: C0/C1 controls (incl.
 * newlines and DEL), Unicode bidi controls (the "RTL override" trick that makes `gpj.exe` read as
 * `exe.jpg`), line/paragraph separators, zero-width / invisible formatting characters, BOM, and
 * invisible or blank-looking spoofing characters (soft hyphen, combining grapheme joiner, Hangul
 * fillers, Khmer inherent vowels, variation selectors, interlinear annotation marks, braille blank,
 * tag characters), plus lone surrogates.
 */
/* eslint-disable no-misleading-character-class -- each code point is listed on purpose (combining/invisible ones included) */
const UNSAFE_DISPLAY = new RegExp(
  '[' +
    '\\u0000-\\u001f\\u007f-\\u009f\\u00ad\\u034f\\u061c\\u115f\\u1160\\u17b4\\u17b5\\u180e' +
    '\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u206f\\u2800\\u3164' +
    '\\ufe00-\\ufe0f\\ufeff\\uffa0\\ufff9-\\ufffb' +
    '\\u{e0000}-\\u{e007f}\\u{e0100}-\\u{e01ef}\\ud800-\\udfff' +
    ']',
  'gu'
);
/* eslint-enable no-misleading-character-class */

function escapeUnsafe(text: string): string {
  return text.replace(
    UNSAFE_DISPLAY,
    (ch) => `[U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}]`
  );
}

/**
 * Make a wire-supplied string safe to *show*: invisible/reordering characters are replaced by a
 * visible `[U+XXXX]` marker (so the user can see something odd is there), and the result is capped
 * at `max` code points of the *input*. When truncating, the head and the tail are kept
 * (`head…tail`, at most 32 tail code points) so a file extension is never hidden. Truncation happens
 * BEFORE the replacement, so the work is bounded by `max` however long the input is. The output is
 * for text nodes only; it is lossy by design and must never be used as a file name, path, or URL.
 */
export function displayText(raw: string, max: number = MAX_NAME_DISPLAY): string {
  const text = String(raw);
  const tailLen = Math.min(32, Math.floor(max / 4));
  // More than 2*max UTF-16 units is certainly more than max code points: no need to scan it all.
  if (text.length <= 2 * max) {
    const points = Array.from(text);
    if (points.length <= max) return escapeUnsafe(text);
  }
  const headRaw = Array.from(text.slice(0, 2 * max)).slice(0, max - tailLen - 1);
  const tailRaw = tailLen > 0 ? Array.from(text.slice(-2 * tailLen)).slice(-tailLen) : [];
  return `${escapeUnsafe(headRaw.join(''))}…${escapeUnsafe(tailRaw.join(''))}`;
}

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'] as const;

/** Human byte count (binary units). Anything that is not a finite non-negative number is "unknown". */
export function formatBytes(n: number): string {
  if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) return FILE_COPY.unknownSize;
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return unit === 0 ? `${Math.floor(value)} B` : `${value.toFixed(1)} ${UNITS[unit]}`;
}

/** State wording: only what the adapter's own `status` literally says. */
export function transferStatusLabel(t: Pick<TransferInfo, 'status' | 'direction'>): string {
  switch (t.status) {
    case 'in-progress':
      if (t.direction === 'send') return 'Sending';
      if (t.direction === 'receive') return 'Receiving';
      return 'In progress'; // an unknown direction is not assumed to be either
    case 'completed':
      return 'Transfer complete';
    case 'stalled':
      return 'Stalled';
    case 'failed':
      return 'Failed';
    default:
      return 'Unknown state'; // an adapter outside the union must not render as success
  }
}

/** Direction wording; anything outside the union is neutral, never assumed to be incoming. */
export function transferDirectionLabel(direction: TransferInfo['direction']): string {
  if (direction === 'send') return 'Outgoing';
  if (direction === 'receive') return 'Incoming';
  return 'Unknown direction';
}

/** "x of y" as reported. Never a percentage. */
export function transferBytesLabel(t: Pick<TransferInfo, 'bytesDone' | 'totalBytes'>): string {
  return `${formatBytes(t.bytesDone)} of ${formatBytes(t.totalBytes)}`;
}

/**
 * Values for a `<progress>` element, only when both numbers are sane. `value` is clamped to
 * `[0, max]`; `null` means "show no bar" (never a made-up one).
 */
export function progressBar(
  t: Pick<TransferInfo, 'bytesDone' | 'totalBytes'>
): { readonly value: number; readonly max: number } | null {
  const { bytesDone, totalBytes } = t;
  if (!Number.isFinite(bytesDone) || !Number.isFinite(totalBytes)) return null;
  if (totalBytes <= 0 || bytesDone < 0) return null;
  return { value: Math.min(bytesDone, totalBytes), max: totalBytes };
}
