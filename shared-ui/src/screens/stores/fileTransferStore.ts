/**
 * View-model store backing {@link ../FileTransfer.svelte} (task 12.9) — drag-drop/file-picker send,
 * a progress display, and the receive/accept-reject prompt for `mrd.file/1`, wired purely through
 * `MeridianClientAdapter.sendFile`/`listTransfers`/`acceptTransfer`/`rejectTransfer`. No protocol
 * logic here; this only reshapes what the adapter already reports.
 *
 * **Known interface-coverage note (mirrors `messageRequestsStore.ts`'s own "flagged, not silently
 * worked around" shape):** `MeridianClientAdapter` has no live push subscription for transfer
 * progress or new incoming offers — `listTransfers()` is a point-in-time snapshot, `sendFile`
 * resolves once the transfer is *opened*, not once it completes (see that method's own doc comment
 * in `adapter.ts`). This store therefore never assumes progress advances on its own: {@link
 * FileTransferStore.refresh} is the only thing that pulls a fresh snapshot, and the screen calls it
 * explicitly (on mount, after every send/accept/reject, and via a visible "Refresh" control) —
 * exactly `contactsStore.ts`'s existing explicit-refresh shape, not a timer/poll loop this package
 * has no precedent for.
 *
 * **Never overclaims corruption-detection.** `state === "complete"` is rendered/reported exactly as
 * `FileTransferSummary`'s own doc comment scopes it — transport-level completion, never "verified"
 * or "corruption-free" (the 11.8 residual this task's Scope→Out note inherits as-is). This store
 * does not invent a stronger signal than what `listTransfers()` actually returned.
 */

import { writable, type Readable } from "svelte/store";

import type {
  FileTransferSummary,
  MeridianClientAdapter,
  MeridianId,
  StreamHandle,
} from "../../lib/adapter";
import { errorMessage } from "./errors";

export interface FileTransferState {
  transfers: FileTransferSummary[];
  loading: boolean;
  /** Set while a drag-drop/file-picker send is in flight. */
  sending: boolean;
  /** The `streamId` currently being accepted/rejected, if any — disables just that row's actions. */
  busy: StreamHandle | null;
  error: string | null;
}

export interface FileTransferStore extends Readable<FileTransferState> {
  /** (Re)loads the transfer list from the adapter. */
  refresh(): Promise<void>;
  /** Sends `file` to `peer` (`adapter.sendFile`) and refreshes the list. */
  send(peer: MeridianId, file: Blob, fileName: string): Promise<void>;
  /** Accepts a pending incoming transfer (`state === "offered"`) and refreshes the list. */
  accept(streamId: StreamHandle): Promise<void>;
  /** Rejects a pending incoming transfer and refreshes the list. */
  reject(streamId: StreamHandle): Promise<void>;
}

const initialState: FileTransferState = {
  transfers: [],
  loading: false,
  sending: false,
  busy: null,
  error: null,
};

export function createFileTransferStore(adapter: MeridianClientAdapter): FileTransferStore {
  const { subscribe, update } = writable<FileTransferState>({ ...initialState });

  async function refresh(): Promise<void> {
    update((s) => ({ ...s, loading: true, error: null }));
    try {
      const transfers = await adapter.listTransfers();
      update((s) => ({ ...s, transfers, loading: false }));
    } catch (err) {
      update((s) => ({ ...s, loading: false, error: errorMessage(err) }));
    }
  }

  async function send(peer: MeridianId, file: Blob, fileName: string): Promise<void> {
    update((s) => ({ ...s, sending: true, error: null }));
    try {
      await adapter.sendFile(peer, file, fileName);
      update((s) => ({ ...s, sending: false }));
      await refresh();
    } catch (err) {
      update((s) => ({ ...s, sending: false, error: errorMessage(err) }));
      throw err;
    }
  }

  async function accept(streamId: StreamHandle): Promise<void> {
    update((s) => ({ ...s, busy: streamId, error: null }));
    try {
      await adapter.acceptTransfer(streamId);
      update((s) => ({ ...s, busy: null }));
      await refresh();
    } catch (err) {
      update((s) => ({ ...s, busy: null, error: errorMessage(err) }));
      throw err;
    }
  }

  async function reject(streamId: StreamHandle): Promise<void> {
    update((s) => ({ ...s, busy: streamId, error: null }));
    try {
      await adapter.rejectTransfer(streamId);
      update((s) => ({ ...s, busy: null }));
      await refresh();
    } catch (err) {
      update((s) => ({ ...s, busy: null, error: errorMessage(err) }));
      throw err;
    }
  }

  return { subscribe, refresh, send, accept, reject };
}

/**
 * Percent complete for a transfer's progress bar — pure display math, same zero-guard shape as
 * `apps/tui/src/streams/file.rs::TransferEntry::percent`. `state === "complete"` always reports
 * 100 regardless of the raw byte counters (mirrors that same precedent), everything else derives
 * from `transferredBytes`/`totalBytes` directly, clamped, never dividing by zero.
 */
export function transferPercent(t: Pick<FileTransferSummary, "state" | "transferredBytes" | "totalBytes">): number {
  if (t.state === "complete") return 100;
  if (t.totalBytes <= 0) return 0;
  const done = Math.min(t.transferredBytes, t.totalBytes);
  return Math.round((done / t.totalBytes) * 100);
}

/** Human-facing label for a transfer's state — never stronger than what `FileTransferSummary.state`
 * itself reports (see this module's own doc comment on not overclaiming corruption detection). */
export function transferStateLabel(state: FileTransferSummary["state"]): string {
  switch (state) {
    case "offered":
      return "Awaiting your decision";
    case "in_progress":
      return "In progress";
    case "paused":
      return "Paused";
    case "complete":
      return "Complete";
    case "failed":
      return "Failed";
    case "rejected":
      return "Rejected";
  }
}
