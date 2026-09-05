/**
 * The app shell's one {@link TauriMeridianClientAdapter} instance (task 12.6), plus a small
 * reactive mirror of `currentAccount()` `App.svelte` reads to decide whether to render the
 * protected app area or the onboarding (`CreateAccount`) screen — mirrors `apps/web/src/lib/
 * session.ts` (task 12.14) field-for-field, same reasoning: `MeridianClientAdapter.
 * currentAccount()` is a plain synchronous getter, not a subscribable store, so this file is the
 * one place that gap gets bridged into a Svelte store the rest of the shell can react to.
 *
 * A single module-scoped instance (not one per component) is deliberate, for the identical reason
 * `apps/web/src/lib/session.ts`'s own doc comment gives: every view needs to observe the *same*
 * signed-in account, and `MeridianClientAdapter`'s own contract assumes one adapter instance per
 * running client.
 */

import { writable, type Readable } from "svelte/store";

import type { MeridianId } from "shared-ui";
import { TauriMeridianClientAdapter } from "./adapter";

/**
 * The rendezvous server this shell dials through `TauriMeridianClientAdapter`'s own
 * `rendezvousServer` option (see that type's doc comment in `adapter.ts` for why it is
 * adapter-level configuration rather than a per-call argument). Matches `apps/cli`'s and
 * `apps/web`'s own local-dev default (`ws://127.0.0.1:8443` — `apps/cli/src/main.rs`'s
 * `--rendezvous` default, `apps/web/svelte.config.js`'s CSP `connect-src` entry).
 *
 * TODO: confirm — no design doc specifies a settings/preferences UI for a desktop user to point
 * this shell at a different (e.g. their own org's) rendezvous server; a fixed local-dev default is
 * what every sibling client in this repo ships today, so this shell does the same rather than
 * inventing a settings screen out of scope for this task.
 */
const DEFAULT_RENDEZVOUS_SERVER = "ws://127.0.0.1:8443";

export const adapter = new TauriMeridianClientAdapter({
  rendezvousServer: DEFAULT_RENDEZVOUS_SERVER,
});

const accountId = writable<MeridianId | null>(null);

/** The signed-in account id, or `null` before onboarding / after sign-out. */
export const currentAccountId: Readable<MeridianId | null> = accountId;

// `adapter.ready` resolves once the adapter's base event subscriptions are attached *and* its
// best-effort `account_get` priming call has returned (see `adapter.ts`'s own `ready`/`init` doc
// comments) — only after that does `adapter.currentAccount()` reliably reflect an
// already-onboarded account picked up on this launch. Reading it any earlier would race the
// priming call and could show the onboarding screen for one already-signed-in launch.
void adapter.ready.then(() => {
  accountId.set(adapter.currentAccount());
});

/** Called by `App.svelte`'s `CreateAccount.onCreated` once `generateAccount` succeeds. */
export function noteAccountCreated(id: MeridianId): void {
  accountId.set(id);
}

/** Closes the current account (`MeridianClientAdapter.closeAccount`) and clears the local mirror —
 * the shell's own "sign out" action (`App.svelte`, wired to both the header button and the native
 * "Sign Out" menu item, `../src/main.rs::menu_ids::SIGN_OUT`). */
export async function signOut(): Promise<void> {
  await adapter.closeAccount();
  accountId.set(null);
}
