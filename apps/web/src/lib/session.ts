/**
 * The app shell's one `WasmMeridianClientAdapter` instance (task 12.13), plus a small reactive
 * mirror of `currentAccount()` every route reads to decide whether to render the protected app
 * area or bounce back to onboarding (`src/routes/+page.svelte`). Deliberately thin: this file adds
 * **no** protocol/session logic of its own — it only tracks the one thing the adapter interface
 * itself doesn't expose reactively (`currentAccount()` is a plain synchronous getter, not a
 * subscribable store), mirroring account-open/close events back into a Svelte store so
 * `src/routes/(app)/+layout.svelte`'s guard re-renders correctly instead of polling.
 *
 * A single module-scoped instance (not one per component) is deliberate: every route needs to
 * observe the *same* signed-in account, and `MeridianClientAdapter`'s own contract
 * (`shared-ui/src/lib/adapter.ts`) assumes one adapter instance per running client, exactly like
 * `apps/desktop/ui`'s own equivalent Tauri-command adapter singleton.
 */

import { writable, type Readable } from "svelte/store";

import type { MeridianId } from "shared-ui";
import { WasmMeridianClientAdapter } from "./adapter";

export const adapter = new WasmMeridianClientAdapter();

const accountId = writable<MeridianId | null>(adapter.currentAccount());

/** The signed-in account id, or `null` before onboarding / after sign-out. */
export const currentAccountId: Readable<MeridianId | null> = accountId;

/** Called by `routes/+page.svelte`'s `CreateAccount.onCreated` once `generateAccount` succeeds. */
export function noteAccountCreated(id: MeridianId): void {
  accountId.set(id);
}

/** Closes the current account (`MeridianClientAdapter.closeAccount`) and clears the local mirror —
 * the shell's own "sign out" action (`routes/(app)/+layout.svelte`). */
export async function signOut(): Promise<void> {
  await adapter.closeAccount();
  accountId.set(null);
}
