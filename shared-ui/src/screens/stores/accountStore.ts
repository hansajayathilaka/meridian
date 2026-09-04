/**
 * View-model store backing {@link ../CreateAccount.svelte}. Thin wrapper over
 * `MeridianClientAdapter.generateAccount` — the account-creation flow named in this task's Scope
 * ("account creation flow") but not listed as its own file in the Deliverables list; folded into
 * a small dedicated `CreateAccount.svelte` + this store rather than into `Contacts.svelte`, since
 * it is a distinct pre-onboarding step (no account ⇒ no contacts/chat to show yet) — see this
 * task's final report for the documented reasoning.
 */

import { writable, type Readable } from "svelte/store";

import type { MeridianClientAdapter, MeridianId } from "../../lib/adapter";
import { errorMessage } from "./errors";

export interface CreateAccountState {
  status: "idle" | "creating" | "done" | "error";
  accountId: MeridianId | null;
  error: string | null;
}

export interface CreateAccountStore extends Readable<CreateAccountState> {
  /** Generates a fresh account with the given routing `hint` (`MeridianClientAdapter.generateAccount`). */
  createAccount(hint: string): Promise<MeridianId>;
}

const initialState: CreateAccountState = { status: "idle", accountId: null, error: null };

export function createAccountStore(adapter: MeridianClientAdapter): CreateAccountStore {
  const { subscribe, set } = writable<CreateAccountState>({ ...initialState });

  async function createAccount(hint: string): Promise<MeridianId> {
    set({ status: "creating", accountId: null, error: null });
    try {
      const id = await adapter.generateAccount(hint.trim());
      set({ status: "done", accountId: id, error: null });
      return id;
    } catch (err) {
      set({ status: "error", accountId: null, error: errorMessage(err) });
      throw err;
    }
  }

  return { subscribe, createAccount };
}
