/**
 * View-model for the account-creation flow. All key generation happens inside the adapter (core);
 * this only collects the advisory hint and the protection choice and hands them over.
 *
 * The passphrase is the one secret that passes through here. It is held only in `passphrase` /
 * `confirm`, never rendered, logged, or copied elsewhere, and both fields are cleared in a
 * `finally` as soon as the adapter call settles (success or failure). JS strings cannot be
 * zeroised, so this limits the *retained state*, not memory the engine may still hold.
 */
import type { AccountSummary, KeyProtection, MeridianClientAdapter } from '../adapter';
import { describeError } from './copy';
import { notify } from './safe-call';

export type ProtectionChoice = 'platform' | 'passphrase';

export class AccountCreateViewModel {
  hint = $state('');
  protection = $state<ProtectionChoice>('platform');
  passphrase = $state('');
  confirm = $state('');
  busy = $state(false);
  error = $state<string | null>(null);

  constructor(
    private readonly adapter: MeridianClientAdapter,
    private readonly onCreated?: (account: AccountSummary) => void
  ) {}

  /** Wipe the secret-bearing state. Also called on teardown. */
  clearSecrets(): void {
    this.passphrase = '';
    this.confirm = '';
  }

  async submit(): Promise<AccountSummary | null> {
    if (this.busy) return null;
    let protection: KeyProtection;
    if (this.protection === 'passphrase') {
      if (this.passphrase === '') {
        this.error = 'Enter a passphrase, or choose device protection.';
        return null;
      }
      if (this.passphrase !== this.confirm) {
        this.error = 'The passphrases do not match.';
        this.clearSecrets();
        return null;
      }
      protection = { kind: 'passphrase', passphrase: this.passphrase };
    } else {
      protection = { kind: 'platform' };
    }

    this.busy = true;
    this.error = null;
    let account: AccountSummary;
    try {
      account = await this.adapter.generateAccount(this.hint.trim(), protection);
    } catch (e) {
      this.error = describeError(e, 'create-account');
      return null;
    } finally {
      // Clear on every outcome; `protection` (the only other reference) goes out of scope here.
      this.clearSecrets();
      this.busy = false;
    }
    // Outside the try: the account exists, so a throwing shell callback is not a creation failure.
    notify(this.onCreated, account);
    return account;
  }
}
