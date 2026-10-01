/**
 * Reusable contract suite for {@link MeridianClientAdapter} implementations.
 *
 * Every adapter — the in-memory `FakeMeridianClientAdapter` (here), the desktop Tauri adapter
 * (12.6) and the browser wasm adapter (12.13) — must pass this same suite, so the shared screens
 * (12.7-12.9) can rely on identical observable behaviour whichever backend they run on.
 *
 * Exposed only via the `shared-ui/contract-tests` subpath: it imports vitest and MUST NOT be
 * reachable from the production entry (`src/lib/index.ts`).
 *
 * A real backend cannot be told to "pretend a peer's key changed" or "pretend a message request
 * arrived", so those moments are supplied by the harness as optional `hooks` (a real adapter's
 * harness drives a second adapter/test peer). Tests that need a hook are skipped when it is
 * absent — the skip is visible in the vitest report, never silent.
 */
import { describe, expect, it } from 'vitest';
import {
  MeridianAdapterError,
  type AdapterErrorCode,
  type ChatMessage,
  type ClientEvent,
  type FileOffer,
  type FileSource,
  type MeridianClientAdapter,
  type MessageRequest,
  type PeerId
} from '../lib/adapter';

export interface ContractHooks {
  /**
   * Make the contact's key change as core would observe it: verified -> `blocked`, pinned ->
   * `pinned-key-changed` (or `blocked` when `escalatePinned`). Must emit `trust-changed`.
   */
  keyChange?(peerId: PeerId, escalatePinned?: boolean): void | Promise<void>;
  /** Deliver a first-contact message request from the peer named by `label` (via `makeId`). */
  inboundMessageRequest?(label: string, introText: string | null): MessageRequest | Promise<MessageRequest>;
  /** Deliver an inbound chat message from an already-accepted contact. */
  inboundMessage?(peerId: PeerId, body: string): ChatMessage | Promise<ChatMessage>;
  /** Deliver an inbound `mrd.file/1` OPEN that needs the user's decision. */
  fileOffer?(peerId: PeerId, name: string, size: number): FileOffer | Promise<FileOffer>;
}

export interface ContractHarness {
  readonly adapter: MeridianClientAdapter;
  /** A well-formed ID string for a distinct peer, stable per `label`, valid for this adapter. */
  makeId(label: string): string;
  /** Build a file this adapter's `sendFile` accepts. Defaults to an in-memory blob. */
  makeFile?(name: string, size: number): FileSource;
  readonly hooks?: ContractHooks;
}

export type HarnessFactory = () => ContractHarness | Promise<ContractHarness>;

/**
 * Which optional hooks the harness provides. Declared statically (not discovered at run time) so
 * hook-dependent tests are reported as skipped by vitest rather than silently passing. A harness
 * that claims a capability but does not supply the hook fails loudly.
 */
export interface ContractCapabilities {
  readonly keyChange: boolean;
  readonly inboundMessageRequest: boolean;
  readonly inboundMessage: boolean;
  readonly fileOffer: boolean;
}

function need<T>(hook: T | undefined, name: string): T {
  if (hook === undefined) throw new Error(`harness claims capability but lacks hooks.${name}`);
  return hook;
}

async function rejectsWith(p: Promise<unknown>, code: AdapterErrorCode): Promise<void> {
  const err = await p.then(
    () => null,
    (e: unknown) => e
  );
  expect(err).toBeInstanceOf(MeridianAdapterError);
  expect((err as MeridianAdapterError).code).toBe(code);
}

export function runAdapterContractTests(
  name: string,
  factory: HarnessFactory,
  caps: ContractCapabilities
): void {
  async function setup() {
    const h = await factory();
    await h.adapter.generateAccount('org-b.test', { kind: 'platform' });
    const file = (n: string, size = 16): FileSource =>
      h.makeFile?.(n, size) ?? { kind: 'blob', name: n, blob: new Blob([new Uint8Array(size)]) };
    return { h, a: h.adapter, hooks: h.hooks ?? {}, file };
  }

  describe(`MeridianClientAdapter contract: ${name}`, () => {
    describe('account & ids', () => {
      it('generateAccount makes the account ready', async () => {
        const { a } = await setup();
        const loaded = await a.loadAccount();
        expect(loaded.kind).toBe('ready');
      });

      it('parseId rejects malformed ids with invalid-id and accepts a valid one', async () => {
        const { a, h } = await setup();
        await rejectsWith(a.parseId('not-an-id'), 'invalid-id');
        const parsed = await a.parseId(h.makeId('alice'));
        expect(parsed.id).toBe(h.makeId('alice'));
      });
    });

    describe('contacts', () => {
      it('adds a contact pinned and unverified, with no petname derived from the id', async () => {
        const { a, h } = await setup();
        const c = await a.addContact(h.makeId('alice'));
        expect(c.trust).toBe('pinned');
        expect(c.petname).toBeNull();
        expect(await a.listContacts()).toHaveLength(1);
      });

      it('re-adding without a petname does not clobber an existing one', async () => {
        const { a, h } = await setup();
        await a.addContact(h.makeId('alice'), 'Alice');
        const again = await a.addContact(h.makeId('alice'));
        expect(again.petname).toBe('Alice');
        expect(await a.listContacts()).toHaveLength(1);
      });

      it('rename, clear petname, block, policy override; unknown peer rejects unknown-contact', async () => {
        const { a, h } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        await a.setPetname(peerId, 'Al');
        await a.setUserBlocked(peerId, true);
        await a.setPolicyOverride(peerId, 'relay-only');
        let [c] = await a.listContacts();
        expect(c).toMatchObject({ petname: 'Al', userBlocked: true, policyOverride: 'relay-only' });
        await a.setPetname(peerId, null);
        [c] = await a.listContacts();
        expect(c?.petname).toBeNull();
        await rejectsWith(a.setPetname(h.makeId('stranger'), 'x'), 'unknown-contact');
      });

      it('returned records are snapshots, not live views of adapter state', async () => {
        const { a, h } = await setup();
        const c = await a.addContact(h.makeId('alice'));
        await a.setPetname(c.peerId, 'Changed');
        expect(c.petname).toBeNull();
      });
    });

    describe('deleteContact removes only the display entry (binding rule)', () => {
      it('block -> delete -> re-add is still blocked', async () => {
        const { a, h } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        await a.setUserBlocked(peerId, true);
        await a.deleteContact(peerId);
        expect(await a.listContacts()).toHaveLength(0);
        const again = await a.addContact(h.makeId('alice'));
        expect(again.userBlocked).toBe(true);
        expect((await a.getSendGate(again.peerId)).kind).toBe('blocked');
        await rejectsWith(a.sendMessage(again.peerId, 'hi'), 'send-blocked');
      });

      it('verified trust survives delete + re-add', async () => {
        const { a, h } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        await a.markVerified(peerId);
        await a.deleteContact(peerId);
        const again = await a.addContact(h.makeId('alice'));
        expect(again.trust).toBe('verified');
      });

      it.skipIf(!caps.keyChange)('a verified-then-key-changed contact stays gated across delete + re-add', async () => {
        const { a, h, hooks } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        await a.markVerified(peerId);
        await need(hooks.keyChange, 'keyChange')(peerId);
        expect((await a.getSendGate(peerId)).kind).toBe('blocked');
        await a.deleteContact(peerId);
        const again = await a.addContact(h.makeId('alice'));
        expect(again.trust).toBe('blocked');
        expect((await a.getSendGate(again.peerId)).kind).toBe('blocked');
      });
    });

    describe('trust, verification and the send gate', () => {
      it('safety number is 60 digits, grouped consistently and stable; unknown peer rejects', async () => {
        const { a, h } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        const n = await a.getSafetyNumber(peerId);
        expect(n.digits).toMatch(/^\d{60}$/);
        expect(n.display.replaceAll(' ', '')).toBe(n.digits);
        expect(await a.getSafetyNumber(peerId)).toEqual(n);
        await rejectsWith(a.getSafetyNumber(h.makeId('stranger')), 'unknown-contact');
      });

      it('markVerified: pinned -> verified; unknown contact rejects; unseen peer reads new', async () => {
        const { a, h } = await setup();
        await rejectsWith(a.markVerified(h.makeId('stranger')), 'unknown-contact');
        expect(await a.getTrustState(h.makeId('stranger'))).toBe('new');
        const { peerId } = await a.addContact(h.makeId('alice'));
        await a.markVerified(peerId);
        expect(await a.getTrustState(peerId)).toBe('verified');
      });

      it('a user-blocked contact blocks sendMessage and sendFile with send-blocked', async () => {
        const { a, h, file } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        await a.setUserBlocked(peerId, true);
        expect((await a.getSendGate(peerId)).kind).toBe('blocked');
        await rejectsWith(a.sendMessage(peerId, 'hi'), 'send-blocked');
        await rejectsWith(a.sendFile(peerId, file('x.bin')), 'send-blocked');
      });

      it.skipIf(!caps.keyChange)('a WARN gate (pinned key changed) blocks sendMessage and sendFile until acknowledged', async () => {
        const { a, h, hooks, file } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        await need(hooks.keyChange, 'keyChange')(peerId);
        expect(await a.getTrustState(peerId)).toBe('pinned-key-changed');
        expect((await a.getSendGate(peerId)).kind).toBe('warn');
        await rejectsWith(a.sendMessage(peerId, 'hi'), 'send-blocked');
        await rejectsWith(a.sendFile(peerId, file('x.bin')), 'send-blocked');
        await a.acknowledgeKeyChange(peerId);
        expect((await a.getSendGate(peerId)).kind).toBe('ok');
        await a.sendMessage(peerId, 'hi');
        await a.sendFile(peerId, file('x.bin'));
      });

      it.skipIf(!caps.keyChange)('a BLOCKED gate (verified key changed) blocks both sends; only re-verification clears it', async () => {
        const { a, h, hooks, file } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        await a.markVerified(peerId);
        await need(hooks.keyChange, 'keyChange')(peerId);
        expect(await a.getTrustState(peerId)).toBe('blocked');
        expect((await a.getSendGate(peerId)).kind).toBe('blocked');
        await rejectsWith(a.acknowledgeKeyChange(peerId), 'not-acknowledgeable');
        await rejectsWith(a.sendMessage(peerId, 'hi'), 'send-blocked');
        await rejectsWith(a.sendFile(peerId, file('x.bin')), 'send-blocked');
        await a.markVerified(peerId);
        expect((await a.getSendGate(peerId)).kind).toBe('ok');
      });
    });

    describe('chat', () => {
      it('sendMessage records an outgoing history entry with the returned mid', async () => {
        const { a, h } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        const sent = await a.sendMessage(peerId, 'hello');
        const history = await a.loadHistory(peerId);
        expect(history).toHaveLength(1);
        expect(history[0]).toMatchObject({ mid: sent.mid, direction: 'out', body: 'hello' });
      });

      it('sending to an unknown peer rejects unknown-contact', async () => {
        const { a, h } = await setup();
        await rejectsWith(a.sendMessage(h.makeId('stranger'), 'hi'), 'unknown-contact');
      });

      it.skipIf(!caps.inboundMessage)('inbound messages are pushed and persisted', async () => {
        const { a, h, hooks } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        const events: ClientEvent[] = [];
        a.subscribe((e) => events.push(e));
        const m = await need(hooks.inboundMessage, 'inboundMessage')(peerId, 'yo');
        expect(events).toContainEqual({ type: 'message', peerId, message: m });
        expect(await a.loadHistory(peerId)).toContainEqual(m);
      });
    });

    describe('message requests', () => {
      it.skipIf(!caps.inboundMessageRequest)('a request pins nothing until accepted; accept pins and delivers the intro', async () => {
        const { a, hooks } = await setup();
        const req = await need(hooks.inboundMessageRequest, 'inboundMessageRequest')('bob', 'hi, it is Bob');
        expect(await a.listMessageRequests()).toContainEqual(req);
        expect(await a.listContacts()).toHaveLength(0);
        const contact = await a.acceptMessageRequest(req.senderId);
        expect(contact.trust).toBe('pinned');
        expect(contact.petname).toBeNull();
        expect(await a.listMessageRequests()).toHaveLength(0);
        expect((await a.loadHistory(contact.peerId)).map((m) => m.body)).toContain('hi, it is Bob');
      });

      it.skipIf(!caps.inboundMessageRequest)('reject leaves no trace and rejects not-found when repeated', async () => {
        const { a, hooks } = await setup();
        const req = await need(hooks.inboundMessageRequest, 'inboundMessageRequest')('bob', 'hi');
        await a.rejectMessageRequest(req.senderId);
        expect(await a.listMessageRequests()).toHaveLength(0);
        expect(await a.listContacts()).toHaveLength(0);
        expect(await a.loadHistory(req.senderId)).toHaveLength(0);
        await rejectsWith(a.rejectMessageRequest(req.senderId), 'not-found');
        await rejectsWith(a.acceptMessageRequest(req.senderId), 'not-found');
      });
    });

    describe('files', () => {
      it('sendFile opens an in-progress outgoing transfer that is listed', async () => {
        const { a, h, file } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        const t = await a.sendFile(peerId, file('a.bin', 100));
        expect(t).toMatchObject({ direction: 'send', status: 'in-progress', bytesDone: 0 });
        expect((await a.listTransfers()).map((x) => x.transferId)).toContain(t.transferId);
      });

      it.skipIf(!caps.fileOffer)('offer: accept starts a receive transfer, reject drops it, unknown id rejects', async () => {
        const { a, h, hooks } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        const accepted = await need(hooks.fileOffer, 'fileOffer')(peerId, 'doc.pdf', 10);
        await a.answerFileOffer(accepted.transferId, true);
        expect(await a.listTransfers()).toMatchObject([{ direction: 'receive', name: 'doc.pdf' }]);
        const rejected = await need(hooks.fileOffer, 'fileOffer')(peerId, 'x.zip', 10);
        await a.answerFileOffer(rejected.transferId, false);
        expect(await a.listTransfers()).toHaveLength(1);
        await rejectsWith(a.answerFileOffer(rejected.transferId, true), 'not-found');
      });
    });

    describe('events', () => {
      it.skipIf(!caps.keyChange)('unsubscribe is idempotent and a throwing listener does not break others', async () => {
        const { a, h, hooks } = await setup();
        const { peerId } = await a.addContact(h.makeId('alice'));
        const seen: ClientEvent[] = [];
        const off = a.subscribe((e) => seen.push(e));
        a.subscribe(() => {
          throw new Error('bad listener');
        });
        await need(hooks.keyChange, 'keyChange')(peerId);
        expect(seen).toHaveLength(1);
        off();
        off();
        await need(hooks.keyChange, 'keyChange')(peerId);
        expect(seen).toHaveLength(1);
      });
    });
  });
}
