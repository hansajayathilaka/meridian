import { describe, expect, it } from 'vitest';
import { runAdapterContractTests } from '../contract';
import {
  FakeMeridianClientAdapter,
  MeridianAdapterError,
  type AdapterErrorCode,
  type ClientEvent
} from './index';

const ALICE = 'mrd1:alice@org-a.test';
const ALICE_PEER = 'mrd1:alice';

async function rejectsWith(p: Promise<unknown>, code: AdapterErrorCode): Promise<void> {
  const err = await p.then(
    () => null,
    (e: unknown) => e
  );
  expect(err).toBeInstanceOf(MeridianAdapterError);
  expect((err as MeridianAdapterError).code).toBe(code);
}

async function ready(): Promise<FakeMeridianClientAdapter> {
  const a = new FakeMeridianClientAdapter();
  await a.generateAccount('org-b.test', { kind: 'platform' });
  return a;
}

// The shared contract every adapter (fake, desktop 12.6, browser 12.13) must pass.
runAdapterContractTests(
  'FakeMeridianClientAdapter',
  () => {
    const adapter = new FakeMeridianClientAdapter();
    const peerOf = (label: string) => `mrd1:${label}`;
    return {
      adapter,
      makeId: (label) => `mrd1:${label}@org-a.test`,
      hooks: {
        keyChange: (peerId, escalate) => adapter.simulateKeyChange(peerId, escalate),
        inboundMessageRequest: (label, intro) =>
          adapter.simulateInboundMessageRequest(peerOf(label), intro),
        inboundMessage: (peerId, body) => adapter.simulateInboundMessage(peerId, body),
        fileOffer: (peerId, name, size) => adapter.simulateFileOffer(peerId, name, size)
      }
    };
  },
  { keyChange: true, inboundMessageRequest: true, inboundMessage: true, fileOffer: true }
);

// Fake-only behaviour: the `simulate*`/`set*` controls and the fake's own stand-ins.
describe('FakeMeridianClientAdapter: fake-specific', () => {
  it('starts with no account, then generate makes it ready', async () => {
    const a = new FakeMeridianClientAdapter();
    expect(await a.loadAccount()).toEqual({ kind: 'no-account' });
    const account = await a.generateAccount('org-b.test', { kind: 'platform' });
    expect(await a.loadAccount()).toEqual({ kind: 'ready', account });
  });

  it('seeded locked account: wrong passphrase rejects, right one unlocks', async () => {
    const a = new FakeMeridianClientAdapter({
      account: { id: 'mrd1:me@org-b.test', label: 'me' },
      lockedWithPassphrase: 'pw'
    });
    expect(await a.loadAccount()).toEqual({ kind: 'locked' });
    await rejectsWith(a.unlockAccount('nope'), 'wrong-passphrase');
    await a.unlockAccount('pw');
    expect((await a.loadAccount()).kind).toBe('ready');
  });

  it('passphrase-protected generated account relocks on restart; platform-protected does not', async () => {
    const a = new FakeMeridianClientAdapter();
    await a.generateAccount('h', { kind: 'passphrase', passphrase: 'secret' });
    expect((await a.loadAccount()).kind).toBe('ready'); // unlocked for this session
    a.simulateRestart();
    expect(await a.loadAccount()).toEqual({ kind: 'locked' });
    await rejectsWith(a.getSafetyNumber(ALICE_PEER), 'locked');
    await rejectsWith(a.unlockAccount('wrong'), 'wrong-passphrase');
    await a.unlockAccount('secret');
    expect((await a.loadAccount()).kind).toBe('ready');

    const b = new FakeMeridianClientAdapter();
    await b.generateAccount('h', { kind: 'platform' });
    b.simulateRestart();
    expect((await b.loadAccount()).kind).toBe('ready');
  });

  it('safety number is symmetric: two adapters computing for each other agree', async () => {
    const a = new FakeMeridianClientAdapter();
    const b = new FakeMeridianClientAdapter();
    const accA = await a.generateAccount('org-a.test', { kind: 'platform' });
    const accB = await b.generateAccount('org-b.test', { kind: 'platform' });
    const contactB = await a.addContact(accB.id);
    const contactA = await b.addContact(accA.id);
    expect((await a.getSafetyNumber(contactB.peerId)).digits).toBe(
      (await b.getSafetyNumber(contactA.peerId)).digits
    );
  });

  it('decodeQr / renderQrText round-trip through the fake codec', async () => {
    const a = await ready();
    const payload = '12345';
    const luma = new TextEncoder().encode(payload);
    expect(await a.decodeQr({ width: luma.length, height: 1, luma })).toBe(payload);
    expect(await a.renderQrText(payload)).toContain(payload);
  });

  it('a receipt flips an outgoing message to delivered and is pushed', async () => {
    const a = await ready();
    await a.addContact(ALICE);
    const events: ClientEvent[] = [];
    a.subscribe((e) => events.push(e));
    const sent = await a.sendMessage(ALICE_PEER, 'hello');
    expect(sent).toMatchObject({ delivered: true, queued: false });
    let [m] = await a.loadHistory(ALICE_PEER);
    expect(m?.state).toBe('sent');
    a.simulateReceipt(ALICE_PEER, sent.mid);
    [m] = await a.loadHistory(ALICE_PEER);
    expect(m?.state).toBe('delivered');
    expect(events).toContainEqual({ type: 'receipt', peerId: ALICE_PEER, mid: sent.mid });
  });

  it('models queued and offline routing outcomes honestly', async () => {
    const a = await ready();
    await a.addContact(ALICE);
    a.setRouting({ delivered: false, queued: true });
    await a.sendMessage(ALICE_PEER, 'q');
    a.setRouting({ delivered: false, queued: false });
    await a.sendMessage(ALICE_PEER, 'x');
    expect((await a.loadHistory(ALICE_PEER)).map((m) => m.state)).toEqual(['pending', 'failed']);
  });

  it('accept does not discard the pending request if pinning the sender throws', async () => {
    const a = await ready();
    a.simulateInboundMessageRequest('not a valid id', 'hi');
    await rejectsWith(a.acceptMessageRequest('not a valid id'), 'invalid-id');
    expect(await a.listMessageRequests()).toHaveLength(1);
    expect(await a.listContacts()).toHaveLength(0);
  });

  it('transfer progress completes at total and failures carry the reason', async () => {
    const a = await ready();
    await a.addContact(ALICE);
    const events: ClientEvent[] = [];
    a.subscribe((e) => events.push(e));
    const t = await a.sendFile(ALICE_PEER, {
      kind: 'blob',
      name: 'a.bin',
      blob: new Blob([new Uint8Array(100)])
    });
    expect(a.simulateTransferProgress(t.transferId, 40).status).toBe('in-progress');
    expect(a.simulateTransferProgress(t.transferId, 100).status).toBe('completed');
    expect(events.filter((e) => e.type === 'transfer')).toHaveLength(3);
    const t2 = await a.sendFile(ALICE_PEER, { kind: 'path', path: '/tmp/x' });
    expect(a.simulateTransferFailure(t2.transferId, 'peer closed')).toMatchObject({
      status: 'failed',
      failureReason: 'peer closed'
    });
  });

  it('is deterministic given an injected clock', async () => {
    const mk = async () => {
      const a = new FakeMeridianClientAdapter({ now: () => 42 });
      await a.generateAccount('h', { kind: 'platform' });
      await a.addContact(ALICE);
      await a.sendMessage(ALICE_PEER, 'x');
      return a.loadHistory(ALICE_PEER);
    };
    expect(await mk()).toEqual(await mk());
  });
});
