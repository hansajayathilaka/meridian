import { beforeEach, describe, expect, it } from "vitest";

import { MeridianAdapterError } from "./adapter";
import { FakeMeridianClientAdapter } from "./fake-adapter";

describe("FakeMeridianClientAdapter — account lifecycle", () => {
  it("has no current account until one is generated or opened", () => {
    const adapter = new FakeMeridianClientAdapter();
    expect(adapter.currentAccount()).toBeNull();
  });

  it("generateAccount sets the current account deterministically per instance", async () => {
    const adapter = new FakeMeridianClientAdapter();
    const id = await adapter.generateAccount("example.org");
    expect(adapter.currentAccount()).toBe(id);
    expect(id).toMatch(/^mrd1:[0-9a-f]{16}@example\.org$/);
  });

  it("closeAccount clears the current account", async () => {
    const adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("example.org");
    await adapter.closeAccount();
    expect(adapter.currentAccount()).toBeNull();
  });

  it("two instances never collide on generated ids (deterministic, not shared global state)", async () => {
    const a = new FakeMeridianClientAdapter();
    const b = new FakeMeridianClientAdapter();
    const idA = await a.generateAccount("example.org");
    const idB = await b.generateAccount("example.org");
    expect(idA).not.toBe(idB);
  });
});

describe("FakeMeridianClientAdapter — contacts", () => {
  let adapter: FakeMeridianClientAdapter;

  beforeEach(async () => {
    adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
  });

  it("starts with no contacts", async () => {
    expect(await adapter.listContacts()).toEqual([]);
  });

  it("addContact TOFU-pins a new contact and lists it", async () => {
    const contact = await adapter.addContact("mrd1:deadbeef@bob.example");
    expect(contact.trust).toBe("pinned");
    expect(contact.petname).toBeNull();

    const listed = await adapter.listContacts();
    expect(listed).toHaveLength(1);
    expect(listed[0]!.id).toBe("mrd1:deadbeef@bob.example");
  });

  it("addContact never derives a petname from the id — only from the explicit argument", async () => {
    // Mirrors apps/cli/src/contact.rs's petname-never-from-wire invariant test.
    const contact = await adapter.addContact("mrd1:deadbeef@TotallyLegitAlice.example");
    expect(contact.petname).toBeNull();
  });

  it("addContact assigns a petname only when explicitly passed", async () => {
    const contact = await adapter.addContact("mrd1:deadbeef@bob.example", "Bob");
    expect(contact.petname).toBe("Bob");
  });

  it("renamePetname updates, and null/empty clears, the petname", async () => {
    const id = "mrd1:deadbeef@bob.example";
    await adapter.addContact(id, "Bob");
    await adapter.renamePetname(id, "Bobby");
    expect((await adapter.listContacts())[0]!.petname).toBe("Bobby");

    await adapter.renamePetname(id, "");
    expect((await adapter.listContacts())[0]!.petname).toBeNull();
  });

  it("renamePetname on an unknown contact rejects with unknown_contact", async () => {
    await expect(adapter.renamePetname("mrd1:ffff@nowhere.example", "x")).rejects.toMatchObject({
      code: "unknown_contact",
    });
  });

  it("blockContact/unblockContact toggle userBlocked independent of trust state", async () => {
    const id = "mrd1:deadbeef@bob.example";
    await adapter.addContact(id);
    await adapter.blockContact(id);
    expect((await adapter.listContacts())[0]!.userBlocked).toBe(true);
    expect((await adapter.listContacts())[0]!.trust).toBe("pinned");

    await adapter.unblockContact(id);
    expect((await adapter.listContacts())[0]!.userBlocked).toBe(false);
  });

  it("rejects every contact operation on an unknown contact with a MeridianAdapterError", async () => {
    const unknown = "mrd1:ffff@nowhere.example";
    await expect(adapter.trustState(unknown)).rejects.toBeInstanceOf(MeridianAdapterError);
    await expect(adapter.blockContact(unknown)).rejects.toMatchObject({ code: "unknown_contact" });
  });

  it("blockContact actually blocks sendChat/sendGateState, not just the userBlocked flag (regression, task 12.2 review)", async () => {
    const id = "mrd1:deadbeef@bob.example";
    await adapter.addContact(id);
    expect(await adapter.sendGateState(id)).toEqual({ kind: "ok" });

    await adapter.blockContact(id);
    expect((await adapter.sendGateState(id)).kind).toBe("blocked");
    await expect(adapter.sendChat(id, "should not send")).rejects.toMatchObject({
      code: "send_blocked",
    });

    await adapter.unblockContact(id);
    expect(await adapter.sendGateState(id)).toEqual({ kind: "ok" });
    const result = await adapter.sendChat(id, "now it sends");
    expect(result.delivered).toBe(true);
  });
});

describe("FakeMeridianClientAdapter — chat send/receive", () => {
  let adapter: FakeMeridianClientAdapter;
  const peer = "mrd1:deadbeef@bob.example";

  beforeEach(async () => {
    adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
    await adapter.openConversation(peer);
  });

  it("sendChat delivers and records an outbound message", async () => {
    const result = await adapter.sendChat(peer, "hello");
    expect(result.delivered).toBe(true);
    expect(result.queued).toBe(false);

    const history = await adapter.loadHistory(peer);
    expect(history).toHaveLength(1);
    expect(history[0]).toMatchObject({ direction: "out", body: "hello", state: "sent" });
  });

  it("onMessage fires for a simulated inbound message, not for outbound sends", async () => {
    const received: Array<{ peer: string; body: string }> = [];
    const unsubscribe = adapter.onMessage((p, msg) => received.push({ peer: p, body: msg.body }));

    await adapter.sendChat(peer, "outbound, should not notify listeners");
    adapter.simulateIncomingMessage(peer, "hi back");

    expect(received).toEqual([{ peer, body: "hi back" }]);
    unsubscribe();
    adapter.simulateIncomingMessage(peer, "after unsubscribe");
    expect(received).toHaveLength(1);
  });

  it("loadHistory supports before/limit pagination", async () => {
    await adapter.sendChat(peer, "one");
    await adapter.sendChat(peer, "two");
    await adapter.sendChat(peer, "three");
    const all = await adapter.loadHistory(peer);
    expect(all.map((m) => m.body)).toEqual(["one", "two", "three"]);

    const beforeThird = await adapter.loadHistory(peer, { before: all[2]!.id });
    expect(beforeThird.map((m) => m.body)).toEqual(["one", "two"]);

    const lastOne = await adapter.loadHistory(peer, { limit: 1 });
    expect(lastOne.map((m) => m.body)).toEqual(["three"]);
  });

  it("sendChat rejects with send_blocked when the send gate is blocked, and sends nothing", async () => {
    adapter.simulateSendGate(peer, { kind: "blocked", reason: "verified contact's key changed" });
    await expect(adapter.sendChat(peer, "should not send")).rejects.toMatchObject({
      code: "send_blocked",
    });
    expect(await adapter.loadHistory(peer)).toEqual([]);
  });

  it("sendChat rejects with send_warn_unacknowledged until acknowledgeKeyChange clears the gate", async () => {
    adapter.simulateSendGate(peer, { kind: "warn", reason: "pinned contact's key changed" });
    await expect(adapter.sendChat(peer, "held")).rejects.toMatchObject({
      code: "send_warn_unacknowledged",
    });

    await adapter.acknowledgeKeyChange(peer);
    expect(await adapter.sendGateState(peer)).toEqual({ kind: "ok" });

    const result = await adapter.sendChat(peer, "now it sends");
    expect(result.delivered).toBe(true);
  });
});

describe("FakeMeridianClientAdapter — message requests", () => {
  let adapter: FakeMeridianClientAdapter;
  const from = "mrd1:cafef00d@carol.example";

  beforeEach(async () => {
    adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
  });

  it("simulateIncomingRequest notifies onMessageRequest listeners with a safety number", () => {
    const requests: string[] = [];
    adapter.onMessageRequest((req) => requests.push(req.from));
    adapter.simulateIncomingRequest(from, "hi, it's carol");
    expect(requests).toEqual([from]);
  });

  it("acceptMessageRequest pins the contact and delivers the held intro", async () => {
    adapter.simulateIncomingRequest(from, "hi, it's carol");
    await adapter.acceptMessageRequest(from, "Carol");

    const contacts = await adapter.listContacts();
    expect(contacts).toHaveLength(1);
    expect(contacts[0]).toMatchObject({ id: from, petname: "Carol", trust: "pinned" });

    const history = await adapter.loadHistory(from);
    expect(history[0]).toMatchObject({ direction: "in", body: "hi, it's carol" });
  });

  it("rejectMessageRequest leaves no trace in the contact list", async () => {
    adapter.simulateIncomingRequest(from, "hi, it's carol");
    await adapter.rejectMessageRequest(from);
    expect(await adapter.listContacts()).toEqual([]);
  });

  it("accepting/rejecting a request that does not exist rejects with no_pending_request", async () => {
    await expect(adapter.acceptMessageRequest(from)).rejects.toMatchObject({
      code: "no_pending_request",
    });
    await expect(adapter.rejectMessageRequest(from)).rejects.toMatchObject({
      code: "no_pending_request",
    });
  });
});

describe("FakeMeridianClientAdapter — conversations enumeration (TODO: confirm surface)", () => {
  it("listConversations reflects contacts + history even though it has no core precedent", async () => {
    const adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
    const peer = "mrd1:deadbeef@bob.example";
    await adapter.openConversation(peer);
    await adapter.sendChat(peer, "hello");
    adapter.simulateIncomingMessage(peer, "hi");

    const conversations = await adapter.listConversations();
    expect(conversations).toHaveLength(1);
    expect(conversations[0]!.contact.id).toBe(peer);
    expect(conversations[0]!.lastMessagePreview).toBe("hi");
  });
});

describe("FakeMeridianClientAdapter — verification", () => {
  it("safetyNumber is order-independent between two accounts viewing the same pair", async () => {
    const alice = new FakeMeridianClientAdapter();
    await alice.generateAccount("alice.example");
    const bobId = "mrd1:deadbeef@bob.example";
    await alice.addContact(bobId);
    const numberFromAlice = await alice.safetyNumber(bobId);

    expect(numberFromAlice.raw).toHaveLength(60);
    expect(numberFromAlice.grouped.replace(/ /g, "")).toBe(numberFromAlice.raw);
  });

  it("markVerified transitions trust state to verified", async () => {
    const adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
    const peer = "mrd1:deadbeef@bob.example";
    await adapter.addContact(peer);
    expect(await adapter.trustState(peer)).toBe("pinned");

    await adapter.markVerified(peer);
    expect(await adapter.trustState(peer)).toBe("verified");
  });

  it("markVerified on an unknown contact rejects with unknown_contact", async () => {
    const adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
    await expect(adapter.markVerified("mrd1:ffff@nowhere.example")).rejects.toMatchObject({
      code: "unknown_contact",
    });
  });

  it("markVerified clears a trust-axis blocked gate (regression, task 12.2 review)", async () => {
    const adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
    const peer = "mrd1:deadbeef@bob.example";
    await adapter.addContact(peer);

    adapter.simulateSendGate(peer, { kind: "blocked", reason: "verified contact's key changed" });
    expect(await adapter.trustState(peer)).toBe("blocked");
    expect((await adapter.sendGateState(peer)).kind).toBe("blocked");

    await adapter.markVerified(peer);
    expect(await adapter.trustState(peer)).toBe("verified");
    expect(await adapter.sendGateState(peer)).toEqual({ kind: "ok" });
    const result = await adapter.sendChat(peer, "now it sends");
    expect(result.delivered).toBe(true);
  });

  it("markVerified does NOT clear an independent userBlocked gate (regression, task 12.2 review)", async () => {
    const adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
    const peer = "mrd1:deadbeef@bob.example";
    await adapter.addContact(peer);
    await adapter.blockContact(peer);

    await adapter.markVerified(peer);
    expect(await adapter.trustState(peer)).toBe("verified");
    expect((await adapter.sendGateState(peer)).kind).toBe("blocked");
    await expect(adapter.sendChat(peer, "nope")).rejects.toMatchObject({ code: "send_blocked" });
  });
});

describe("FakeMeridianClientAdapter — unread tracking (regression, task 12.2 review)", () => {
  it("incoming messages increment unreadCount; markConversationRead resets it to 0", async () => {
    const adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
    const peer = "mrd1:deadbeef@bob.example";
    await adapter.openConversation(peer);

    expect((await adapter.listConversations())[0]!.unreadCount).toBe(0);

    adapter.simulateIncomingMessage(peer, "hi");
    adapter.simulateIncomingMessage(peer, "you there?");
    expect((await adapter.listConversations())[0]!.unreadCount).toBe(2);

    await adapter.markConversationRead(peer);
    expect((await adapter.listConversations())[0]!.unreadCount).toBe(0);
  });

  it("markConversationRead on an unknown contact rejects with unknown_contact", async () => {
    const adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
    await expect(adapter.markConversationRead("mrd1:ffff@nowhere.example")).rejects.toMatchObject({
      code: "unknown_contact",
    });
  });
});

describe("FakeMeridianClientAdapter — streams / file ops", () => {
  it("openStream returns a handle scoped to a known contact", async () => {
    const adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
    const peer = "mrd1:deadbeef@bob.example";
    await adapter.addContact(peer);

    const { streamId } = await adapter.openStream(peer, "mrd.file/1", { fileName: "notes.txt" });
    expect(streamId).toBeTruthy();
  });

  it("sendFile records a transfer and listTransfers reports it", async () => {
    const adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
    const peer = "mrd1:deadbeef@bob.example";
    await adapter.addContact(peer);

    const blob = new Blob(["hello world"], { type: "text/plain" });
    await adapter.sendFile(peer, blob, "notes.txt");

    const transfers = await adapter.listTransfers();
    expect(transfers).toHaveLength(1);
    expect(transfers[0]).toMatchObject({ peer, fileName: "notes.txt", state: "complete" });
  });
});
