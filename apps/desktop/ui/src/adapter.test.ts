import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { MeridianAdapterError } from "shared-ui";

// ---------------------------------------------------------------------------
// Mocks for `@tauri-apps/api/core` (`invoke`) and `@tauri-apps/api/event` (`listen`) — no real
// Tauri runtime involved, per this task's Deliverable 2. `vi.hoisted` is needed because `vi.mock`
// factories run before this file's own top-level `const`s.
// ---------------------------------------------------------------------------

const { invokeMock, listeners, emit } = vi.hoisted(() => {
  const listeners = new Map<string, Array<(event: { event: string; id: number; payload: unknown }) => void>>();
  return {
    invokeMock: vi.fn<(cmd: string, args?: Record<string, unknown>) => Promise<unknown>>(),
    listeners,
    emit: (event: string, payload: unknown) => {
      for (const cb of listeners.get(event) ?? []) cb({ event, id: 0, payload });
    },
  };
});

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: Record<string, unknown>) => invokeMock(cmd, args),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((event: string, cb: (event: { event: string; id: number; payload: unknown }) => void) => {
    const arr = listeners.get(event) ?? [];
    arr.push(cb);
    listeners.set(event, arr);
    return Promise.resolve(() => {
      const idx = arr.indexOf(cb);
      if (idx >= 0) arr.splice(idx, 1);
    });
  }),
}));

// Imported *after* the mocks above so the module under test picks them up.
const { TauriMeridianClientAdapter } = await import("./adapter");

const ACCOUNT = { id: "mrd1:aaaaaaaaaaaaaaaa@me.example", pubkey_hex: "aa".repeat(32), hint: "me.example" };
const BOB_ID = "mrd1:bbbbbbbbbbbbbbbb@bob.example";
const BOB_PUBKEY_HEX = "bb".repeat(32);
const BOB_CONTACT_VIEW = {
  id: BOB_ID,
  pubkey_hex: BOB_PUBKEY_HEX,
  petname: null,
  hint: "bob.example",
  state: "pinned",
  user_blocked: false,
};

function defaultInvokeImpl(cmd: string, _args?: Record<string, unknown>): Promise<unknown> {
  void _args;
  switch (cmd) {
    case "account_get":
      return Promise.resolve(null);
    default:
      throw new Error(`unmocked invoke command in test: ${cmd}`);
  }
}

async function makeAdapter() {
  const adapter = new TauriMeridianClientAdapter({ rendezvousServer: "wss://rendezvous.example" });
  await adapter.ready;
  return adapter;
}

beforeEach(() => {
  listeners.clear();
  invokeMock.mockReset();
  invokeMock.mockImplementation(defaultInvokeImpl);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("TauriMeridianClientAdapter — construction", () => {
  it("subscribes to the base event set and primes currentAccount from account_get", async () => {
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "account_get") return Promise.resolve(ACCOUNT);
      throw new Error(`unmocked: ${cmd}`);
    });
    const adapter = await makeAdapter();
    expect(adapter.currentAccount()).toBe(ACCOUNT.id);
    for (const event of ["account:changed", "contact:changed", "chat:message", "chat:receipt", "chat:message_request", "session:closed", "file:incoming", "file:progress", "file:received", "file:failed"]) {
      expect(listeners.has(event)).toBe(true);
    }
  });

  it("currentAccount stays null when no account exists yet", async () => {
    const adapter = await makeAdapter();
    expect(adapter.currentAccount()).toBeNull();
  });
});

describe("TauriMeridianClientAdapter — account lifecycle", () => {
  it("generateAccount invokes account_create and sets currentAccount", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd, args) => {
      if (cmd === "account_create") {
        expect(args).toEqual({ hint: "me.example" });
        return Promise.resolve(ACCOUNT);
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    const id = await adapter.generateAccount("me.example");
    expect(id).toBe(ACCOUNT.id);
    expect(adapter.currentAccount()).toBe(ACCOUNT.id);
  });

  it("account:changed events keep currentAccount in sync", async () => {
    const adapter = await makeAdapter();
    expect(adapter.currentAccount()).toBeNull();
    emit("account:changed", ACCOUNT);
    expect(adapter.currentAccount()).toBe(ACCOUNT.id);
  });

  it("closeAccount clears the local cache (GAP: cannot clear backend key material — see adapter.ts doc)", async () => {
    const adapter = await makeAdapter();
    emit("account:changed", ACCOUNT);
    expect(adapter.currentAccount()).toBe(ACCOUNT.id);
    await adapter.closeAccount();
    expect(adapter.currentAccount()).toBeNull();
  });

  it("openAccount ignores its descriptor argument (GAP: no parameterized open command) and calls account_load", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "account_load") return Promise.resolve(ACCOUNT);
      throw new Error(`unmocked: ${cmd}`);
    });
    const id = await adapter.openAccount({ some: "opaque descriptor" });
    expect(id).toBe(ACCOUNT.id);
  });

  it("openAccount rejects with unavailable when no account exists to load", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "account_load") return Promise.resolve(null);
      throw new Error(`unmocked: ${cmd}`);
    });
    await expect(adapter.openAccount(undefined)).rejects.toMatchObject({ code: "unavailable" });
  });
});

describe("TauriMeridianClientAdapter — contacts", () => {
  it("listContacts maps ContactView[] to Contact[] and caches them", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "contact_list") return Promise.resolve([BOB_CONTACT_VIEW]);
      throw new Error(`unmocked: ${cmd}`);
    });
    const contacts = await adapter.listContacts();
    expect(contacts).toEqual([
      { id: BOB_ID, pubkey: BOB_PUBKEY_HEX, hint: "bob.example", petname: null, trust: "pinned", userBlocked: false },
    ]);
  });

  it("addContact invokes contact_add with the petname and maps the result", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd, args) => {
      if (cmd === "contact_add") {
        expect(args).toEqual({ id: BOB_ID, petname: "Bob" });
        return Promise.resolve({ ...BOB_CONTACT_VIEW, petname: "Bob" });
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    const contact = await adapter.addContact(BOB_ID, "Bob");
    expect(contact.petname).toBe("Bob");
  });

  it("renamePetname sends an empty string to clear (mirrors contact_rename's null/empty equivalence)", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd, args) => {
      if (cmd === "contact_rename") {
        expect(args).toEqual({ id: BOB_ID, petname: "" });
        return Promise.resolve(BOB_CONTACT_VIEW);
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    await adapter.renamePetname(BOB_ID, null);
  });

  it("blockContact/unblockContact invoke contact_block with the right blocked flag", async () => {
    const adapter = await makeAdapter();
    const calls: unknown[] = [];
    invokeMock.mockImplementation((cmd, args) => {
      if (cmd === "contact_block") {
        calls.push(args);
        return Promise.resolve({ ...BOB_CONTACT_VIEW, user_blocked: (args as { blocked: boolean }).blocked });
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    await adapter.blockContact(BOB_ID);
    await adapter.unblockContact(BOB_ID);
    expect(calls).toEqual([{ id: BOB_ID, blocked: true }, { id: BOB_ID, blocked: false }]);
  });

  it("trustState fetches contact_list and finds the peer (GAP: no single-contact query command)", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "contact_list") return Promise.resolve([BOB_CONTACT_VIEW]);
      throw new Error(`unmocked: ${cmd}`);
    });
    expect(await adapter.trustState(BOB_ID)).toBe("pinned");
  });

  it("trustState on an unknown contact rejects with unknown_contact", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "contact_list") return Promise.resolve([]);
      throw new Error(`unmocked: ${cmd}`);
    });
    await expect(adapter.trustState(BOB_ID)).rejects.toMatchObject({ code: "unknown_contact" });
  });

  it("sendGateState derives ok/warn/blocked from ContactView.state/user_blocked", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "contact_list") {
        return Promise.resolve([{ ...BOB_CONTACT_VIEW, state: "warn (key change)" }]);
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    expect((await adapter.sendGateState(BOB_ID)).kind).toBe("warn");
  });

  it("sendGateState reports blocked when userBlocked is true regardless of trust state", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "contact_list") {
        return Promise.resolve([{ ...BOB_CONTACT_VIEW, user_blocked: true }]);
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    expect((await adapter.sendGateState(BOB_ID)).kind).toBe("blocked");
  });
});

describe("TauriMeridianClientAdapter — sessions & messaging", () => {
  it("openConversation is a no-op invoke wise when a session is already open (session_get hit)", async () => {
    const adapter = await makeAdapter();
    const calls: string[] = [];
    invokeMock.mockImplementation((cmd) => {
      calls.push(cmd);
      if (cmd === "session_get") return Promise.resolve({ peer_pubkey_hex: BOB_PUBKEY_HEX, transport: "loopback", path: "direct", streams: [] });
      throw new Error(`unmocked: ${cmd}`);
    });
    await adapter.openConversation(BOB_ID);
    expect(calls).toEqual(["session_get"]);
  });

  it("openConversation calls session_connect with the configured server when no session exists", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd, args) => {
      if (cmd === "session_get") return Promise.resolve(null);
      if (cmd === "session_connect") {
        expect(args).toEqual({ peerId: BOB_ID, server: "wss://rendezvous.example" });
        return Promise.resolve({ peer_pubkey_hex: BOB_PUBKEY_HEX, transport: "loopback", path: "direct", streams: [] });
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    await adapter.openConversation(BOB_ID);
  });

  it("openConversation starts a pump_once poll loop that stops on session:closed", async () => {
    vi.useFakeTimers();
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "session_get") return Promise.resolve(null);
      if (cmd === "session_connect") {
        return Promise.resolve({ peer_pubkey_hex: BOB_PUBKEY_HEX, transport: "loopback", path: "direct", streams: [] });
      }
      if (cmd === "pump_once") return Promise.resolve(null);
      throw new Error(`unmocked: ${cmd}`);
    });
    await adapter.openConversation(BOB_ID);
    invokeMock.mockClear();

    await vi.advanceTimersByTimeAsync(300);
    expect(invokeMock).toHaveBeenCalledWith("pump_once", { peerId: BOB_ID });

    invokeMock.mockClear();
    emit("chat:message_request", { kind: "MessageRequest", peer_pubkey_hex: "irrelevant", safety_number: "0".repeat(60) });
    emit("session:closed", { kind: "Closed", peer_pubkey_hex: BOB_PUBKEY_HEX });
    await vi.advanceTimersByTimeAsync(1000);
    expect(invokeMock).not.toHaveBeenCalledWith("pump_once", expect.anything());

    adapter.dispose();
  });

  it("sendChat invokes chat_send and records the outbound message locally", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd, args) => {
      if (cmd === "chat_send") {
        expect(args).toEqual({ peerId: BOB_ID, text: "hello" });
        return Promise.resolve({ id_hex: "deadbeef" });
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    const result = await adapter.sendChat(BOB_ID, "hello");
    expect(result).toEqual({ id: "deadbeef", delivered: true, queued: false });

    invokeMock.mockImplementation((cmd) => {
      if (cmd === "contact_list") return Promise.resolve([BOB_CONTACT_VIEW]);
      throw new Error(`unmocked: ${cmd}`);
    });
    const history = await adapter.loadHistory(BOB_ID);
    expect(history).toEqual([
      { id: "deadbeef", direction: "out", timestamp: expect.any(Number), streamType: "mrd.chat/1", body: "hello", state: "sent" },
    ]);
  });

  it("sendChat maps a chat_send 'blocked: ...' error to send_blocked", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "chat_send") return Promise.reject("blocked: the safety number changed");
      throw new Error(`unmocked: ${cmd}`);
    });
    await expect(adapter.sendChat(BOB_ID, "nope")).rejects.toMatchObject({ code: "send_blocked" });
  });

  it("sendChat maps a chat_send acknowledge-first error to send_warn_unacknowledged", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "chat_send") {
        return Promise.reject(
          "the safety number changed — call contact_acknowledge_key_change first, or contact_mark_verified after an out-of-band compare",
        );
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    await expect(adapter.sendChat(BOB_ID, "held")).rejects.toMatchObject({ code: "send_warn_unacknowledged" });
  });

  it("sendChat maps an unrecognized error string to code 'unknown'", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "chat_send") return Promise.reject("something totally unexpected happened");
      throw new Error(`unmocked: ${cmd}`);
    });
    await expect(adapter.sendChat(BOB_ID, "x")).rejects.toMatchObject({ code: "unknown" });
  });

  it("onMessage fires with the resolved MeridianId once the peer's pubkey is cached via openConversation", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "session_get") return Promise.resolve(null);
      if (cmd === "session_connect") {
        return Promise.resolve({ peer_pubkey_hex: BOB_PUBKEY_HEX, transport: "loopback", path: "direct", streams: [] });
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    await adapter.openConversation(BOB_ID);

    const received: Array<{ peer: string; body: string }> = [];
    const unsubscribe = adapter.onMessage((peer, msg) => received.push({ peer, body: msg.body }));
    emit("chat:message", { kind: "Message", peer_pubkey_hex: BOB_PUBKEY_HEX, id_hex: "cafe", body: "hi" });
    expect(received).toEqual([{ peer: BOB_ID, body: "hi" }]);

    unsubscribe();
    emit("chat:message", { kind: "Message", peer_pubkey_hex: BOB_PUBKEY_HEX, id_hex: "cafe2", body: "after unsub" });
    expect(received).toHaveLength(1);
  });

  it("onMessage silently drops events for a pubkey never resolved to a MeridianId (documented narrow GAP)", async () => {
    const adapter = await makeAdapter();
    const received: unknown[] = [];
    adapter.onMessage((peer, msg) => received.push({ peer, msg }));
    emit("chat:message", { kind: "Message", peer_pubkey_hex: "unknown-pubkey", id_hex: "x", body: "y" });
    expect(received).toEqual([]);
  });

  it("onMessageRequest surfaces a safety number grouped into 5-digit chunks; introPreview is always null (GAP)", async () => {
    const adapter = await makeAdapter();
    const requests: unknown[] = [];
    adapter.onMessageRequest((req) => requests.push(req));
    const digits = "1".repeat(60);
    emit("chat:message_request", { kind: "MessageRequest", peer_pubkey_hex: BOB_PUBKEY_HEX, safety_number: digits });
    expect(requests).toEqual([
      {
        from: BOB_PUBKEY_HEX,
        safetyNumber: { raw: digits, grouped: digits.match(/.{1,5}/g)!.join(" ") },
        introPreview: null,
      },
    ]);
  });

  it("acceptMessageRequest invokes contact_answer_request(accept: true) then renames if a petname is given", async () => {
    const adapter = await makeAdapter();
    const calls: unknown[] = [];
    invokeMock.mockImplementation((cmd, args) => {
      calls.push([cmd, args]);
      if (cmd === "contact_answer_request") return Promise.resolve(null);
      if (cmd === "contact_rename") return Promise.resolve(BOB_CONTACT_VIEW);
      throw new Error(`unmocked: ${cmd}`);
    });
    await adapter.acceptMessageRequest(BOB_ID, "Bob");
    expect(calls).toEqual([
      ["contact_answer_request", { id: BOB_ID, accept: true }],
      ["contact_rename", { id: BOB_ID, petname: "Bob" }],
    ]);
  });

  it("rejectMessageRequest invokes contact_answer_request(accept: false)", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd, args) => {
      if (cmd === "contact_answer_request") {
        expect(args).toEqual({ id: BOB_ID, accept: false });
        return Promise.resolve(null);
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    await adapter.rejectMessageRequest(BOB_ID);
  });

  it("acknowledgeKeyChange invokes contact_acknowledge_key_change and re-caches the contact", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd, args) => {
      if (cmd === "contact_acknowledge_key_change") {
        expect(args).toEqual({ id: BOB_ID });
        return Promise.resolve(BOB_CONTACT_VIEW);
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    await adapter.acknowledgeKeyChange(BOB_ID);
  });
});

describe("TauriMeridianClientAdapter — conversations / unread", () => {
  it("markConversationRead resets unreadCount only for a known contact", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "contact_list") return Promise.resolve([BOB_CONTACT_VIEW]);
      throw new Error(`unmocked: ${cmd}`);
    });

    // Prime the pubkey cache the same way openConversation would, then simulate an inbound message
    // so unreadCount becomes non-zero.
    await adapter.listContacts();
    emit("chat:message", { kind: "Message", peer_pubkey_hex: BOB_PUBKEY_HEX, id_hex: "m1", body: "hi" });

    let conversations = await adapter.listConversations();
    expect(conversations[0]!.unreadCount).toBe(1);

    await adapter.markConversationRead(BOB_ID);
    conversations = await adapter.listConversations();
    expect(conversations[0]!.unreadCount).toBe(0);
  });

  it("markConversationRead on an unknown contact rejects with unknown_contact", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "contact_list") return Promise.resolve([]);
      throw new Error(`unmocked: ${cmd}`);
    });
    await expect(adapter.markConversationRead(BOB_ID)).rejects.toMatchObject({ code: "unknown_contact" });
  });
});

describe("TauriMeridianClientAdapter — verification (GAP: no backing command)", () => {
  it("safetyNumber always fails closed with 'unavailable'", async () => {
    const adapter = await makeAdapter();
    await expect(adapter.safetyNumber(BOB_ID)).rejects.toBeInstanceOf(MeridianAdapterError);
    await expect(adapter.safetyNumber(BOB_ID)).rejects.toMatchObject({ code: "unavailable" });
  });

  it("markVerified invokes contact_mark_verified", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd, args) => {
      if (cmd === "contact_mark_verified") {
        expect(args).toEqual({ id: BOB_ID });
        return Promise.resolve({ ...BOB_CONTACT_VIEW, state: "verified" });
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    await adapter.markVerified(BOB_ID);
  });
});

describe("TauriMeridianClientAdapter — streams / file ops (GAPs: generic streams, Blob->path)", () => {
  it("openStream supports mrd.file/1 with a {path} param by delegating to file_send", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd, args) => {
      if (cmd === "file_send") {
        expect(args).toEqual({ peerId: BOB_ID, path: "/tmp/notes.txt" });
        return Promise.resolve({ name: "notes.txt", root_hex: "abcd" });
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    const result = await adapter.openStream(BOB_ID, "mrd.file/1", { path: "/tmp/notes.txt" });
    expect(result.streamId).toBeTruthy();
  });

  it("openStream rejects any other stream type with 'unavailable' (no generic command exists)", async () => {
    const adapter = await makeAdapter();
    await expect(adapter.openStream(BOB_ID, "mrd.custom/1", {})).rejects.toMatchObject({
      code: "unavailable",
    });
  });

  it("sendFile rejects a plain Blob with no filesystem path", async () => {
    const adapter = await makeAdapter();
    const blob = new Blob(["hello"], { type: "text/plain" });
    await expect(adapter.sendFile(BOB_ID, blob, "notes.txt")).rejects.toMatchObject({
      code: "unavailable",
    });
  });

  it("sendFile succeeds when the Blob-like object exposes a .path (native file-picker shape)", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd, args) => {
      if (cmd === "file_send") {
        expect(args).toEqual({ peerId: BOB_ID, path: "/tmp/notes.txt" });
        return Promise.resolve({ name: "notes.txt", root_hex: "abcd" });
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    const fileLike = Object.assign(new Blob(["hello"]), { path: "/tmp/notes.txt" });
    const result = await adapter.sendFile(BOB_ID, fileLike, "notes.txt");
    expect(result.streamId).toBeTruthy();

    const transfers = await adapter.listTransfers();
    expect(transfers).toHaveLength(1);
    expect(transfers[0]).toMatchObject({ peer: BOB_ID, fileName: "notes.txt", state: "complete" });
  });

  it("onStreamFrame registers/unregisters a listener that this command surface never fires (documented GAP)", async () => {
    const adapter = await makeAdapter();
    const cb = vi.fn();
    const unsubscribe = adapter.onStreamFrame(cb);
    unsubscribe();
    expect(cb).not.toHaveBeenCalled();
  });

  it("file:incoming/file:progress/file:received events materialize a transfer client-side", async () => {
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "session_get") return Promise.resolve(null);
      if (cmd === "session_connect") {
        return Promise.resolve({ peer_pubkey_hex: BOB_PUBKEY_HEX, transport: "loopback", path: "direct", streams: [] });
      }
      throw new Error(`unmocked: ${cmd}`);
    });
    await adapter.openConversation(BOB_ID);

    emit("file:incoming", { peer_pubkey_hex: BOB_PUBKEY_HEX, name: "pic.png", size: 1000 });
    emit("file:progress", { peer_pubkey_hex: BOB_PUBKEY_HEX, name: "pic.png", bytes_sent: 500, total_bytes: 1000, bytes_per_sec: 500 });
    let transfers = await adapter.listTransfers();
    expect(transfers[0]).toMatchObject({ peer: BOB_ID, fileName: "pic.png", state: "in_progress", transferredBytes: 500 });

    emit("file:received", { peer_pubkey_hex: BOB_PUBKEY_HEX, name: "pic.png", root_hex: "beef", path: "/downloads/pic.png" });
    transfers = await adapter.listTransfers();
    expect(transfers[0]).toMatchObject({ state: "complete" });
  });
});

describe("TauriMeridianClientAdapter — dispose", () => {
  it("stops pump timers and releases listeners", async () => {
    vi.useFakeTimers();
    const adapter = await makeAdapter();
    invokeMock.mockImplementation((cmd) => {
      if (cmd === "session_get") return Promise.resolve(null);
      if (cmd === "session_connect") {
        return Promise.resolve({ peer_pubkey_hex: BOB_PUBKEY_HEX, transport: "loopback", path: "direct", streams: [] });
      }
      if (cmd === "pump_once") return Promise.resolve(null);
      throw new Error(`unmocked: ${cmd}`);
    });
    await adapter.openConversation(BOB_ID);
    adapter.dispose();
    invokeMock.mockClear();
    await vi.advanceTimersByTimeAsync(1000);
    expect(invokeMock).not.toHaveBeenCalled();
  });
});
