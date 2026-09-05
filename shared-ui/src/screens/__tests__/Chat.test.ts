import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";

import { MeridianAdapterError } from "../../lib/adapter";
import { FakeMeridianClientAdapter } from "../../lib/fake-adapter";
import Chat from "../Chat.svelte";

/** Task 12.14 regression fixture — an `openConversation()` that always fails closed, the same
 * shape `apps/web/src/lib/adapter.ts`'s real `WasmMeridianClientAdapter` returns today (no
 * session/chat orchestration binding exists yet). Confirms this screen surfaces `$store.error`
 * rather than rendering an indistinguishable "No messages yet." for a failed open (the bug 12.14
 * found and fixed in `Chat.svelte` itself). */
class FailingOpenAdapter extends FakeMeridianClientAdapter {
  async openConversation(): ReturnType<FakeMeridianClientAdapter["openConversation"]> {
    throw new MeridianAdapterError("unavailable", "openConversation: no session orchestration exists");
  }
}

afterEach(() => cleanup());

const peer = "mrd1:deadbeef@bob.example";

async function newAdapter(): Promise<FakeMeridianClientAdapter> {
  const adapter = new FakeMeridianClientAdapter();
  await adapter.generateAccount("me.example");
  return adapter;
}

async function sendMessage(body: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Message"), { target: { value: body } });
  await fireEvent.click(screen.getByRole("button", { name: /^send$/i }));
}

describe("Chat screen — send/receive", () => {
  it("sending a message renders it in the transcript as outbound", async () => {
    const adapter = await newAdapter();
    render(Chat, { props: { adapter, peer } });

    await waitFor(() => expect(screen.getByLabelText("Message")).toBeTruthy());
    await sendMessage("hello bob");

    await waitFor(async () => {
      const history = await adapter.loadHistory(peer);
      expect(history).toHaveLength(1);
    });
    const bubble = await screen.findByText("hello bob");
    expect(bubble.closest(".message-out")).toBeTruthy();
  });

  it("an incoming message from the open peer renders as inbound", async () => {
    const adapter = await newAdapter();
    render(Chat, { props: { adapter, peer } });
    await waitFor(() => expect(screen.getByLabelText("Message")).toBeTruthy());

    adapter.simulateIncomingMessage(peer, "hi there");

    const bubble = await screen.findByText("hi there");
    expect(bubble.closest(".message-in")).toBeTruthy();
  });

  it("the composer clears after a successful send", async () => {
    const adapter = await newAdapter();
    render(Chat, { props: { adapter, peer } });
    await waitFor(() => expect(screen.getByLabelText("Message")).toBeTruthy());

    await sendMessage("clears me");
    await waitFor(() => {
      const textarea = screen.getByLabelText("Message") as HTMLTextAreaElement;
      expect(textarea.value).toBe("");
    });
  });

  it("the send button is disabled while the composer is empty", async () => {
    const adapter = await newAdapter();
    render(Chat, { props: { adapter, peer } });
    await waitFor(() => expect(screen.getByLabelText("Message")).toBeTruthy());
    expect((screen.getByRole("button", { name: /^send$/i }) as HTMLButtonElement).disabled).toBe(
      true,
    );
  });
});

describe("Chat screen — fail-closed adapter errors (task 12.14)", () => {
  it("a failed openConversation renders the adapter's error, not a silent empty transcript", async () => {
    const adapter = new FailingOpenAdapter();
    await adapter.generateAccount("me.example");
    render(Chat, { props: { adapter, peer } });

    const alert = await screen.findByTestId("chat-error");
    expect(alert.textContent).toMatch(/no session orchestration/i);
  });
});

describe("Chat screen — block-on-verified / D06 send-gate enforcement (UI layer)", () => {
  it("a blocked contact's composer is disabled, shows the blocked reason, and no send reaches the adapter", async () => {
    const adapter = await newAdapter();
    await adapter.addContact(peer, "Bob");
    await adapter.blockContact(peer);
    expect((await adapter.sendGateState(peer)).kind).toBe("blocked");

    render(Chat, { props: { adapter, peer } });

    const banner = await screen.findByTestId("send-gate-blocked");
    expect(banner.textContent).toMatch(/blocked/i);

    const textarea = (await screen.findByLabelText("Message")) as HTMLTextAreaElement;
    expect(textarea.disabled).toBe(true);

    const sendButton = screen.getByRole("button", { name: /^send$/i }) as HTMLButtonElement;
    expect(sendButton.disabled).toBe(true);

    // Belt-and-suspenders: even if some future regression re-enabled the button, clicking it must
    // not reach the adapter — assert history stays empty either way.
    await fireEvent.click(sendButton);
    expect(await adapter.loadHistory(peer)).toEqual([]);
  });

  it("a key-changed (unverified) contact shows a warn banner, and sending is refused until acknowledged", async () => {
    const adapter = await newAdapter();
    await adapter.addContact(peer, "Bob");
    adapter.simulateSendGate(peer, { kind: "warn", reason: "key changed" });

    render(Chat, { props: { adapter, peer } });

    await screen.findByTestId("send-gate-warn");
    const sendButton = screen.getByRole("button", { name: /^send$/i }) as HTMLButtonElement;

    await fireEvent.input(screen.getByLabelText("Message"), { target: { value: "still safe?" } });
    expect(sendButton.disabled).toBe(true);
    expect(await adapter.loadHistory(peer)).toEqual([]);

    await fireEvent.click(screen.getByRole("button", { name: /acknowledge and re-pin/i }));

    await waitFor(() => {
      expect(screen.queryByTestId("send-gate-warn")).toBeNull();
    });
    await waitFor(() => {
      expect((screen.getByRole("button", { name: /^send$/i }) as HTMLButtonElement).disabled).toBe(
        false,
      );
    });

    await fireEvent.click(screen.getByRole("button", { name: /^send$/i }));
    await waitFor(async () => {
      expect(await adapter.loadHistory(peer)).toHaveLength(1);
    });
  });

  it("blocking a contact mid-conversation (e.g. from another screen) is caught by the pre-send re-check even if a stale render slipped through", async () => {
    // Regression guard for chatStore's own documented defense-in-depth: send() re-reads
    // sendGateState immediately before sendChat, rather than trusting the last-rendered gate.
    const adapter = await newAdapter();
    render(Chat, { props: { adapter, peer } });
    await waitFor(() => expect(screen.getByLabelText("Message")).toBeTruthy());

    await fireEvent.input(screen.getByLabelText("Message"), { target: { value: "typed before block" } });

    // Simulate another tab/screen blocking the contact after this screen last rendered the gate,
    // but before the user's in-flight click resolves the store's own re-check.
    await adapter.blockContact(peer);

    await fireEvent.click(screen.getByRole("button", { name: /^send$/i }));

    await waitFor(async () => {
      expect(await adapter.loadHistory(peer)).toEqual([]);
    });
    await waitFor(() => {
      expect(screen.getByTestId("send-gate-blocked")).toBeTruthy();
    });
  });
});
