import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";

import { FakeMeridianClientAdapter } from "../../lib/fake-adapter";
import MessageRequests from "../MessageRequests.svelte";

afterEach(() => cleanup());

const from = "mrd1:cafef00d@carol.example";

async function newAdapter(): Promise<FakeMeridianClientAdapter> {
  const adapter = new FakeMeridianClientAdapter();
  await adapter.generateAccount("me.example");
  return adapter;
}

describe("MessageRequests screen", () => {
  it("shows an empty state with no pending requests", async () => {
    const adapter = await newAdapter();
    render(MessageRequests, { props: { adapter } });
    expect(await screen.findByText("No pending requests.")).toBeTruthy();
  });

  it("a simulated incoming request renders with its safety number and intro", async () => {
    const adapter = await newAdapter();
    render(MessageRequests, { props: { adapter } });
    await screen.findByText("No pending requests.");

    adapter.simulateIncomingRequest(from, "hi, it's carol");

    expect(await screen.findByText(from)).toBeTruthy();
    expect(await screen.findByText("hi, it's carol")).toBeTruthy();
  });

  it("accepting a request pins the contact, delivers the intro, and removes it from the queue", async () => {
    const adapter = await newAdapter();
    render(MessageRequests, { props: { adapter } });
    adapter.simulateIncomingRequest(from, "hi, it's carol");
    await screen.findByText(from);

    await fireEvent.click(screen.getByRole("button", { name: /accept/i }));

    await waitFor(() => expect(screen.queryByText(from)).toBeNull());
    const contacts = await adapter.listContacts();
    expect(contacts).toHaveLength(1);
    expect(contacts[0]).toMatchObject({ id: from, trust: "pinned" });

    const history = await adapter.loadHistory(from);
    expect(history[0]).toMatchObject({ direction: "in", body: "hi, it's carol" });
  });

  it("fires onAccepted with the sender's id", async () => {
    const adapter = await newAdapter();
    let acceptedPeer: string | null = null;
    render(MessageRequests, { props: { adapter, onAccepted: (p: string) => (acceptedPeer = p) } });
    adapter.simulateIncomingRequest(from, "hi, it's carol");
    await screen.findByText(from);

    await fireEvent.click(screen.getByRole("button", { name: /accept/i }));
    await waitFor(() => expect(acceptedPeer).toBe(from));
  });

  it("rejecting requires confirmation, then leaves no trace in the contact list", async () => {
    const adapter = await newAdapter();
    render(MessageRequests, { props: { adapter } });
    adapter.simulateIncomingRequest(from, "hi, it's carol");
    await screen.findByText(from);

    await fireEvent.click(screen.getByRole("button", { name: /^reject$/i }));
    // Still visible until confirmed — the request has not been discarded by a single click.
    expect(screen.getByText(from)).toBeTruthy();

    await fireEvent.click(screen.getByRole("button", { name: /confirm reject/i }));

    await waitFor(() => expect(screen.queryByText(from)).toBeNull());
    expect(await adapter.listContacts()).toEqual([]);
  });

  it("canceling a reject confirmation leaves the request pending", async () => {
    const adapter = await newAdapter();
    render(MessageRequests, { props: { adapter } });
    adapter.simulateIncomingRequest(from, "hi, it's carol");
    await screen.findByText(from);

    await fireEvent.click(screen.getByRole("button", { name: /^reject$/i }));
    await fireEvent.click(screen.getByRole("button", { name: /cancel/i }));

    expect(screen.getByText(from)).toBeTruthy();
    expect(await adapter.listContacts()).toEqual([]);
  });
});
