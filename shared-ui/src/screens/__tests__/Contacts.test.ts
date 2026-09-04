import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";

import { FakeMeridianClientAdapter } from "../../lib/fake-adapter";
import Contacts from "../Contacts.svelte";

afterEach(() => cleanup());

async function newAdapter(): Promise<FakeMeridianClientAdapter> {
  const adapter = new FakeMeridianClientAdapter();
  await adapter.generateAccount("me.example");
  return adapter;
}

describe("Contacts screen", () => {
  it("shows an empty state with no contacts", async () => {
    const adapter = await newAdapter();
    render(Contacts, { props: { adapter } });
    expect(await screen.findByText("No contacts yet.")).toBeTruthy();
  });

  it("lists existing contacts on mount", async () => {
    const adapter = await newAdapter();
    await adapter.addContact("mrd1:deadbeef@bob.example", "Bob");
    render(Contacts, { props: { adapter } });
    expect(await screen.findByText("Bob")).toBeTruthy();
  });

  it("adding a contact via the form pins it and renders it in the list", async () => {
    const adapter = await newAdapter();
    render(Contacts, { props: { adapter } });
    await screen.findByText("No contacts yet.");

    await fireEvent.input(screen.getByLabelText("Contact id"), {
      target: { value: "mrd1:deadbeef@carol.example" },
    });
    await fireEvent.input(screen.getByLabelText("Petname (optional)"), {
      target: { value: "Carol" },
    });
    await fireEvent.click(screen.getByRole("button", { name: /add contact/i }));

    expect(await screen.findByText("Carol")).toBeTruthy();
    const contacts = await adapter.listContacts();
    expect(contacts).toHaveLength(1);
    expect(contacts[0]).toMatchObject({ id: "mrd1:deadbeef@carol.example", petname: "Carol" });
  });

  it("selecting a row fires onSelect with the contact's id", async () => {
    const adapter = await newAdapter();
    const peer = "mrd1:deadbeef@bob.example";
    await adapter.addContact(peer, "Bob");
    let selected: string | null = null;

    render(Contacts, { props: { adapter, onSelect: (p: string) => (selected = p) } });
    const row = await screen.findByText("Bob");
    await fireEvent.click(row);

    expect(selected).toBe(peer);
  });
});
