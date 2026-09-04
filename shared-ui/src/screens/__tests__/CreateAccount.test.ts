import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";

import { FakeMeridianClientAdapter } from "../../lib/fake-adapter";
import CreateAccount from "../CreateAccount.svelte";

afterEach(() => cleanup());

describe("CreateAccount screen", () => {
  it("creating an account with a routing hint sets the adapter's current account and shows the id", async () => {
    const adapter = new FakeMeridianClientAdapter();
    expect(adapter.currentAccount()).toBeNull();

    render(CreateAccount, { props: { adapter } });

    const hintInput = screen.getByLabelText("Routing hint");
    await fireEvent.input(hintInput, { target: { value: "example.org" } });
    await fireEvent.click(screen.getByRole("button", { name: /create account/i }));

    const success = await screen.findByRole("status");
    expect(success.textContent).toContain("Account created");
    expect(adapter.currentAccount()).not.toBeNull();
    expect(adapter.currentAccount()).toMatch(/@example\.org$/);
  });

  it("fires onCreated with the new account id", async () => {
    const adapter = new FakeMeridianClientAdapter();
    let created: string | null = null;

    render(CreateAccount, {
      props: { adapter, onCreated: (id: string) => (created = id) },
    });

    await fireEvent.input(screen.getByLabelText("Routing hint"), {
      target: { value: "example.org" },
    });
    await fireEvent.click(screen.getByRole("button", { name: /create account/i }));

    await screen.findByRole("status");
    expect(created).toBe(adapter.currentAccount());
  });

  it("the submit button stays disabled until a hint is entered", () => {
    const adapter = new FakeMeridianClientAdapter();
    render(CreateAccount, { props: { adapter } });
    const button = screen.getByRole("button", { name: /create account/i }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
  });
});
