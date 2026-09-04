import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";

import { FakeMeridianClientAdapter } from "../../lib/fake-adapter";
import FileTransfer from "../FileTransfer.svelte";

afterEach(() => cleanup());

const peer = "mrd1:cafef00d@carol.example";

async function newAdapter(): Promise<FakeMeridianClientAdapter> {
  const adapter = new FakeMeridianClientAdapter();
  await adapter.generateAccount("me.example");
  await adapter.addContact(peer, "Carol");
  return adapter;
}

describe("FileTransfer screen — drag-drop / file-picker send (send-initiate)", () => {
  it("dropping a file on the dropzone sends it and it appears complete in the transfer list", async () => {
    const adapter = await newAdapter();
    render(FileTransfer, { props: { adapter, peer } });
    await screen.findByText("No transfers with this contact yet.");

    const file = new File(["hello world"], "notes.txt", { type: "text/plain" });
    const dropzone = screen.getByTestId("dropzone");
    await fireEvent.drop(dropzone, { dataTransfer: { files: [file] } });

    const row = await screen.findByText("notes.txt");
    const li = row.closest("li") as HTMLElement;
    expect(within(li).getByTestId("transfer-state").textContent).toBe("Complete");
    expect(within(li).getByTestId("transfer-percent").textContent).toBe("100%");

    const transfers = await adapter.listTransfers();
    expect(transfers).toHaveLength(1);
    expect(transfers[0]).toMatchObject({ peer, fileName: "notes.txt", direction: "out", state: "complete" });
  });

  it("choosing a file via the hidden file input also sends it", async () => {
    const adapter = await newAdapter();
    render(FileTransfer, { props: { adapter, peer } });
    await screen.findByText("No transfers with this contact yet.");

    const file = new File(["some bytes"], "photo.png", { type: "image/png" });
    const input = screen.getByTestId("file-input") as HTMLInputElement;
    await fireEvent.change(input, { target: { files: [file] } });

    await screen.findByText("photo.png");
    const transfers = await adapter.listTransfers();
    expect(transfers.map((t) => t.fileName)).toContain("photo.png");
  });

  it("does not send anything, and shows no transfer, until a file is actually provided", async () => {
    const adapter = await newAdapter();
    render(FileTransfer, { props: { adapter, peer } });
    await screen.findByText("No transfers with this contact yet.");

    expect(await adapter.listTransfers()).toEqual([]);
  });
});

describe("FileTransfer screen — progress updates", () => {
  it("renders progress as an accepted incoming transfer advances, without claiming more than the adapter reports", async () => {
    const adapter = await newAdapter();
    const streamId = adapter.simulateIncomingTransferOffer(peer, "vacation.mp4", 1000);

    render(FileTransfer, { props: { adapter, peer } });
    await screen.findByText("vacation.mp4");

    await fireEvent.click(screen.getByTestId("accept-transfer"));
    await waitFor(async () => {
      expect((await adapter.listTransfers())[0]?.state).toBe("in_progress");
    });

    // No live push channel exists (see fileTransferStore.ts's own doc comment) — progress only
    // advances once the adapter is asked again via refresh().
    adapter.simulateTransferProgress(streamId, 380);
    await fireEvent.click(screen.getByTestId("refresh"));

    await waitFor(() => {
      expect(screen.getByTestId("transfer-percent").textContent).toBe("38%");
    });
    expect(screen.getByTestId("transfer-state").textContent).toBe("In progress");

    adapter.simulateTransferProgress(streamId, 1000, "complete");
    await fireEvent.click(screen.getByTestId("refresh"));

    await waitFor(() => {
      expect(screen.getByTestId("transfer-percent").textContent).toBe("100%");
    });
    // "Complete" only — never a stronger, unearned claim like "verified" or "corruption-free".
    expect(screen.getByTestId("transfer-state").textContent).toBe("Complete");
  });
});

describe("FileTransfer screen — receive prompt: accept", () => {
  it("an incoming offer renders a prompt, and accepting it moves the transfer out of the offered state", async () => {
    const adapter = await newAdapter();
    const streamId = adapter.simulateIncomingTransferOffer(peer, "resume.pdf", 2048);

    render(FileTransfer, { props: { adapter, peer } });

    const prompt = await screen.findByTestId("offer-prompt");
    expect(prompt.textContent).toContain("resume.pdf");
    expect(screen.getByTestId("transfer-state").textContent).toBe("Awaiting your decision");

    await fireEvent.click(screen.getByTestId("accept-transfer"));

    await waitFor(() => {
      expect(screen.queryByTestId("offer-prompt")).toBeNull();
    });
    expect(screen.getByTestId("transfer-state").textContent).toBe("In progress");

    const transfers = await adapter.listTransfers();
    expect(transfers.find((t) => t.streamId === streamId)).toMatchObject({ state: "in_progress" });
  });
});

describe("FileTransfer screen — receive prompt: reject", () => {
  it("rejecting an incoming offer marks it rejected and removes the prompt", async () => {
    const adapter = await newAdapter();
    const streamId = adapter.simulateIncomingTransferOffer(peer, "unwanted.exe", 500);

    render(FileTransfer, { props: { adapter, peer } });
    await screen.findByTestId("offer-prompt");

    await fireEvent.click(screen.getByTestId("reject-transfer"));

    await waitFor(() => {
      expect(screen.queryByTestId("offer-prompt")).toBeNull();
    });
    expect(screen.getByTestId("transfer-state").textContent).toBe("Rejected");

    const transfers = await adapter.listTransfers();
    expect(transfers.find((t) => t.streamId === streamId)).toMatchObject({ state: "rejected" });

    // Rejecting again is refused — not a silently-repeatable action.
    await expect(adapter.rejectTransfer(streamId)).rejects.toThrow();
  });
});
