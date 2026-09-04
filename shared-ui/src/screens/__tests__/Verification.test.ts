/**
 * Component tests for {@link ../Verification.svelte}. Camera access is mocked via a fake
 * {@link QrScanner} (task 12.8 Deliverables: "camera access itself mocked, not exercised in this
 * task's own test suite") — no real `navigator.mediaDevices`/jsQR call happens here. The
 * match/mismatch/invalid comparison logic itself is exercised in full against real T08 fixtures in
 * `../stores/verificationStore.test.ts`; these tests instead prove the screen wires that logic up
 * correctly end to end — in particular, that `markVerified` is reachable ONLY through a rendered
 * "Mark verified" button that only exists in the `"match"` state.
 */

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";

import type { QrScanner } from "../../lib/qrScanner";
import { FakeMeridianClientAdapter } from "../../lib/fake-adapter";
import Verification from "../Verification.svelte";

afterEach(() => cleanup());

const peer = "mrd1:deadbeef@bob.example";

async function newAdapter(): Promise<FakeMeridianClientAdapter> {
  const adapter = new FakeMeridianClientAdapter();
  await adapter.generateAccount("me.example");
  await adapter.addContact(peer, "Bob");
  return adapter;
}

/** Deterministic fake scanner: `start` records the decode callback (never touching a real camera)
 * and exposes {@link emit}/{@link failStart} so a test can drive it directly. */
class FakeQrScanner implements QrScanner {
  private onDecode: ((text: string) => void) | null = null;
  startCount = 0;
  stopCount = 0;
  private startError: Error | null = null;

  async start(_video: HTMLVideoElement, onDecode: (text: string) => void): Promise<void> {
    this.startCount += 1;
    if (this.startError) throw this.startError;
    this.onDecode = onDecode;
  }

  stop(): void {
    this.stopCount += 1;
  }

  /** Simulates a fully decoded QR frame — the only way this fake ever delivers scanned text,
   * mirroring the real `QrScanner`'s contract that `onDecode` only ever fires for a complete
   * decode, never a partial one (see `qrScanner.ts`'s own doc comment). */
  emit(text: string): void {
    this.onDecode?.(text);
  }

  failNextStart(message: string): void {
    this.startError = new Error(message);
  }
}

describe("Verification screen — local safety number display", () => {
  it("renders the local safety number (grouped) and a QR image once loaded", async () => {
    const adapter = await newAdapter();
    const scanner = new FakeQrScanner();
    render(Verification, { props: { adapter, peer, scanner } });

    const expected = await adapter.safetyNumber(peer);
    const grouped = await screen.findByTestId("local-safety-number");
    expect(grouped.textContent).toBe(expected.grouped);

    await waitFor(() => {
      const qr = screen.getByTestId("qr-code");
      expect(qr.querySelector("svg")).toBeTruthy();
    });
  });
});

describe("Verification screen — D06 safety-critical scan → markVerified gating", () => {
  it("an exact-match scan shows the match state and enables Mark verified; clicking it calls markVerified", async () => {
    const adapter = await newAdapter();
    const scanner = new FakeQrScanner();
    render(Verification, { props: { adapter, peer, scanner } });

    await screen.findByTestId("local-safety-number");
    const expected = await adapter.safetyNumber(peer);

    await fireEvent.click(screen.getByTestId("start-scan"));
    await waitFor(() => expect(scanner.startCount).toBe(1));

    scanner.emit(expected.raw);

    await screen.findByTestId("scan-result-match");
    expect(screen.queryByTestId("scan-result-mismatch")).toBeNull();
    expect(screen.queryByTestId("scan-result-invalid")).toBeNull();

    expect(await adapter.trustState(peer)).not.toBe("verified");

    await fireEvent.click(screen.getByTestId("mark-verified"));

    await waitFor(async () => {
      expect(await adapter.trustState(peer)).toBe("verified");
    });
    await screen.findByTestId("verified-banner");
  });

  it("a mismatched scan (different but well-formed safety number) never shows Mark verified and never calls markVerified", async () => {
    const adapter = await newAdapter();
    const scanner = new FakeQrScanner();
    render(Verification, { props: { adapter, peer, scanner } });

    await screen.findByTestId("local-safety-number");

    await fireEvent.click(screen.getByTestId("start-scan"));
    await waitFor(() => expect(scanner.startCount).toBe(1));

    // A well-formed 60-digit number, but a *different* one — e.g. read from a different (wrong)
    // device or a substituted/attacker QR.
    const wrongButWellFormed = "9".repeat(60);
    scanner.emit(wrongButWellFormed);

    await screen.findByTestId("scan-result-mismatch");
    expect(screen.queryByTestId("mark-verified")).toBeNull();
    expect(await adapter.trustState(peer)).not.toBe("verified");
  });

  it.each([
    ["a truncated/partial scan", "12345"],
    ["garbage (non-numeric)", "not-a-real-safety-number-at-all-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
    ["an empty decode", ""],
  ])(
    "%s never shows Mark verified and is reported as an invalid scan, not a mismatch or a match",
    async (_label, decoded) => {
      const adapter = await newAdapter();
      const scanner = new FakeQrScanner();
      render(Verification, { props: { adapter, peer, scanner } });

      await screen.findByTestId("local-safety-number");
      await fireEvent.click(screen.getByTestId("start-scan"));
      await waitFor(() => expect(scanner.startCount).toBe(1));

      scanner.emit(decoded);

      await screen.findByTestId("scan-result-invalid");
      expect(screen.queryByTestId("mark-verified")).toBeNull();
      expect(screen.queryByTestId("scan-result-match")).toBeNull();
      expect(screen.queryByTestId("scan-result-mismatch")).toBeNull();
      expect(await adapter.trustState(peer)).not.toBe("verified");
    },
  );

  it("a camera/permission failure surfaces an error and never reaches a scan result or Mark verified", async () => {
    const adapter = await newAdapter();
    const scanner = new FakeQrScanner();
    scanner.failNextStart("Permission denied");
    render(Verification, { props: { adapter, peer, scanner } });

    await screen.findByTestId("local-safety-number");
    await fireEvent.click(screen.getByTestId("start-scan"));

    await screen.findByTestId("camera-error");
    expect(screen.queryByTestId("mark-verified")).toBeNull();
    expect(screen.queryByTestId("scan-result-match")).toBeNull();
    expect(await adapter.trustState(peer)).not.toBe("verified");
  });

  it("cancelling an in-progress scan stops the scanner and shows no result", async () => {
    const adapter = await newAdapter();
    const scanner = new FakeQrScanner();
    render(Verification, { props: { adapter, peer, scanner } });

    await screen.findByTestId("local-safety-number");
    await fireEvent.click(screen.getByTestId("start-scan"));
    await waitFor(() => expect(scanner.startCount).toBe(1));

    await fireEvent.click(screen.getByTestId("stop-scan"));

    expect(scanner.stopCount).toBe(1);
    expect(screen.queryByTestId("mark-verified")).toBeNull();
    expect(screen.queryByTestId("scan-result-match")).toBeNull();
  });

  it("a match found after a prior invalid scan (rescan) still requires the fresh scan to itself be exact — stale invalid state never counts as a match", async () => {
    const adapter = await newAdapter();
    const scanner = new FakeQrScanner();
    render(Verification, { props: { adapter, peer, scanner } });

    await screen.findByTestId("local-safety-number");
    const expected = await adapter.safetyNumber(peer);

    await fireEvent.click(screen.getByTestId("start-scan"));
    await waitFor(() => expect(scanner.startCount).toBe(1));
    scanner.emit("garbage-not-a-number");
    await screen.findByTestId("scan-result-invalid");
    expect(screen.queryByTestId("mark-verified")).toBeNull();

    await fireEvent.click(screen.getByTestId("rescan"));
    await waitFor(() => expect(scanner.startCount).toBe(2));
    scanner.emit(expected.raw);

    await screen.findByTestId("scan-result-match");
    await fireEvent.click(screen.getByTestId("mark-verified"));
    await waitFor(async () => {
      expect(await adapter.trustState(peer)).toBe("verified");
    });
  });
});
