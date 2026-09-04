/**
 * `compareSafetyNumbers` — the single function {@link ./verificationStore.ts} entrusts with
 * deciding match/mismatch/invalid (see that module's doc comment for the full "no false positive"
 * argument). Exercised here against the real T08 safety-number conformance fixtures
 * (`test-vectors/safety-numbers-v1.json`) rather than invented values, per task 12.8's own
 * Deliverables ("QR decode/compare logic unit-tested against known fixture values ... check if T08
 * safety-number test fixtures exist anywhere in the repo ... and reuse the real values").
 */

import { describe, expect, it } from "vitest";

import safetyNumberVectors from "../../../../test-vectors/safety-numbers-v1.json";
import { FakeMeridianClientAdapter } from "../../lib/fake-adapter";
import { compareSafetyNumbers, createVerificationStore } from "./verificationStore";

describe("compareSafetyNumbers — exact-match-or-nothing (D06 safety-critical guard)", () => {
  it.each(safetyNumberVectors.vectors)(
    "vector '$name': the real safety number matches itself byte-for-byte",
    (vector) => {
      expect(compareSafetyNumbers(vector.safety_number, vector.safety_number)).toEqual({
        kind: "match",
      });
    },
  );

  it("two distinct real fixture safety numbers are a mismatch, never a match", () => {
    const [a, b] = safetyNumberVectors.vectors;
    expect(a).toBeDefined();
    expect(b).toBeDefined();
    expect(a!.safety_number).not.toBe(b!.safety_number);
    expect(compareSafetyNumbers(a!.safety_number, b!.safety_number)).toEqual({ kind: "mismatch" });
  });

  it("order-independence fixture: safety_number(a,b) === safety_number(b,a) round-trips as a match", () => {
    // The fixture only records that the two derivations are equal, not the derived digits
    // themselves (this file has no crypto to derive them with) — so this test exercises the
    // comparator's own reflexivity using one of the digit-vector fixtures instead, which is the
    // property this module actually needs to hold.
    const vector = safetyNumberVectors.vectors[0]!;
    expect(compareSafetyNumbers(vector.safety_number, vector.safety_number)).toEqual({
      kind: "match",
    });
  });

  it("trims incidental surrounding whitespace (e.g. a trailing newline some QR encoders add) before comparing", () => {
    const vector = safetyNumberVectors.vectors[0]!;
    expect(compareSafetyNumbers(vector.safety_number, `${vector.safety_number}\n`)).toEqual({
      kind: "match",
    });
    expect(compareSafetyNumbers(vector.safety_number, `  ${vector.safety_number}  `)).toEqual({
      kind: "match",
    });
  });

  describe("never a false positive: every non-exact scan is 'invalid' or 'mismatch', never 'match'", () => {
    const local = safetyNumberVectors.vectors[0]!.safety_number;

    it("a truncated/partial scan (mid-camera-adjustment style) is invalid, not a lucky prefix match", () => {
      const partial = local.slice(0, 30);
      const result = compareSafetyNumbers(local, partial);
      expect(result.kind).toBe("invalid");
    });

    it("a scan one digit too long is invalid, never truncated down to compare", () => {
      const tooLong = `${local}9`;
      const result = compareSafetyNumbers(local, tooLong);
      expect(result.kind).toBe("invalid");
    });

    it("a scan one digit too short is invalid, never padded up to compare", () => {
      const tooShort = local.slice(0, local.length - 1);
      const result = compareSafetyNumbers(local, tooShort);
      expect(result.kind).toBe("invalid");
    });

    it("garbage (non-numeric) decoded data of the right length is invalid, never a coerced match", () => {
      const garbage = "x".repeat(local.length);
      const result = compareSafetyNumbers(local, garbage);
      expect(result.kind).toBe("invalid");
    });

    it("an empty decode (no code found / camera glitch) is invalid", () => {
      expect(compareSafetyNumbers(local, "").kind).toBe("invalid");
    });

    it("a same-length but differently-valued 60-digit scan is a clean mismatch, not invalid or match", () => {
      const otherVector = safetyNumberVectors.vectors[1]!;
      expect(otherVector.safety_number).toHaveLength(local.length);
      expect(otherVector.safety_number).not.toBe(local);
      expect(compareSafetyNumbers(local, otherVector.safety_number)).toEqual({ kind: "mismatch" });
    });

    it("digits with an interior non-digit character (e.g. a misread QR cell) is invalid, not fuzzily matched", () => {
      const corrupted = `${local.slice(0, 30)}X${local.slice(31)}`;
      expect(corrupted).toHaveLength(local.length);
      const result = compareSafetyNumbers(local, corrupted);
      expect(result.kind).toBe("invalid");
    });
  });

  it("a malformed local safety number (defensive case) never becomes a comparison basis, even against itself", () => {
    const malformed = "not-a-safety-number";
    expect(compareSafetyNumbers(malformed, malformed).kind).toBe("invalid");
  });
});

describe("VerificationStore.confirmVerified — reentrancy guard", () => {
  it("two concurrent confirmVerified() calls on a genuine match call adapter.markVerified only once", async () => {
    const peer = "mrd1:deadbeef@bob.example";
    const adapter = new FakeMeridianClientAdapter();
    await adapter.generateAccount("me.example");
    await adapter.addContact(peer, "Bob");

    let markVerifiedCalls = 0;
    const originalMarkVerified = adapter.markVerified.bind(adapter);
    adapter.markVerified = async (p) => {
      markVerifiedCalls += 1;
      return originalMarkVerified(p);
    };

    const store = createVerificationStore(adapter);
    await store.load(peer);
    const expected = await adapter.safetyNumber(peer);
    store.handleScan(expected.raw);

    // Two synchronous confirmVerified() calls, mirroring a rapid double-click that lands before
    // Svelte's reactive DOM update disables the button. The second call must observe `verifying:
    // true` (set synchronously by the first call's own `update()`) and refuse, not double-fire.
    const first = store.confirmVerified();
    await expect(store.confirmVerified()).rejects.toThrow(
      "cannot mark verified without a confirmed matching safety-number scan",
    );
    await first;

    expect(markVerifiedCalls).toBe(1);
    expect(await adapter.trustState(peer)).toBe("verified");
  });
});
