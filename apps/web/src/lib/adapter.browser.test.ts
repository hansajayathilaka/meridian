/**
 * `WasmMeridianClientAdapter` integration tests — task 12.13 Deliverable 2. Runs in a **real**
 * headless Chromium (Vitest browser mode / Playwright provider, see `vitest.config.ts`'s own doc
 * comment for why), never a Node/jsdom polyfill: this is the first task where genuine
 * `crypto.subtle`/`RTCPeerConnection` behavior actually matters end to end.
 *
 * Three groups, matching the task file's Deliverable 2 wording, plus this task's own honest
 * findings where that wording's literal positive scenario is not reachable against today's real
 * `meridian-wasm` bindings (see `adapter.ts`'s own top doc comment for the full report):
 *
 * 1. **Account creation** — real, via `WasmMeridianClientAdapter.generateAccount` (genuine
 *    `crypto.subtle` key generation) plus a direct `meridian-wasm` sign/verify round trip (the
 *    adapter interface itself deliberately excludes raw sign/verify, per its own top doc comment,
 *    so this checks the underlying binding directly, the same way `apps/wasm/tests/
 *    webcrypto_account.rs`'s Rust-side suite does — from the TS layer, which that suite cannot
 *    reach).
 * 2. **"Survives a simulated reload"** — a second adapter instance (a fresh page load never shares
 *    JS heap with the first) does *not* regain the first account, and `openAccount` fails closed
 *    rather than fabricating success. This is the honest, current behavior, not the literal
 *    "keys are still usable after reload" success scenario the task file describes — see
 *    `adapter.ts`'s own "Account persistence across a reload" doc section for exactly why that
 *    scenario is structurally unreachable today (no `CryptoKey`-persistence binding exists).
 * 3. **Chat round-trip over `BrowserTransport`** — real, using `WasmTransport` (this task's own thin
 *    `apps/wasm/src/lib.rs` addition) directly, **not** through `WasmMeridianClientAdapter.sendChat`
 *    (which is itself a GAP — see `adapter.ts`'s doc comment): two peers, two real
 *    `RTCPeerConnection`s in this one headless tab, negotiate and exchange real bytes over a real
 *    `RTCDataChannel`. Proves the substrate `sendChat`/`onMessage` will eventually ride on already
 *    works end to end, without pretending `sendChat` itself is implemented.
 */

import { beforeEach, describe, expect, it } from "vitest";

import { WasmMeridianClientAdapter } from "./adapter";
import { MeridianAdapterError } from "shared-ui";

// meridian-wasm's own bindings, used directly (not through the adapter) for the pieces the adapter
// interface itself deliberately has no method for (raw sign/verify, and the transport substrate) —
// see this file's own top doc comment.
import init, { generateAccount, verify, WasmTransport } from "meridian-wasm";
// eslint-disable-next-line import/no-unresolved
import wasmUrl from "meridian-wasm/meridian_wasm_bg.wasm?url";

beforeEach(async () => {
  // See `adapter.ts`'s own `ensureWasmInit` doc comment for why the explicit asset URL is needed
  // against this harness's dev server rather than `init()`'s own default resolution.
  await init({ module_or_path: wasmUrl });
});

describe("account creation — real crypto.subtle, real headless browser", () => {
  it("generateAccount produces a usable id via the adapter", async () => {
    const adapter = new WasmMeridianClientAdapter();
    expect(adapter.currentAccount()).toBeNull();

    const id = await adapter.generateAccount("web.example");
    expect(id).toContain("@web.example");
    expect(id.startsWith("mrd1:")).toBe(true);
    expect(adapter.currentAccount()).toBe(id);

    await adapter.closeAccount();
    expect(adapter.currentAccount()).toBeNull();
  });

  it("rejects an invalid routing hint as invalid_id, not a generic failure", async () => {
    const adapter = new WasmMeridianClientAdapter();
    await expect(adapter.generateAccount("not a valid hint!")).rejects.toMatchObject({
      code: "invalid_id",
    });
  });

  it("a freshly generated account's key really signs and verifies (direct binding, genuine WebCrypto)", async () => {
    // Exercises `generateAccount`/`WasmAccount.sign`/`verify` directly — real
    // `crypto.subtle.importKey(..., extractable: false, ...)` + real `crypto.subtle.sign`, in a
    // genuine browser, not a Node/jsdom polyfill.
    const account = await generateAccount("sign.example");
    const msg = new TextEncoder().encode("hello from the browser adapter integration test");
    const sig = await account.sign(msg);
    expect(sig).toHaveLength(64);

    expect(verify(account.publicKey, msg, sig)).toBe(true);

    const tampered = new TextEncoder().encode("hello from the browser adapter integration tesT");
    expect(verify(account.publicKey, tampered, sig)).toBe(false);

    account.free();
  });
});

describe("account persistence across a simulated reload — honest current behavior", () => {
  it(
    "a second adapter instance (simulated reload) does not regain the first account, and " +
      "openAccount fails closed rather than fabricating success",
    async () => {
      const first = new WasmMeridianClientAdapter();
      const id = await first.generateAccount("reload.example");
      expect(first.currentAccount()).toBe(id);

      // Simulated reload: a brand-new adapter instance, exactly as a real page reload would produce
      // (no shared JS heap, no shared WasmAccount reference) — see this file's top doc comment for
      // why this is the honest scenario to assert, not a false "it works" claim.
      const second = new WasmMeridianClientAdapter();
      expect(second.currentAccount()).toBeNull();

      await expect(second.openAccount(undefined)).rejects.toBeInstanceOf(MeridianAdapterError);
      await expect(second.openAccount(undefined)).rejects.toMatchObject({ code: "unavailable" });

      await first.closeAccount();
    },
  );
});

describe("chat round-trip over BrowserTransport — real RTCPeerConnection/RTCDataChannel", () => {
  it(
    "two WasmTransport peers negotiate and exchange real bytes over a real data channel",
    async () => {
      const a = new WasmTransport();
      const b = new WasmTransport();

      const sessionA = await a.newSession([]);
      const sessionB = await b.newSession([]);

      const channelA = await a.addDataChannel(sessionA, "mrd.chat/1");
      const channelB = await b.addDataChannel(sessionB, "mrd.chat/1");
      // Both peers hash the same channel label to the same pre-negotiated SCTP stream id (see
      // `apps/wasm/src/transport.rs::stream_id_for_label`) — no wire coordination needed for this.
      expect(channelA).toBe(channelB);

      // Call order finding (this task's own — reported back to 12.11, not fixed here; `transport.rs`
      // is that task's own file, out of this task's scope to change): `BrowserTransport`'s dialer
      // side does *not* actually call the real `RTCPeerConnection.setLocalDescription` the moment
      // `local_description()` is read — it lazily commits on first use of `local_candidates()`
      // (`ensure_committed`, see that method's own doc comment in `transport.rs`). If a caller reads
      // `local_description()` and sends it to the peer *without* having called `local_candidates()`
      // first, `committed_local_sdp` is still unset by the time the peer's real answer comes back —
      // `set_remote_description` then misclassifies that genuine answer as a *fresh offer* (its own
      // "already committed ⇒ must be an answer" heuristic reads `false`), silently scrambling the
      // negotiation (confirmed empirically while building this test: the data channel never opened,
      // with no error at any individual call site — each call "succeeded" on its own terms). This
      // never surfaces in production because the real substrate (`apps/core/src/session.rs`'s
      // `dial_with_config`) always calls `local_candidates()` (via `candidate_strings`, to embed
      // candidates in the sealed offer envelope) *before* ever sending the offer out — but nothing in
      // `Transport`'s own trait doc states this ordering as a precondition, and the existing
      // `apps/wasm/tests/browser_transport.rs` suite (12.11) doesn't catch a violation of it, since
      // that suite's own assertions (fingerprint text parses out of the cached SDP either way) don't
      // require the data channel to actually open. Matched here, deliberately, to the real
      // production call order.
      const candidatesA = await a.localCandidates(sessionA);
      const offer = a.localDescription(sessionA);
      await b.setRemoteDescription(sessionB, offer);
      const candidatesB = await b.localCandidates(sessionB);
      const answer = b.localDescription(sessionB);
      await a.setRemoteDescription(sessionA, answer);

      expect(candidatesA.length).toBeGreaterThan(0);
      expect(candidatesB.length).toBeGreaterThan(0);
      for (const c of candidatesA) await b.addIceCandidate(sessionB, c);
      for (const c of candidatesB) await a.addIceCandidate(sessionA, c);

      // The real payload — this is deliberately opaque bytes, not a real chat envelope (see this
      // file's top doc comment: `sendChat` itself is not implemented against today's bindings).
      const payload = new TextEncoder().encode("hello over a real data channel");
      await a.send(sessionA, channelA, payload);

      const frame = await b.recv(sessionB);
      expect(frame).toBeDefined();
      const [receivedChannel, receivedBytes] = frame as [bigint, Uint8Array];
      expect(receivedChannel).toBe(channelB);
      expect(new TextDecoder().decode(receivedBytes)).toBe("hello over a real data channel");

      // And the reverse direction, proving this is a genuine bidirectional data channel, not a
      // one-shot fluke.
      const reply = new TextEncoder().encode("and back the other way");
      await b.send(sessionB, channelB, reply);
      const replyFrame = await a.recv(sessionA);
      const [, replyBytes] = replyFrame as [bigint, Uint8Array];
      expect(new TextDecoder().decode(replyBytes)).toBe("and back the other way");

      await a.close(sessionA);
      await b.close(sessionB);
    },
    60_000,
  );

  it("sendChat itself still fails closed — the substrate above is real, the chat protocol on top of it is not", async () => {
    const adapter = new WasmMeridianClientAdapter();
    await adapter.generateAccount("gap.example");
    await expect(adapter.sendChat("mrd1:bogus@peer.example", "hi")).rejects.toMatchObject({
      code: "unavailable",
    });
  });
});
