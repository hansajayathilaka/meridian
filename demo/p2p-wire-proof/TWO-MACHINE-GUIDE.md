# Two real machines, real P2P — coordination guide

The Docker rig ([`run-wire-proof.sh`](./run-wire-proof.sh)) and the live-server run
([`LIVE-SERVER-PROOF.md`](./LIVE-SERVER-PROOF.md)) both proved the server never carries message
content. What neither one exercised: **two genuinely different machines, on two genuinely
different networks**, actually finding each other through NAT. This guide is for doing that —
one side is your machine, the other is mine (this session's sandbox), both talking through the
real `wss://rendezvous.hansajayathilaka.com`, while I capture and analyze the traffic on my end.

## What you need

1. The `meridian` binary. Easiest: download the prebuilt release —
   **[github.com/hansajayathilaka/meridian/releases/tag/cli-latest](https://github.com/hansajayathilaka/meridian/releases/tag/cli-latest)**
   — grab `meridian-linux-x86_64-*.tar.gz` (Linux/macOS-via-Linux-binary) or
   `meridian-windows-x86_64-*.zip` (Windows), whichever matches your machine. No Rust toolchain
   needed. Verify it if you want (`sha256sum -c *.sha256` next to the file you downloaded).
2. This repo's [`demo/p2p-wire-proof/two-machine-chat.sh`](./two-machine-chat.sh) script (already
   in the repo — `git pull` or download it directly). Needs `bash` — on Windows, run it under
   WSL/Git Bash, or just run the two `meridian` commands by hand (shown inline in the script).

## Steps

**1. Extract the binary and point the script at it (skip if `meridian` is already on your PATH):**

```sh
tar xzf meridian-linux-x86_64-*.tar.gz     # or unzip the Windows one
export MERIDIAN_BIN=$(pwd)/meridian        # path to the extracted binary
```

**2. Learn your own ID:**

```sh
cd demo/p2p-wire-proof
bash two-machine-chat.sh
```

This creates a local identity (in `demo/p2p-wire-proof/two-machine-home/`, gitignored) and
registers it with the real server, then prints your `mrd1:…` ID. **Send that ID to me** (paste it
in this conversation).

**3. I'll do the same on my side and give you my ID.** Mine for this run:

```
mrd1:5ua5vgi2ryoqp5cxdehugtpr66qw3ht6igvwc63isjnpjmlzhfewhvj6mt53i@rendezvous.hansajayathilaka.com
```

**4. Once we both have each other's ID, run this at the same time I do** (say so in this
conversation right before you run it, so we're roughly synced — the script retries for a bit if
we're a few seconds off):

```sh
bash two-machine-chat.sh mrd1:MY-ID-FROM-STEP-3@rendezvous.hansajayathilaka.com 3
```

That's 3 rounds — each one a fresh, real P2P handshake and one short message exchanged each way
over the data channel directly between our two machines (not through the server). You'll see
`established:true` and a `path` (`direct` if we can reach each other directly, `relay` if either
of us is behind a NAT that needs coturn's help — either is a legitimate, expected outcome; the
point isn't which one wins, it's that the server never carries what we actually said either way).

**5. I'll capture and analyze the traffic on my end** (you don't need to run any capture tooling)
and post the results here, then commit a write-up to the repo — with your public IP address
**redacted** by default (it'll show up in my capture since that's how real P2P works, but I won't
publish it without asking first — let me know in this conversation if you're fine with it being
included plainly instead).

## If it doesn't establish

- **`recipient offline` / timeouts on both sides:** we're not running our rounds closely enough
  together — just retry step 4, saying "go" right before each of us runs it.
- **`path: "relay"` instead of `"direct"`:** expected if either of us is behind a restrictive NAT
  (very common on home/mobile networks) — coturn on the real server picks up the slack. Still a
  valid, complete proof; the write-up will just say so honestly instead of claiming direct when it
  wasn't.
- **Nothing establishes at all even after several retries:** tell me in this conversation and I'll
  help diagnose from my side's logs/capture.
