<!-- Source: tasks/T16-tier2-tunnels.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T16 — Tier-2 Tunnels: SSH-over-P2P & `mrd.fs/1`

**Priority:** P4 — the payoff task · **Design refs:** §5.3 (Tier-2), §6 (terminal client), §7.2 · **Depends on:** T09 · **Indicative effort:** 2–3 eng-weeks

## Goal
Deliver the "ultimate sharing platform" proof: arbitrary TCP tunneling (`mrd.tunnel.tcp/1`) and a native file-service protocol (`mrd.fs/1`) riding the identical identity + rendezvous + encrypted-transport substrate — headlined by SSH-ing into a NAT'd headless box addressed by its Meridian ID.

## Scope
In: `mrd.tunnel.tcp/1` — one TCP connection ↔ one reliable-ordered channel; tiny connect header (`host:port`); **recipient-side policy allowlist is mandatory and default-empty** (`tunnel.allow = ["127.0.0.1:22"]`) — a peer can never open a tunnel target the recipient didn't explicitly permit; per-contact tunnel grants (verified contacts only, org-configurable); `meridian tunnel <id> --local 2222 --remote 127.0.0.1:22` client UX + a ProxyCommand recipe so plain `ssh` works unmodified; SSH's own crypto retained (double encryption deliberate, §5.3 — the tunnel adds reach, not trust); `mrd.fs/1` — list/stat/get/put/rename verbs over CBOR, reusing T09 chunking/merkle/resume, rooted at an explicitly exported directory, read-only by default; `meridian fs mount`-style CLI (FUSE optional/stretch) + browser file-browser panel; throughput/latency report vs. direct SSH (SCTP tax measured — feeds ADR-6's Phase-4 QUIC call).
Out: UDP tunneling, SOCKS mode, FTP *protocol* proxying (the compat TCP tunnel covers legacy FTP if someone insists; `mrd.fs/1` is the recommended path per §5.3), multi-hop.

## Deliverables
1. Both stream types + spec sections (again: implementable-by-a-third-party standard applies).
2. `tunnel-security.md` — the policy model, the double-encryption rationale, and an explicit abuse analysis (what a compromised *initiator* can reach = the allowlist, nothing else; what the servers see = nothing, they're not in the path).
3. The headline demo, scripted in CI on the netns rig.

## Working output (demo script)
```
— headless box behind symmetric NAT, no inbound ports, runs: meridian daemon
  with tunnel.allow=["127.0.0.1:22"] and fs.export=/srv/share (ro) —
$ ssh -o ProxyCommand='meridian tunnel mrd1:<box>@org-a.test --stdio 127.0.0.1:22' user@box
  user@box:~$                                   ← interactive shell, across NATs, no port-forward
$ meridian tunnel <box> --remote 10.0.0.5:5432  # NOT on allowlist
  → rejected by peer policy: target not permitted
$ meridian fs ls <box>:/ && meridian fs get <box>:/data.tar --resume
  — 4 GiB pull, killed and resumed, merkle-verified —
$ latency/throughput report printed: ssh-direct vs ssh-over-meridian deltas
```

## Acceptance criteria
Interactive SSH usable (echo latency overhead < 15 ms on direct path); allowlist bypass attempts (header games, port 0, IPv6 literals, DNS names resolving elsewhere) all rejected by tests; `mrd.fs` write ops fail on read-only exports; tunnels refused from non-granted contacts; the whole demo passes with the rendezvous *stopped* after session establishment — reasserting the core property one last time.

## Risks / notes
Tunneling is the feature most likely to alarm enterprise security teams — `tunnel-security.md` is written *for that reviewer*: default-deny, explicit grants, verified-contacts-only option, and org-level kill switch. Ship the controls with the capability, never after it.
