# nat-matrix

Purpose and acceptance: see [feature 05](../../docs/architecture/features/05-nat-traversal-relay-policy.md),
[docs/testing/strategy.md](../../docs/testing/strategy.md), and the
[webrtc-nat-traversal skill](../../.claude/skills/webrtc-nat-traversal/SKILL.md). Run: `./run.sh`.

Covers the four NAT cells (full-cone, port-restricted, symmetric×symmetric, UDP-blocked), the
TLS-443 hostile-egress fallback, ephemeral TURN credential minting distinct per request (reuse of a
captured credential is quota-bounded server-side, not rejected outright), and the
`relay-only` strip-host/srflx-before-gathering privacy guarantee. The deterministic checks run in CI
without `NET_ADMIN`; the wire-level `tools/netns-nat-matrix.sh` rig (with `tools/testrig`) adds the
tcpdump assertions (no host/srflx at the peer; ciphertext-only at the TURN) when run as root.
