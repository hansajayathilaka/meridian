# Adversarial & Verification Harnesses

These prove the security claims in [docs/security/threat-mitigation-matrix.md](../docs/security/threat-mitigation-matrix.md)
and are wired into CI ([testing/strategy.md §3](../docs/testing/strategy.md)). Scaffold stubs today;
each graduates into a real crate/harness as the feature it guards lands.

| Harness | Proves | Feature | Status |
|---------|--------|---------|--------|
| [opacity-audit](./opacity-audit/) | server sees only ciphertext (A1/A7) | 03 | stub |
| [mitm-sim](./mitm-sim/) | key substitution never wins silently (A2) | 08 | stub |
| [ghost-device](./ghost-device/) | forged device rejected; key-theft surfaced (A7) | 13 | stub |
| [nat-matrix](./nat-matrix/) | four NAT cells connect; TLS-443 fallback; single-session creds; relay-only hides IPs | 05 | live |

Also referenced but created with their features: conformance-vector runner (feature 01/08), FS/PCS
and fingerprint-mismatch tests (features 03/04). The NAT netns rig (feature 05) is
[`tools/netns-nat-matrix.sh`](../tools/netns-nat-matrix.sh), driven by the nat-matrix harness.
