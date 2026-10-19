# Test vectors

One directory per scenario. Every directory is a bundle root: run `verify
<dir>` against it, or `sha256sum -c SHA256SUMS && sha256sum -c
metadata.json.sha256` inside it with stock tools. The seal is deliberately
sha256sum(1)-compatible.

These vectors pin the contract in [docs/SPEC.md](../docs/SPEC.md): the
layout, the seal algorithm, the metadata sidecar, the `bundle_hash` promise,
the provenance-proof rules and the post-seal allowlist. They were generated
by the closed reference implementation and re-verified by both its CI and
this repo's CI on every commit, so the producer and the standard cannot
drift apart silently.

| Name | Case | Purpose | Expected `verify` |
|------|------|---------|-------------------|
| `minimal-full-coverage/` | `CASE-2026-9001` | Smallest valid bundle: one camera, full requested window, one `original/` file plus derived `playable/` and `thumbnails/` entries, complete metadata/camera/audit/custody set. | **PASS** (exit 0) |
| `coverage-gaps/` | `CASE-2026-9002` | Partial coverage: `CAM-W01` covered, `CAM-W02` recorded as a `source_unreachable` gap. Gaps are first-class, never silent. | **PASS** (exit 0) |
| `notary-provenance/` | `CASE-2026-9003` | `provenance.kind = "notary"` with `notary/segments.jsonl` and `notary/pubkey.json` inside the seal. Every Ed25519 signature verifies, the key id matches, seq 1→2 links, and the retrieved hash is covered by the signed segment record. | **PASS** (exit 0), 2 signed records verified |
| `disk-image-provenance/` | `CASE-2026-9004` | `provenance.kind = "disk_image"` with the seven `forensic/` proof files; `retrieved[]` carries the literal `"unknown"` times, because carved streams carry no trustworthy clock. | **PASS** (exit 0) |
| `tampered-original/` | `CASE-2026-9001` | Same as `minimal-full-coverage` after one flipped byte in the sole `original/` payload. The rejection must name the file and contain the phrase `hash mismatch`. | **FAIL** (exit 2) |
| `tampered-notary-signature/` | `CASE-2026-9003` | A copy of `notary-provenance` with one byte of one record's `sig` flipped, then re-sealed. The seal holds; the Ed25519 check must fail and name `notary/segments.jsonl`. | **FAIL** (exit 2) |
| `tampered-notary-chain/` | `CASE-2026-9003` | A copy of `notary-provenance` with the two records reordered, then re-sealed. Signatures still verify; seq continuity and the link check must fail. | **FAIL** (exit 2) |

All bytes are tiny synthetic markers, not media: the vectors test the
contract, not codecs.

Extending or regenerating vectors is a spec change first: see
[CONTRIBUTING](../CONTRIBUTING.md) for the rule that a spec change without a
fixture cannot merge.
