# evidence-bundle

The sealed evidence bundle, as an open format. This repo is the normative
specification of the bundle layout, the SHA-256 seal algorithm, the metadata
schema (version `1`) and the provenance-proof rules, plus a standalone
verifier: the seal, and the notary proof's Ed25519 signatures and record
chain.

Think of the seal as an SBOM for video evidence: any examiner, auditor or
integrator can check, without camera code, without a subscription, without
building anything of ours, that the bytes in a bundle are the bytes that were
sealed, and that the bundle's own integrity record agrees with the files.

<p align="center">
  <a href="https://github.com/alecto-security/evidence-bundle/actions/workflows/ci.yml"><img src="https://github.com/alecto-security/evidence-bundle/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/schema_version-1-purple.svg" alt="Schema version 1">
</p>

## What an expert witness checks, and why

1. **The payload is intact.** Every payload file is listed in `SHA256SUMS`;
   hashing each file reproduces the listed digest. A flipped byte is found and
   named: `original/CAM-W01_...: hash mismatch`.
2. **The manifest is intact.** `metadata.json.bundle_hash` is the SHA-256 of
   the `SHA256SUMS` file itself. Change one line of the manifest and the bundle
   is rejected.
3. **The metadata is intact.** `metadata.json` is not inside the manifest
   (that would be self-referential); its integrity is a separate sidecar,
   `metadata.json.sha256`.
4. **Provenance claims carry proof, and a notary proof is re-verified.** A
   bundle that claims signed-recorder footage must carry the signed record
   slice and public key; `verify` re-checks every Ed25519 signature, the key
   id, seq continuity and the links inside the slice, and requires each
   retrieved hash to be covered by a signed segment. A recovered-disk claim
   must carry the seven `forensic/` proof files.
5. **Nothing is hidden.** Files on disk that the seal does not cover cause a
   failure, except a written-after-sealing report (`evidence-report.pdf`).
   Gaps in camera coverage are first-class records, printed by the verifier,
   never silently absent.

## Quickstart

```bash
# from source, no camera code, no ffmpeg, no network
cargo install --path .
verify ./CASE-2026-1842                 # human-readable report
verify ./CASE-2026-1842 --json          # machine-readable
sha256sum -c SHA256SUMS                 # stock tools verify too, by design
```

Exit codes mirror the producing gateway's contract:

| Code | Meaning |
|------|---------|
| `0` | verified: seal holds, metadata agrees, proofs verified |
| `2` | bundle rejected: tamper, unlisted file, missing proof, broken seal |
| `3` | usage error |

## Repository layout

```text
docs/SPEC.md      normative specification (schema v1)
fixtures/         canonical test bundles: this is what CI re-verifies
src/lib.rs        the verifier logic (seal + notary proof)
src/main.rs       the `verify` CLI
tests/            fixture matrix + mutation tests
```

## Verifier scope, stated plainly

- **Does:** set parity between `SHA256SUMS` and disk, per-file digests,
  sidecar digest, `bundle_hash` recomputation, `schema_version`
  acceptance, required-field presence, provenance-proof presence,
  `retrieved[].source_sha256` consistency, and real notary proof
  verification: Ed25519 signatures over the canonical record, the key id,
  seq continuity, chain links, and coverage of every retrieved hash.
- **Does not:** establish that the public key belongs to a recorder you
  trust (the key travels with the bundle), or check the first record's link
  to earlier history (a slice is a window). Tail truncation needs an
  off-box signed checkpoint. See SPEC §5.6.
- Reads only. Writes nothing. Makes no network requests (enforced by test:
  network-capable crates cannot enter `Cargo.lock`). Signature verification
  needs no network and no keystore: the key is a file in the bundle.

## Known limits

- Payload files are hashed streamed in 1 MiB chunks; bundle trees can be
  gigabytes. `metadata.json` is parsed whole, by design: it is scoped to
  stay small.
- Notary verification mirrors the public record format; it does not import
  recorder code (Contract C2 stays one public contract).
- The notary public key is pinned by the bundle, not by an external trust
  anchor. Whether that key is the recorder you trust is a policy decision
  (SPEC §5.6).
- The spec is versioned; this verifier accepts `schema_version: "1"` only.
  The manifest is `sha256sum(1)`-compatible two-space format.

## License

Apache-2.0. The spec is open; producing software that writes these bundles
stays closed, and closed is the point: the standard is what you verify,
not who sold you the tool.
