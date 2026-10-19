# evidence-bundle

The sealed evidence bundle, as an open format. This repo is the normative
specification of the bundle layout, the SHA-256 seal algorithm, the metadata
schema (version `1`) and the provenance-proof rules, plus a standalone,
hash-only verifier.

Think of the seal as an SBOM for video evidence: any examiner, auditor or
integrator can check, without camera code, without a subscription, without
building anything of ours, that the bytes in a bundle are the bytes that were
sealed, and that the bundle's own integrity record agrees with the files.

<p align="center">
  <a href="https://github.com/alecto-security/evidence-bundle/actions/workflows/ci.yml"><img src="https://github.com/alecto-security/evidence-bundle/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://github.com/alecto-security/evidence-bundle/releases"><img src="https://img.shields.io/github/v/release/alecto-security/evidence-bundle?label=release&sort=semver" alt="Latest release"></a>
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
4. **Provenance claims carry proof files.** A bundle that claims its footage
   came from a continuously signed recorder or a recovered disk image must
   contain that proof or `verify` fails. (Signature and chain
   re-verification of the recorder proof lives in the public
   [alecto-notary](https://github.com/alecto-security/alecto-notary) verifier;
   this crate checks that the proof is present and sealed.)
5. **Nothing is hidden.** Files on disk that the seal does not cover cause a
   failure, except a written-after-sealing report (`evidence-report.pdf`).
   Gaps in camera coverage are first-class records, printed by the verifier,
   never silently absent.

## Quickstart

No Rust needed. Download the archive for your platform from
[Releases](https://github.com/alecto-security/evidence-bundle/releases),
check it against the release's `sha256sums.txt`, and run it:

```console
$ sha256sum -c sha256sums.txt
verify-v0.1.0-x86_64-unknown-linux-musl.tar.gz: OK
$ tar -xzf verify-v0.1.0-x86_64-unknown-linux-musl.tar.gz
$ ./verify-v0.1.0-x86_64-unknown-linux-musl/verify ./CASE-2026-1842
# exit 0: seal holds. exit 2: bundle rejected, and the file is named.
```

Linux builds are static (musl), so they do not depend on the host's glibc.
On Windows the archive is a `.zip` and the binary is `verify.exe`.

Or build from source — same binary, no camera code, no ffmpeg, no network:

```bash
cargo install --path .
verify ./CASE-2026-1842                 # human-readable report
verify ./CASE-2026-1842 --json          # machine-readable
sha256sum -c SHA256SUMS                 # stock tools verify too, by design
```

Exit codes mirror the producing gateway's contract:

| Code | Meaning |
|------|---------|
| `0` | verified: seal holds, metadata agrees, proofs present |
| `2` | bundle rejected: tamper, unlisted file, missing proof, broken seal |
| `3` | usage error |

## Repository layout

```text
docs/SPEC.md      normative specification (schema v1)
fixtures/         canonical test bundles: this is what CI re-verifies
src/verify.rs     the verifier logic (hash-only)
src/main.rs       the `verify` CLI
tests/            fixture matrix + mutation tests
```

## Verifier scope, stated plainly

- **Does:** set parity between `SHA256SUMS` and disk, per-file digests,
  sidecar digest, `bundle_hash` recomputation, `schema_version`
  acceptance, required-field presence, provenance-proof presence,
  `retrieved[].source_sha256` consistency.
- **Does not (v0.1.0):** re-verify recorder signatures and hash chains.
  That is a deliberate boundary: hash checks have no key dependencies, so
  this tool has no reason to touch the network or a keystore. Signature
  verification is additive already in the producing gateways, and a future
  `1.x` here can add it without a spec change.
- Reads only. Writes nothing. Makes no network requests (enforced by test:
  network-capable crates cannot enter `Cargo.lock`).

## Known limits

- Payload files are hashed streamed in 1 MiB chunks; bundle trees can be
  gigabytes. `metadata.json` is parsed whole, by design: it is scoped to
  stay small.
- Hash-only by design (see above).
- The spec is versioned; this verifier accepts `schema_version: "1"` only.
  The manifest is `sha256sum(1)`-compatible two-space format.

## License

Apache-2.0. The spec is open; producing software that writes these bundles
stays closed, and closed is the point: the standard is what you verify,
not who sold you the tool.
