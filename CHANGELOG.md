# Changelog

Versions follow SemVer. The spec (docs/SPEC.md §7) is authoritative for what
a version may change.

## [Unreleased]

### Added

- Release workflow: a `vX.Y.Z` tag builds `verify` for linux (x86_64 and
  aarch64, static musl), macOS (x86_64 and aarch64) and windows (x86_64),
  gates on clippy and the test suite, smoke-tests the shipped linux binary
  against `fixtures/`, and publishes the archives with a `sha256sums.txt` as
  a GitHub Release. `workflow_dispatch` republishes an existing tag.
- README quickstart for the prebuilt binaries, so running the verifier needs
  no Rust toolchain.

## [0.2.0] - 2026-10-19

### Added

- Notary proof verification: `verify` now re-checks the signed record slice
  instead of only requiring it to be present. `notary/pubkey.json` must
  parse to a 32-byte Ed25519 key whose derived key id matches; every record
  must carry `v: 1`, that key id, and a valid Ed25519 signature over the
  canonical record with `sig` removed; `seq` must be continuous per camera
  and each `prev_record_hash` must link to its predecessor. A slice may
  begin mid-chain: the first record's earlier link is not claimed.
- Coverage: every `retrieved[].source_sha256` must be present and covered by
  a signed `segment` record; `provenance.detail` counts, seq bounds, key id
  and camera must agree with the slice when present.
- `BundleReport.notary_records` (CLI `--json`: `notary_records`) reports how
  many signed records were verified.
- Negative vectors `tampered-notary-signature` and `tampered-notary-chain`,
  re-sealed so the failure lands inside the proof, plus a mid-chain unit
  test signed with the published test-vector seed.

### Changed

- `verify` names the signed-record count for notary provenance.
- Dependencies: `base64` and `ed25519-dalek` (verification only; no network
  capability, guarded by the existing `Cargo.lock` test).

### Spec

- docs/SPEC.md §5.5 step 8 now specifies the signature, key-id, chain and
  coverage checks; §5.6 states what a bundled key does and does not prove;
  §7 allows verifier strictness to increase in a MINOR release for bundles
  that never conformed.

## [0.1.0] - 2026-10-19

Born public, born tagged.

### Added

- Normative specification, schema v1: bundle layout, `SHA256SUMS` seal
  algorithm with metadata sidecar and `bundle_hash` promise, provenance
  proof rules (`notary`, `disk_image`), the post-seal allowlist, symlink
  prohibition, and the additive-only versioning policy.
- `verify` CLI and library: hash-only verification with streamed file
  hashing, set parity between manifest and disk, tamper rejection naming
  the file, and the exit contract (0 verified, 2 rejected, 3 usage).
- Canonical fixture set: `minimal-full-coverage`, `coverage-gaps`,
  `notary-provenance`, `disk-image-provenance`, and the negative
  `tampered-original` vector.
- CI: test, clippy `-D warnings`, the fixture gate, and a no-network crate
  guard over `Cargo.lock`.
