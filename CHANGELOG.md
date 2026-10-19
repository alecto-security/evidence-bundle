# Changelog

Versions follow SemVer. The spec (docs/SPEC.md §7) is authoritative for what
a version may change.

## [Unreleased]

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
