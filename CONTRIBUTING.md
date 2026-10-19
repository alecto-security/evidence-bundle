# Contributing

Issues, bug reports and pull requests are welcome. This repo is the
normative home of the bundle contract, so changes come in two kinds, and
the rules differ.

## Spec changes (docs/SPEC.md)

Schema, seal, metadata or provenance rules:

1. Open an issue first: what changes, who conforms today, what the additive
   path is.
2. Additive-optional is the default bar (SPEC §2.5). Removing or renaming a
   field, or changing what the seal covers, is a new schema version and a
   MAJOR release, with the old section kept for consumers.
3. A spec change without a fixture cannot merge: extend or add vectors in
   `fixtures/` in the same PR, including the negative case where one
   exists.

## Code changes (verifier, CLI, CI)

- Tests for new behavior; clippy must stay green at `-D warnings`.
- Keep the no-network guarantee: no network-capable crates in `Cargo.lock`
  (the guard test fails the build otherwise).
- Keep the read-only guarantee: the verifier writes nothing, anywhere.

## Setup

Rust stable, nothing else on `PATH`. No ffmpeg, no vendor tooling.

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

## Hygiene

Bundles are evidence. Never attach a real case bundle to an issue or PR:
use the synthetic fixtures, or describe the shape in text. Real cases open
real exposure for the people in the footage.

Windows, Linux and macOS are supported. unix-only tests are `cfg`-gated; if
your change is platform-limited, say so in the PR.
