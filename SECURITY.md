# Security Policy

## Reporting a vulnerability

Please report vulnerabilities through GitHub's private security advisories:
open the repository's **Security** tab and choose **Report a vulnerability**.

Do not open a public issue for a security report.

We aim to acknowledge reports within 72 hours and will coordinate disclosure
with you before any public advisory.

## Scope

The verifier reads bundles it may not have produced, and external parties
rely on the spec. Bugs that matter most to us:

- **Verification bypass:** a tampered payload, stray file, missing proof
  file, forged sidecar or reshuffled manifest that passes `verify`.
- **Path handling:** a manifest or metadata path that escapes the bundle
  (`..`, absolute paths, backslashes, duplicate entries) without rejection.
- **Symlink traversal:** a link inside a bundle that this tool follows
  instead of rejecting.
- **Parser safety:** a panic, hang, stack overflow or unbounded allocation
  on a hostile manifest or `metadata.json`.
- **Side effects:** any write to the bundle, any network syscall at runtime,
  or any network-capable crate entering `Cargo.lock` (enforced by test).

## Known limitations (not bugs)

- Hash-only: the verifier does not re-check recorder signatures or hash
  chains. That boundary is documented in docs/SPEC.md §5.6: a passing seal
  claims internal consistency, and provenance is a separate sealed claim.
- Accepts schema v1 only (`metadata.schema_version`). Support for future
  schema versions must ship explicitly, never implicitly.

## Supported versions

Security fixes land on `main` and release as patch versions of the current
minor line.
