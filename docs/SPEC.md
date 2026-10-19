# Evidence Bundle Specification

**Version:** schema `1` · datetime: the seal algorithm as specified here was
first sealed 2026-10-02 and re-validated against this spec 2026-10-19
**Status:** normative. This document owns the bundle contract.

## Conformance language

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as
described in RFC 2119. `SHOULD` deviations must be recorded in the bundle's
own audit log.

## 1. Bundle layout

One case is one directory. The directory name SHOULD be `CASE-YYYY-NNNN`.

```text
CASE-2026-1842/
├── original/                  # byte-identical source recordings, MUST NOT be rewritten
├── playable/                  # derived container copies; regenerable, never the evidence of record
├── thumbnails/                # derived stills
├── metadata.json              # case + retrieval record (§3), sealed separately (§5)
├── camera.json                # per-source descriptors (array) (§4)
├── custody-log.json           # custody events (§4)
├── audit-log.json             # append-only action log, one JSON object per line (§4)
├── SHA256SUMS                 # sha256sum(1)-compatible manifest (§5)
├── metadata.json.sha256       # sidecar hash of metadata.json (§5)
├── evidence-report.pdf        # OPTIONAL, written after sealing (§5.4)
├── notary/                    # REQUIRED iff provenance kind is `notary` (§6)
└── forensic/                  # REQUIRED iff provenance kind is `disk_image` (§6)
```

## 2. Top-level rules

1. **Original is sacred.** Files under `original/` are stream copies of what
   the source system served. They MUST NOT be transcoded, re-encoded or
   renamed after hashing.
2. **Derived copies never masquerade.** `playable/` and `thumbnails/` MUST
   exist only as derivations; their hashes are recorded like any payload.
3. **UTC everywhere.** Machine-readable timestamps MUST be ISO 8601 UTC.
   Local time appears only inside human-facing reports (never in
   machine-readable files).
4. **Gaps are first-class.** Missing footage MUST be recorded in
   `metadata.gaps` with a reason. Silent omission is a conformance failure.
5. **Additive-optional only.** Fields MAY be added in schema v1 when absent
   values are skippable on read. Removing or renaming a field requires
   schema version `2` and a MAJOR release of any enforcing software.

## 3. `metadata.json` (schema v1)

Required fields:

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | string | exactly `"1"` |
| `case_id` | string | `CASE-YYYY-NNNN` |
| `requested_window` | object | `{start, end}`, ISO 8601 UTC: what was asked |
| `retrieved` | array of objects | `{source_id, start, end, file, source_sha256?}`: what was obtained. `start`/`end` MAY be the literal `"unknown"` for streams reconstructed without timing |
| `gaps` | array of objects | `{source_id, start, end, reason}`; reasons are an open set; known values: `source_unreachable`, `recording_starts_late`, `no_coverage`, `retention_deleted`, `disk_regions_unrecovered`, `codec_gap` and later additions |
| `retrieved_at` | string | ISO 8601 UTC, producer clock (SHOULD be NTP-disciplined) |
| `gateway` | object | `{id, version, software_only}`: provenance of the producing software |
| `bundle_hash` | string | lowercase SHA-256 of the `SHA256SUMS` bytes (§5.3) |

Optional (additive, v1-stable):

| Field | Type | Notes |
|-------|------|-------|
| `origin` | object | `{kind: "operator"\|"rule", approved_by?}`; a `rule` origin implies operator `rule:<id>` and MUST record `approved_by` |
| `provenance` | object | `{kind: "notary"\|"disk_image", detail?}`; MUST satisfy §6 |
| `report_status` | string | producer bookkeeping for the post-seal report |

`camera.json` is an array; each entry: `{source_id, name, vendor, model,
firmware, onvif_profile, rtsp_uri_redacted, resolution, fps, codec,
time_source}`. `rtsp_uri_redacted` MUST have credentials removed. Unknown
fields are permitted by the additive rule.

## 4. Event files

`custody-log.json`: object `{events: [...]}`, each event
`{actor, at, phase, note}`. Known phases: `identified`, `acquired`,
`preserved`. Phases are an open set (additive).

`audit-log.json`: append-only, one JSON object per line:
`{ts, actor, action, source, detail}`. Known actions: `request`, `discover`,
`warn`, `retrieve`, `fill_gap`, `derive`, `hash`, `package`, `ingest`,
`verify`. `transfer` is reserved for a future version. The file MUST NOT be
rewritten.

## 5. The seal

### 5.1 Manifest coverage

`SHA256SUMS` MUST list every file under the bundle root that is not itself
and is not `metadata.json` and is not `metadata.json.sha256`. Both proof
directories (`notary/`, `forensic/`) are payload: they are listed.

Format: sha256sum(1) text, `<lowercase hex digest>␠␠<relative path>`, LF
separated, `/` separators, UTF-8. Each path MUST be a safe relative path:
no absolute paths, no `..`, no backslashes, no empty segments. A path MUST
be listed at most once.

Symlinks MUST NOT appear anywhere in the bundle. A verifier MUST reject a
bundle containing one rather than traverse it: the dishonest use of a link
is to walk verification outside the tree it is checking.

### 5.2 Metadata sidecar

`metadata.json` MUST NOT be a line in `SHA256SUMS` (the `bundle_hash`
promise would be self-referential). Its integrity is a separate file:

```text
<sha256 hex of metadata.json bytes>  metadata.json
```

### 5.3 Bundle hash

`metadata.bundle_hash` is the lowercase SHA-256 of the exact bytes of the
final `SHA256SUMS` file. The manifest is generated last. Any change to the
manifest after sealing rejects the bundle in §5.5 below.

### 5.4 Files written after sealing

By definition, bytes written after the manifest was frozen cannot be inside
it. The only such file recognized by schema v1 is `evidence-report.pdf`
(MAY be present, is not seal-covered, is regenerable and MUST NOT be
treated as evidence of record). Verifiers MUST reject any other unlisted
file: a stranger in the tree is a stranger.

### 5.5 Verification semantics

`verify` on a bundle MUST:

1. Parse `SHA256SUMS` (malformed line → reject; duplicate path → reject;
   empty → reject).
2. Compare the disk tree with the manifest: an unlisted non-allowed file →
   reject with its path; a listed-but-missing file → reject with its path.
   Same for `metadata.json.sha256` referencing non-`metadata.json`.
3. Hash every listed file and compare: any mismatch rejects the bundle,
   naming the file and the word `hash mismatch`.
4. Recompute the sidecar digest and compare: any mismatch rejects, naming
   `metadata.json`.
5. Recompute `sha256(SHA256SUMS bytes)` and compare to
   `metadata.bundle_hash`: any mismatch rejects.
6. Parse `metadata.json` as UTF-8 JSON; check `schema_version` against
   supported versions, required-field presence, `case_id` shape.
7. Check `retrieved[].file` paths are safe relative paths and, when
   `source_sha256` is present, that it equals the manifest digest for that
   file.
8. If `provenance` claims `notary`, the bundle MUST contain sealed
   `notary/segments.jsonl` and `notary/pubkey.json`; if it claims
   `disk_image`, it MUST contain `forensic/{acquisition.json, image.sha256,
   parser.json, index.json, gaps.json, parser-log.jsonl,
   package.sha256sums}`. Missing proof rejects.

Exit contract: `0` verified; `2` rejected; `3` usage. A verifier MAY
report extras (gap counts, provenance kind) but MUST NOT report a passing
seal that failed steps 1-8.

Gaps in camera coverage do not fail verification: they are records, not
absences of integrity.

### 5.6 What hash verification does not prove

This spec's verifier establishes internal consistency: the tree agrees with
its manifest and the manifest agrees with itself. It does not establish
where the bytes came from, who signed them, or that the recorder chain is
unbroken: those claims live in the provenance proofs, and their
cryptographic verification is a separate component (the recorder is a
separate public artifact, and producing gateways re-verify before sealing).
A bundle proves only what it documents: policy decides the rest.

## 6. Provenance proofs

### 6.1 `notary` proof

Required files (all listed in `SHA256SUMS` as payload):

- `notary/segments.jsonl`: the signed record slice covering every retrieved
  file's hash, including signed gap records where the source lost windows.
- `notary/pubkey.json`: the public key material identifying the signer.

The record chain format is specified by the recorder that produced it:
see the public [alecto-notary](https://github.com/alecto-security/alecto-notary)
repository for the segment record format, the Ed25519 signatures, the
key id rules and the shared test vectors.

### 6.2 `disk_image` proof

Required files (all listed in `SHA256SUMS` as payload):

`forensic/acquisition.json`, `forensic/image.sha256`,
`forensic/parser.json`, `forensic/index.json`, `forensic/gaps.json`,
`forensic/parser-log.jsonl`, `forensic/package.sha256sums`.

An image-carved stream carries no trustworthy timestamps:
`retrieved[].start`/`end` MUST be the literal string `"unknown"` rather
than invented values. Inventing timestamps is the failure mode this rule
exists to prevent.

## 7. Versioning

- Schema: `metadata.schema_version` selects the field contract. Version `1`
  is frozen: additive-optional only.
- Breaking change (field removal/renaming, meaning change): new schema
  version, new MAJOR release of enforcing software, this document updated
  with a new section, old section kept for consumers.
- The seal algorithm (§5) changes atomically with `SHA256SUMS` format
  changes only under §5.1's grammar. Any tool that changes what
  `sha256sum -c` accepts is a breaking change.

## 8. Test vectors

The `fixtures/` directory holds canonical bundles: the expected result of
every rule in §5 is pinned by one of them, including the negative case
(post-seal tamper). They are generated from the reference implementation
and re-verified by this repo's CI on every commit. Fixtures are synthetic
markers, not media; they test the contract, not codecs.
