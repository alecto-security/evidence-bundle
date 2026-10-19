//! Verification for sealed evidence bundles.
//!
//! Scope (v0.2.0): the seal algorithm plus the notary provenance proof.
//! Every payload file named in `SHA256SUMS` is re-hashed and compared; the
//! `metadata.json` sidecar is re-hashed; `metadata.bundle_hash` is
//! re-computed from the `SHA256SUMS` bytes; provenance claims are checked
//! for their proof files. When the proof is a notary slice, every record's
//! Ed25519 signature is verified over the canonical record, the record key
//! id is checked, and seq continuity plus `prev_record_hash` links are
//! verified inside the slice. The first record's link to earlier history
//! cannot be checked from a slice and is not claimed.
//!
//! This crate never sees the network and never writes anything. It mirrors
//! the public notary record format; it does not import notary code.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

const SCHEMA_VERSION: &str = "1";
const SEAL_MANIFEST: &str = "SHA256SUMS";
const METADATA: &str = "metadata.json";
const METADATA_SIDECAR: &str = "metadata.json.sha256";
/// Files written after sealing are not covered by the seal. `evidence-report.pdf`
/// is the only such file today; the set is additive-optional.
const POST_SEAL_ALLOWLIST: &[&str] = &["evidence-report.pdf"];

const NOTARY_PROOF: &[&str] = &["notary/segments.jsonl", "notary/pubkey.json"];
const NOTARY_PUBKEY: &str = "notary/pubkey.json";
const NOTARY_SEGMENTS: &str = "notary/segments.jsonl";
/// Contract C2 record version this verifier knows (alecto-notary 0.1.0).
const NOTARY_RECORD_VERSION: u64 = 1;

const DISK_IMAGE_PROOF: &[&str] = &[
    "forensic/acquisition.json",
    "forensic/image.sha256",
    "forensic/parser.json",
    "forensic/index.json",
    "forensic/gaps.json",
    "forensic/parser-log.jsonl",
    "forensic/package.sha256sums",
];

pub type VerifyResult<T> = Result<T, VerifyError>;

/// Verification failure, always carrying the file that caused it when one
/// caused it. `exit_code()` maps onto the producing gateway's CLI contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    pub message: String,
    /// 2 = bundle rejected, 3 = config/usage error.
    pub exit_code: u8,
}

impl VerifyError {
    pub fn failure(message: impl Into<String>) -> Self {
        Self { message: message.into(), exit_code: 2 }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VerifyError {}

/// What a passing bundle contains, for tooling that wants to read the result.
#[derive(Debug, Clone, Default)]
pub struct BundleReport {
    pub case_id: String,
    pub bundle_hash: String,
    pub files_verified: usize,
    pub gaps: usize,
    pub provenance: Option<String>,
    /// Present when a notary proof was verified: how many signed records it holds.
    pub notary_records: Option<usize>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A manifest path is safe when it is non-empty and made only of normal
/// components. This rejects absolute paths, `..`, empty segments, backslash
/// separators, and Windows drive/UNC forms.
fn safe_relative_path(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.contains('\\')
        && Path::new(rel)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

/// Parse a sha256sum(1)-style manifest: `<64 hex>  <path>`, two spaces.
/// Duplicates are errors: a file listed twice is either an accident or an
/// attempt to smuggle a second meaning into one path.
fn parse_manifest(text: &str) -> VerifyResult<Vec<(String, String)>> {
    let mut seen: Vec<&str> = Vec::new();
    let mut entries = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() {
            return Err(VerifyError::failure(format!(
                "SHA256SUMS line {}: unexpected empty line",
                n + 1
            )));
        }
        let mut parts = line.splitn(2, "  ");
        let (digest, rest) = match (parts.next(), parts.next()) {
            (Some(d), Some(r)) if d.len() == 64 && !r.is_empty() => (d, r),
            _ => {
                return Err(VerifyError::failure(format!(
                    "SHA256SUMS line {}: not a sha256sum(1) entry",
                    n + 1
                )))
            }
        };
        let digest = digest.to_lowercase();
        if !hex::decode(&digest).is_ok_and(|v| v.len() == 32) {
            return Err(VerifyError::failure(format!(
                "SHA256SUMS line {}: digest is not 32 bytes of hex",
                n + 1
            )));
        }
        if seen.contains(&rest) {
            return Err(VerifyError::failure(format!(
                "SHA256SUMS line {}: duplicate path {}",
                n + 1,
                rest
            )));
        }
        seen.push(rest);
        if !safe_relative_path(rest) {
            return Err(VerifyError::failure(format!(
                "SHA256SUMS line {}: unsafe path {}",
                n + 1,
                rest
            )));
        }
        entries.push((digest, rest.to_string()));
    }
    if entries.is_empty() {
        return Err(VerifyError::failure("SHA256SUMS lists nothing"));
    }
    Ok(entries)
}

fn parse_sidecar(text: &str) -> VerifyResult<String> {
    let mut parts = text.trim_end().splitn(2, "  ");
    match (parts.next(), parts.next()) {
        (Some(d), Some(name)) if name.trim() == METADATA => {
            let d = d.to_lowercase();
            if hex::decode(&d).is_ok_and(|v| v.len() == 32) {
                Ok(d)
            } else {
                Err(VerifyError::failure("metadata.json.sha256: digest is not 32 bytes of hex"))
            }
        }
        _ => Err(VerifyError::failure(
            "metadata.json.sha256: not a sha256sum(1) entry naming metadata.json",
        )),
    }
}

fn required_field<'a>(meta: &'a Value, field: &str, ctx: &str) -> VerifyResult<&'a Value> {
    meta.get(field)
        .ok_or_else(|| VerifyError::failure(format!("metadata.json: missing required field `{field}` ({ctx})")))
}

fn require_str(meta: &Value, field: &str, ctx: &str) -> VerifyResult<String> {
    required_field(meta, field, ctx)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| VerifyError::failure(format!("metadata.json: field `{field}` is not a string ({ctx})")))
}

/// `CASE-YYYY-NNNN`.
fn valid_case_id(case_id: &str) -> bool {
    let rest = match case_id.strip_prefix("CASE-") {
        Some(r) if r.len() >= 3 => r,
        _ => return false,
    };
    let mut parts = rest.split('-');
    let (year, seq) = match (parts.next(), parts.next()) {
        (Some(y), Some(s)) if parts.next().is_none() => (y, s),
        _ => return false,
    };
    year.len() == 4 && year.bytes().all(|b| b.is_ascii_digit()) && seq.len() == 4 && seq.bytes().all(|b| b.is_ascii_digit())
}

fn require_provenance_files(kind: &str, required: &[&str], on_disk: &[(String, String)]) -> VerifyResult<()> {
    for file in required {
        if !on_disk.iter().any(|(rel, _)| rel == file) {
            return Err(VerifyError::failure(format!(
                "provenance `{kind}` requires {file} to exist and be listed in SHA256SUMS"
            )));
        }
    }
    Ok(())
}

/// What `verify` needs from `metadata.retrieved[]` to check notary coverage.
struct RetrievedProof {
    file: String,
    source_sha256: Option<String>,
}

/// Canonical JSON for the notary record format: object keys sorted, no
/// insignificant whitespace, arrays in order. Mirrors Contract C2.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).expect("string serializes"),
                        canonical_json(&map[k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        other => serde_json::to_string(other).expect("scalar serializes"),
    }
}

fn parse_notary_public(b64: &str) -> VerifyResult<VerifyingKey> {
    let bytes = B64
        .decode(b64.trim())
        .map_err(|_| VerifyError::failure(format!("{NOTARY_PUBKEY}: public_key_b64 is not valid base64")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| VerifyError::failure(format!("{NOTARY_PUBKEY}: public key must be 32 bytes")))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|_| VerifyError::failure(format!("{NOTARY_PUBKEY}: invalid Ed25519 public key")))
}

/// First 8 bytes of SHA-256 of the public key, hex (Contract C2 key id).
fn notary_key_id(public: &VerifyingKey) -> String {
    hex::encode(&Sha256::digest(public.as_bytes())[..8])
}

/// SHA-256 of the canonical record including `sig`: what the next record links to.
fn notary_record_hash(record: &Value) -> String {
    hex::encode(Sha256::digest(canonical_json(record).as_bytes()))
}

fn verify_notary_signature(record: &Value, public: &VerifyingKey) -> VerifyResult<()> {
    let sig_b64 = record
        .get("sig")
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyError::failure("record has no sig"))?;
    let bytes = B64
        .decode(sig_b64)
        .map_err(|_| VerifyError::failure("record sig is not valid base64"))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| VerifyError::failure("record sig must be 64 bytes"))?;
    let mut unsigned = record.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| VerifyError::failure("record is not an object"))?
        .remove("sig");
    public
        .verify(canonical_json(&unsigned).as_bytes(), &Signature::from_bytes(&arr))
        .map_err(|_| VerifyError::failure("signature does not verify"))
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Verify one contiguous notary slice: every signature over the canonical
/// record, the key id, the record version, seq continuity and the
/// `prev_record_hash` links inside each camera's run. A slice may start in the
/// middle of a chain, so the first record's own link to earlier history is
/// not checked. Returns the signed `segment` hashes and the cameras seen.
fn verify_notary_slice(
    records: &[Value],
    expected_key_id: &str,
    public: &VerifyingKey,
) -> VerifyResult<(HashSet<String>, BTreeSet<String>)> {
    // An empty slice is valid only when the bundle claims no footage; the
    // caller enforces that, because coverage is its job.
    // Chain state is per camera: a slice is one camera's contiguous run.
    let mut prev_by_camera: BTreeMap<String, (u64, String)> = BTreeMap::new();
    let mut signed_hashes: HashSet<String> = HashSet::new();
    let mut cameras: BTreeSet<String> = BTreeSet::new();

    for record in records {
        let seq = record
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| VerifyError::failure(format!("{NOTARY_SEGMENTS}: a record has no seq")))?;
        if record.get("v").and_then(Value::as_u64) != Some(NOTARY_RECORD_VERSION) {
            return Err(VerifyError::failure(format!(
                "{NOTARY_SEGMENTS} seq {seq}: unsupported record version (this verifier knows {NOTARY_RECORD_VERSION})"
            )));
        }
        if record.get("key_id").and_then(Value::as_str) != Some(expected_key_id) {
            return Err(VerifyError::failure(format!(
                "{NOTARY_SEGMENTS} seq {seq}: signed by a different key id"
            )));
        }
        verify_notary_signature(record, public)
            .map_err(|e| VerifyError::failure(format!("{NOTARY_SEGMENTS} seq {seq}: {e}")))?;
        let prev_hash = record
            .get("prev_record_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| VerifyError::failure(format!("{NOTARY_SEGMENTS} seq {seq}: no prev_record_hash")))?;
        if !hex64(prev_hash) {
            return Err(VerifyError::failure(format!(
                "{NOTARY_SEGMENTS} seq {seq}: prev_record_hash is not 32 bytes of hex"
            )));
        }
        let camera = record
            .get("camera_id")
            .and_then(Value::as_str)
            .ok_or_else(|| VerifyError::failure(format!("{NOTARY_SEGMENTS} seq {seq}: no camera_id")))?;
        if let Some((prev_seq, expected_hash)) = prev_by_camera.get(camera) {
            if seq != prev_seq + 1 {
                return Err(VerifyError::failure(format!(
                    "{NOTARY_SEGMENTS}: seq discontinuity: expected {}, found {seq}",
                    prev_seq + 1
                )));
            }
            if prev_hash != expected_hash {
                return Err(VerifyError::failure(format!(
                    "{NOTARY_SEGMENTS} seq {seq}: chain break (prev_record_hash does not match)"
                )));
            }
        }
        if record.get("kind").and_then(Value::as_str) == Some("segment") {
            if let Some(sha) = record.get("sha256").and_then(Value::as_str) {
                signed_hashes.insert(sha.to_string());
            }
        }
        cameras.insert(camera.to_string());
        prev_by_camera.insert(camera.to_string(), (seq, notary_record_hash(record)));
    }
    Ok((signed_hashes, cameras))
}

/// Verify the `notary` provenance proof: the public key, every Ed25519
/// signature over the canonical record, the key id, seq continuity and the
/// `prev_record_hash` links inside each camera's slice.
///
/// The first record's own link to earlier history cannot be checked from a
/// slice and is not claimed. Every retrieved file must be covered by a signed
/// `segment` record, and the metadata's own summary of the slice must agree
/// with the records when present.
fn verify_notary_proof(dir: &Path, meta: &Value, retrieved: &[RetrievedProof]) -> VerifyResult<usize> {
    let key_bytes = fs::read(dir.join(NOTARY_PUBKEY))
        .map_err(|e| VerifyError::failure(format!("{NOTARY_PUBKEY}: cannot read: {e}")))?;
    let key: Value = serde_json::from_slice(&key_bytes)
        .map_err(|e| VerifyError::failure(format!("{NOTARY_PUBKEY}: not valid JSON ({e})")))?;
    let alg = key
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyError::failure(format!("{NOTARY_PUBKEY}: missing `alg`")))?;
    if !alg.eq_ignore_ascii_case("ed25519") {
        return Err(VerifyError::failure(format!(
            "{NOTARY_PUBKEY}: unsupported alg `{alg}` (expected `ed25519`)"
        )));
    }
    let public_b64 = key
        .get("public_key_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyError::failure(format!("{NOTARY_PUBKEY}: missing `public_key_b64`")))?;
    let public = parse_notary_public(public_b64)?;
    let expected_key_id = notary_key_id(&public);
    if let Some(declared) = key.get("key_id").and_then(Value::as_str) {
        if declared != expected_key_id {
            return Err(VerifyError::failure(format!(
                "{NOTARY_PUBKEY}: key_id `{declared}` does not match the public key (`{expected_key_id}`)"
            )));
        }
    }

    let text = fs::read_to_string(dir.join(NOTARY_SEGMENTS))
        .map_err(|e| VerifyError::failure(format!("{NOTARY_SEGMENTS}: cannot read: {e}")))?;
    let mut records: Vec<Value> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            return Err(VerifyError::failure(format!(
                "{NOTARY_SEGMENTS} line {}: unexpected empty line",
                n + 1
            )));
        }
        let record: Value = serde_json::from_str(line).map_err(|e| {
            VerifyError::failure(format!("{NOTARY_SEGMENTS} line {}: not valid JSON ({e})", n + 1))
        })?;
        if !record.is_object() {
            return Err(VerifyError::failure(format!(
                "{NOTARY_SEGMENTS} line {}: not a JSON object",
                n + 1
            )));
        }
        records.push(record);
    }
    if records.is_empty() && !retrieved.is_empty() {
        return Err(VerifyError::failure(format!(
            "{NOTARY_SEGMENTS}: the notary proof is empty but the bundle claims footage"
        )));
    }

    let (signed_hashes, cameras) = verify_notary_slice(&records, &expected_key_id, &public)?;

    // The proof must actually cover the footage the bundle claims.
    for item in retrieved {
        match item.source_sha256.as_deref() {
            Some(sha) => {
                if !signed_hashes.contains(sha) {
                    return Err(VerifyError::failure(format!(
                        "{}: not covered by a signed notary segment record",
                        item.file
                    )));
                }
            }
            None => {
                return Err(VerifyError::failure(format!(
                    "{}: no source_sha256, so the notary proof cannot cover it",
                    item.file
                )));
            }
        }
    }

    // The metadata's summary of the slice must agree with the slice itself.
    if let Some(detail) = meta.get("provenance").and_then(|p| p.get("detail")) {
        if let Some(n) = detail.get("records").and_then(Value::as_u64) {
            if n as usize != records.len() {
                return Err(VerifyError::failure(format!(
                    "metadata.json: provenance.detail.records is {n}, but {NOTARY_SEGMENTS} holds {}",
                    records.len()
                )));
            }
        }
        if let Some(first) = detail.get("first_seq").and_then(Value::as_u64) {
            if records.first().and_then(|r| r.get("seq")).and_then(Value::as_u64) != Some(first) {
                return Err(VerifyError::failure(
                    "metadata.json: provenance.detail.first_seq does not match the first record",
                ));
            }
        }
        if let Some(last) = detail.get("last_seq").and_then(Value::as_u64) {
            if records.last().and_then(|r| r.get("seq")).and_then(Value::as_u64) != Some(last) {
                return Err(VerifyError::failure(
                    "metadata.json: provenance.detail.last_seq does not match the last record",
                ));
            }
        }
        if let Some(key_id) = detail.get("key_id").and_then(Value::as_str) {
            if key_id != expected_key_id {
                return Err(VerifyError::failure(
                    "metadata.json: provenance.detail.key_id does not match the signing key",
                ));
            }
        }
        if let Some(camera) = detail.get("camera").and_then(Value::as_str) {
            if cameras.len() != 1 || !cameras.contains(camera) {
                return Err(VerifyError::failure(
                    "metadata.json: provenance.detail.camera does not match the records",
                ));
            }
        }
    }

    Ok(records.len())
}

/// Stream-hash one file in fixed-size chunks: bundle payloads are megabytes
/// to gigabytes, and nothing here may load a payload whole into memory.
fn hash_file(path: &Path) -> VerifyResult<String> {
    let mut file = fs::File::open(path)
        .map_err(|e| VerifyError::failure(format!("cannot read {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| VerifyError::failure(format!("cannot read {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Walk the bundle, hash every actual file and keep the set of relative paths
/// with their digests. Symlinks are rejected, never traversed: a bundler has
/// no honest reason to ship one, and a consumer must not be made to follow
/// one to the outside.
fn collect_files(dir: &Path) -> VerifyResult<Vec<(String, String)>> {
    let mut out = Vec::new();
    for entry in WalkDir::new(dir)
        .sort_by_file_name()
        .into_iter()
        .map(|e| e.map_err(|e| VerifyError::failure(format!("cannot walk bundle: {e}"))))
    {
        let entry = entry?;
        let rel = entry
            .path()
            .strip_prefix(dir)
            .unwrap_or(entry.path())
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join("/");
        if entry.file_type().is_symlink() {
            return Err(VerifyError::failure(format!("symlink in bundle: {rel}")));
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let digest = hash_file(entry.path())?;
        out.push((rel, digest));
    }
    Ok(out)
}

/// Verify a bundle directory. Hash checks only.
pub fn verify_bundle(dir: &Path) -> VerifyResult<BundleReport> {
    let meta_path = dir.join(METADATA);
    let manifest_path = dir.join(SEAL_MANIFEST);
    let sidecar_path = dir.join(METADATA_SIDECAR);

    for p in [&manifest_path, &meta_path, &sidecar_path] {
        if !p.is_file() {
            return Err(VerifyError::failure(format!(
                "bundle is missing required seal file `{}`",
                p.display()
            )));
        }
    }

    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|e| VerifyError::failure(format!("cannot read SHA256SUMS: {e}")))?;
    let entries = parse_manifest(std::str::from_utf8(manifest_bytes.as_slice()).map_err(|e| {
        VerifyError::failure(format!("SHA256SUMS: not utf-8 ({e})"))
    })?)?;

    let meta_bytes = fs::read(&meta_path)
        .map_err(|e| VerifyError::failure(format!("cannot read metadata.json: {e}")))?;
    let sidecar_bytes = fs::read(&sidecar_path)
        .map_err(|e| VerifyError::failure(format!("cannot read metadata.json.sha256: {e}")))?;

    // 1. Set parity: everything on disk that is not seal-excluded or
    //    post-seal must be listed; everything listed must be on disk.
    let excluded: &[&str] = &[SEAL_MANIFEST, METADATA, METADATA_SIDECAR];
    let files = collect_files(dir)?;
    for (rel, digest) in &files {
        if excluded.contains(&rel.as_str()) || POST_SEAL_ALLOWLIST.contains(&rel.as_str()) {
            continue;
        }
        if !entries.iter().any(|(_, path)| path == rel) {
            return Err(VerifyError::failure(format!("unlisted file: {rel}")));
        }
        // 2. Tamper check: the bytes hash to the listed digest.
        if let Some((listed, _)) = entries.iter().find(|(_, path)| path == rel) {
            if listed != digest {
                return Err(VerifyError::failure(format!("{rel}: hash mismatch")));
            }
        }
    }
    for (_digest, path) in &entries {
        if excluded.contains(&path.as_str()) {
            return Err(VerifyError::failure(format!(
                "SHA256SUMS may not list `{path}` (metadata is covered by the sidecar; the manifest covers itself)"
            )));
        }
        if !files.iter().any(|(rel, _)| rel == path) {
            return Err(VerifyError::failure(format!("listed file missing: {path}")));
        }
    }

    // 3. Metadata sidecar and bundle hash.
    let sidecar_hex = parse_sidecar(std::str::from_utf8(sidecar_bytes.as_slice()).map_err(|e| {
        VerifyError::failure(format!("metadata.json.sha256: not utf-8 ({e})"))
    })?)?;
    if sidecar_hex != sha256_hex(&meta_bytes) {
        return Err(VerifyError::failure(format!("{METADATA}: hash mismatch")));
    }

    let meta: Value = serde_json::from_slice(&meta_bytes)
        .map_err(|e| VerifyError::failure(format!("metadata.json: not valid JSON ({e})")))?;

    let schema_version = require_str(&meta, "schema_version", "schema")?;
    if schema_version != SCHEMA_VERSION {
        return Err(VerifyError::failure(format!(
            "{METADATA}: unsupported schema_version `{schema_version}` (this verifier knows `{SCHEMA_VERSION}`)"
        )));
    }

    let case_id = require_str(&meta, "case_id", "identity")?;
    valid_case_id(&case_id)
        .then_some(())
        .ok_or_else(|| VerifyError::failure(format!("metadata.json: case_id `{case_id}` is not CASE-YYYY-NNNN")))?;

    let bundle_hash = required_field(&meta, "bundle_hash", "seal")?
        .as_str()
        .ok_or_else(|| VerifyError::failure("metadata.json: `bundle_hash` is not a string"))?
        .to_lowercase();
    if bundle_hash != sha256_hex(&manifest_bytes) {
        return Err(VerifyError::failure(format!(
            "{SEAL_MANIFEST}: bundle_hash does not match the manifest bytes"
        )));
    }

    // 4. Required metadata fields exist (additive tolerance: extras allowed).
    for field in ["requested_window", "retrieved", "gaps", "retrieved_at", "gateway"] {
        let v = required_field(&meta, field, "schema v1")?;
        if !v.is_object() && !v.is_array() && !v.is_string() {
            return Err(VerifyError::failure(format!("metadata.json: `{field}` has the wrong type")));
        }
    }
    if let Some(window) = meta.get("requested_window") {
        for edge in ["start", "end"] {
            if !window.get(edge).is_some_and(|v| v.is_string()) {
                return Err(VerifyError::failure(format!(
                    "metadata.json: requested_window.{edge} missing or not a string"
                )));
            }
        }
    }
    let mut retrieved_proof: Vec<RetrievedProof> = Vec::new();
    if let Some(retrieved) = meta.get("retrieved") {
        let arr = retrieved.as_array().cloned().unwrap_or_default();
        for (i, r) in arr.iter().enumerate() {
            let file = match r.get("file").and_then(Value::as_str) {
                Some(f) => f.to_string(),
                None => {
                    return Err(VerifyError::failure(format!(
                        "metadata.json: retrieved[{i}].file missing or not a string"
                    )))
                }
            };
            if !safe_relative_path(&file) {
                return Err(VerifyError::failure(format!(
                    "metadata.json: retrieved[{i}].file is not a safe relative path: `{file}`"
                )));
            }
            let source_sha256 = r.get("source_sha256").and_then(Value::as_str).map(str::to_owned);
            if let Some(sha) = &source_sha256 {
                let listed = entries
                    .iter()
                    .find(|(_, path)| path == &file)
                    .map(|(digest, _)| digest.clone())
                    .ok_or_else(|| {
                        VerifyError::failure(format!(
                            "metadata.json: retrieved[{i}] names `{file}`, which SHA256SUMS does not list"
                        ))
                    })?;
                if !sha.eq_ignore_ascii_case(&listed) {
                    return Err(VerifyError::failure(format!(
                        "original/{file}: source_sha256 does not match SHA256SUMS"
                    )));
                }
            }
            retrieved_proof.push(RetrievedProof { file, source_sha256 });
        }
    }
    let gaps = meta
        .get("gaps")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .ok_or_else(|| VerifyError::failure("metadata.json: `gaps` is not an array"))?;

    // 5. Provenance claims must carry their proof files.
    let provenance = meta
        .get("provenance")
        .and_then(Value::as_object)
        .map(|p| p.get("kind").and_then(Value::as_str).map(str::to_owned));
    let (provenance, notary_records) = match provenance {
        Some(Some(kind)) => {
            let required = match kind.as_str() {
                "notary" => NOTARY_PROOF,
                "disk_image" => DISK_IMAGE_PROOF,
                other => {
                    return Err(VerifyError::failure(format!(
                        "metadata.json: unknown provenance.kind `{other}`"
                    )))
                }
            };
            require_provenance_files(&kind, required, &files)?;
            let records = if kind == "notary" {
                Some(verify_notary_proof(dir, &meta, &retrieved_proof)?)
            } else {
                None
            };
            (Some(kind), records)
        }
        Some(None) => {
            return Err(VerifyError::failure(
                "metadata.json: provenance.kind missing or not a string",
            ))
        }
        None => (None, None),
    };

    Ok(BundleReport {
        case_id,
        bundle_hash,
        files_verified: entries.len(),
        gaps,
        provenance,
        notary_records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public key carried by the notary test vectors (seed bytes 1..=32).
    const PUBLIC_B64: &str = "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=";
    const KEY_ID: &str = "65b60673d6ed884b";

    #[test]
    fn canonical_json_sorts_keys_and_strips_whitespace() {
        let v: Value = serde_json::json!({"b": 1, "a": {"d": [1, 2], "c": "x"}});
        assert_eq!(canonical_json(&v), r#"{"a":{"c":"x","d":[1,2]},"b":1}"#);
    }

    #[test]
    fn key_id_is_the_first_eight_bytes_of_the_public_key_hash() {
        let public = parse_notary_public(PUBLIC_B64).unwrap();
        assert_eq!(notary_key_id(&public), KEY_ID);
    }

    /// A slice may begin mid-chain: `seq` does not have to start at 1, and the
    /// first record's link to earlier history is not claimed. Records are
    /// signed here with the published test-vector seed, so this also proves the
    /// verifier's canonical form matches the notary's.
    #[test]
    fn a_slice_may_start_in_the_middle_of_a_chain() {
        use ed25519_dalek::{Signer, SigningKey};
        let seed: [u8; 32] = std::array::from_fn(|i| (i + 1) as u8);
        let signing = SigningKey::from_bytes(&seed);
        assert_eq!(notary_key_id(&signing.verifying_key()), KEY_ID);

        let sign_record = |mut record: Value, prev: String| -> Value {
            record["prev_record_hash"] = Value::String(prev);
            let mut unsigned = record.clone();
            unsigned.as_object_mut().unwrap().remove("sig");
            let sig = signing.sign(canonical_json(&unsigned).as_bytes());
            record["sig"] = Value::String(B64.encode(sig.to_bytes()));
            record
        };

        let sha = "aa".repeat(32);
        let first = sign_record(
            serde_json::json!({
                "v": 1, "kind": "segment", "device_id": "notary-fixture",
                "key_id": KEY_ID, "camera_id": "CAM-W01", "seq": 41,
                "start_utc": "2026-10-02T14:03:00.000Z", "end_utc": "2026-10-02T14:04:00.000Z",
                "file": "segments/CAM-W01/2026-10-02/140300_41.ts",
                "sha256": sha, "bytes": 35,
                "clock": {"source": "ntp", "skew_ms": 400}, "sig": ""
            }),
            "a".repeat(64),
        );
        let second = sign_record(
            serde_json::json!({
                "v": 1, "kind": "gap", "device_id": "notary-fixture",
                "key_id": KEY_ID, "camera_id": "CAM-W01", "seq": 42,
                "start_utc": "2026-10-02T14:04:00.000Z", "end_utc": "2026-10-02T14:05:30.000Z",
                "reason": "source_unreachable",
                "clock": {"source": "ntp", "skew_ms": 400}, "sig": ""
            }),
            notary_record_hash(&first),
        );

        let public = parse_notary_public(PUBLIC_B64).unwrap();
        let (signed, cameras) = verify_notary_slice(&[first, second], KEY_ID, &public)
            .expect("a slice starting at seq 41 verifies");
        assert!(signed.contains(&sha));
        assert_eq!(cameras.len(), 1);
    }

    #[test]
    fn an_empty_slice_is_allowed_when_no_footage_is_claimed() {
        let public = parse_notary_public(PUBLIC_B64).unwrap();
        let (signed, cameras) = verify_notary_slice(&[], KEY_ID, &public).unwrap();
        assert!(signed.is_empty());
        assert!(cameras.is_empty());
    }

    #[test]
    fn a_reordered_slice_breaks_the_chain() {
        // Take the fixture's two real records, swap them: every signature still
        // verifies, but seq 1 after seq 2 is a discontinuity.
        let text = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/notary-provenance/notary/segments.jsonl"),
        )
        .unwrap();
        let mut records: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        records.reverse();
        let public = parse_notary_public(PUBLIC_B64).unwrap();
        let err = verify_notary_slice(&records, KEY_ID, &public).unwrap_err();
        assert!(err.message.contains("seq discontinuity"), "got: {}", err.message);
        assert_eq!(err.exit_code, 2);
    }
}
