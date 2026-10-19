//! Hash-only verification for sealed evidence bundles.
//!
//! Scope (v0.1.0): the seal algorithm. Every payload file named in
//! `SHA256SUMS` is re-hashed and compared; the `metadata.json` sidecar is
//! re-hashed; `metadata.bundle_hash` is re-computed from the `SHA256SUMS`
//! bytes; provenance claims are checked for the presence of their proof
//! files. Signature and chain re-verification for notary provenance is
//! deliberately out of scope here: that belongs to the notary's own
//! public verifier and the producing gateway. This crate never sees the
//! network and never writes anything.

use std::fs;
use std::io::Read;
use std::path::{Component, Path};

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
            if let Some(sha) = r.get("source_sha256").and_then(Value::as_str) {
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
    let provenance = match provenance {
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
            Some(kind.clone())
        }
        Some(None) => {
            return Err(VerifyError::failure(
                "metadata.json: provenance.kind missing or not a string",
            ))
        }
        None => None,
    };

    Ok(BundleReport {
        case_id,
        bundle_hash,
        files_verified: entries.len(),
        gaps,
        provenance,
    })
}
