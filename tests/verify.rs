//! Mutation tests on a copied valid bundle: every way the seal can fail,
//! each producing a named file and exit code 2.

use std::fs;
use std::path::{Path, PathBuf};

use evidence_bundle::verify_bundle;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

/// Minimal `std::fs` recursive copy; fixture payloads are small synthetic
/// markers, nothing here needs to stream.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dst = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dst);
        } else {
            fs::copy(entry.path(), dst).unwrap();
        }
    }
}

fn copied(name: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join(name);
    copy_tree(&fixture(name), &dst);
    (tmp, dst)
}

#[test]
fn a_post_seal_byte_flip_fails_naming_the_file() {
    let (_tmp, bundle) = copied("minimal-full-coverage");
    let target = bundle.join("original/CAM-W01_20260914T2210-2235.mp4");
    let mut bytes = fs::read(&target).unwrap();
    bytes[0] ^= 0x01;
    fs::write(&target, &bytes).unwrap();

    let err = verify_bundle(&bundle).expect_err("flipped payload must fail");
    assert_eq!(err.exit_code, 2);
    assert!(err.message.contains("hash mismatch"));
}

#[test]
fn an_unlisted_file_fails() {
    let (_tmp, bundle) = copied("minimal-full-coverage");
    fs::write(bundle.join("original/extra-file.mp4"), b"smuggled").unwrap();

    let err = verify_bundle(&bundle).expect_err("unlisted file must fail");
    assert!(err.message.contains("unlisted file"), "got: {}", err.message);
}

#[test]
fn a_reshuffled_metadata_fails_via_the_sidecar() {
    let (_tmp, bundle) = copied("coverage-gaps");
    let path = bundle.join("metadata.json");
    let mut meta: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    meta["retrieved_at"] = serde_json::json!("2026-09-14T23:00:00Z");
    fs::write(&path, serde_json::to_vec_pretty(&meta).unwrap()).unwrap();

    let err = verify_bundle(&bundle).expect_err("sealed metadata is over the line");
    assert_eq!(err.exit_code, 2);
    assert!(
        err.message.contains("metadata.json"),
        "the sidecar is what catches this, got: {}",
        err.message
    );
}

#[test]
fn manifest_rewrite_breaks_bundle_hash() {
    let (_tmp, bundle) = copied("minimal-full-coverage");
    // Add one extra payload file and list it correctly in SHA256SUMS. Every
    // digest now matches disk and there are no strays, so the only possible
    // failure is the hash-level promise: metadata.bundle_hash over the
    // manifest bytes changed.
    fs::write(bundle.join("case-scenario.txt"), b"scoped note").unwrap();
    let sums = bundle.join("SHA256SUMS");
    let mut text = fs::read_to_string(&sums).unwrap();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let file_bytes = fs::read(bundle.join("case-scenario.txt")).unwrap();
    text.push_str(&format!("{}  case-scenario.txt\n", hex::encode(sha256_bytes(&file_bytes))));
    fs::write(&sums, text).unwrap();

    let err = verify_bundle(&bundle).expect_err("manifest bytes changed");
    assert!(
        err.message.contains("bundle_hash"),
        "must fail on the hash-level promise, got: {}",
        err.message
    );
    assert_eq!(err.exit_code, 2);
}

#[test]
fn an_unknown_schema_version_fails() {
    let (_tmp, bundle) = copied("minimal-full-coverage");
    let path = bundle.join("metadata.json");
    let mut meta: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    meta["schema_version"] = serde_json::json!("9");
    // Update the sidecar so only the version check fails.
    let meta_bytes = serde_json::to_vec_pretty(&meta).unwrap();
    let meta_hex = hex::encode(sha256_bytes(&meta_bytes));
    fs::write(&path, &meta_bytes).unwrap();
    fs::write(
        bundle.join("metadata.json.sha256"),
        format!("{meta_hex}  metadata.json\n"),
    )
    .unwrap();

    let err = verify_bundle(&bundle).expect_err("unknown schema version");
    assert!(err.message.contains("schema_version"), "got: {}", err.message);
    assert_eq!(err.exit_code, 2);
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

#[test]
fn missing_provenance_proof_fails() {
    let (_tmp, bundle) = copied("notary-provenance");
    let sums = bundle.join("SHA256SUMS");
    fs::remove_dir_all(bundle.join("notary")).unwrap();
    // Remove the notary files from the manifest too, then re-seal: the
    // bundle_hash promise must be satisfied first so the failure surfaces
    // where it belongs, in the provenance rule.
    let text = fs::read_to_string(&sums).unwrap();
    let kept = text
        .lines()
        .filter(|l| !l.contains("notary/"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(sums, &kept).unwrap();
    let sums_bytes = fs::read(bundle.join("SHA256SUMS")).unwrap();

    let path = bundle.join("metadata.json");
    let mut meta: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    meta["bundle_hash"] = serde_json::json!(hex::encode(sha256_bytes(&sums_bytes)));
    let meta_bytes = serde_json::to_vec_pretty(&meta).unwrap();
    fs::write(&path, &meta_bytes).unwrap();
    fs::write(
        bundle.join("metadata.json.sha256"),
        format!("{}  metadata.json\n", hex::encode(sha256_bytes(&meta_bytes))),
    )
    .unwrap();

    let err = verify_bundle(&bundle).expect_err("proof removed");
    assert!(
        err.message.contains("requires notary"),
        "got: {}",
        err.message
    );
    assert_eq!(err.exit_code, 2);
}

#[cfg(unix)]
#[test]
fn a_symlink_is_rejected_not_followed() {
    let (_tmp, bundle) = copied("minimal-full-coverage");
    std::os::unix::fs::symlink("/etc/hostname", bundle.join("original/link.mp4")).unwrap();

    let err = verify_bundle(&bundle).expect_err("symlink must fail");
    assert_eq!(err.exit_code, 2);
    assert!(
        err.message.contains("symlink in bundle"),
        "got: {}",
        err.message
    );
}

#[cfg(unix)]
#[test]
fn an_unreadable_file_fails_loudly() {
    use std::os::unix::fs::PermissionsExt;

    let (_tmp, bundle) = copied("minimal-full-coverage");
    let target = bundle.join("audit-log.json");
    let mut perms = fs::metadata(&target).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&target, perms).unwrap();

    let err = verify_bundle(&bundle).expect_err("unreadable payload must fail");
    assert_eq!(err.exit_code, 2);
    assert!(
        err.message.contains("cannot read"),
        "the file is named in the failure, got: {}",
        err.message
    );
}
