//! The canonical C1 fixture matrix. A pass here means the standard, the test
//! vectors and the verifier agree.

use std::path::Path;

use evidence_bundle::verify_bundle;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

#[test]
fn valid_fixtures_verify() {
    for name in [
        "minimal-full-coverage",
        "coverage-gaps",
        "notary-provenance",
        "disk-image-provenance",
    ] {
        let report = verify_bundle(&fixture(name)).unwrap_or_else(|e| {
            panic!("{name}: expected pass, failed with: {e}");
        });
        assert!(report.case_id.starts_with("CASE-"), "{name}: case id shape");
        assert!(report.bundle_hash.len() == 64, "{name}: bundle hash shape");
    }
}

#[test]
fn coverage_gaps_are_first_class_and_reported() {
    let report = verify_bundle(&fixture("coverage-gaps")).expect("coverage-gaps verifies");
    assert_eq!(report.gaps, 1, "the CAM-W02 gap is counted, never silent");
}

#[test]
fn provenance_is_reported() {
    let notary = verify_bundle(&fixture("notary-provenance")).expect("notary fixture verifies");
    assert_eq!(notary.provenance.as_deref(), Some("notary"));
    let disk = verify_bundle(&fixture("disk-image-provenance")).expect("disk fixture verifies");
    assert_eq!(disk.provenance.as_deref(), Some("disk_image"));
    let plain = verify_bundle(&fixture("minimal-full-coverage")).expect("minimal verifies");
    assert_eq!(plain.provenance, None);
}

#[test]
fn tampered_original_fails_naming_the_file() {
    let err = verify_bundle(&fixture("tampered-original"))
        .expect_err("tampered fixture must fail");
    assert_eq!(err.exit_code, 2, "rejected bundles exit 2");
    assert!(
        err.message.contains("original/CAM-W01_20260914T2210-2235.mp4"),
        "the failing file is named, got: {}",
        err.message
    );
    assert!(err.message.contains("hash mismatch"));
}
