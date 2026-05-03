//! Integration tests for snapshot artifact handling.
//!
//! These tests do not require KVM/libkrun — they exercise the
//! file-format, integrity-check, and archive layers by synthesizing
//! manifests + upper files directly. End-to-end tests that boot a
//! VM live alongside the other `msb_test`-gated integration tests.

use std::collections::BTreeMap;
use std::path::Path;

use microsandbox::Snapshot;
use microsandbox_image::snapshot::{
    DEFAULT_UPPER_FILE, ImageRef, MANIFEST_FILENAME, Manifest, SCHEMA_VERSION, SnapshotFormat,
    UpperIntegrity, UpperLayer,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

/// Build a synthetic snapshot artifact directory with a known upper
/// file. Returns `(artifact_dir, manifest_digest)`.
fn make_artifact(parent: &Path, name: &str, upper_bytes: &[u8]) -> (std::path::PathBuf, String) {
    make_artifact_with_integrity(parent, name, upper_bytes, false)
}

fn make_artifact_with_integrity(
    parent: &Path,
    name: &str,
    upper_bytes: &[u8],
    record_integrity: bool,
) -> (std::path::PathBuf, String) {
    let dir = parent.join(name);
    std::fs::create_dir_all(&dir).unwrap();

    let upper_path = dir.join(DEFAULT_UPPER_FILE);
    std::fs::write(&upper_path, upper_bytes).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(upper_bytes);
    let upper_integrity = record_integrity.then(|| UpperIntegrity {
        algorithm: "sha256".into(),
        digest: format!("sha256:{}", hex::encode(hasher.finalize())),
    });

    let manifest = Manifest {
        schema: SCHEMA_VERSION,
        format: SnapshotFormat::Raw,
        fstype: "ext4".into(),
        image: ImageRef {
            reference: "docker.io/library/alpine:3.20".into(),
            manifest_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000001".into(),
        },
        parent: None,
        created_at: "2026-05-01T12:00:00Z".into(),
        labels: BTreeMap::new(),
        upper: UpperLayer {
            file: DEFAULT_UPPER_FILE.into(),
            size_bytes: upper_bytes.len() as u64,
            integrity: upper_integrity,
        },
        source_sandbox: Some("synthetic".into()),
    };
    let bytes = manifest.to_canonical_bytes().unwrap();
    let digest = manifest.digest().unwrap();
    std::fs::write(dir.join(MANIFEST_FILENAME), bytes).unwrap();
    (dir, digest)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn open_reads_valid_artifact_metadata() {
    let tmp = TempDir::new().unwrap();
    let (dir, expected_digest) = make_artifact(tmp.path(), "snap-a", b"upper data goes here");

    let snap = Snapshot::open(dir.to_string_lossy().as_ref())
        .await
        .unwrap();
    assert_eq!(snap.digest(), expected_digest);
    assert_eq!(snap.path(), dir);
    assert_eq!(snap.size_bytes(), b"upper data goes here".len() as u64);
}

#[tokio::test]
async fn open_rejects_tampered_upper_size() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact(tmp.path(), "snap-tamper", b"original");

    // Mutate the upper file after the manifest is written.
    std::fs::write(dir.join(DEFAULT_UPPER_FILE), b"TAMPERED-LONGER").unwrap();

    let err = Snapshot::open(dir.to_string_lossy().as_ref())
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("integrity") || msg.contains("size") || msg.contains("sha"),
        "expected integrity error, got: {msg}"
    );
}

#[tokio::test]
async fn verify_rejects_tampered_upper_contents() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) =
        make_artifact_with_integrity(tmp.path(), "snap-tamper-content", b"original", true);

    // Keep the size identical so metadata-only open still succeeds.
    std::fs::write(dir.join(DEFAULT_UPPER_FILE), b"tampered").unwrap();

    let snap = Snapshot::open(dir.to_string_lossy().as_ref())
        .await
        .unwrap();
    let err = snap.verify().await.unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("digest mismatch"), "unexpected error: {msg}");
}

#[tokio::test]
async fn open_rejects_missing_upper_file() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact(tmp.path(), "snap-missing", b"x");

    std::fs::remove_file(dir.join(DEFAULT_UPPER_FILE)).unwrap();

    let err = Snapshot::open(dir.to_string_lossy().as_ref())
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("integrity"));
}

#[tokio::test]
async fn open_rejects_unknown_schema() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("bad");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(DEFAULT_UPPER_FILE), b"data").unwrap();
    // Hand-write a manifest with an unknown schema version.
    std::fs::write(
        dir.join(MANIFEST_FILENAME),
        br#"{"schema":42,"format":"raw","fstype":"ext4","image":{"ref":"x","manifest_digest":"sha256:01"},"parent":null,"created_at":"2026-05-01T12:00:00Z","labels":{},"upper":{"file":"upper.ext4","size_bytes":4,"integrity":null},"source_sandbox":null}"#,
    )
    .unwrap();

    let err = Snapshot::open(dir.to_string_lossy().as_ref())
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("schema") || format!("{err}").contains("integrity"));
}

#[tokio::test]
async fn list_dir_skips_non_artifact_directories() {
    let tmp = TempDir::new().unwrap();
    make_artifact(tmp.path(), "good", b"hello");
    std::fs::create_dir_all(tmp.path().join("not-a-snapshot")).unwrap();

    let snaps = Snapshot::list_dir(tmp.path()).await.unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].path().file_name().unwrap(), "good");
}

#[tokio::test]
async fn export_then_import_round_trips_via_zstd() {
    let tmp = TempDir::new().unwrap();
    let (dir, original_digest) = make_artifact(tmp.path(), "src-snap", b"the upper bytes");

    let archive = tmp.path().join("bundle.tar.zst");
    Snapshot::export(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::ExportOpts::default(),
    )
    .await
    .unwrap();
    assert!(archive.exists());
    assert!(std::fs::metadata(&archive).unwrap().len() > 0);

    let dest = tmp.path().join("imported");
    let handle = Snapshot::import(&archive, Some(&dest)).await.unwrap();
    assert_eq!(handle.digest(), original_digest);

    // Re-open the imported artifact via path; integrity should hold.
    let imported = Snapshot::open(handle.path().to_string_lossy().as_ref())
        .await
        .unwrap();
    assert_eq!(imported.digest(), original_digest);
}

#[tokio::test]
async fn export_then_import_round_trips_via_plain_tar() {
    let tmp = TempDir::new().unwrap();
    let (dir, original_digest) = make_artifact(tmp.path(), "src-plain", b"plain tar bytes");

    let archive = tmp.path().join("bundle.tar");
    Snapshot::export(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::ExportOpts {
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let dest = tmp.path().join("imported-plain");
    let handle = Snapshot::import(&archive, Some(&dest)).await.unwrap();
    assert_eq!(handle.digest(), original_digest);
}

#[tokio::test]
async fn manifest_digest_is_stable_across_processes() {
    // Regenerating the manifest from the same logical inputs should
    // yield the same digest. This is the load-bearing invariant for
    // file-first identity.
    let tmp = TempDir::new().unwrap();
    let (_, digest_a) = make_artifact(tmp.path(), "a", b"same upper");

    let tmp2 = TempDir::new().unwrap();
    let (_, digest_b) = make_artifact(tmp2.path(), "a", b"same upper");

    assert_eq!(digest_a, digest_b);
}
