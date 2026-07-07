//! Integration tests for snapshot artifact handling.
//!
//! These tests do not require KVM/libkrun — they exercise the
//! file-format, integrity-check, and archive layers by synthesizing
//! manifests + upper files directly. End-to-end tests that boot a
//! VM live alongside the other `msb_test`-gated integration tests.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use microsandbox::Snapshot;
use microsandbox::backend::{Backend, LocalBackend};
use microsandbox_image::snapshot::{
    DEFAULT_UPPER_FILE, DESCRIPTOR_FILENAME, ImageRef, Manifest, SCHEMA_VERSION,
    SNAPSHOT_ARTIFACT_KIND, SnapshotFormat, SnapshotScope, UpperIntegrity, UpperLayer,
};
use sha2::{Digest, Sha256};
use tar::{Builder, EntryType, Header};
use tempfile::TempDir;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct SeededImageCache {
    image_ref: microsandbox_image::Reference,
    manifest_digest: String,
    image_digest: microsandbox_image::Digest,
    diff_id: microsandbox_image::Digest,
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Build a synthetic snapshot artifact directory with a known upper
/// file. Returns `(artifact_dir, manifest_digest)`.
fn make_artifact(parent: &Path, name: &str, upper_bytes: &[u8]) -> (std::path::PathBuf, String) {
    make_artifact_with_parent_and_integrity(parent, name, upper_bytes, None, false)
}

fn make_artifact_with_scope(
    parent: &Path,
    name: &str,
    upper_bytes: &[u8],
    scope: SnapshotScope,
) -> (std::path::PathBuf, String) {
    let dir = parent.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(DEFAULT_UPPER_FILE), upper_bytes).unwrap();

    let manifest = Manifest {
        scope,
        ..sample_manifest(upper_bytes.len() as u64)
    };
    let bytes = manifest.to_canonical_bytes().unwrap();
    let digest = manifest.digest().unwrap();
    std::fs::write(dir.join(DESCRIPTOR_FILENAME), bytes).unwrap();
    (dir, digest)
}

fn sample_manifest(upper_size: u64) -> Manifest {
    Manifest {
        schema: SCHEMA_VERSION,
        artifact: SNAPSHOT_ARTIFACT_KIND.into(),
        scope: SnapshotScope::Disk,
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
            size_bytes: upper_size,
            integrity: None,
        },
        source_sandbox: Some("synthetic".into()),
        extensions: BTreeMap::new(),
        requires: Vec::new(),
    }
}

/// Build an artifact whose manifest names a required extension this
/// runtime does not understand.
fn make_artifact_with_unknown_require(
    parent: &Path,
    name: &str,
    upper_bytes: &[u8],
) -> (std::path::PathBuf, String) {
    let dir = parent.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(DEFAULT_UPPER_FILE), upper_bytes).unwrap();

    let mut manifest = sample_manifest(upper_bytes.len() as u64);
    manifest
        .extensions
        .insert("msb.future/1".into(), serde_json::json!({}));
    manifest.requires = vec!["msb.future/1".into()];
    let bytes = manifest.to_canonical_bytes().unwrap();
    let digest = manifest.digest().unwrap();
    std::fs::write(dir.join(DESCRIPTOR_FILENAME), bytes).unwrap();
    (dir, digest)
}

fn make_artifact_with_integrity(
    parent: &Path,
    name: &str,
    upper_bytes: &[u8],
    record_integrity: bool,
) -> (std::path::PathBuf, String) {
    make_artifact_with_parent_and_integrity(parent, name, upper_bytes, None, record_integrity)
}

fn make_artifact_with_parent(
    parent: &Path,
    name: &str,
    upper_bytes: &[u8],
    parent_digest: Option<String>,
) -> (std::path::PathBuf, String) {
    make_artifact_with_parent_and_integrity(parent, name, upper_bytes, parent_digest, false)
}

fn make_artifact_with_parent_and_integrity(
    parent: &Path,
    name: &str,
    upper_bytes: &[u8],
    parent_digest: Option<String>,
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

    let mut manifest = sample_manifest(upper_bytes.len() as u64);
    manifest.parent = parent_digest;
    manifest.upper.integrity = upper_integrity;
    let bytes = manifest.to_canonical_bytes().unwrap();
    let digest = manifest.digest().unwrap();
    std::fs::write(dir.join(DESCRIPTOR_FILENAME), bytes).unwrap();
    (dir, digest)
}

fn make_artifact_with_image(
    parent: &Path,
    name: &str,
    upper_bytes: &[u8],
    image_reference: String,
    image_manifest_digest: String,
) -> (std::path::PathBuf, String) {
    let dir = parent.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(DEFAULT_UPPER_FILE), upper_bytes).unwrap();

    let mut manifest = sample_manifest(upper_bytes.len() as u64);
    manifest.image = ImageRef {
        reference: image_reference,
        manifest_digest: image_manifest_digest,
    };
    let bytes = manifest.to_canonical_bytes().unwrap();
    let digest = manifest.digest().unwrap();
    std::fs::write(dir.join(DESCRIPTOR_FILENAME), bytes).unwrap();
    (dir, digest)
}

fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Build a synthetic snapshot artifact whose upper file is sparse: apparent size `len`, with the given `(offset, bytes)` data extents and holes everywhere else. Records a sha256
/// integrity digest over the logical content. Returns `(artifact_dir, manifest_digest, logical_content)`.
///
/// Holes are made real per platform: `mark_sparse` before writing so NTFS keeps unwritten ranges unallocated, and explicit hole punching afterwards on APFS, which densifies
/// seek-written files.
fn make_sparse_artifact(
    parent: &Path,
    name: &str,
    len: u64,
    extents: &[(u64, Vec<u8>)],
) -> (std::path::PathBuf, String, Vec<u8>) {
    use std::io::{Seek, SeekFrom, Write};

    let dir = parent.join(name);
    std::fs::create_dir_all(&dir).unwrap();

    let upper_path = dir.join(DEFAULT_UPPER_FILE);
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&upper_path)
        .unwrap();
    microsandbox_utils::extent::mark_sparse(&f).unwrap();
    f.set_len(len).unwrap();
    let mut logical = vec![0u8; len as usize];
    for (offset, bytes) in extents {
        f.seek(SeekFrom::Start(*offset)).unwrap();
        f.write_all(bytes).unwrap();
        logical[*offset as usize..*offset as usize + bytes.len()].copy_from_slice(bytes);
    }
    f.sync_all().unwrap();

    // Punch the hole ranges explicitly (no-op outside macOS).
    let mut sorted: Vec<(u64, u64)> = extents
        .iter()
        .map(|(off, bytes)| (*off, bytes.len() as u64))
        .collect();
    sorted.sort_unstable();
    let mut cursor = 0u64;
    for (off, extent_len) in sorted {
        if off > cursor {
            microsandbox_utils::extent::punch_hole_aligned(&f, cursor, off - cursor).unwrap();
        }
        cursor = cursor.max(off + extent_len);
    }
    if len > cursor {
        microsandbox_utils::extent::punch_hole_aligned(&f, cursor, len - cursor).unwrap();
    }

    let mut manifest = sample_manifest(len);
    manifest.upper.integrity = Some(UpperIntegrity {
        algorithm: "sha256".into(),
        digest: sha256_digest(&logical),
    });
    let bytes = manifest.to_canonical_bytes().unwrap();
    let digest = manifest.digest().unwrap();
    std::fs::write(dir.join(DESCRIPTOR_FILENAME), bytes).unwrap();
    (dir, digest, logical)
}

/// Bytes allocated on disk. Sparseness assertions are guarded on the source actually being sparse, since not every test filesystem keeps holes even with `mark_sparse` + hole
/// punching.
fn allocated_bytes(path: &Path) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).unwrap().blocks() * 512
    }
    #[cfg(not(unix))]
    {
        // No st_blocks on Windows; the extent map's data bytes are the
        // allocation for NTFS sparse files (dense fallback: full size).
        match microsandbox_utils::extent::ExtentMap::scan(path).unwrap() {
            Some(map) => map.data_bytes(),
            None => std::fs::metadata(path).unwrap().len(),
        }
    }
}

async fn seed_image_cache(cache: &microsandbox_image::GlobalCache) -> SeededImageCache {
    let image_ref: microsandbox_image::Reference = "docker.io/library/alpine:3.20".parse().unwrap();
    let raw_manifest = br#"{"schemaVersion":2,"layers":[]}"#;
    let raw_config =
        br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#;
    let manifest_digest = sha256_digest(raw_manifest);
    let config_digest = sha256_digest(raw_config);
    let diff_id: microsandbox_image::Digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000001000"
            .parse()
            .unwrap();
    let layer_digest = "sha256:0000000000000000000000000000000000000000000000000000000000002000";
    let metadata = microsandbox_image::CachedImageMetadata {
        manifest_digest: manifest_digest.clone(),
        config_digest,
        raw_manifest_json: String::from_utf8(raw_manifest.to_vec()).unwrap(),
        raw_config_json: String::from_utf8(raw_config.to_vec()).unwrap(),
        config: microsandbox_image::ImageConfig::default(),
        layers: vec![microsandbox_image::CachedLayerMetadata {
            digest: layer_digest.into(),
            media_type: Some("application/vnd.oci.image.layer.v1.tar+gzip".into()),
            size_bytes: Some(10),
            diff_id: diff_id.to_string(),
        }],
    };
    cache
        .write_image_metadata_async(&image_ref, &metadata)
        .await
        .unwrap();

    let image_digest: microsandbox_image::Digest = manifest_digest.parse().unwrap();
    std::fs::write(cache.layer_erofs_path(&diff_id), vec![0u8; 4096]).unwrap();
    std::fs::write(cache.fsmeta_erofs_path(&image_digest), vec![0u8; 4096]).unwrap();
    std::fs::write(cache.vmdk_path(&image_digest), b"# vmdk").unwrap();

    SeededImageCache {
        image_ref,
        manifest_digest,
        image_digest,
        diff_id,
    }
}

fn write_archive_from_artifacts(archive: &Path, artifacts: &[(&Path, &str)]) {
    let file = std::fs::File::create(archive).unwrap();
    let mut builder = Builder::new(file);
    for (artifact, archive_name) in artifacts {
        builder
            .append_path_with_name(
                artifact.join(DESCRIPTOR_FILENAME),
                format!("{archive_name}/{DESCRIPTOR_FILENAME}"),
            )
            .unwrap();
        builder
            .append_path_with_name(
                artifact.join(DEFAULT_UPPER_FILE),
                format!("{archive_name}/{DEFAULT_UPPER_FILE}"),
            )
            .unwrap();
    }
    builder.finish().unwrap();
}

fn write_regular_file_archive(archive: &Path, path: &str, payload: &[u8]) {
    let file = std::fs::File::create(archive).unwrap();
    let mut builder = Builder::new(file);

    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_path(path).unwrap();
    header.set_mode(0o644);
    header.set_size(payload.len() as u64);
    header.set_cksum();
    builder.append(&header, Cursor::new(payload)).unwrap();
    builder.finish().unwrap();
}

fn write_symlink_traversal_archive(archive: &Path, escape_dir: &Path) {
    let file = std::fs::File::create(archive).unwrap();
    let mut builder = Builder::new(file);

    let mut link_header = Header::new_gnu();
    link_header.set_entry_type(EntryType::Symlink);
    link_header.set_path("snap/link").unwrap();
    link_header.set_link_name(escape_dir).unwrap();
    link_header.set_mode(0o777);
    link_header.set_size(0);
    link_header.set_cksum();
    builder
        .append(&link_header, Cursor::new(Vec::new()))
        .unwrap();

    let payload = b"pwned via snapshot import symlink traversal\n";
    let mut file_header = Header::new_gnu();
    file_header.set_entry_type(EntryType::Regular);
    file_header.set_path("snap/link/pwned.txt").unwrap();
    file_header.set_mode(0o644);
    file_header.set_size(payload.len() as u64);
    file_header.set_cksum();
    builder
        .append(&file_header, Cursor::new(payload.as_slice()))
        .unwrap();

    builder.finish().unwrap();
}

async fn isolated_backend(home: &Path) -> Arc<dyn Backend> {
    Arc::new(LocalBackend::builder().home(home).build().await.unwrap())
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

#[test]
fn builder_supports_name_first_contract() {
    let config = Snapshot::builder("clean-python")
        .from_sandbox("build-box")
        .label("stage", "deps")
        .build()
        .unwrap();

    assert_eq!(config.name, "clean-python");
    assert_eq!(config.source_sandbox, "build-box");
    assert_eq!(config.labels, vec![("stage".into(), "deps".into())]);
}

#[test]
fn builder_carries_dest_dir() {
    let config = Snapshot::builder("clean")
        .from_sandbox("box")
        .dest_dir("/mnt/big")
        .build()
        .unwrap();
    assert_eq!(config.name, "clean");
    assert_eq!(
        config.dest_dir.as_deref(),
        Some(std::path::Path::new("/mnt/big"))
    );
}

#[test]
fn builder_requires_source_sandbox() {
    let err = Snapshot::builder("clean").build().unwrap_err();
    assert!(err.to_string().contains("from_sandbox"));
}

#[tokio::test]
async fn legacy_manifest_json_artifacts_are_not_recognized() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("legacy");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(DEFAULT_UPPER_FILE), b"old upper bytes").unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        br#"{"schema":1,"format":"raw","fstype":"ext4","image":{"ref":"docker.io/library/alpine:3.20","manifest_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000001"},"parent":null,"created_at":"2026-05-01T12:00:00Z","labels":{},"upper":{"file":"upper.ext4","size_bytes":15,"integrity":null},"source_sandbox":"synthetic"}"#,
    )
    .unwrap();

    let err = Snapshot::open(dir.to_string_lossy().as_ref())
        .await
        .unwrap_err();
    assert!(err.to_string().contains(DESCRIPTOR_FILENAME));

    let snaps = Snapshot::list_dir(tmp.path()).await.unwrap();
    assert!(snaps.is_empty());
}

#[tokio::test]
async fn open_accepts_resumable_scope_artifact() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact_with_scope(
        tmp.path(),
        "resumable-snap",
        b"upper",
        SnapshotScope::Resumable,
    );

    let snap = Snapshot::open(dir.to_string_lossy().as_ref())
        .await
        .unwrap();
    assert_eq!(snap.manifest().scope, SnapshotScope::Resumable);
}

#[tokio::test]
async fn from_snapshot_rejects_resumable_scope_at_restore() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact_with_scope(
        tmp.path(),
        "resumable-snap",
        b"upper",
        SnapshotScope::Resumable,
    );

    let err = microsandbox::Sandbox::builder("restore-scope-test")
        .from_snapshot(dir.to_string_lossy().to_string())
        .build()
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("non-disk"),
        "unexpected error: {err}"
    );
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
        dir.join(DESCRIPTOR_FILENAME),
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
async fn save_then_load_round_trips_via_zstd() {
    let tmp = TempDir::new().unwrap();
    let (dir, original_digest) = make_artifact(tmp.path(), "src-snap", b"the upper bytes");

    let archive = tmp.path().join("bundle.tar.zst");
    Snapshot::save(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts::default(),
    )
    .await
    .unwrap();
    assert!(archive.exists());
    assert!(std::fs::metadata(&archive).unwrap().len() > 0);

    let dest = tmp.path().join("imported");
    let handle = Snapshot::load(&archive, Some(&dest)).await.unwrap();
    assert_eq!(handle.digest(), original_digest);

    // Re-open the imported artifact via path; integrity should hold.
    let imported = Snapshot::open(handle.path().to_string_lossy().as_ref())
        .await
        .unwrap();
    assert_eq!(imported.digest(), original_digest);
}

#[tokio::test]
async fn save_then_load_round_trips_via_plain_tar() {
    let tmp = TempDir::new().unwrap();
    let (dir, original_digest) = make_artifact(tmp.path(), "src-plain", b"plain tar bytes");

    let archive = tmp.path().join("bundle.tar");
    Snapshot::save(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts {
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let dest = tmp.path().join("imported-plain");
    let handle = Snapshot::load(&archive, Some(&dest)).await.unwrap();
    assert_eq!(handle.digest(), original_digest);
}

#[tokio::test]
async fn save_sparse_upper_round_trips_and_preserves_holes() {
    let tmp = TempDir::new().unwrap();
    let len: u64 = 16 * 1024 * 1024;
    // Data at the start, in the middle, and at a 512-unaligned offset;
    // trailing hole after the last extent.
    let extents = vec![
        (0u64, vec![0xAB; 64 * 1024]),
        (4 * 1024 * 1024, vec![0xCD; 64 * 1024]),
        (12 * 1024 * 1024 + 300, vec![0xEF; 1000]),
    ];
    let (dir, original_digest, logical) =
        make_sparse_artifact(tmp.path(), "src-sparse", len, &extents);
    if allocated_bytes(&dir.join(DEFAULT_UPPER_FILE)) >= len / 2 {
        eprintln!("filesystem did not sparsify the upper; sparse save not exercised");
        return;
    }

    let archive = tmp.path().join("sparse.tar.zst");
    Snapshot::save(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts::default(),
    )
    .await
    .unwrap();

    // Load verifies the recorded sha256 over the unpacked upper's
    // logical content; compare the bytes explicitly as well.
    let dest = tmp.path().join("imported-sparse");
    let handle = Snapshot::load(&archive, Some(&dest)).await.unwrap();
    assert_eq!(handle.digest(), original_digest);
    let imported_upper = handle.path().join(DEFAULT_UPPER_FILE);
    assert_eq!(std::fs::read(&imported_upper).unwrap(), logical);

    // Holes must come back as holes, not zero-filled blocks.
    let imported_allocated = allocated_bytes(&imported_upper);
    assert!(
        imported_allocated < len / 2,
        "imported upper was densified: {imported_allocated} bytes allocated for apparent size {len}",
    );
}

#[tokio::test]
async fn sparse_save_stores_only_data_extents_in_plain_tar() {
    let tmp = TempDir::new().unwrap();
    let len: u64 = 16 * 1024 * 1024;
    let extents = vec![
        (0u64, vec![0x5A; 64 * 1024]),
        (8 * 1024 * 1024, vec![0xA5; 64 * 1024]),
    ];
    let (dir, _, logical) = make_sparse_artifact(tmp.path(), "src-plain-sparse", len, &extents);
    if allocated_bytes(&dir.join(DEFAULT_UPPER_FILE)) >= len / 2 {
        eprintln!("filesystem did not sparsify the upper; sparse save not exercised");
        return;
    }

    let archive = tmp.path().join("sparse.tar");
    Snapshot::save(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts {
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // A dense entry would make the uncompressed archive at least the
    // upper's 16 MiB apparent size.
    let archive_len = std::fs::metadata(&archive).unwrap().len();
    assert!(
        archive_len < 2 * 1024 * 1024,
        "archive stored hole bytes: {archive_len} bytes",
    );

    // The upper is an old-GNU sparse entry that an independent tar
    // implementation (the sync `tar` crate) reads back to identical
    // logical content.
    let mut ar = tar::Archive::new(std::fs::File::open(&archive).unwrap());
    let mut upper_entry_type = None;
    for entry in ar.entries().unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().unwrap().to_path_buf();
        if path.file_name().and_then(|n| n.to_str()) == Some(DEFAULT_UPPER_FILE) {
            upper_entry_type = Some(entry.header().entry_type());
        }
    }
    assert_eq!(upper_entry_type, Some(EntryType::GNUSparse));

    let unpack_dir = tmp.path().join("external-unpack");
    std::fs::create_dir_all(&unpack_dir).unwrap();
    let mut ar = tar::Archive::new(std::fs::File::open(&archive).unwrap());
    ar.unpack(&unpack_dir).unwrap();
    let unpacked_upper = std::fs::read_dir(&unpack_dir)
        .unwrap()
        .map(|e| e.unwrap().path().join(DEFAULT_UPPER_FILE))
        .find(|p| p.exists())
        .expect("unpacked artifact dir with upper file");
    assert_eq!(std::fs::read(&unpacked_upper).unwrap(), logical);
}

#[tokio::test]
async fn sparse_save_many_extents_round_trips() {
    // Enough extents to spill past the 4 inline sparse-map slots into
    // chained extended sparse headers (21 slots each). The file ends
    // with data, so no trailing-hole terminator is needed.
    let tmp = TempDir::new().unwrap();
    let len: u64 = 8 * 1024 * 1024;
    let mut extents: Vec<(u64, Vec<u8>)> = (0..60u64)
        .map(|i| (i * 128 * 1024, vec![(i % 251) as u8 + 1; 4096]))
        .collect();
    extents.push((len - 4096, vec![0x77; 4096]));
    let (dir, original_digest, logical) =
        make_sparse_artifact(tmp.path(), "src-many-extents", len, &extents);
    if allocated_bytes(&dir.join(DEFAULT_UPPER_FILE)) >= len / 2 {
        eprintln!("filesystem did not sparsify the upper; sparse save not exercised");
        return;
    }

    let archive = tmp.path().join("many.tar.zst");
    Snapshot::save(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts::default(),
    )
    .await
    .unwrap();

    let dest = tmp.path().join("imported-many");
    let handle = Snapshot::load(&archive, Some(&dest)).await.unwrap();
    assert_eq!(handle.digest(), original_digest);
    let imported_upper = handle.path().join(DEFAULT_UPPER_FILE);
    assert_eq!(std::fs::read(&imported_upper).unwrap(), logical);
}

#[tokio::test]
async fn sparse_save_all_hole_upper_round_trips() {
    let tmp = TempDir::new().unwrap();
    let len: u64 = 4 * 1024 * 1024;
    let (dir, original_digest, logical) =
        make_sparse_artifact(tmp.path(), "src-all-hole", len, &[]);
    if allocated_bytes(&dir.join(DEFAULT_UPPER_FILE)) >= len / 2 {
        eprintln!("filesystem did not sparsify the upper; sparse save not exercised");
        return;
    }

    let archive = tmp.path().join("hole.tar.zst");
    Snapshot::save(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts::default(),
    )
    .await
    .unwrap();

    let dest = tmp.path().join("imported-hole");
    let handle = Snapshot::load(&archive, Some(&dest)).await.unwrap();
    assert_eq!(handle.digest(), original_digest);
    let imported_upper = handle.path().join(DEFAULT_UPPER_FILE);
    assert_eq!(std::fs::read(&imported_upper).unwrap(), logical);
}

#[tokio::test]
async fn dense_upper_keeps_regular_entry() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact(tmp.path(), "src-dense", b"fully allocated upper");

    let archive = tmp.path().join("dense.tar");
    Snapshot::save(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts {
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let mut ar = tar::Archive::new(std::fs::File::open(&archive).unwrap());
    let mut upper_entry_type = None;
    for entry in ar.entries().unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().unwrap().to_path_buf();
        if path.file_name().and_then(|n| n.to_str()) == Some(DEFAULT_UPPER_FILE) {
            upper_entry_type = Some(entry.header().entry_type());
        }
    }
    assert_eq!(upper_entry_type, Some(EntryType::Regular));
}

/// The load walker's grammar is closed: GNU long-name entries (which our save path never produces; archive names are two short components) must be rejected, not resolved.
#[tokio::test]
async fn load_rejects_long_name_entries() {
    let tmp = TempDir::new().unwrap();
    let long_name = format!("sha256-0000000000000000/{}", "x".repeat(120));

    let mut bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut bytes);
        let mut header = Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header.set_cksum();
        // The sync tar Builder emits a GNU long-name ('L') entry for
        // names beyond the 100-byte header field.
        builder
            .append_data(&mut header, &long_name, &b"data"[..])
            .unwrap();
        builder.finish().unwrap();
    }
    let archive = tmp.path().join("longname.tar");
    std::fs::write(&archive, &bytes).unwrap();

    let err = Snapshot::load(&archive, Some(&tmp.path().join("dest")))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unsupported entry type"),
        "expected long-name rejection, got: {err}"
    );
}

/// A header whose recorded checksum disagrees with its bytes is corruption, not something to unpack around.
#[tokio::test]
async fn load_rejects_corrupt_header_checksum() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact(tmp.path(), "src-cksum", b"upper bytes");

    let archive = tmp.path().join("ok.tar");
    Snapshot::save(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts {
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let mut bytes = std::fs::read(&archive).unwrap();
    // Flip a bit in the first header's name field without refreshing
    // the recorded checksum.
    bytes[0] ^= 0x01;
    let corrupt = tmp.path().join("corrupt.tar");
    std::fs::write(&corrupt, &bytes).unwrap();

    let err = Snapshot::load(&corrupt, Some(&tmp.path().join("dest")))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("checksum mismatch"),
        "expected checksum rejection, got: {err}"
    );
}

/// A sparse map whose runs overlap or run backwards is malformed and must be rejected before any data is written.
#[tokio::test]
async fn load_rejects_overlapping_sparse_map() {
    fn octal12(field: &mut [u8; 12], value: u64) {
        let octal = format!("{value:011o}");
        field[..11].copy_from_slice(octal.as_bytes());
        field[11] = 0;
    }

    let tmp = TempDir::new().unwrap();

    let mut header = Header::new_gnu();
    header
        .set_path("sha256-0000000000000000/upper.ext4")
        .unwrap();
    header.set_mode(0o644);
    header.set_entry_type(EntryType::GNUSparse);
    header.set_size(1024);
    {
        let gnu = header.as_gnu_mut().unwrap();
        octal12(&mut gnu.realsize, 768);
        // Two 512-byte runs that overlap: [0, 512) then [256, 768).
        octal12(&mut gnu.sparse[0].offset, 0);
        octal12(&mut gnu.sparse[0].numbytes, 512);
        octal12(&mut gnu.sparse[1].offset, 256);
        octal12(&mut gnu.sparse[1].numbytes, 512);
    }
    header.set_cksum();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(&[0xAAu8; 1024]); // the two data runs
    bytes.extend_from_slice(&[0u8; 1024]); // end-of-archive marker

    let archive = tmp.path().join("overlap.tar");
    std::fs::write(&archive, &bytes).unwrap();

    let err = Snapshot::load(&archive, Some(&tmp.path().join("dest")))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("out of order or overlapping"),
        "expected sparse-map rejection, got: {err}"
    );
}

#[tokio::test]
async fn save_with_image_includes_only_pinned_cache_artifacts() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let cache_dir = home.join("cache");
    let cache = microsandbox_image::GlobalCache::new(&cache_dir).unwrap();
    let seeded = seed_image_cache(&cache).await;
    std::fs::write(cache.layers_dir().join("unrelated.erofs"), vec![0u8; 4096]).unwrap();
    std::fs::write(cache.fsmeta_dir().join("unrelated.erofs"), vec![0u8; 4096]).unwrap();

    let (dir, _) = make_artifact_with_image(
        tmp.path(),
        "src-with-image",
        b"upper",
        seeded.image_ref.to_string(),
        seeded.manifest_digest.clone(),
    );
    let archive = tmp.path().join("with-image.tar");

    microsandbox::with_backend(backend, async {
        Snapshot::save(
            dir.to_string_lossy().as_ref(),
            &archive,
            microsandbox::snapshot::SaveOpts {
                with_image: true,
                plain_tar: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    })
    .await;

    let file = std::fs::File::open(&archive).unwrap();
    let mut tar = tar::Archive::new(file);
    let names = tar
        .entries()
        .unwrap()
        .map(|entry| entry.unwrap().path().unwrap().to_string_lossy().to_string())
        .collect::<Vec<_>>();

    let metadata_name = cache
        .image_metadata_path(&seeded.image_ref)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert!(
        names
            .iter()
            .any(|name| name == &format!("cache/manifests/{metadata_name}")),
        "archive did not include image metadata: {names:?}"
    );
    assert!(
        names.iter().any(|name| name.starts_with("cache/layers/"))
            && names.iter().any(|name| name.starts_with("cache/fsmeta/"))
            && names.iter().any(|name| name.starts_with("cache/vmdk/")),
        "archive did not include required image artifacts: {names:?}"
    );
    assert!(
        !names.iter().any(|name| name.contains("unrelated")),
        "archive swept unrelated cache entries: {names:?}"
    );
}

#[tokio::test]
async fn load_rejects_symlink_entries_without_writing_outside_dest() {
    let tmp = TempDir::new().unwrap();
    let archive = tmp.path().join("malicious.tar");
    let dest = tmp.path().join("dest");
    let escape_dir = tmp.path().join("escape");
    let escape_file = escape_dir.join("pwned.txt");
    std::fs::create_dir_all(&escape_dir).unwrap();

    write_symlink_traversal_archive(&archive, &escape_dir);

    let err = Snapshot::load(&archive, Some(&dest))
        .await
        .expect_err("expected import to reject symlink archive entry");

    let msg = err.to_string();
    assert!(
        msg.contains("unsupported entry type"),
        "expected unsupported entry type error, got: {msg}"
    );
    assert!(
        !escape_file.exists(),
        "archive import wrote outside the destination"
    );
    assert!(
        !dest.join("snap/link").exists() && !dest.join("snap/link").is_symlink(),
        "archive import created the rejected symlink entry"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn load_does_not_follow_preexisting_symlink_parent() {
    let tmp = TempDir::new().unwrap();
    let archive = tmp.path().join("regular.tar");
    let dest = tmp.path().join("dest");
    let escape_dir = tmp.path().join("escape");
    let escape_file = escape_dir.join("pwned.txt");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::create_dir_all(&escape_dir).unwrap();
    std::os::unix::fs::symlink(&escape_dir, dest.join("snap")).unwrap();
    write_regular_file_archive(&archive, "snap/pwned.txt", b"should not escape\n");

    let err = Snapshot::load(&archive, Some(&dest))
        .await
        .expect_err("expected import without a manifest to fail");

    let msg = err.to_string();
    assert!(
        msg.contains("no snapshot manifest") || msg.contains("manifest"),
        "unexpected error: {msg}"
    );
    assert!(
        !escape_file.exists(),
        "archive import followed a pre-existing symlink parent"
    );
}

#[tokio::test]
async fn open_rejects_manifest_upper_file_that_escapes_artifact() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("bad-upper-path");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(tmp.path().join("outside.ext4"), b"data").unwrap();

    let mut manifest = sample_manifest(4);
    manifest.upper.file = "../outside.ext4".into();
    std::fs::write(
        dir.join(DESCRIPTOR_FILENAME),
        manifest.to_canonical_bytes().unwrap(),
    )
    .unwrap();

    let err = Snapshot::open(dir.to_string_lossy().as_ref())
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("upper.file"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn load_verifies_every_snapshot_manifest_before_indexing() {
    let tmp = TempDir::new().unwrap();
    let (bad_dir, _) = make_artifact_with_integrity(tmp.path(), "bad-snap", b"original", true);
    std::fs::write(bad_dir.join(DEFAULT_UPPER_FILE), b"tampered").unwrap();
    let (good_dir, _) = make_artifact(tmp.path(), "good-snap", b"good");
    let archive = tmp.path().join("multi.tar");
    write_archive_from_artifacts(
        &archive,
        &[
            (bad_dir.as_path(), "bad-snap"),
            (good_dir.as_path(), "good-snap"),
        ],
    );

    let dest = tmp.path().join("imported");
    let err = Snapshot::load(&archive, Some(&dest))
        .await
        .expect_err("expected tampered sibling to fail import");

    assert!(
        err.to_string().contains("digest mismatch"),
        "unexpected error: {err}"
    );
    assert!(
        !dest.join("bad-snap").exists() && !dest.join("good-snap").exists(),
        "failed import promoted staged snapshots"
    );
}

#[tokio::test]
async fn load_detects_zstd_by_magic_bytes() {
    let tmp = TempDir::new().unwrap();
    let (dir, original_digest) = make_artifact(tmp.path(), "src-magic", b"magic zstd");

    let archive = tmp.path().join("bundle.snapshot");
    Snapshot::save(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts::default(),
    )
    .await
    .unwrap();

    let dest = tmp.path().join("imported-magic");
    let handle = Snapshot::load(&archive, Some(&dest)).await.unwrap();
    assert_eq!(handle.digest(), original_digest);
}

#[tokio::test]
async fn load_selects_child_head_when_parents_are_present() {
    let tmp = TempDir::new().unwrap();
    let (parent_dir, parent_digest) = make_artifact(tmp.path(), "parent", b"parent");
    let (child_dir, child_digest) =
        make_artifact_with_parent(tmp.path(), "child", b"child", Some(parent_digest));
    let archive = tmp.path().join("chain.tar");
    write_archive_from_artifacts(
        &archive,
        &[
            (child_dir.as_path(), "child"),
            (parent_dir.as_path(), "parent"),
        ],
    );

    let dest = tmp.path().join("imported-chain");
    let handle = Snapshot::load(&archive, Some(&dest)).await.unwrap();
    assert_eq!(handle.digest(), child_digest);
    assert_eq!(handle.path(), dest.join("child"));
}

#[tokio::test]
async fn failed_load_does_not_install_staged_cache_entries() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let archive = tmp.path().join("cache-poison.tar");
    write_regular_file_archive(
        &archive,
        "cache/manifests/not-real.json",
        br#"{"manifest_digest":"sha256:bad"}"#,
    );
    let dest = tmp.path().join("dest");

    microsandbox::with_backend(backend, async {
        let err = Snapshot::load(&archive, Some(&dest))
            .await
            .expect_err("expected cache-only import to fail");
        assert!(
            err.to_string().contains("no snapshot manifest"),
            "unexpected error: {err}"
        );
    })
    .await;

    assert!(
        !home.join("cache/manifests/not-real.json").exists(),
        "failed import installed cache entry"
    );
}

#[tokio::test]
async fn failed_load_with_conflicting_cache_target_does_not_install_cache_entries() {
    let tmp = TempDir::new().unwrap();
    let export_home = tmp.path().join("export-home");
    let export_backend = isolated_backend(&export_home).await;
    let export_cache = microsandbox_image::GlobalCache::new(&export_home.join("cache")).unwrap();
    let seeded = seed_image_cache(&export_cache).await;
    let (dir, _) = make_artifact_with_image(
        tmp.path(),
        "src-cache-conflict",
        b"upper",
        seeded.image_ref.to_string(),
        seeded.manifest_digest.clone(),
    );
    let archive = tmp.path().join("cache-conflict.tar");

    microsandbox::with_backend(
        export_backend,
        Box::pin(async {
            Snapshot::save(
                dir.to_string_lossy().as_ref(),
                &archive,
                microsandbox::snapshot::SaveOpts {
                    with_image: true,
                    plain_tar: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }),
    )
    .await;

    let import_home = tmp.path().join("import-home");
    let import_backend = isolated_backend(&import_home).await;
    let import_cache = microsandbox_image::GlobalCache::new(&import_home.join("cache")).unwrap();
    let conflicting_metadata = import_cache.image_metadata_path(&seeded.image_ref);
    std::fs::write(&conflicting_metadata, b"conflicting metadata").unwrap();
    let expected_layer = import_cache.layer_erofs_path(&seeded.diff_id);
    let expected_fsmeta = import_cache.fsmeta_erofs_path(&seeded.image_digest);
    let expected_vmdk = import_cache.vmdk_path(&seeded.image_digest);
    let dest = tmp.path().join("cache-conflict-dest");

    microsandbox::with_backend(
        import_backend,
        Box::pin(async {
            let err = Snapshot::load(&archive, Some(&dest))
                .await
                .expect_err("expected conflicting cache target to fail import");
            assert!(
                err.to_string()
                    .contains("cache target already exists with different content"),
                "unexpected error: {err}"
            );
        }),
    )
    .await;

    assert!(
        !dest.join("src-cache-conflict").exists(),
        "failed import promoted staged snapshot"
    );
    assert_eq!(
        std::fs::read(&conflicting_metadata).unwrap(),
        b"conflicting metadata"
    );
    assert!(
        !expected_layer.exists() && !expected_fsmeta.exists() && !expected_vmdk.exists(),
        "failed import installed cache artifacts"
    );
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

// A slurp implementation would allocate 4 GiB and OOM the runner;
// a streaming implementation reads a few tar blocks and errors fast.
#[tokio::test]
async fn load_streams_large_archive_without_buffering() {
    let tmp = TempDir::new().unwrap();
    let archive = tmp.path().join("sparse.tar");

    let file = std::fs::File::create(&archive).unwrap();
    file.set_len(4 * 1024 * 1024 * 1024).unwrap();
    drop(file);

    let dest = tmp.path().join("dest");
    let err = Snapshot::load(&archive, Some(&dest))
        .await
        .expect_err("expected import of sparse archive to fail");

    let msg = err.to_string();
    assert!(
        msg.contains("no snapshot manifest") || msg.contains("manifest"),
        "got: {msg}"
    );
}

#[tokio::test]
async fn create_rejects_resumable_before_touching_anything() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;

    microsandbox::with_backend(backend, async {
        let err = Snapshot::builder("warm")
            .from_sandbox("box")
            .resumable()
            .create()
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Resumable snapshots"),
            "unexpected error: {err}"
        );
    })
    .await;

    assert!(!home.join("snapshots").join("warm").exists());
}

#[tokio::test]
async fn create_rejects_unaddressable_names() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;

    microsandbox::with_backend(backend, async {
        for name in ["~cache", "sha256:v1", "a\\b"] {
            let err = Snapshot::builder(name)
                .from_sandbox("box")
                .create()
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("bare identifier"),
                "{name}: unexpected error: {err}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn from_snapshot_rejects_unknown_required_extension_but_open_works() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact_with_unknown_require(tmp.path(), "future-snap", b"upper");

    let snap = Snapshot::open(dir.to_string_lossy().as_ref())
        .await
        .unwrap();
    assert_eq!(snap.manifest().requires, vec!["msb.future/1".to_string()]);

    let err = microsandbox::Sandbox::builder("requires-gate-test")
        .from_snapshot(dir.to_string_lossy().to_string())
        .build()
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("msb.future/1"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn replacing_child_in_place_does_not_inflate_parent_child_count() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let snapshots = home.join("snapshots");
    std::fs::create_dir_all(&snapshots).unwrap();

    microsandbox::with_backend(backend, async {
        let (_pdir, pdigest) = make_artifact(&snapshots, "parent", b"parent upper");
        let (cdir, _c1) =
            make_artifact_with_parent(&snapshots, "child", b"child v1", Some(pdigest.clone()));
        Snapshot::reindex(&snapshots).await.unwrap();

        // Replace the child in place: same name and path, different digest,
        // same parent. Opening it runs the auto-reindex upsert, which must
        // not double-count the parent edge.
        std::fs::remove_dir_all(&cdir).unwrap();
        make_artifact_with_parent(
            &snapshots,
            "child",
            b"child v2 with different size",
            Some(pdigest.clone()),
        );
        Snapshot::open("child").await.unwrap();

        Snapshot::remove("child", false).await.unwrap();
        Snapshot::remove("parent", false)
            .await
            .expect("parent should be removable once its only child is gone");
    })
    .await;
}

#[tokio::test]
async fn list_dir_skips_dot_prefixed_staging_directories() {
    let tmp = TempDir::new().unwrap();
    make_artifact(tmp.path(), "real", b"upper");
    make_artifact(tmp.path(), ".ghost.staging", b"upper");

    let snaps = Snapshot::list_dir(tmp.path()).await.unwrap();
    assert_eq!(snaps.len(), 1);
    assert!(snaps[0].path().ends_with("real"));
}
