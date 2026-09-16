//! Integration tests for snapshot artifact handling.
//!
//! These tests do not require KVM/libkrun — they exercise the
//! file-format, integrity-check, and archive layers by synthesizing
//! manifests + upper files directly. End-to-end tests that boot a
//! VM live alongside the other `msb_test`-gated integration tests.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox::backend::{Backend, LocalBackend};
use microsandbox::{MicrosandboxResult, SaveOpts, Snapshot, SnapshotReference};
use microsandbox_types::snapshot::{
    CheckpointSnapshotState, DEFAULT_UPPER_FILE, DESCRIPTOR_FILENAME, DiskLayer, DiskLayerId,
    FileSnapshotState, ImageRef, LayerFileKind, LayerPayload, Manifest, SCHEMA, SnapshotCapture,
    SnapshotConsistency, SnapshotFormat, SnapshotId, SnapshotRootDisk, SnapshotScope,
    SnapshotState, UpperIntegrity,
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

fn reference_path(reference: SnapshotReference) -> PathBuf {
    match reference {
        SnapshotReference::Path(path) => PathBuf::from(path),
        other => panic!("expected path-backed snapshot, got {other:?}"),
    }
}

async fn save_snapshot(name_or_path: &str, out: &Path, opts: SaveOpts) -> MicrosandboxResult<()> {
    Snapshot::open(name_or_path).await?.save_to(out, opts).await
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

    let manifest = if scope == SnapshotScope::Full {
        Manifest {
            scope,
            state: SnapshotState::Checkpoint(CheckpointSnapshotState {
                checkpoint_id: "ckpt_synthetic".into(),
                checkpoint_root:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
                restore_intents: vec!["resume".into()],
                requirements_summary: BTreeMap::new(),
            }),
            ..sample_manifest(upper_bytes.len() as u64)
        }
    } else {
        sample_manifest(upper_bytes.len() as u64)
    };
    let bytes = manifest.to_canonical_bytes().unwrap();
    let digest = manifest.digest().unwrap();
    std::fs::write(dir.join(DESCRIPTOR_FILENAME), bytes).unwrap();
    (dir, digest)
}

fn sample_manifest(upper_size: u64) -> Manifest {
    let snapshot_id = SnapshotId::new(format!("snap_{:032x}", rand::random::<u128>())).unwrap();
    let layer_id = DiskLayerId::new(format!("layer_{:032x}", rand::random::<u128>())).unwrap();
    Manifest {
        schema: SCHEMA.into(),
        snapshot_id,
        scope: SnapshotScope::Disk,
        state: SnapshotState::File(FileSnapshotState {
            disk_format: SnapshotFormat::Raw,
            filesystem: "ext4".into(),
            virtual_size: upper_size,
            head: layer_id.clone(),
            layers: vec![DiskLayer {
                layer_id,
                format: SnapshotFormat::Raw,
                virtual_size: upper_size,
                backing: None,
                payload: LayerPayload {
                    file_kind: LayerFileKind::Regular,
                    integrity: Some(UpperIntegrity::SparseSha256V1 {
                        digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                    }),
                },
            }],
        }),
        capture: SnapshotCapture {
            created_at: "2026-05-01T12:00:00Z".into(),
            source_lineage: Some("synthetic".into()),
            source_checkpoint: None,
            consistency: SnapshotConsistency::CrashConsistent,
        },
        image: ImageRef {
            reference: "docker.io/library/alpine:3.20".into(),
            manifest_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000001".into(),
        },
        root_disk: SnapshotRootDisk::Managed,
        parent: None,
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
    parent_id: Option<String>,
) -> (std::path::PathBuf, String) {
    make_artifact_with_parent_and_integrity(parent, name, upper_bytes, parent_id, false)
}

fn make_artifact_with_parent_and_integrity(
    parent: &Path,
    name: &str,
    upper_bytes: &[u8],
    parent_id: Option<String>,
    record_integrity: bool,
) -> (std::path::PathBuf, String) {
    let dir = parent.join(name);
    std::fs::create_dir_all(&dir).unwrap();

    let upper_path = dir.join(DEFAULT_UPPER_FILE);
    std::fs::write(&upper_path, upper_bytes).unwrap();

    let mut manifest = sample_manifest(upper_bytes.len() as u64);
    manifest.parent = parent_id.map(|id| SnapshotId::new(id).unwrap());
    let SnapshotState::File(file) = &mut manifest.state else {
        unreachable!()
    };
    file.layers[0].payload.integrity = record_integrity.then(|| UpperIntegrity::SparseSha256V1 {
        digest: sparse_digest(upper_bytes),
    });
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
    let SnapshotState::File(file) = &mut manifest.state else {
        unreachable!()
    };
    file.layers[0].payload.integrity = Some(UpperIntegrity::SparseSha256V1 {
        digest: sparse_digest(upper_bytes),
    });
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

fn artifact_id(dir: &Path) -> String {
    let bytes = std::fs::read(dir.join(DESCRIPTOR_FILENAME)).unwrap();
    Manifest::from_bytes(&bytes)
        .unwrap()
        .snapshot_id
        .to_string()
}

fn artifact_payload_path(dir: &Path) -> std::path::PathBuf {
    let layers = dir.join("layers");
    if layers.is_dir() {
        return std::fs::read_dir(layers)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
    }
    dir.join(DEFAULT_UPPER_FILE)
}

fn sparse_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"msb-sparse-sha256-v1\0");
    hasher.update((bytes.len() as u64).to_le_bytes());
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
    let SnapshotState::File(file) = &mut manifest.state else {
        unreachable!()
    };
    file.layers[0].payload.integrity = Some(UpperIntegrity::SparseSha256V1 {
        digest: sparse_digest(&logical),
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
    // Cache validation parses the EROFS superblock and root inode, so these
    // fixtures must be real filesystem images rather than aligned zero files.
    let empty_tree = microsandbox_image::tree::FileTree::new();
    microsandbox_image::erofs::write_erofs(&empty_tree, &cache.layer_erofs_path(&diff_id)).unwrap();
    microsandbox_image::erofs::write_erofs(&empty_tree, &cache.fsmeta_erofs_path(&image_digest))
        .unwrap();
    std::fs::write(cache.vmdk_path(&image_digest), b"# vmdk").unwrap();

    SeededImageCache {
        image_ref,
        manifest_digest,
        image_digest,
        diff_id,
    }
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

/// Flip one stored byte without touching the member header. Tar's header
/// checksum therefore still passes, leaving member transport integrity as the
/// check that must reject the archive.
fn corrupt_dense_tar_member(archive: &Path, suffix: &str) {
    const BLOCK: usize = 512;

    let mut bytes = std::fs::read(archive).unwrap();
    let mut offset = 0usize;
    while offset + BLOCK <= bytes.len() {
        if bytes[offset..offset + BLOCK].iter().all(|byte| *byte == 0) {
            break;
        }
        let mut header = Header::new_old();
        header
            .as_mut_bytes()
            .copy_from_slice(&bytes[offset..offset + BLOCK]);
        let size = header.entry_size().unwrap() as usize;
        let path = header.path().unwrap();
        if path.to_string_lossy().ends_with(suffix) {
            assert!(size > 0, "selected archive member is empty");
            bytes[offset + BLOCK] ^= 0x01;
            std::fs::write(archive, bytes).unwrap();
            return;
        }
        offset += BLOCK + size.div_ceil(BLOCK) * BLOCK;
    }
    panic!("archive member ending in {suffix} was not found");
}

fn write_v066_archive(archive: &Path, prefix: &str, upper: &[u8]) {
    let file = std::fs::File::create(archive).unwrap();
    let mut builder = Builder::new(file);
    let descriptor = format!(
        "{{\"schema\":1,\"format\":\"raw\",\"fstype\":\"ext4\",\"image\":{{\"ref\":\"docker.io/library/alpine:3.20\",\"manifest_digest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000001\"}},\"parent\":null,\"created_at\":\"2026-05-01T12:00:00Z\",\"labels\":{{}},\"upper\":{{\"file\":\"upper.ext4\",\"size_bytes\":{},\"integrity\":null}},\"source_sandbox\":\"synthetic\"}}",
        upper.len()
    );
    let mut descriptor_header = Header::new_gnu();
    descriptor_header.set_entry_type(EntryType::Regular);
    descriptor_header
        .set_path(format!("{prefix}/manifest.json"))
        .unwrap();
    descriptor_header.set_mode(0o644);
    descriptor_header.set_size(descriptor.len() as u64);
    descriptor_header.set_cksum();
    builder
        .append(&descriptor_header, Cursor::new(descriptor.as_bytes()))
        .unwrap();

    let mut upper_header = Header::new_gnu();
    upper_header.set_entry_type(EntryType::Regular);
    upper_header
        .set_path(format!("{prefix}/upper.ext4"))
        .unwrap();
    upper_header.set_mode(0o644);
    upper_header.set_size(upper.len() as u64);
    upper_header.set_cksum();
    builder.append(&upper_header, Cursor::new(upper)).unwrap();
    builder.finish().unwrap();
}

fn write_v066_artifact(dir: &Path, upper: &[u8], parent: Option<&str>) -> String {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(DEFAULT_UPPER_FILE), upper).unwrap();
    let parent = serde_json::to_string(&parent).unwrap();
    // Keep the exact field order emitted by the v0.6.6 model: its canonical
    // SHA-256 identity is what the child's legacy parent edge references.
    let descriptor = format!(
        "{{\"schema\":1,\"format\":\"raw\",\"fstype\":\"ext4\",\"image\":{{\"ref\":\"docker.io/library/alpine:3.20\",\"manifest_digest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000001\"}},\"parent\":{parent},\"created_at\":\"2026-05-01T12:00:00Z\",\"labels\":{{}},\"upper\":{{\"file\":\"upper.ext4\",\"size_bytes\":{},\"integrity\":null}},\"source_sandbox\":\"synthetic\"}}",
        upper.len()
    );
    std::fs::write(dir.join("manifest.json"), descriptor.as_bytes()).unwrap();
    sha256_digest(descriptor.as_bytes())
}

fn write_released_flat_archive(archive: &Path, upper: &[u8]) {
    let descriptor = format!(
        "{{\"schema\":1,\"artifact\":\"snapshot\",\"scope\":\"disk\",\"created_at\":\"2026-05-01T12:00:00Z\",\"parent\":null,\"image\":{{\"ref\":\"docker.io/library/alpine:3.20\",\"manifest_digest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000001\"}},\"source_sandbox\":\"synthetic\",\"state\":{{\"kind\":\"file\",\"format\":\"raw\",\"fstype\":\"ext4\",\"upper\":{{\"file\":\"upper.ext4\",\"size_bytes\":{},\"integrity\":null}}}},\"labels\":{{}},\"extensions\":{{}},\"requires\":[]}}",
        upper.len()
    );
    let descriptor_digest = sha256_digest(descriptor.as_bytes());
    let digest_hex = descriptor_digest.strip_prefix("sha256:").unwrap();
    let descriptor_path = format!("snapshots/{digest_hex}/snapshot.json");
    let upper_path = format!("files/{digest_hex}/upper.ext4");
    let inventory = format!(
        "{{\"schema\":1,\"artifact\":\"snapshot-archive\",\"head\":\"{descriptor_digest}\",\"suggested_name\":\"released\",\"completeness\":\"boot-complete\",\"with_parents\":false,\"with_image\":false,\"snapshots\":[{{\"snapshot_id\":\"{descriptor_digest}\",\"descriptor\":\"{descriptor_path}\"}}],\"entries\":[{{\"path\":\"{upper_path}\",\"owner_snapshot\":\"{descriptor_digest}\",\"kind\":\"file-payload\",\"included\":true,\"encoded_size\":{},\"apparent_size\":{},\"integrity\":null}},{{\"path\":\"{descriptor_path}\",\"owner_snapshot\":\"{descriptor_digest}\",\"kind\":\"snapshot-descriptor\",\"included\":true,\"encoded_size\":{},\"apparent_size\":{},\"integrity\":{{\"algorithm\":\"sha256\",\"digest\":\"{descriptor_digest}\"}}}}],\"protection_requirements\":[],\"extensions\":{{}},\"requires\":[]}}",
        upper.len(),
        upper.len(),
        descriptor.len(),
        descriptor.len()
    );

    let file = std::fs::File::create(archive).unwrap();
    let mut builder = Builder::new(file);
    for (path, contents) in [
        (descriptor_path.as_str(), descriptor.as_bytes()),
        (upper_path.as_str(), upper),
        ("archive.json", inventory.as_bytes()),
    ] {
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_path(path).unwrap();
        header.set_mode(0o644);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        builder.append(&header, Cursor::new(contents)).unwrap();
    }
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

/// Export complete synthetic artifacts independently: their parent edges describe history,
/// not a requirement to have every ancestor present merely to read the disk payload.
async fn save_batch_fixtures(parent: &Path, artifacts: &[PathBuf]) -> Vec<PathBuf> {
    let mut archives = Vec::new();
    for (index, artifact) in artifacts.iter().enumerate() {
        let archive = parent.join(format!("batch-{index}.msb"));
        Snapshot::save(
            artifact.to_string_lossy().as_ref(),
            &archive,
            microsandbox::snapshot::SaveOpts {
                plain_tar: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        archives.push(archive);
    }
    archives
}

fn batch_group_options(group: &str) -> microsandbox::snapshot::LoadOpts {
    microsandbox::snapshot::LoadOpts {
        group: Some(group.into()),
        ..Default::default()
    }
}

/// A failed batch may leave an empty group/staging directory, but no immutable member
/// may become visible before every input archive and publication conflict is checked.
fn assert_no_batch_members(root: &Path) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if !path.exists() {
            continue;
        }
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            assert_ne!(entry.file_name(), DESCRIPTOR_FILENAME);
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            }
        }
    }
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
    assert_eq!(snap.path().unwrap(), dir);
    assert_eq!(snap.digest(), expected_digest);
    assert_eq!(reference_path(snap.reference()), dir);
    assert_eq!(
        snap.size_bytes(),
        Some(b"upper data goes here".len() as u64)
    );
}

#[tokio::test]
async fn typed_id_reference_is_resolved_by_the_local_backend() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let snapshots = home.join("snapshots");
    std::fs::create_dir_all(&snapshots).unwrap();
    let (_dir, expected_digest) = make_artifact(&snapshots, "snap-by-id", b"upper data");
    let backend = isolated_backend(&home).await;

    microsandbox::with_backend(backend, async {
        Snapshot::reindex(&snapshots).await.unwrap();
        let snap = Snapshot::open_ref(SnapshotReference::id(&expected_digest))
            .await
            .unwrap();
        assert_eq!(snap.digest(), expected_digest);
        assert_eq!(snap.reference().kind(), "path");
    })
    .await;
}

#[tokio::test]
async fn indexed_handle_can_remove_a_missing_local_artifact() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let snapshots = home.join("snapshots");
    std::fs::create_dir_all(&snapshots).unwrap();
    let (dir, digest) = make_artifact(&snapshots, "stale", b"upper data");
    let backend = isolated_backend(&home).await;

    microsandbox::with_backend(backend, async {
        Snapshot::reindex(&snapshots).await.unwrap();
        let handle = Snapshot::get(&digest).await.unwrap();
        assert_eq!(handle.path().unwrap(), std::fs::canonicalize(&dir).unwrap());
        std::fs::remove_dir_all(dir).unwrap();

        handle.remove(false).await.unwrap();
        assert!(Snapshot::get(&digest).await.is_err());
    })
    .await;
}

#[tokio::test]
async fn snapshot_resolved_pins_the_validated_descriptor_in_both_builder_orders() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact(tmp.path(), "resolved-source", b"disk state");
    let manifest =
        Manifest::from_bytes(&std::fs::read(dir.join(DESCRIPTOR_FILENAME)).unwrap()).unwrap();
    let backend = isolated_backend(&tmp.path().join("home")).await;
    for image_first in [true, false] {
        let builder = microsandbox::Sandbox::builder("resolved-child");
        let upper = dir.join(DEFAULT_UPPER_FILE);
        let builder = if image_first {
            builder
                .image("alpine:latest")
                .snapshot_resolved("untrusted-hint", &upper)
        } else {
            builder
                .snapshot_resolved("untrusted-hint", &upper)
                .image("alpine:latest")
        };
        let mut config = builder.build().await.unwrap();
        backend
            .snapshots()
            .prepare_restore(
                backend.clone(),
                &mut config,
                SnapshotReference::path(dir.to_string_lossy()),
            )
            .await
            .unwrap();
        let value = serde_json::to_value(&config).unwrap();
        assert_eq!(value["manifest_digest"], manifest.image.manifest_digest);
        let microsandbox_types::RootfsSource::Oci(image) = &config.spec.image else {
            panic!("validated descriptor must pin the OCI source");
        };
        assert_eq!(image.reference, manifest.image.reference);
    }
}

#[tokio::test]
async fn labels_only_copy_preserves_identity_and_every_layer() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact(tmp.path(), "layered", &[42; 512]);
    let descriptor = dir.join(DESCRIPTOR_FILENAME);
    let mut manifest = Manifest::from_bytes(&std::fs::read(&descriptor).unwrap()).unwrap();
    let file = manifest.state.as_file().unwrap();
    let base = file.layers[0].clone();
    std::fs::create_dir_all(dir.join("layers")).unwrap();
    std::fs::rename(
        dir.join(DEFAULT_UPPER_FILE),
        dir.join(file.layer_path(&base)),
    )
    .unwrap();
    let child_id = DiskLayerId::new(format!("layer_{:032x}", 987)).unwrap();
    let SnapshotState::File(file) = &mut manifest.state else {
        unreachable!()
    };
    file.disk_format = SnapshotFormat::Qcow2;
    file.head = child_id.clone();
    file.layers.push(DiskLayer {
        layer_id: child_id,
        format: SnapshotFormat::Qcow2,
        virtual_size: file.virtual_size,
        backing: Some(base.layer_id),
        payload: LayerPayload {
            file_kind: LayerFileKind::Regular,
            integrity: None,
        },
    });
    microsandbox_image::checkpoint::create_qcow2_overlay(
        &dir.join(file.layer_path(&file.layers[1])),
        file.virtual_size,
        &dir.join(file.layer_path(&file.layers[0])),
        "raw",
    )
    .await
    .unwrap();
    std::fs::write(&descriptor, manifest.to_canonical_bytes().unwrap()).unwrap();
    let backend = isolated_backend(&tmp.path().join("home")).await;
    microsandbox::with_backend(backend, async {
        let source = Snapshot::open(dir.to_str().unwrap()).await.unwrap();
        let labels = BTreeMap::from([("owner".into(), "copy".into())]);
        let out = tmp.path().join("layered-copy.msb");
        let copied = source
            .copy_to(&out)
            .labels(labels.clone())
            .save()
            .await
            .unwrap();
        assert_eq!(copied, manifest);
        let imported = Snapshot::load(&out, None)
            .await
            .unwrap()
            .open()
            .await
            .unwrap();
        assert_eq!(imported.id(), source.id());
        assert_eq!(imported.labels(), &labels);
        for layer in &manifest.state.as_file().unwrap().layers {
            assert_eq!(
                std::fs::read(imported.layer_path(layer).unwrap()).unwrap(),
                std::fs::read(source.layer_path(layer).unwrap()).unwrap()
            );
        }
        let integrity_out = tmp.path().join("layered-integrity.msb");
        let recorded = source
            .copy_to(&integrity_out)
            .record_integrity(true)
            .save()
            .await
            .unwrap();
        assert_ne!(recorded.snapshot_id, source.manifest().snapshot_id);
        Snapshot::load(&integrity_out, None)
            .await
            .unwrap()
            .open()
            .await
            .unwrap()
            .verify()
            .await
            .unwrap();
    })
    .await;
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
async fn explicit_open_migrates_v066_manifest_json_artifact() {
    let tmp = TempDir::new().unwrap();
    let backend = isolated_backend(&tmp.path().join("home")).await;
    let dir = tmp.path().join("legacy");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(DEFAULT_UPPER_FILE), b"old upper bytes").unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        br#"{"schema":1,"format":"raw","fstype":"ext4","image":{"ref":"docker.io/library/alpine:3.20","manifest_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000001"},"parent":null,"created_at":"2026-05-01T12:00:00Z","labels":{"stage":"legacy"},"upper":{"file":"upper.ext4","size_bytes":15,"integrity":null},"source_sandbox":"synthetic"}"#,
    )
    .unwrap();

    let snap = microsandbox::with_backend(backend, async {
        Snapshot::open(dir.to_string_lossy().as_ref())
            .await
            .unwrap()
    })
    .await;
    assert_eq!(snap.state().as_file().unwrap().virtual_size, 15);
    assert!(dir.join(DESCRIPTOR_FILENAME).is_file());
    assert_eq!(
        snap.labels().get("stage").map(String::as_str),
        Some("legacy")
    );
    assert!(dir.join("metadata.json").is_file());
    assert!(dir.join(".manifest.json.legacy").is_file());
    assert!(!dir.join("manifest.json").exists());
}

#[tokio::test]
async fn managed_v066_migration_rewrites_parent_to_stable_snapshot_id() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let snapshots = home.join("snapshots");
    let parent_dir = snapshots.join("legacy-parent");
    let child_dir = snapshots.join("legacy-child");
    let parent_legacy_digest = write_v066_artifact(&parent_dir, b"parent upper", None);
    write_v066_artifact(&child_dir, b"child upper", Some(&parent_legacy_digest));

    let backend = isolated_backend(&home).await;
    let (parent, child) = microsandbox::with_backend(backend, async {
        // The first DB-backed operation reconciles the complete managed graph
        // in parent-first order before returning any indexed handles.
        Snapshot::list().await.unwrap();
        let parent = Snapshot::open(parent_dir.to_string_lossy().as_ref())
            .await
            .unwrap();
        let child = Snapshot::open(child_dir.to_string_lossy().as_ref())
            .await
            .unwrap();
        (parent, child)
    })
    .await;

    assert_eq!(child.manifest().parent.as_ref(), Some(parent.id()));
    assert_ne!(
        child.manifest().parent.as_ref().map(|id| id.as_str()),
        Some(parent.digest())
    );
}

#[tokio::test]
async fn open_accepts_full_scope_artifact() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact_with_scope(tmp.path(), "full-snap", b"upper", SnapshotScope::Full);

    let snap = Snapshot::open(dir.to_string_lossy().as_ref())
        .await
        .unwrap();
    assert_eq!(snap.manifest().scope, SnapshotScope::Full);
}

#[tokio::test]
async fn from_snapshot_rejects_full_artifact_without_checkpoint_closure() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact_with_scope(tmp.path(), "full-snap", b"upper", SnapshotScope::Full);

    let err = microsandbox::Sandbox::restore_ref(SnapshotReference::path(dir.to_string_lossy()))
        .name("restore-scope-test")
        .restore()
        .await
        .err()
        .expect("incomplete full snapshot must be rejected");
    assert!(
        err.to_string().contains("snapshot"),
        "unexpected error: {err}"
    );
    assert!(
        !err.to_string().contains("restoring non-disk snapshots"),
        "full restore should reach closure validation: {err}"
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
    let err = Snapshot::verify(&snap).await.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("integrity mismatch"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn verify_reports_not_recorded_without_reading_payload_contents() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact(tmp.path(), "snap-unchecked", b"original");
    std::fs::write(dir.join(DEFAULT_UPPER_FILE), b"tampered").unwrap();

    let snapshot = Snapshot::open(dir.to_string_lossy().as_ref())
        .await
        .unwrap();
    let report = Snapshot::verify(&snapshot).await.unwrap();
    assert!(matches!(
        report.upper,
        microsandbox::snapshot::UpperVerifyStatus::NotRecorded
    ));
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
    assert_eq!(
        reference_path(snaps[0].reference()).file_name().unwrap(),
        "good"
    );
}

#[tokio::test]
async fn save_then_load_round_trips_via_zstd() {
    let tmp = TempDir::new().unwrap();
    let (dir, original_digest) = make_artifact(tmp.path(), "src-snap", b"the upper bytes");
    std::fs::write(
        dir.join("metadata.json"),
        br#"{"schema":"microsandbox.snapshot-metadata/1","labels":{"stage":"deps"}}"#,
    )
    .unwrap();

    let archive = tmp.path().join("bundle.tar.zst");
    save_snapshot(
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

    let handle_archive = tmp.path().join("bundle-from-handle.tar.zst");
    handle
        .save_to(&handle_archive, SaveOpts::default())
        .await
        .unwrap();
    assert!(handle_archive.exists());

    // Re-open the imported artifact via path; integrity should hold.
    let imported_path = reference_path(handle.reference());
    let imported = Snapshot::open(imported_path.to_string_lossy().as_ref())
        .await
        .unwrap();
    assert_eq!(imported.digest(), original_digest);
    assert_eq!(
        imported.labels().get("stage").map(String::as_str),
        Some("deps")
    );
}

#[tokio::test]
async fn copy_to_applies_labels_and_records_integrity_without_changing_the_source() {
    let tmp = TempDir::new().unwrap();
    let (source_dir, source_digest) =
        make_artifact(tmp.path(), "checkpoint", b"durable checkpoint data");
    let source_archive = tmp.path().join("checkpoint.tar.zst");
    save_snapshot(
        source_dir.to_string_lossy().as_ref(),
        &source_archive,
        SaveOpts::default(),
    )
    .await
    .unwrap();
    let source_archive_bytes = std::fs::read(&source_archive).unwrap();

    let backend = isolated_backend(&tmp.path().join("copy-home")).await;
    let work_dir = tmp.path().join("copy-work");
    let output_archive = tmp.path().join("explicit.tar.zst");
    let labels = BTreeMap::from([
        ("environment".into(), "staging".into()),
        ("purpose".into(), "backup".into()),
    ]);
    let (manifest, imported_manifest, imported_descriptor) =
        microsandbox::with_backend(backend, async {
            let snapshot = Snapshot::load(&source_archive, Some(&work_dir))
                .await?
                .open()
                .await?;
            let imported_manifest = snapshot.manifest().clone();
            let imported_descriptor =
                tokio::fs::read(snapshot.path()?.join(DESCRIPTOR_FILENAME)).await?;
            let manifest = snapshot
                .copy_to(&output_archive)
                .labels(labels.clone())
                .record_integrity(true)
                .save()
                .await?;

            assert_eq!(snapshot.manifest(), &imported_manifest);
            assert_eq!(
                tokio::fs::read(snapshot.path()?.join(DESCRIPTOR_FILENAME)).await?,
                imported_descriptor
            );

            Ok::<_, microsandbox::MicrosandboxError>((
                manifest,
                imported_manifest,
                imported_descriptor,
            ))
        })
        .await
        .unwrap();

    assert!(
        manifest.state.as_file().unwrap().layers[0]
            .payload
            .integrity
            .is_some()
    );
    assert_ne!(manifest.digest().unwrap(), source_digest);
    assert_ne!(manifest.snapshot_id, imported_manifest.snapshot_id);
    assert_eq!(
        std::fs::read(&source_archive).unwrap(),
        source_archive_bytes
    );
    assert_eq!(
        imported_manifest.to_canonical_bytes().unwrap(),
        imported_descriptor
    );

    let verify_backend = isolated_backend(&tmp.path().join("verify-home")).await;
    let imported = microsandbox::with_backend(verify_backend, async {
        Snapshot::load(&output_archive, Some(&tmp.path().join("copied")))
            .await?
            .open()
            .await
    })
    .await
    .unwrap();
    assert_eq!(imported.manifest(), &manifest);
    assert_eq!(imported.labels(), &labels);
    assert_eq!(
        std::fs::read(artifact_payload_path(imported.path().unwrap())).unwrap(),
        b"durable checkpoint data"
    );
    assert!(matches!(
        imported.verify().await.unwrap().upper,
        microsandbox::snapshot::UpperVerifyStatus::Verified { .. }
    ));

    let backend = isolated_backend(&tmp.path().join("copy-without-integrity-home")).await;
    let output_without_integrity = tmp.path().join("explicit-without-integrity.tar.zst");
    let manifest = microsandbox::with_backend(backend, async {
        let snapshot = Snapshot::load(
            &output_archive,
            Some(&tmp.path().join("copy-without-integrity-work")),
        )
        .await?
        .open()
        .await?;
        snapshot
            .copy_to(&output_without_integrity)
            .labels(BTreeMap::new())
            .record_integrity(false)
            .save()
            .await
    })
    .await
    .unwrap();

    assert!(
        manifest.state.as_file().unwrap().layers[0]
            .payload
            .integrity
            .is_none()
    );
}

#[tokio::test]
async fn copy_to_translates_a_legacy_checkpoint() {
    let tmp = TempDir::new().unwrap();
    let source_archive = tmp.path().join("legacy-checkpoint.tar");
    write_v066_archive(
        &source_archive,
        "sha256-0123456789abcdef",
        b"legacy checkpoint data",
    );
    let backend = isolated_backend(&tmp.path().join("copy-legacy-home")).await;
    let output_archive = tmp.path().join("explicit.tar.zst");

    let manifest = microsandbox::with_backend(backend, async {
        let snapshot = Snapshot::load(&source_archive, Some(&tmp.path().join("legacy-copy-work")))
            .await?
            .open()
            .await?;
        snapshot
            .copy_to(&output_archive)
            .labels(BTreeMap::from([(
                "origin".into(),
                "legacy-checkpoint".into(),
            )]))
            .record_integrity(true)
            .save()
            .await
    })
    .await
    .unwrap();

    assert_eq!(manifest.schema, SCHEMA);
    assert!(
        manifest.state.as_file().unwrap().layers[0]
            .payload
            .integrity
            .is_some()
    );
    let verify_backend = isolated_backend(&tmp.path().join("legacy-verify-home")).await;
    let imported = microsandbox::with_backend(verify_backend, async {
        Snapshot::load(&output_archive, Some(&tmp.path().join("legacy-copied")))
            .await?
            .open()
            .await
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(artifact_payload_path(imported.path().unwrap())).unwrap(),
        b"legacy checkpoint data"
    );
}

#[tokio::test]
async fn copy_to_rejects_checkpoint_state_without_writing_an_archive() {
    let tmp = TempDir::new().unwrap();
    let (source_dir, _) = make_artifact_with_scope(
        tmp.path(),
        "resumable",
        b"checkpoint state",
        SnapshotScope::Full,
    );
    let output_archive = tmp.path().join("copy.tar.zst");
    let backend = isolated_backend(&tmp.path().join("resumable-copy-home")).await;
    let error = microsandbox::with_backend(backend, async {
        let snapshot = Snapshot::open(source_dir.to_str().unwrap()).await?;
        snapshot.copy_to(&output_archive).save().await
    })
    .await
    .expect_err("checkpoint-state copy should fail");

    assert!(error.to_string().contains("checkpoint-state"));
    assert!(!output_archive.exists());
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
async fn repeated_loads_preserve_ids_and_resolve_local_group_names() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let (source, digest) = make_artifact(tmp.path(), "clean", b"group payload");
    let snapshot_id = artifact_id(&source);
    let archive = tmp.path().join("group.msb");
    let reexport = tmp.path().join("renamed.msb");

    microsandbox::with_backend(backend, async {
        Snapshot::save(
            source.to_string_lossy().as_ref(),
            &archive,
            microsandbox::snapshot::SaveOpts::default(),
        )
        .await
        .unwrap();
        let options = microsandbox::snapshot::LoadOpts {
            group: Some("work".into()),
            ..Default::default()
        };
        let first = Snapshot::load_with_options(&archive, options.clone())
            .await
            .unwrap();
        assert_eq!(first.group(), Some("work"));
        assert_eq!(first.name(), Some("clean"));
        assert_eq!(
            first.path().unwrap(),
            home.join("snapshots/work").join(&snapshot_id)
        );
        assert_eq!(
            first.head_update().unwrap().reason,
            microsandbox::snapshot::HeadUpdateReason::Initialized
        );

        // Reimporting the same identity into the same group is idempotent.
        let repeated = Snapshot::load_with_options(&archive, options)
            .await
            .unwrap();
        assert_eq!(repeated.path().unwrap(), first.path().unwrap());
        assert_eq!(repeated.id(), snapshot_id);
        assert_eq!(
            repeated.head_update().unwrap().reason,
            microsandbox::snapshot::HeadUpdateReason::Unchanged
        );
        assert_eq!(Snapshot::list().await.unwrap().len(), 1);
        assert_eq!(Snapshot::open("work").await.unwrap().digest(), digest);
        assert_eq!(
            Snapshot::open("work:clean").await.unwrap().id().as_str(),
            snapshot_id
        );
        assert_eq!(
            Snapshot::open(format!("work:{snapshot_id}"))
                .await
                .unwrap()
                .digest(),
            digest
        );

        // A default import always gets its own local namespace, even for identical bytes.
        let fresh = Snapshot::load(&archive, None).await.unwrap();
        let another = Snapshot::load(&archive, None).await.unwrap();
        assert_ne!(fresh.group(), another.group());
        assert_ne!(fresh.group(), Some("work"));
        assert_eq!(fresh.id(), first.id());
        assert_eq!(another.id(), first.id());
        assert_eq!(Snapshot::list().await.unwrap().len(), 3);

        Snapshot::save(
            "work:clean",
            &reexport,
            microsandbox::snapshot::SaveOpts::default(),
        )
        .await
        .unwrap();
        let renamed = Snapshot::load_with_options(
            &reexport,
            microsandbox::snapshot::LoadOpts {
                group: Some("renamed".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(renamed.name(), Some("clean"));
        assert_eq!(renamed.id(), snapshot_id);
        assert_eq!(
            Snapshot::group_head("renamed").await.unwrap().head,
            snapshot_id
        );

        // Removing one installed copy does not erase another group's membership or payload.
        Snapshot::remove(&format!("{}:clean", fresh.group().unwrap()), false)
            .await
            .unwrap();
        assert!(!fresh.path().unwrap().exists());
        assert!(first.path().unwrap().is_dir());
        assert!(another.path().unwrap().is_dir());
        assert!(renamed.path().unwrap().is_dir());
        assert_eq!(Snapshot::list().await.unwrap().len(), 3);
        assert_eq!(Snapshot::open("work:clean").await.unwrap().digest(), digest);
    })
    .await;
}

#[tokio::test]
async fn group_alias_collision_keeps_the_installed_snapshot_and_head() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let (first, first_digest) = make_artifact(&tmp.path().join("first"), "clean", b"first");
    let (second, _) = make_artifact(&tmp.path().join("second"), "clean", b"second");
    let original_id = artifact_id(&first);
    let competing_id = artifact_id(&second);
    let archive = tmp.path().join("first.msb");
    let competing = tmp.path().join("second.msb");
    microsandbox::with_backend(backend, async {
        for (source, destination) in [(&first, &archive), (&second, &competing)] {
            Snapshot::save(
                source.to_string_lossy().as_ref(),
                destination,
                microsandbox::snapshot::SaveOpts::default(),
            )
            .await
            .unwrap();
        }
        let options = microsandbox::snapshot::LoadOpts {
            group: Some("work".into()),
            ..Default::default()
        };
        let installed = Snapshot::load_with_options(&archive, options.clone())
            .await
            .unwrap();
        let error = Snapshot::load_with_options(&competing, options)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("conflicts"),
            "unexpected error: {error}"
        );
        assert_eq!(
            Snapshot::group_head("work").await.unwrap().head,
            original_id
        );
        assert_eq!(
            Snapshot::open("work:clean").await.unwrap().digest(),
            first_digest
        );
        assert_eq!(
            std::fs::read(artifact_payload_path(installed.path().unwrap())).unwrap(),
            b"first"
        );
        assert!(!home.join("snapshots/work").join(competing_id).exists());
        assert_eq!(Snapshot::list().await.unwrap().len(), 1);
    })
    .await;
}

#[tokio::test]
async fn load_many_selects_lineage_tip_independently_of_input_order() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let source = tmp.path().join("source-artifacts");
    let (first, _) = make_artifact(&source, "cp01", b"first disk");
    let first_id = artifact_id(&first);
    let (second, _) =
        make_artifact_with_parent(&source, "cp02", b"second disk", Some(first_id.clone()));
    let second_id = artifact_id(&second);
    let (third, _) =
        make_artifact_with_parent(&source, "cp03", b"third disk", Some(second_id.clone()));
    let third_id = artifact_id(&third);
    microsandbox::with_backend(backend, async {
        let archives = save_batch_fixtures(tmp.path(), &[first, second, third]).await;
        for (group, order) in [("reverse", [2, 1, 0]), ("shuffled", [1, 0, 2])] {
            let input = order.map(|index| archives[index].clone());
            let handles = Snapshot::load_many(&input, batch_group_options(group))
                .await
                .unwrap();
            let expected_ids = [&first_id, &second_id, &third_id];
            assert_eq!(handles.len(), input.len());
            for (handle, index) in handles.iter().zip(order) {
                assert_eq!(handle.id(), expected_ids[index]);
                assert_eq!(handle.group(), Some(group));
            }
            assert_eq!(Snapshot::group_head(group).await.unwrap().head, third_id);
            assert_eq!(
                Snapshot::open(format!("{group}:cp01"))
                    .await
                    .unwrap()
                    .id()
                    .as_str(),
                first_id
            );
        }
        // Loading owns the reconstructed artifacts, never a path into an input archive
        // or the sender's snapshot directory.
        std::fs::remove_dir_all(&source).unwrap();
        for archive in archives {
            std::fs::remove_file(archive).unwrap();
        }
        for (group, name, expected) in [
            ("reverse", "cp01", b"first disk".as_slice()),
            ("reverse", "cp02", b"second disk".as_slice()),
            ("shuffled", "cp03", b"third disk".as_slice()),
        ] {
            let artifact = Snapshot::open(format!("{group}:{name}")).await.unwrap();
            assert_eq!(
                std::fs::read(artifact_payload_path(artifact.path().unwrap())).unwrap(),
                expected
            );
        }
    })
    .await;
}

#[tokio::test]
async fn load_many_duplicate_inputs_return_input_heads_but_install_once() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let (source, _) = make_artifact(tmp.path(), "baseline", b"owned bytes");
    microsandbox::with_backend(backend, async {
        let archive = save_batch_fixtures(tmp.path(), &[source]).await.remove(0);
        let copied_archive = tmp.path().join("identical-copy.msb");
        std::fs::copy(&archive, &copied_archive).unwrap();
        let handles = Snapshot::load_many(
            &[archive.clone(), copied_archive, archive],
            batch_group_options("work"),
        )
        .await
        .unwrap();
        assert_eq!(handles.len(), 3);
        assert!(
            handles
                .iter()
                .all(|handle| handle.path().unwrap() == handles[0].path().unwrap())
        );
        assert_eq!(Snapshot::list().await.unwrap().len(), 1);
    })
    .await;
}

#[tokio::test]
async fn load_many_sibling_batch_preserves_existing_head_and_leaves_new_group_headless() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let (base, _) = make_artifact(tmp.path(), "base", b"base");
    let base_id = artifact_id(&base);
    let (left, _) = make_artifact_with_parent(tmp.path(), "left", b"left", Some(base_id.clone()));
    let left_id = artifact_id(&left);
    let (right, _) =
        make_artifact_with_parent(tmp.path(), "right", b"right", Some(base_id.clone()));
    microsandbox::with_backend(backend, async {
        let archives = save_batch_fixtures(tmp.path(), &[base, left, right]).await;
        Snapshot::load_with_options(&archives[0], batch_group_options("existing"))
            .await
            .unwrap();
        let siblings = [archives[2].clone(), archives[1].clone()];
        Snapshot::load_many(&siblings, batch_group_options("existing"))
            .await
            .unwrap();
        assert_eq!(
            Snapshot::group_head("existing").await.unwrap().head,
            base_id
        );
        let handles = Snapshot::load_many(&siblings, batch_group_options("fresh"))
            .await
            .unwrap();
        assert_eq!(handles.len(), 2);
        assert!(handles.iter().all(|handle| handle.head_update().is_none()));
        assert!(Snapshot::open("fresh").await.is_err());
        assert_eq!(
            Snapshot::open("fresh:left").await.unwrap().id().as_str(),
            left_id
        );
        assert_eq!(
            Snapshot::group_head("fresh:left").await.unwrap().head,
            left_id
        );
        assert_eq!(
            Snapshot::open("fresh").await.unwrap().id().as_str(),
            left_id
        );
    })
    .await;
}

#[tokio::test]
async fn load_many_ambiguous_set_head_rejects_before_publishing_members() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let (left, _) = make_artifact(tmp.path(), "left", b"left");
    let (right, _) = make_artifact(tmp.path(), "right", b"right");
    microsandbox::with_backend(backend, async {
        let archives = save_batch_fixtures(tmp.path(), &[left, right]).await;
        let mut options = batch_group_options("ambiguous");
        options.set_head = true;
        assert!(Snapshot::load_many(&archives, options).await.is_err());
        assert_no_batch_members(&home.join("snapshots/ambiguous"));
        assert!(Snapshot::list().await.unwrap().is_empty());
    })
    .await;
}

#[tokio::test]
async fn load_many_accepts_complete_payload_with_missing_historical_parent() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let missing = format!("snap_{:032x}", 7);
    let (source, _) =
        make_artifact_with_parent(tmp.path(), "complete", b"complete payload", Some(missing));
    let id = artifact_id(&source);
    microsandbox::with_backend(backend, async {
        let archives = save_batch_fixtures(tmp.path(), &[source]).await;
        let handles = Snapshot::load_many(&archives, batch_group_options("work"))
            .await
            .unwrap();
        assert_eq!(handles[0].id(), id);
        assert_eq!(Snapshot::group_head("work").await.unwrap().head, id);
        assert_eq!(
            std::fs::read(artifact_payload_path(handles[0].path().unwrap())).unwrap(),
            b"complete payload"
        );
    })
    .await;
}

#[tokio::test]
async fn load_many_conflicting_aliases_rejects_before_any_member_is_published() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let (first, _) = make_artifact(&tmp.path().join("one"), "same-name", b"one");
    let (second, _) = make_artifact(&tmp.path().join("two"), "same-name", b"two");
    microsandbox::with_backend(backend, async {
        let archives = save_batch_fixtures(tmp.path(), &[first, second]).await;
        let error = Snapshot::load_many(&archives, batch_group_options("work"))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("conflict"),
            "unexpected error: {error}"
        );
        assert_no_batch_members(&home.join("snapshots/work"));
    })
    .await;
}

#[tokio::test]
async fn load_many_duplicate_ids_with_conflicting_labels_rejects_before_publication() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    // Keep both descriptor bytes and suggested aliases identical. Labels are the only conflict,
    // and reversing the archive order must not silently choose either local metadata sidecar.
    let (first, digest) = make_artifact(&tmp.path().join("one"), "same", b"same disk");
    let (second, _) = make_artifact(&tmp.path().join("two"), "same", b"same disk");
    std::fs::copy(
        first.join(DESCRIPTOR_FILENAME),
        second.join(DESCRIPTOR_FILENAME),
    )
    .unwrap();
    for (artifact, label) in [(&first, "first"), (&second, "second")] {
        std::fs::write(
            artifact.join("metadata.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "microsandbox.snapshot-metadata/1",
                "labels": {"stage": label},
            }))
            .unwrap(),
        )
        .unwrap();
    }
    microsandbox::with_backend(backend, async {
        for artifact in [&first, &second] {
            assert_eq!(
                Snapshot::open(artifact.to_string_lossy().as_ref())
                    .await
                    .unwrap()
                    .digest(),
                digest
            );
        }
        let archives = save_batch_fixtures(tmp.path(), &[first, second]).await;
        for (group, order) in [("forward", [0, 1]), ("reverse", [1, 0])] {
            let inputs = order.map(|index| archives[index].clone());
            let error = Snapshot::load_many(&inputs, batch_group_options(group))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("conflicting labels"), "{error}");
            assert_no_batch_members(&home.join("snapshots").join(group));
        }
        assert!(Snapshot::list().await.unwrap().is_empty());
    })
    .await;
}

#[tokio::test]
async fn load_many_conflicting_ids_rejects_before_any_member_is_published() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let (first, _) = make_artifact(tmp.path(), "first", b"one");
    let (second, _) = make_artifact(tmp.path(), "second", b"two");
    let mut descriptor =
        Manifest::from_bytes(&std::fs::read(second.join(DESCRIPTOR_FILENAME)).unwrap()).unwrap();
    descriptor.snapshot_id = SnapshotId::new(artifact_id(&first)).unwrap();
    std::fs::write(
        second.join(DESCRIPTOR_FILENAME),
        descriptor.to_canonical_bytes().unwrap(),
    )
    .unwrap();
    microsandbox::with_backend(backend, async {
        let archives = save_batch_fixtures(tmp.path(), &[first, second]).await;
        assert!(
            Snapshot::load_many(&archives, batch_group_options("work"))
                .await
                .is_err()
        );
        assert_no_batch_members(&home.join("snapshots/work"));
    })
    .await;
}

#[tokio::test]
async fn load_many_corrupt_later_archive_never_publishes_valid_earlier_member() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let (first, _) = make_artifact(tmp.path(), "first", b"one");
    let (second, _) = make_artifact(tmp.path(), "second", b"two");
    microsandbox::with_backend(backend, async {
        let archives = save_batch_fixtures(tmp.path(), &[first, second]).await;
        corrupt_dense_tar_member(&archives[1], ".raw");
        let error = Snapshot::load_many(&archives, batch_group_options("work"))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("integrity"),
            "unexpected error: {error}"
        );
        assert_no_batch_members(&home.join("snapshots/work"));
    })
    .await;
}

#[tokio::test]
async fn load_many_single_legacy_archive_preserves_single_load_compatibility() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let archive = tmp.path().join("legacy.tar");
    write_v066_archive(&archive, "sha256-0123456789abcdef", b"legacy disk");
    microsandbox::with_backend(backend, async {
        let batch = Snapshot::load_many(&[archive.clone()], batch_group_options("batch"))
            .await
            .unwrap();
        let single = Snapshot::load_with_options(&archive, batch_group_options("single"))
            .await
            .unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].id(), single.id());
        assert_eq!(
            std::fs::read(artifact_payload_path(batch[0].path().unwrap())).unwrap(),
            b"legacy disk"
        );
    })
    .await;
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
    save_snapshot(
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
    let imported_upper = artifact_payload_path(handle.path().unwrap());
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
    save_snapshot(
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
    let mut upper_archive_path = None;
    for entry in ar.entries().unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().unwrap().to_path_buf();
        if path.extension().and_then(|n| n.to_str()) == Some("raw") {
            upper_entry_type = Some(entry.header().entry_type());
            upper_archive_path = Some(path);
        }
    }
    assert_eq!(upper_entry_type, Some(EntryType::GNUSparse));

    let unpack_dir = tmp.path().join("external-unpack");
    std::fs::create_dir_all(&unpack_dir).unwrap();
    let mut ar = tar::Archive::new(std::fs::File::open(&archive).unwrap());
    ar.unpack(&unpack_dir).unwrap();
    let unpacked_upper = unpack_dir.join(upper_archive_path.unwrap());
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
    save_snapshot(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts::default(),
    )
    .await
    .unwrap();

    let dest = tmp.path().join("imported-many");
    let handle = Snapshot::load(&archive, Some(&dest)).await.unwrap();
    assert_eq!(handle.digest(), original_digest);
    let imported_upper = artifact_payload_path(handle.path().unwrap());
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
    save_snapshot(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts::default(),
    )
    .await
    .unwrap();

    let dest = tmp.path().join("imported-hole");
    let handle = Snapshot::load(&archive, Some(&dest)).await.unwrap();
    assert_eq!(handle.digest(), original_digest);
    let imported_upper = artifact_payload_path(handle.path().unwrap());
    assert_eq!(std::fs::read(&imported_upper).unwrap(), logical);
}

#[tokio::test]
async fn dense_upper_keeps_regular_entry() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact(tmp.path(), "src-dense", b"fully allocated upper");

    let archive = tmp.path().join("dense.tar");
    save_snapshot(
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
        if path.extension().and_then(|n| n.to_str()) == Some("raw") {
            upper_entry_type = Some(entry.header().entry_type());
        }
    }
    assert_eq!(upper_entry_type, Some(EntryType::Regular));
}

/// GNU long-name entries may be decoded for checkpoint members, but the resolved path must still
/// pass the snapshot archive's closed path grammar.
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
    assert!(err.contains("unsupported path"), "unexpected error: {err}");
}

/// A header whose recorded checksum disagrees with its bytes is corruption, not something to unpack around.
#[tokio::test]
async fn load_rejects_corrupt_header_checksum() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact(tmp.path(), "src-cksum", b"upper bytes");

    let archive = tmp.path().join("ok.tar");
    save_snapshot(
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

/// Persistent payload integrity is optional, but the archive boundary always
/// binds the stored payload bytes while they flow through save/load.
#[tokio::test]
async fn load_rejects_payload_corruption_without_recorded_snapshot_integrity() {
    let tmp = TempDir::new().unwrap();
    let (dir, _) = make_artifact(tmp.path(), "src-transport", b"transport bytes");
    let archive = tmp.path().join("transport.tar");
    save_snapshot(
        dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts {
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    corrupt_dense_tar_member(&archive, ".raw");
    let err = Snapshot::load(&archive, Some(&tmp.path().join("dest")))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("transport integrity mismatch"),
        "expected transport rejection, got: {err}"
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
        save_snapshot(
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
            .any(|name| name == &format!("images/manifests/{metadata_name}")),
        "archive did not include image metadata: {names:?}"
    );
    assert!(
        names.iter().any(|name| name.starts_with("images/layers/"))
            && names.iter().any(|name| name.starts_with("images/fsmeta/"))
            && names.iter().any(|name| name.starts_with("images/vmdk/")),
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
        msg.contains("unsupported path")
            || msg.contains("no snapshot manifest")
            || msg.contains("manifest"),
        "unexpected error: {msg}"
    );
    assert!(
        !escape_file.exists(),
        "archive import followed a pre-existing symlink parent"
    );
}

#[test]
fn manifest_validation_rejects_noncanonical_layer_identity() {
    let manifest = sample_manifest(4);
    let mut value = serde_json::to_value(manifest).unwrap();
    value["state"]["layers"][0]["layer_id"] = serde_json::json!("../outside.ext4");
    let bytes = serde_json::to_vec(&value).unwrap();
    let error = Manifest::from_bytes(&bytes).unwrap_err().to_string();

    assert!(error.contains("layer_id"), "unexpected error: {error}");
}

#[tokio::test]
async fn archive_round_trip_preserves_integrity_without_implicitly_executing_it() {
    let tmp = TempDir::new().unwrap();
    let (bad_dir, _) = make_artifact_with_integrity(tmp.path(), "bad-snap", b"original", true);
    std::fs::write(bad_dir.join(DEFAULT_UPPER_FILE), b"tampered").unwrap();
    let archive = tmp.path().join("tampered.tar");
    save_snapshot(
        bad_dir.to_string_lossy().as_ref(),
        &archive,
        microsandbox::snapshot::SaveOpts::default(),
    )
    .await
    .unwrap();

    let dest = tmp.path().join("imported");
    let handle = Snapshot::load(&archive, Some(&dest)).await.unwrap();
    let imported_path = reference_path(handle.reference());
    let imported = Snapshot::open(imported_path.to_string_lossy().as_ref())
        .await
        .unwrap();
    let error = Snapshot::verify(&imported).await.unwrap_err();
    assert!(error.to_string().contains("integrity mismatch"));
}

#[tokio::test]
async fn load_detects_zstd_by_magic_bytes() {
    let tmp = TempDir::new().unwrap();
    let (dir, original_digest) = make_artifact(tmp.path(), "src-magic", b"magic zstd");

    let archive = tmp.path().join("bundle.snapshot");
    save_snapshot(
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
async fn load_translates_v066_plain_and_zstd_archives() {
    use tokio::io::AsyncWriteExt;

    let tmp = TempDir::new().unwrap();
    let plain = tmp.path().join("legacy.tar");
    write_v066_archive(&plain, "sha256-0123456789abcdef", b"legacy upper");
    let compressed = tmp.path().join("legacy.tar.zst");
    let mut encoder = async_compression::tokio::write::ZstdEncoder::new(
        tokio::fs::File::create(&compressed).await.unwrap(),
    );
    encoder
        .write_all(&std::fs::read(&plain).unwrap())
        .await
        .unwrap();
    encoder.shutdown().await.unwrap();

    for (index, archive) in [plain, compressed].iter().enumerate() {
        let home = tmp.path().join(format!("home-{index}"));
        let backend = isolated_backend(&home).await;
        let dest = tmp.path().join(format!("imported-{index}"));
        let handle = microsandbox::with_backend(backend, async {
            Snapshot::load(archive, Some(&dest)).await.unwrap()
        })
        .await;
        let handle_path = reference_path(handle.reference());
        let manifest =
            Manifest::from_bytes(&std::fs::read(handle_path.join(DESCRIPTOR_FILENAME)).unwrap())
                .unwrap();
        assert_eq!(manifest.state.as_file().unwrap().virtual_size, 12);
        assert!(handle.path().unwrap().join(DESCRIPTOR_FILENAME).is_file());
        assert!(
            handle
                .path()
                .unwrap()
                .join(".manifest.json.legacy")
                .is_file()
        );
    }
}

#[tokio::test]
async fn load_translates_released_flat_inventory_archive() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let archive = tmp.path().join("released.tar");
    write_released_flat_archive(&archive, b"released upper");

    microsandbox::with_backend(backend, async {
        let handle = Snapshot::load(&archive, None).await.unwrap();
        let snapshot = handle.open().await.unwrap();
        assert_eq!(
            std::fs::read(artifact_payload_path(snapshot.path().unwrap())).unwrap(),
            b"released upper"
        );
    })
    .await;
}

#[tokio::test]
async fn load_selects_child_head_when_parents_are_present() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let snapshots_dir = home.join("snapshots");
    let (parent_dir, _) = make_artifact(&snapshots_dir, "parent", b"parent");
    let parent_id = artifact_id(&parent_dir);
    let (child_dir, child_digest) =
        make_artifact_with_parent(&snapshots_dir, "child", b"child", Some(parent_id.clone()));
    let child_id = artifact_id(&child_dir);
    let archive = tmp.path().join("chain.tar");
    let dest = tmp.path().join("imported-chain");
    let handle = microsandbox::with_backend(
        backend,
        Box::pin(async {
            Snapshot::open(parent_dir.to_string_lossy().as_ref())
                .await
                .unwrap();
            Snapshot::open(child_dir.to_string_lossy().as_ref())
                .await
                .unwrap();
            save_snapshot(
                child_dir.to_string_lossy().as_ref(),
                &archive,
                microsandbox::snapshot::SaveOpts {
                    with_parents: true,
                    plain_tar: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            Snapshot::load(&archive, Some(&dest)).await.unwrap()
        }),
    )
    .await;
    assert_eq!(handle.digest(), child_digest);
    assert_eq!(handle.id(), child_id);
    let imported_group = dest.join(handle.group().expect("load creates a local group"));
    assert_eq!(handle.path().unwrap(), imported_group.join(&child_id));
    assert_eq!(handle.head_update().unwrap().head, child_id);
    assert_eq!(handle.head_update().unwrap().previous, None);
    assert!(
        imported_group
            .join(parent_id)
            .join(DESCRIPTOR_FILENAME)
            .is_file()
    );
    assert_eq!(Snapshot::list_dir(&imported_group).await.unwrap().len(), 2);
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
            save_snapshot(
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
        Snapshot::list_dir(&dest).await.unwrap().is_empty(),
        "failed import promoted a grouped snapshot"
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
    // Canonicalization is stable for one immutable descriptor. Independent
    // captures intentionally receive different opaque snapshot IDs.
    let manifest = sample_manifest(10);
    assert_eq!(
        manifest.digest().unwrap(),
        manifest.clone().digest().unwrap()
    );
}

// A slurp implementation would allocate 4 GiB and OOM the runner;
// a streaming implementation reads a few tar blocks and errors fast.
#[tokio::test]
async fn load_streams_large_archive_without_buffering() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;
    let archive = tmp.path().join("sparse.tar");

    let file = std::fs::File::create(&archive).unwrap();
    file.set_len(4 * 1024 * 1024 * 1024).unwrap();
    drop(file);

    let err = microsandbox::with_backend(backend, async {
        Snapshot::load(&archive, Some(&tmp.path().join("dest")))
            .await
            .expect_err("expected import of sparse archive to fail")
    })
    .await;

    let msg = err.to_string();
    assert!(
        msg.contains("no snapshot manifest") || msg.contains("manifest"),
        "got: {msg}"
    );
}

#[tokio::test]
async fn create_full_resolves_source_before_touching_anything() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let backend = isolated_backend(&home).await;

    microsandbox::with_backend(backend, async {
        let err = Snapshot::builder("warm")
            .from_sandbox("box")
            .full()
            .create()
            .await
            .unwrap_err();
        assert!(matches!(
            &err,
            microsandbox::MicrosandboxError::SandboxNotFound(_)
        ));
    })
    .await;

    assert!(!home.join("snapshots").join("box").exists());
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

    let err = microsandbox::Sandbox::restore_ref(snap.reference())
        .name("requires-gate-test")
        .restore()
        .await
        .err()
        .expect("unknown required extension must be rejected");
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
        let (pdir, _pdigest) = make_artifact(&snapshots, "parent", b"parent upper");
        let parent_id = artifact_id(&pdir);
        let (cdir, _c1) =
            make_artifact_with_parent(&snapshots, "child", b"child v1", Some(parent_id.clone()));
        Snapshot::reindex(&snapshots).await.unwrap();

        // Replace the child in place: same name and path, different digest,
        // same parent. Opening it runs the auto-reindex upsert, which must
        // not double-count the parent edge.
        std::fs::remove_dir_all(&cdir).unwrap();
        make_artifact_with_parent(
            &snapshots,
            "child",
            b"child v2 with different size",
            Some(parent_id),
        );
        Snapshot::open(cdir.to_string_lossy().as_ref())
            .await
            .unwrap();

        Snapshot::remove(cdir.to_string_lossy().as_ref(), false)
            .await
            .unwrap();
        Snapshot::remove(pdir.to_string_lossy().as_ref(), false)
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
    assert!(reference_path(snaps[0].reference()).ends_with("real"));
}
