//! Snapshot save / load via `.tar.zst` bundles.
//!
//! Default archive format is zstd-compressed tar. Regular files with holes, notably the sparse `upper.ext4` whose logical size is the configured upper cap rather than the data
//! written, are stored as old-GNU sparse entries (type `S`): only allocated extents are read and archived, so save cost scales with the data a sandbox actually wrote instead of
//! the upper layer's logical size. Dense files keep plain regular entries. Plain `.tar` archives are also accepted on load.
//!
//! Load walks the tar records itself rather than going through `tokio_tar::Archive`: the entry grammar is closed (regular files, directories, and old-GNU sparse entries at fixed
//! depths, produced by our own save path), and owning the walk lets sparse entries be restored map-driven: data runs copied straight off the wire, holes never written and kept
//! unallocated per platform ([`extent::mark_sparse`] on NTFS, [`extent::punch_hole_aligned`] on APFS). `tokio_tar` remains the header codec and the dense-entry writer.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
#[cfg(windows)]
use std::iter;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use async_compression::tokio::bufread::ZstdDecoder;
use async_compression::tokio::write::ZstdEncoder;
use microsandbox_image::checkpoint::{CheckpointClosure, MemoryExtentContent, ObjectId};
use microsandbox_image::snapshot::migration::V066_DESCRIPTOR_FILENAME;
use microsandbox_image::snapshot::{
    DEFAULT_UPPER_FILE, DESCRIPTOR_FILENAME, MAX_JSON_SAFE_INTEGER, SnapshotState, UpperIntegrity,
};
use microsandbox_utils::extent::{self, ExtentMap};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader, ReadBuf};
use tokio_tar::{Builder, EntryType, Header, HeaderMode};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

use crate::backend::LocalBackend;
use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

use super::{CHECKPOINT_DIRECTORY, Snapshot, SnapshotHandle, store};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ARCHIVE_MEMBER_TRANSPORT_ALGORITHM: &str = "msb-archive-member-blake3-v1";
const ARCHIVE_MEMBER_TRANSPORT_DOMAIN: &[u8] = b"msb-archive-member-blake3-v1\0";
const TAR_BLOCK: u64 = 512;

// Sparse-map slots inline in a GNU header / per extended sparse block.
const GNU_HEADER_SPARSE_SLOTS: usize = 4;
const GNU_EXT_SPARSE_SLOTS: usize = 21;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for [`super::Snapshot::save`].
#[derive(Debug, Clone, Default)]
pub struct SaveOpts {
    /// Walk parent chain and include each ancestor in the archive.
    pub with_parents: bool,
    /// Include the OCI image artifacts (EROFS layers, VMDK descriptor)
    /// from the global cache so the archive boots offline.
    pub with_image: bool,
    /// Skip zstd compression and write a plain `.tar`. Default: zstd.
    pub plain_tar: bool,
}

struct UnpackedArchive {
    manifest_dirs: Vec<PathBuf>,
    head: Option<String>,
    inventory: Option<ArchiveInventory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveInventory {
    schema: String,
    head: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    suggested_name: Option<String>,
    completeness: String,
    members: Vec<ArchiveSnapshot>,
    entries: Vec<ArchiveEntry>,
    limits: ArchiveLimits,
    extensions: BTreeMap<String, serde_json::Value>,
    requires: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveSnapshot {
    snapshot_id: String,
    descriptor_path: String,
    descriptor_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveLimits {
    entry_count: u64,
    encoded_bytes: u64,
    apparent_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveEntry {
    path: String,
    owner_snapshot: Option<String>,
    kind: String,
    included: bool,
    encoded_size: u64,
    apparent_size: u64,
    sparse_ranges: Vec<[u64; 2]>,
    #[serde(deserialize_with = "deserialize_required_option")]
    integrity: Option<UpperIntegrity>,
    /// Package-bound integrity computed while this member's stored bytes flow.
    /// Released inventory archives omit this field and remain readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport_integrity: Option<ArchiveTransportIntegrity>,
}

/// Inventory emitted by the released v0.6.7-v0.6.16 archive writer.
///
/// It remains a private decoder: successful imports are normalized to the
/// current descriptor and index model instead of preserving this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasedArchiveInventory {
    schema: u32,
    artifact: String,
    head: String,
    suggested_name: Option<String>,
    completeness: String,
    with_parents: bool,
    with_image: bool,
    snapshots: Vec<ReleasedArchiveSnapshot>,
    entries: Vec<ReleasedArchiveEntry>,
    protection_requirements: Vec<serde_json::Value>,
    extensions: BTreeMap<String, serde_json::Value>,
    requires: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasedArchiveSnapshot {
    snapshot_id: String,
    descriptor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasedArchiveEntry {
    path: String,
    owner_snapshot: Option<String>,
    kind: String,
    included: bool,
    encoded_size: u64,
    apparent_size: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    integrity: Option<UpperIntegrity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport_integrity: Option<ArchiveTransportIntegrity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveTransportIntegrity {
    algorithm: String,
    digest: String,
}

struct ObservedArchiveEntry {
    encoded_size: u64,
    apparent_size: u64,
    sparse_ranges: Vec<[u64; 2]>,
    transport_integrity: ArchiveTransportIntegrity,
}

struct WrittenArchiveMember {
    encoded_size: u64,
    apparent_size: u64,
    transport_integrity: ArchiveTransportIntegrity,
    sparse_ranges: Vec<[u64; 2]>,
}

#[derive(Clone)]
struct CheckpointArchiveMember {
    source: PathBuf,
    archive_path: String,
    kind: &'static str,
    apparent_size: u64,
}

/// Child construction state streamed from one archive without installing a snapshot artifact.
pub(crate) struct ArchiveChildMaterialization {
    pub(crate) manifest: microsandbox_image::snapshot::Manifest,
    pub(crate) checkpoint_restore: Option<microsandbox_runtime::launch::CheckpointRestoreConfig>,
    pub(crate) upper_layers: Vec<microsandbox_runtime::launch::RootfsUpperLayerConfig>,
}

/// Updates a member transport hash as the archive writer consumes the source.
struct TransportHashingReader<R> {
    inner: R,
    hasher: blake3::Hasher,
    bytes_read: u64,
}

/// Allocation map of a sparse file, in tar-block granularity.
struct SparseMap {
    /// Logical (apparent) file size.
    len: u64,
    /// Sum of segment lengths = the tar header `size` field.
    archived: u64,
    /// Sorted `(offset, length)` data segments, 512-aligned except the
    /// final one, which may end at an unaligned `len`.
    segments: Vec<(u64, u64)>,
}

impl SparseMap {
    /// Map entries for the GNU header: the data segments, plus the
    /// zero-length terminator GNU tar uses to mark a trailing hole.
    fn entries(&self) -> Vec<(u64, u64)> {
        let mut entries = self.segments.clone();
        let end = entries.last().map(|(off, sz)| off + sz).unwrap_or(0);
        if end < self.len {
            entries.push((self.len, 0));
        }
        entries
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<R> AsyncRead for TransportHashingReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = &buf.filled()[before..];
                self.hasher.update(read);
                self.bytes_read += read.len() as u64;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Bundle a snapshot artifact (and optionally its ancestors / image
/// cache) into an archive at `out`.
pub(super) async fn save_snapshot(
    local: &LocalBackend,
    name_or_path: &str,
    out: &Path,
    opts: SaveOpts,
) -> MicrosandboxResult<()> {
    let total_started = Instant::now();
    let resolve_started = Instant::now();
    // Collect the artifact dirs we need to ship: the head snapshot
    // and (optionally) all ancestors via their stable snapshot IDs.
    let head = store::open_snapshot(local, name_or_path).await?;
    let mut parents: Vec<Snapshot> = Vec::new();

    if opts.with_parents {
        let mut current = head.manifest().parent.clone();
        while let Some(parent_id) = current {
            let parent_path = resolve_parent_artifact(local, parent_id.as_str()).await?;
            let parent =
                store::open_snapshot(local, parent_path.to_string_lossy().as_ref()).await?;
            parents.push(parent.clone());
            current = parent.manifest().parent.clone();
        }
    }
    parents.reverse();

    let mut snapshots = parents;
    snapshots.push(head.clone());

    // Optional image cache bundling.
    let mut cache_files: Vec<(PathBuf, String)> = Vec::new();
    if opts.with_image {
        let cache_dir = local.cache_dir();
        let img_digest_str = head.manifest().image.manifest_digest.clone();
        let img_digest: microsandbox_image::Digest = img_digest_str
            .parse()
            .map_err(|e| MicrosandboxError::Custom(format!("invalid image digest: {e}")))?;
        let cache = microsandbox_image::GlobalCache::new_async(&cache_dir).await?;

        let image_ref: microsandbox_image::Reference =
            head.manifest().image.reference.parse().map_err(|e| {
                MicrosandboxError::Custom(format!("invalid snapshot image reference: {e}"))
            })?;
        let metadata = cache
            .read_image_metadata_async(&image_ref)
            .await?
            .ok_or_else(|| {
                MicrosandboxError::Custom(format!(
                    "image metadata missing from cache for {}",
                    head.manifest().image.reference
                ))
            })?;
        if metadata.manifest_digest != img_digest_str {
            return Err(MicrosandboxError::Custom(format!(
                "cached image metadata digest mismatch: snapshot={}, cache={}",
                img_digest_str, metadata.manifest_digest
            )));
        }

        let metadata_path = cache.image_metadata_path(&image_ref);
        push_required_cache_file(&mut cache_files, &metadata_path, "manifests")?;

        let fsmeta = cache.fsmeta_erofs_path(&img_digest);
        push_required_cache_file(&mut cache_files, &fsmeta, "fsmeta")?;

        let vmdk = cache.vmdk_path(&img_digest);
        push_required_cache_file(&mut cache_files, &vmdk, "vmdk")?;

        let mut seen_layers = HashSet::new();
        for layer in &metadata.layers {
            let diff_id: microsandbox_image::Digest = layer.diff_id.parse().map_err(|e| {
                MicrosandboxError::Custom(format!("invalid cached layer diff_id: {e}"))
            })?;
            let layer_path = cache.layer_erofs_path(&diff_id);
            if seen_layers.insert(layer_path.clone()) {
                push_required_cache_file(&mut cache_files, &layer_path, "layers")?;
            }
        }
    }
    let resolve_us = resolve_started.elapsed().as_micros();

    // Write the archive.
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temp_out = archive_temp_path(out)?;
    let out_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_out)
        .await?;
    let write_started = Instant::now();
    let write_result: MicrosandboxResult<()> = async {
        if opts.plain_tar {
            let mut builder = Builder::new(out_file);
            // Entry writers retain hashing and sparse-I/O buffers across await
            // points. Keep that state off Windows' smaller worker stack.
            Box::pin(write_archive_entries(
                &mut builder,
                &snapshots,
                &cache_files,
                &head,
                &opts,
            ))
            .await?;
            let mut inner = builder.into_inner().await?;
            tokio::io::AsyncWriteExt::shutdown(&mut inner).await?;
        } else {
            let writer = ZstdEncoder::new(out_file);
            let mut builder = Builder::new(writer);
            Box::pin(write_archive_entries(
                &mut builder,
                &snapshots,
                &cache_files,
                &head,
                &opts,
            ))
            .await?;
            let mut inner = builder.into_inner().await?;
            tokio::io::AsyncWriteExt::shutdown(&mut inner).await?;
        }
        Ok(())
    }
    .await;
    if let Err(error) = write_result {
        let _ = tokio::fs::remove_file(&temp_out).await;
        return Err(error);
    }
    let write_us = write_started.elapsed().as_micros();
    let durable_started = Instant::now();
    let durable = tokio::fs::OpenOptions::new()
        .read(true)
        // FlushFileBuffers requires a write-capable handle on Windows.
        .write(true)
        .open(&temp_out)
        .await?;
    durable.sync_all().await?;
    // Windows will not replace a file while this durability handle is still
    // open. Close it explicitly before the atomic rename; relying on the
    // function-scope drop kept the source locked until after MoveFileExW.
    drop(durable);
    replace_archive(&temp_out, out).await?;
    #[cfg(unix)]
    if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::File::open(parent)?.sync_all()?;
    }
    let durable_us = durable_started.elapsed().as_micros();
    let archive_bytes = tokio::fs::metadata(out).await?.len();
    tracing::info!(
        target: "microsandbox_checkpoint_timing",
        operation = "snapshot_save_archive",
        source = name_or_path,
        plain_tar = opts.plain_tar,
        with_image = opts.with_image,
        with_parents = opts.with_parents,
        snapshot_count = snapshots.len(),
        cache_file_count = cache_files.len(),
        archive_bytes,
        total_us = total_started.elapsed().as_micros(),
        resolve_us,
        write_us,
        durable_us,
        "snapshot archive save timing"
    );

    Ok(())
}

/// Stream one freshly captured file snapshot directly into an archive.
///
/// The payload is read from the sandbox's pinned upper file and is never copied
/// into an installed snapshot directory or added to `snapshot_index`.
pub(super) async fn save_direct_file_snapshot(
    manifest: &microsandbox_image::snapshot::Manifest,
    labels: &BTreeMap<String, String>,
    suggested_name: &str,
    source_layer: &Path,
    out: &Path,
    plain_tar: bool,
    force: bool,
) -> MicrosandboxResult<()> {
    let total_started = Instant::now();
    manifest.validate().map_err(|error| {
        MicrosandboxError::SnapshotIntegrity(format!("invalid direct snapshot: {error}"))
    })?;
    let SnapshotState::File(file) = &manifest.state else {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(
                "direct checkpoint archives require full capture support".into(),
            ),
        ));
    };
    if file.layers.len() != 1 {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(
                "direct multi-layer capture requires the managed qcow writer".into(),
            ),
        ));
    }
    if out.exists() && !force {
        return Err(MicrosandboxError::SnapshotAlreadyExists(
            out.display().to_string(),
        ));
    }
    if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temp_out = archive_temp_path(out)?;
    let out_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_out)
        .await?;
    let write_started = Instant::now();
    let write_result: MicrosandboxResult<()> = async {
        if plain_tar {
            let mut builder = Builder::new(out_file);
            write_direct_archive_entries(
                &mut builder,
                manifest,
                labels,
                suggested_name,
                source_layer,
            )
            .await?;
            let mut inner = builder.into_inner().await?;
            tokio::io::AsyncWriteExt::shutdown(&mut inner).await?;
        } else {
            let writer = ZstdEncoder::new(out_file);
            let mut builder = Builder::new(writer);
            write_direct_archive_entries(
                &mut builder,
                manifest,
                labels,
                suggested_name,
                source_layer,
            )
            .await?;
            let mut inner = builder.into_inner().await?;
            tokio::io::AsyncWriteExt::shutdown(&mut inner).await?;
        }
        Ok(())
    }
    .await;
    if let Err(error) = write_result {
        let _ = tokio::fs::remove_file(&temp_out).await;
        return Err(error);
    }
    let write_us = write_started.elapsed().as_micros();
    let durable_started = Instant::now();
    let durable = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&temp_out)
        .await?;
    durable.sync_all().await?;
    drop(durable);
    replace_archive(&temp_out, out).await?;
    #[cfg(unix)]
    if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::File::open(parent)?.sync_all()?;
    }
    let durable_us = durable_started.elapsed().as_micros();
    let archive_bytes = tokio::fs::metadata(out).await?.len();
    tracing::info!(
        target: "microsandbox_checkpoint_timing",
        operation = "snapshot_write_direct_file_archive",
        plain_tar,
        archive_bytes,
        total_us = total_started.elapsed().as_micros(),
        write_us,
        durable_us,
        "direct file snapshot archive write timing"
    );
    Ok(())
}

/// Stream one freshly captured full checkpoint directly into an archive.
///
/// The runtime-owned checkpoint closure is read as the archive payload. No installed snapshot
/// artifact or snapshot-index row is created.
pub(super) async fn save_direct_checkpoint_snapshot(
    manifest: &microsandbox_image::snapshot::Manifest,
    labels: &BTreeMap<String, String>,
    suggested_name: &str,
    checkpoint_closure: &Path,
    out: &Path,
    plain_tar: bool,
    force: bool,
) -> MicrosandboxResult<()> {
    let total_started = Instant::now();
    manifest.validate().map_err(|error| {
        MicrosandboxError::SnapshotIntegrity(format!("invalid direct checkpoint: {error}"))
    })?;
    let SnapshotState::Checkpoint(_) = &manifest.state else {
        return Err(MicrosandboxError::InvalidConfig(
            "direct checkpoint archive requires checkpoint state".into(),
        ));
    };
    if out.exists() && !force {
        return Err(MicrosandboxError::SnapshotAlreadyExists(
            out.display().to_string(),
        ));
    }
    if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temp_out = archive_temp_path(out)?;
    let out_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_out)
        .await?;
    let write_started = Instant::now();
    let write_result: MicrosandboxResult<()> = async {
        if plain_tar {
            let mut builder = Builder::new(out_file);
            write_direct_checkpoint_archive_entries(
                &mut builder,
                manifest,
                labels,
                suggested_name,
                checkpoint_closure,
            )
            .await?;
            let mut inner = builder.into_inner().await?;
            tokio::io::AsyncWriteExt::shutdown(&mut inner).await?;
        } else {
            let writer = ZstdEncoder::new(out_file);
            let mut builder = Builder::new(writer);
            write_direct_checkpoint_archive_entries(
                &mut builder,
                manifest,
                labels,
                suggested_name,
                checkpoint_closure,
            )
            .await?;
            let mut inner = builder.into_inner().await?;
            tokio::io::AsyncWriteExt::shutdown(&mut inner).await?;
        }
        Ok(())
    }
    .await;
    if let Err(error) = write_result {
        let _ = tokio::fs::remove_file(&temp_out).await;
        return Err(error);
    }
    let write_us = write_started.elapsed().as_micros();
    let durable_started = Instant::now();
    let durable = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&temp_out)
        .await?;
    durable.sync_all().await?;
    drop(durable);
    replace_archive(&temp_out, out).await?;
    #[cfg(unix)]
    if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::File::open(parent)?.sync_all()?;
    }
    let durable_us = durable_started.elapsed().as_micros();
    let archive_bytes = tokio::fs::metadata(out).await?.len();
    tracing::info!(
        target: "microsandbox_checkpoint_timing",
        operation = "snapshot_write_direct_checkpoint_archive",
        plain_tar,
        archive_bytes,
        total_us = total_started.elapsed().as_micros(),
        write_us,
        durable_us,
        "direct checkpoint snapshot archive write timing"
    );
    Ok(())
}

async fn write_direct_archive_entries<W>(
    builder: &mut Builder<W>,
    manifest: &microsandbox_image::snapshot::Manifest,
    labels: &BTreeMap<String, String>,
    suggested_name: &str,
    source_layer: &Path,
) -> MicrosandboxResult<()>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let descriptor_bytes = manifest.to_canonical_bytes().map_err(|error| {
        MicrosandboxError::SnapshotIntegrity(format!("descriptor serialize: {error}"))
    })?;
    let descriptor_digest = manifest.digest().map_err(|error| {
        MicrosandboxError::SnapshotIntegrity(format!("descriptor digest: {error}"))
    })?;
    let descriptor_path = format!("snapshots/{}/{DESCRIPTOR_FILENAME}", manifest.snapshot_id);
    let mut descriptor_hasher = archive_transport_hasher(
        "snapshot-descriptor",
        &descriptor_path,
        descriptor_bytes.len() as u64,
        descriptor_bytes.len() as u64,
        &[],
    );
    descriptor_hasher.update(&descriptor_bytes);
    append_bytes(builder, &descriptor_path, &descriptor_bytes).await?;

    let file = manifest.state.as_file().expect("validated file descriptor");
    let layer = file.layers.first().expect("validated nonempty closure");
    let layer_path = portable_archive_path(&file.layer_path(layer))?;
    let layer_transport =
        append_artifact_file(builder, source_layer, &layer_path, "file-payload").await?;

    let mut entries = vec![
        ArchiveEntry {
            path: descriptor_path.clone(),
            owner_snapshot: Some(manifest.snapshot_id.to_string()),
            kind: "snapshot-descriptor".into(),
            included: true,
            encoded_size: descriptor_bytes.len() as u64,
            apparent_size: descriptor_bytes.len() as u64,
            sparse_ranges: Vec::new(),
            integrity: Some(UpperIntegrity::Sha256 {
                digest: descriptor_digest.clone(),
            }),
            transport_integrity: Some(finish_archive_transport(descriptor_hasher)),
        },
        ArchiveEntry {
            path: layer_path,
            owner_snapshot: Some(manifest.snapshot_id.to_string()),
            kind: "file-payload".into(),
            included: true,
            encoded_size: layer_transport.encoded_size,
            apparent_size: layer_transport.apparent_size,
            integrity: layer.payload.integrity.clone(),
            sparse_ranges: layer_transport.sparse_ranges,
            transport_integrity: Some(layer_transport.transport_integrity),
        },
    ];
    if !labels.is_empty() {
        let metadata_bytes = super::metadata::encode(labels)?;
        let metadata_path = format!(
            "snapshots/{}/{}",
            manifest.snapshot_id,
            super::metadata::METADATA_FILENAME
        );
        let metadata_digest = format!("sha256:{}", hex::encode(Sha256::digest(&metadata_bytes)));
        let mut metadata_hasher = archive_transport_hasher(
            "snapshot-metadata",
            &metadata_path,
            metadata_bytes.len() as u64,
            metadata_bytes.len() as u64,
            &[],
        );
        metadata_hasher.update(&metadata_bytes);
        append_bytes(builder, &metadata_path, &metadata_bytes).await?;
        entries.push(ArchiveEntry {
            path: metadata_path,
            owner_snapshot: Some(manifest.snapshot_id.to_string()),
            kind: "snapshot-metadata".into(),
            included: true,
            encoded_size: metadata_bytes.len() as u64,
            apparent_size: metadata_bytes.len() as u64,
            sparse_ranges: Vec::new(),
            integrity: Some(UpperIntegrity::Sha256 {
                digest: metadata_digest,
            }),
            transport_integrity: Some(finish_archive_transport(metadata_hasher)),
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let inventory = ArchiveInventory {
        schema: "microsandbox.snapshot-archive/1".into(),
        head: manifest.snapshot_id.to_string(),
        suggested_name: Some(suggested_name.to_string()),
        completeness: "boot-complete".into(),
        members: vec![ArchiveSnapshot {
            snapshot_id: manifest.snapshot_id.to_string(),
            descriptor_path,
            descriptor_digest,
        }],
        limits: ArchiveLimits {
            entry_count: entries.len() as u64,
            encoded_bytes: entries.iter().map(|entry| entry.encoded_size).sum(),
            apparent_bytes: entries.iter().map(|entry| entry.apparent_size).sum(),
        },
        entries,
        extensions: BTreeMap::new(),
        requires: vec![ARCHIVE_MEMBER_TRANSPORT_ALGORITHM.into()],
    };
    let inventory_bytes = serde_json::to_vec(&inventory).map_err(|error| {
        MicrosandboxError::Custom(format!("serialize archive inventory: {error}"))
    })?;
    append_bytes(builder, "archive.json", &inventory_bytes).await
}

async fn write_direct_checkpoint_archive_entries<W>(
    builder: &mut Builder<W>,
    manifest: &microsandbox_image::snapshot::Manifest,
    labels: &BTreeMap<String, String>,
    suggested_name: &str,
    checkpoint_closure: &Path,
) -> MicrosandboxResult<()>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let descriptor_bytes = manifest.to_canonical_bytes().map_err(|error| {
        MicrosandboxError::SnapshotIntegrity(format!("descriptor serialize: {error}"))
    })?;
    let descriptor_digest = manifest.digest().map_err(|error| {
        MicrosandboxError::SnapshotIntegrity(format!("descriptor digest: {error}"))
    })?;
    let descriptor_path = format!("snapshots/{}/{DESCRIPTOR_FILENAME}", manifest.snapshot_id);
    let mut descriptor_hasher = archive_transport_hasher(
        "snapshot-descriptor",
        &descriptor_path,
        descriptor_bytes.len() as u64,
        descriptor_bytes.len() as u64,
        &[],
    );
    descriptor_hasher.update(&descriptor_bytes);
    append_bytes(builder, &descriptor_path, &descriptor_bytes).await?;
    let mut entries = vec![ArchiveEntry {
        path: descriptor_path.clone(),
        owner_snapshot: Some(manifest.snapshot_id.to_string()),
        kind: "snapshot-descriptor".into(),
        included: true,
        encoded_size: descriptor_bytes.len() as u64,
        apparent_size: descriptor_bytes.len() as u64,
        sparse_ranges: Vec::new(),
        integrity: Some(UpperIntegrity::Sha256 {
            digest: descriptor_digest.clone(),
        }),
        transport_integrity: Some(finish_archive_transport(descriptor_hasher)),
    }];

    let SnapshotState::Checkpoint(state) = &manifest.state else {
        unreachable!("caller validates checkpoint state")
    };
    for member in checkpoint_archive_members(
        manifest.snapshot_id.as_str(),
        checkpoint_closure,
        &state.checkpoint_root,
    )? {
        let written =
            append_artifact_file(builder, &member.source, &member.archive_path, member.kind)
                .await?;
        entries.push(ArchiveEntry {
            path: member.archive_path,
            owner_snapshot: Some(manifest.snapshot_id.to_string()),
            kind: member.kind.into(),
            included: true,
            encoded_size: written.encoded_size,
            apparent_size: written.apparent_size,
            sparse_ranges: written.sparse_ranges,
            integrity: None,
            transport_integrity: Some(written.transport_integrity),
        });
    }
    if !labels.is_empty() {
        let metadata_bytes = super::metadata::encode(labels)?;
        let metadata_path = format!(
            "snapshots/{}/{}",
            manifest.snapshot_id,
            super::metadata::METADATA_FILENAME
        );
        let metadata_digest = format!("sha256:{}", hex::encode(Sha256::digest(&metadata_bytes)));
        let mut metadata_hasher = archive_transport_hasher(
            "snapshot-metadata",
            &metadata_path,
            metadata_bytes.len() as u64,
            metadata_bytes.len() as u64,
            &[],
        );
        metadata_hasher.update(&metadata_bytes);
        append_bytes(builder, &metadata_path, &metadata_bytes).await?;
        entries.push(ArchiveEntry {
            path: metadata_path,
            owner_snapshot: Some(manifest.snapshot_id.to_string()),
            kind: "snapshot-metadata".into(),
            included: true,
            encoded_size: metadata_bytes.len() as u64,
            apparent_size: metadata_bytes.len() as u64,
            sparse_ranges: Vec::new(),
            integrity: Some(UpperIntegrity::Sha256 {
                digest: metadata_digest,
            }),
            transport_integrity: Some(finish_archive_transport(metadata_hasher)),
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let inventory = ArchiveInventory {
        schema: "microsandbox.snapshot-archive/1".into(),
        head: manifest.snapshot_id.to_string(),
        suggested_name: Some(suggested_name.to_string()),
        completeness: "boot-complete".into(),
        members: vec![ArchiveSnapshot {
            snapshot_id: manifest.snapshot_id.to_string(),
            descriptor_path,
            descriptor_digest,
        }],
        limits: ArchiveLimits {
            entry_count: entries.len() as u64,
            encoded_bytes: entries.iter().map(|entry| entry.encoded_size).sum(),
            apparent_bytes: entries.iter().map(|entry| entry.apparent_size).sum(),
        },
        entries,
        extensions: BTreeMap::new(),
        requires: vec![ARCHIVE_MEMBER_TRANSPORT_ALGORITHM.into()],
    };
    let inventory_bytes = serde_json::to_vec(&inventory).map_err(|error| {
        MicrosandboxError::Custom(format!("serialize archive inventory: {error}"))
    })?;
    append_bytes(builder, "archive.json", &inventory_bytes).await
}

/// Unpack an archive into `dest` (defaults to the configured snapshots
/// dir). Image-cache entries (`cache/...`) are routed into the global
/// cache. Returns a handle for the head (last-listed) snapshot.
pub(super) async fn load_snapshot(
    local: &LocalBackend,
    archive: &Path,
    dest: Option<&Path>,
) -> MicrosandboxResult<SnapshotHandle> {
    let total_started = Instant::now();
    let snapshots_dir = match dest {
        Some(d) => d.to_path_buf(),
        None => local.snapshots_dir(),
    };
    tokio::fs::create_dir_all(&snapshots_dir).await?;
    let cache_dir = local.cache_dir();
    tokio::fs::create_dir_all(&cache_dir).await?;

    let snapshot_stage = tempfile::Builder::new()
        .prefix(".msb-snapshot-import-")
        .tempdir_in(&snapshots_dir)?;
    let cache_tmp_dir = cache_dir.join("tmp");
    tokio::fs::create_dir_all(&cache_tmp_dir).await?;
    let cache_stage = tempfile::Builder::new()
        .prefix("snapshot-import-")
        .tempdir_in(&cache_tmp_dir)?;

    // Stream rather than slurp — archives carry the full upper layer and are
    // routinely multi-GB.
    let file = tokio::fs::File::open(archive).await?;
    let mut buf = BufReader::new(file);
    let is_zstd = {
        let bytes = buf.fill_buf().await?;
        bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])
    };

    let unpack_started = Instant::now();
    let unpacked = if is_zstd {
        let decoder = ZstdDecoder::new(buf);
        // The decoder and archive walker both carry sizeable buffers across
        // await points. Keep their combined future off Tokio's worker stack.
        Box::pin(unpack_archive(
            decoder,
            snapshot_stage.path(),
            cache_stage.path(),
        ))
        .await?
    } else {
        Box::pin(unpack_archive(
            buf,
            snapshot_stage.path(),
            cache_stage.path(),
        ))
        .await?
    };
    let unpack_us = unpack_started.elapsed().as_micros();

    let validate_started = Instant::now();
    if unpacked.inventory.is_none() {
        super::migration::normalize_staged(local.db().await?, &unpacked.manifest_dirs).await?;
    } else if let Some(inventory) = unpacked.inventory.as_ref() {
        materialize_inventory_layers(inventory, snapshot_stage.path()).await?;
    }
    let imported = verify_imported_snapshots(local, &unpacked.manifest_dirs).await?;
    for snapshot in &imported {
        super::metadata::write(snapshot.path(), snapshot.labels()).await?;
    }
    if let Some(inventory) = unpacked.inventory.as_ref() {
        validate_inventory_snapshot_bindings(inventory, &imported)?;
    }
    let head_index = match unpacked.head.as_deref() {
        Some(head) => imported
            .iter()
            .position(|snapshot| snapshot.id().as_str() == head)
            .ok_or_else(|| {
                MicrosandboxError::Custom(format!("archive inventory head {head} was not imported"))
            })?,
        None => select_head_snapshot(&imported)?,
    };
    let head_stage_path = imported[head_index].path().to_path_buf();
    let head_relative = head_stage_path
        .strip_prefix(snapshot_stage.path())
        .map_err(|_| MicrosandboxError::Custom("imported snapshot escaped staging dir".into()))?
        .to_path_buf();
    let head_manifest = imported[head_index].manifest().clone();
    let head_path = snapshots_dir.join(&head_relative);
    let validate_us = validate_started.elapsed().as_micros();

    let promote_started = Instant::now();
    ensure_promote_targets_available(snapshot_stage.path(), &snapshots_dir).await?;
    // Cache installation carries hashing buffers across await points. Keep
    // that future on the heap so the archive loader remains within Windows'
    // smaller default worker-thread stack.
    Box::pin(install_staged_cache(
        cache_stage.path(),
        &cache_dir,
        &head_manifest,
    ))
    .await?;
    promote_stage(snapshot_stage.path(), &snapshots_dir).await?;

    let snap = store::open_snapshot(local, head_path.to_string_lossy().as_ref()).await?;

    // Index this and any sibling artifacts that landed in the dest dir.
    let _ = store::reindex_dir(local, &snapshots_dir).await;
    let promote_index_us = promote_started.elapsed().as_micros();

    let (state_kind, format, fstype, checkpoint_manifest_digest, size_bytes) =
        match &snap.manifest().state {
            SnapshotState::File(state) => (
                "file".to_string(),
                Some(state.disk_format),
                Some(state.filesystem.clone()),
                None,
                Some(state.virtual_size),
            ),
            SnapshotState::Checkpoint(state) => (
                "checkpoint".to_string(),
                None,
                None,
                Some(state.checkpoint_root.clone()),
                None,
            ),
        };
    let handle = SnapshotHandle {
        snapshot_id: snap.id().to_string(),
        digest: snap.digest().to_string(),
        name: snap
            .path()
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string()),
        parent_digest: snap.manifest().parent.as_ref().map(ToString::to_string),
        scope: snap.manifest().scope,
        image_ref: snap.manifest().image.reference.clone(),
        state_kind,
        format,
        fstype,
        checkpoint_manifest_digest,
        size_bytes,
        locality: "embedded".into(),
        availability: "ready".into(),
        migration_state: "canonical".into(),
        migration_error_code: None,
        created_at: chrono::DateTime::parse_from_rfc3339(&snap.manifest().capture.created_at)
            .map(|d| d.naive_utc())
            .unwrap_or_else(|_| chrono::Utc::now().naive_utc()),
        artifact_path: snap.path().to_path_buf(),
    };
    let archive_bytes = tokio::fs::metadata(archive).await?.len();
    tracing::info!(
        target: "microsandbox_checkpoint_timing",
        operation = "snapshot_load_archive",
        zstd = is_zstd,
        archive_bytes,
        total_us = total_started.elapsed().as_micros(),
        unpack_us,
        validate_us,
        promote_index_us,
        "snapshot archive load timing"
    );
    Ok(handle)
}

/// Consume a current archive directly into a child sandbox's staging directory.
///
/// The archive layer is streamed once into operation-owned staging and renamed
/// to `upper.ext4`; no installed snapshot artifact or index row is published.
pub(crate) async fn materialize_archive_for_child(
    local: &LocalBackend,
    archive: &Path,
    child_stage: &Path,
    disk_only: bool,
) -> MicrosandboxResult<ArchiveChildMaterialization> {
    let total_started = Instant::now();
    tokio::fs::create_dir_all(child_stage).await?;
    let cache_dir = local.cache_dir();
    let cache_tmp_dir = cache_dir.join("tmp");
    tokio::fs::create_dir_all(&cache_tmp_dir).await?;
    let cache_stage = tempfile::Builder::new()
        .prefix("snapshot-child-import-")
        .tempdir_in(&cache_tmp_dir)?;

    let file = tokio::fs::File::open(archive).await?;
    let mut buffered = BufReader::new(file);
    let is_zstd = buffered
        .fill_buf()
        .await?
        .starts_with(&[0x28, 0xb5, 0x2f, 0xfd]);
    let unpack_started = Instant::now();
    let unpacked = if is_zstd {
        Box::pin(unpack_archive(
            ZstdDecoder::new(buffered),
            child_stage,
            cache_stage.path(),
        ))
        .await?
    } else {
        Box::pin(unpack_archive(buffered, child_stage, cache_stage.path())).await?
    };
    let unpack_us = unpack_started.elapsed().as_micros();
    let archive_bytes = tokio::fs::metadata(archive).await?.len();
    tracing::info!(
        target: "microsandbox_checkpoint_timing",
        operation = "snapshot_materialize_child_unpack",
        disk_only,
        zstd = is_zstd,
        archive_bytes,
        total_us = total_started.elapsed().as_micros(),
        unpack_us,
        "direct archive child unpack timing"
    );
    let Some(inventory) = unpacked.inventory else {
        super::migration::normalize_staged(local.db().await?, &unpacked.manifest_dirs).await?;
        let imported = verify_imported_snapshots(local, &unpacked.manifest_dirs).await?;
        let head_index = select_head_snapshot(&imported)?;
        let head = &imported[head_index];
        let manifest = head.manifest().clone();
        let SnapshotState::File(file) = &manifest.state else {
            return Err(MicrosandboxError::unsupported(
                Operation::SnapshotOps,
                UnsupportedReason::NotAvailable(
                    "legacy checkpoint archive restore is not supported".into(),
                ),
            ));
        };
        if disk_only {
            return Err(MicrosandboxError::InvalidConfig(
                "disk_only requires a full snapshot with checkpoint state".into(),
            ));
        }
        if file.layers.len() != 1
            || file.disk_format != super::SnapshotFormat::Raw
            || file.filesystem != "ext4"
        {
            return Err(MicrosandboxError::unsupported(
                Operation::SnapshotOps,
                UnsupportedReason::NotAvailable(
                    "legacy child restore requires one raw ext4 layer".into(),
                ),
            ));
        }
        let layer = file.head_layer().map_err(|error| {
            MicrosandboxError::SnapshotIntegrity(format!("invalid legacy archive closure: {error}"))
        })?;
        tokio::fs::rename(head.layer_path(layer), child_stage.join(DEFAULT_UPPER_FILE)).await?;
        install_staged_cache(cache_stage.path(), &cache_dir, &manifest).await?;
        for directory in unpacked.manifest_dirs {
            if directory.exists() {
                tokio::fs::remove_dir_all(directory).await?;
            }
        }
        return Ok(ArchiveChildMaterialization {
            manifest,
            checkpoint_restore: None,
            upper_layers: Vec::new(),
        });
    };
    let member = inventory
        .members
        .iter()
        .find(|member| member.snapshot_id == inventory.head)
        .ok_or_else(|| MicrosandboxError::SnapshotIntegrity("archive head is missing".into()))?;
    let descriptor_path = child_stage
        .join(&member.snapshot_id)
        .join(DESCRIPTOR_FILENAME);
    let descriptor_bytes = tokio::fs::read(&descriptor_path).await?;
    let manifest = microsandbox_image::snapshot::Manifest::from_bytes(&descriptor_bytes)
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let descriptor_digest = manifest
        .digest()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    if manifest.snapshot_id.as_str() != inventory.head
        || descriptor_digest != member.descriptor_digest
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "archive head descriptor identity mismatch".into(),
        ));
    }
    if let SnapshotState::Checkpoint(state) = &manifest.state {
        let member_dir = child_stage.join(&member.snapshot_id);
        let extracted_closure = member_dir.join(CHECKPOINT_DIRECTORY);
        if disk_only {
            let materialized = super::materialize_checkpoint_child_disk_state(
                &extracted_closure,
                &state.checkpoint_root,
                &state.checkpoint_id,
                child_stage,
            )
            .await?;
            install_staged_cache(cache_stage.path(), &cache_dir, &manifest).await?;
            for member in &inventory.members {
                let member_dir = child_stage.join(&member.snapshot_id);
                if member_dir.exists() {
                    tokio::fs::remove_dir_all(member_dir).await?;
                }
            }
            return Ok(ArchiveChildMaterialization {
                manifest,
                checkpoint_restore: None,
                upper_layers: materialized.upper_layers,
            });
        }
        let child_closure = child_stage.join(".checkpoint-restore");
        tokio::fs::rename(&extracted_closure, &child_closure).await?;
        let materialized = super::materialize_checkpoint_child_state(
            &child_closure,
            &state.checkpoint_root,
            &state.checkpoint_id,
            child_stage,
        )
        .await?;
        install_staged_cache(cache_stage.path(), &cache_dir, &manifest).await?;
        for member in &inventory.members {
            let member_dir = child_stage.join(&member.snapshot_id);
            if member_dir.exists() {
                tokio::fs::remove_dir_all(member_dir).await?;
            }
        }
        return Ok(ArchiveChildMaterialization {
            manifest,
            checkpoint_restore: Some(materialized.restore),
            upper_layers: materialized.upper_layers,
        });
    }
    let SnapshotState::File(file) = &manifest.state else {
        unreachable!("snapshot state is closed")
    };
    if disk_only {
        return Err(MicrosandboxError::InvalidConfig(
            "disk_only requires a full snapshot with checkpoint state".into(),
        ));
    }
    if file.layers.len() != 1
        || file.disk_format != super::SnapshotFormat::Raw
        || file.filesystem != "ext4"
    {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(
                "child restore currently requires one raw ext4 layer".into(),
            ),
        ));
    }
    let layer = file.head_layer().map_err(|error| {
        MicrosandboxError::SnapshotIntegrity(format!("invalid archive closure: {error}"))
    })?;
    let source_layer = child_stage.join(".archive-layers").join(
        file.layer_path(layer)
            .file_name()
            .expect("canonical layer path has a filename"),
    );
    let target_layer = child_stage.join("upper.ext4");
    tokio::fs::rename(&source_layer, &target_layer).await?;
    if let Some(parent) = source_layer.parent()
        && parent.exists()
    {
        tokio::fs::remove_dir_all(parent).await?;
    }

    install_staged_cache(cache_stage.path(), &cache_dir, &manifest).await?;
    for member in &inventory.members {
        let member_dir = child_stage.join(&member.snapshot_id);
        if member_dir.exists() {
            tokio::fs::remove_dir_all(member_dir).await?;
        }
    }
    Ok(ArchiveChildMaterialization {
        manifest,
        checkpoint_restore: None,
        upper_layers: Vec::new(),
    })
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

async fn write_archive_entries<W>(
    builder: &mut Builder<W>,
    snapshots: &[Snapshot],
    cache_files: &[(PathBuf, String)],
    head: &Snapshot,
    opts: &SaveOpts,
) -> MicrosandboxResult<()>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let checkpoint_members = collect_checkpoint_archive_members(snapshots)?;
    let mut inventory =
        build_archive_inventory(snapshots, cache_files, head, opts, &checkpoint_members).await?;

    // The inventory is also the write allowlist. Never sweep artifact
    // directories: migration backups, locks, journals and unknown files are
    // intentionally not exportable. Member hashes are filled while these
    // required writes consume the source; archive.json is written last so no
    // payload needs a preparatory content pass.
    for snapshot in snapshots {
        let snapshot_id = snapshot.id().as_str();
        let descriptor = snapshot.path().join(DESCRIPTOR_FILENAME);
        let descriptor_name = format!("snapshots/{snapshot_id}/{DESCRIPTOR_FILENAME}");
        let written = append_artifact_file(
            builder,
            &descriptor,
            &descriptor_name,
            "snapshot-descriptor",
        )
        .await?;
        set_archive_transport(&mut inventory, &descriptor_name, written)?;
        if !snapshot.labels().is_empty() {
            let metadata_name = format!(
                "snapshots/{snapshot_id}/{}",
                super::metadata::METADATA_FILENAME
            );
            let metadata_bytes = super::metadata::encode(snapshot.labels())?;
            let mut hasher = archive_transport_hasher(
                "snapshot-metadata",
                &metadata_name,
                metadata_bytes.len() as u64,
                metadata_bytes.len() as u64,
                &[],
            );
            hasher.update(&metadata_bytes);
            append_bytes(builder, &metadata_name, &metadata_bytes).await?;
            set_archive_transport(
                &mut inventory,
                &metadata_name,
                WrittenArchiveMember {
                    encoded_size: metadata_bytes.len() as u64,
                    apparent_size: metadata_bytes.len() as u64,
                    transport_integrity: finish_archive_transport(hasher),
                    sparse_ranges: Vec::new(),
                },
            )?;
        }
        match &snapshot.manifest().state {
            SnapshotState::File(file) => {
                for layer in &file.layers {
                    let payload_name = portable_archive_path(&file.layer_path(layer))?;
                    let written = append_artifact_file(
                        builder,
                        &snapshot.layer_path(layer),
                        &payload_name,
                        "file-payload",
                    )
                    .await?;
                    set_archive_transport(&mut inventory, &payload_name, written)?;
                }
            }
            SnapshotState::Checkpoint(_) => {
                for member in checkpoint_members
                    .get(snapshot.id().as_str())
                    .expect("checkpoint members were collected before inventory construction")
                {
                    let written = append_artifact_file(
                        builder,
                        &member.source,
                        &member.archive_path,
                        member.kind,
                    )
                    .await?;
                    set_archive_transport(&mut inventory, &member.archive_path, written)?;
                }
            }
        }
    }
    for (path, archive_name) in cache_files {
        let kind = if archive_name.contains("/manifests/") {
            "image-metadata"
        } else {
            "image-object"
        };
        let written = append_artifact_file(builder, path, archive_name, kind).await?;
        set_archive_transport(&mut inventory, archive_name, written)?;
    }

    let inventory_bytes = serde_json::to_vec(&inventory).map_err(|error| {
        MicrosandboxError::Custom(format!("serialize archive inventory: {error}"))
    })?;
    append_bytes(builder, "archive.json", &inventory_bytes).await?;
    Ok(())
}

async fn append_bytes<W>(
    builder: &mut Builder<W>,
    name: &str,
    bytes: &[u8],
) -> MicrosandboxResult<()>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let mut header = Header::new_gnu();
    header.set_path(name)?;
    header.set_mode(0o644);
    header.set_size(bytes.len() as u64);
    header.set_cksum();
    builder.append_data(&mut header, name, bytes).await?;
    Ok(())
}

async fn build_archive_inventory(
    snapshots: &[Snapshot],
    cache_files: &[(PathBuf, String)],
    head: &Snapshot,
    _opts: &SaveOpts,
    checkpoint_members: &HashMap<String, Vec<CheckpointArchiveMember>>,
) -> MicrosandboxResult<ArchiveInventory> {
    let mut snapshot_members = Vec::with_capacity(snapshots.len());
    let mut entries = Vec::new();
    for snapshot in snapshots {
        let snapshot_id = snapshot.id().as_str();
        let descriptor_path = format!("snapshots/{snapshot_id}/{DESCRIPTOR_FILENAME}");
        let descriptor_size = tokio::fs::metadata(snapshot.path().join(DESCRIPTOR_FILENAME))
            .await?
            .len();
        require_json_safe_size(descriptor_size, &descriptor_path)?;
        snapshot_members.push(ArchiveSnapshot {
            snapshot_id: snapshot_id.to_string(),
            descriptor_path: descriptor_path.clone(),
            descriptor_digest: snapshot.digest().to_string(),
        });
        entries.push(ArchiveEntry {
            path: descriptor_path,
            owner_snapshot: Some(snapshot_id.to_string()),
            kind: "snapshot-descriptor".into(),
            included: true,
            encoded_size: descriptor_size,
            apparent_size: descriptor_size,
            sparse_ranges: Vec::new(),
            integrity: Some(UpperIntegrity::Sha256 {
                digest: snapshot.digest().to_string(),
            }),
            transport_integrity: None,
        });

        if !snapshot.labels().is_empty() {
            let metadata_path = format!(
                "snapshots/{snapshot_id}/{}",
                super::metadata::METADATA_FILENAME
            );
            let metadata_bytes = super::metadata::encode(snapshot.labels())?;
            let metadata_digest =
                format!("sha256:{}", hex::encode(Sha256::digest(&metadata_bytes)));
            entries.push(ArchiveEntry {
                path: metadata_path,
                owner_snapshot: Some(snapshot_id.to_string()),
                kind: "snapshot-metadata".into(),
                included: true,
                encoded_size: metadata_bytes.len() as u64,
                apparent_size: metadata_bytes.len() as u64,
                sparse_ranges: Vec::new(),
                integrity: Some(UpperIntegrity::Sha256 {
                    digest: metadata_digest,
                }),
                transport_integrity: None,
            });
        }

        match &snapshot.manifest().state {
            SnapshotState::File(file) => {
                for layer in &file.layers {
                    let path = snapshot.layer_path(layer);
                    let archive_path = portable_archive_path(&file.layer_path(layer))?;
                    let encoded_size = archive_encoded_size(&path).await?;
                    require_json_safe_size(encoded_size, &archive_path)?;
                    require_json_safe_size(layer.virtual_size, &archive_path)?;
                    entries.push(ArchiveEntry {
                        path: archive_path,
                        owner_snapshot: Some(snapshot_id.to_string()),
                        kind: "file-payload".into(),
                        included: true,
                        encoded_size,
                        apparent_size: layer.virtual_size,
                        sparse_ranges: Vec::new(),
                        integrity: layer.payload.integrity.clone(),
                        transport_integrity: None,
                    });
                }
            }
            SnapshotState::Checkpoint(_) => {
                for member in checkpoint_members
                    .get(snapshot_id)
                    .expect("checkpoint members were collected before inventory construction")
                {
                    let encoded_size = archive_encoded_size(&member.source).await?;
                    require_json_safe_size(encoded_size, &member.archive_path)?;
                    require_json_safe_size(member.apparent_size, &member.archive_path)?;
                    entries.push(ArchiveEntry {
                        path: member.archive_path.clone(),
                        owner_snapshot: Some(snapshot_id.to_string()),
                        kind: member.kind.into(),
                        included: true,
                        encoded_size,
                        apparent_size: member.apparent_size,
                        sparse_ranges: Vec::new(),
                        integrity: None,
                        transport_integrity: None,
                    });
                }
            }
        }
    }

    for (path, archive_path) in cache_files {
        let size = tokio::fs::metadata(path).await?.len();
        require_json_safe_size(size, archive_path)?;
        let digest = format!("sha256:{}", hex::encode(file_sha256(path).await?));
        entries.push(ArchiveEntry {
            path: archive_path.clone(),
            owner_snapshot: None,
            kind: if archive_path.contains("/manifests/") {
                "image-metadata".into()
            } else {
                "image-object".into()
            },
            included: true,
            encoded_size: size,
            apparent_size: size,
            sparse_ranges: Vec::new(),
            integrity: Some(UpperIntegrity::Sha256 { digest }),
            transport_integrity: None,
        });
    }

    snapshot_members.sort_by(|left, right| left.snapshot_id.cmp(&right.snapshot_id));
    entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let suggested_name = head
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && name.len() <= 255)
        .map(str::to_string);
    let encoded_bytes = entries.iter().map(|entry| entry.encoded_size).sum();
    let apparent_bytes = entries.iter().map(|entry| entry.apparent_size).sum();
    Ok(ArchiveInventory {
        schema: "microsandbox.snapshot-archive/1".into(),
        head: head.id().to_string(),
        suggested_name,
        completeness: "boot-complete".into(),
        members: snapshot_members,
        limits: ArchiveLimits {
            entry_count: entries.len() as u64,
            encoded_bytes,
            apparent_bytes,
        },
        entries,
        extensions: BTreeMap::new(),
        requires: vec![ARCHIVE_MEMBER_TRANSPORT_ALGORITHM.into()],
    })
}

fn collect_checkpoint_archive_members(
    snapshots: &[Snapshot],
) -> MicrosandboxResult<HashMap<String, Vec<CheckpointArchiveMember>>> {
    let mut collected = HashMap::new();
    for snapshot in snapshots {
        if let SnapshotState::Checkpoint(state) = &snapshot.manifest().state {
            collected.insert(
                snapshot.id().to_string(),
                checkpoint_archive_members(
                    snapshot.id().as_str(),
                    &snapshot.path().join(CHECKPOINT_DIRECTORY),
                    &state.checkpoint_root,
                )?,
            );
        }
    }
    Ok(collected)
}

/// Resolve the exact transitive closure named by one checkpoint descriptor.
///
/// The archive writer never sweeps the artifact directory. This allowlist is derived from the
/// validated manifests, keeping runtime journals, temporary files, and unrelated objects out of
/// portable archives.
fn checkpoint_archive_members(
    snapshot_id: &str,
    closure_root: &Path,
    checkpoint_root: &str,
) -> MicrosandboxResult<Vec<CheckpointArchiveMember>> {
    let expected = ObjectId::new(checkpoint_root)
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let closure = CheckpointClosure::open_portable(closure_root, Some(&expected))
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let prefix = format!("checkpoints/{snapshot_id}");
    let checkpoint_path = closure_root.join("checkpoint.json");
    let mut members = vec![CheckpointArchiveMember {
        apparent_size: std::fs::metadata(&checkpoint_path)?.len(),
        source: checkpoint_path,
        archive_path: format!("{prefix}/checkpoint.json"),
        kind: "checkpoint-root",
    }];

    let checkpoint = closure.checkpoint();
    let mut objects = BTreeSet::from([
        checkpoint.execution_state.clone(),
        checkpoint.memory.clone(),
    ]);
    objects.extend(checkpoint.disks.iter().cloned());
    objects.extend(checkpoint.devices.iter().map(|device| device.state.clone()));
    for extent in &closure.memory().extents {
        if let MemoryExtentContent::Object(content) = &extent.content {
            objects.insert(content.object.clone());
        }
    }
    for object in objects {
        let encoded = object
            .as_str()
            .strip_prefix("sha256:")
            .expect("ObjectId validates its algorithm");
        let source = closure_root
            .join("objects")
            .join("sha256")
            .join(&encoded[..2])
            .join(encoded);
        members.push(CheckpointArchiveMember {
            apparent_size: std::fs::metadata(&source)?.len(),
            source,
            archive_path: format!("{prefix}/objects/sha256/{}/{}", &encoded[..2], encoded),
            kind: "checkpoint-object",
        });
    }
    for disk in closure.disks() {
        for layer in &disk.layers {
            let source = closure.disk_layer_path(layer);
            members.push(CheckpointArchiveMember {
                apparent_size: std::fs::metadata(&source)?.len(),
                source,
                archive_path: format!("{prefix}/layers/{}.{}", layer.layer_id, layer.format),
                kind: "checkpoint-disk-layer",
            });
        }
    }
    members.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    Ok(members)
}

fn set_archive_transport(
    inventory: &mut ArchiveInventory,
    path: &str,
    written: WrittenArchiveMember,
) -> MicrosandboxResult<()> {
    let entry_index = inventory
        .entries
        .iter()
        .position(|entry| entry.path == path)
        .ok_or_else(|| {
            MicrosandboxError::Custom(format!(
                "archive writer produced an uninventoried member: {path}"
            ))
        })?;
    // The writer is authoritative for the transport representation. A sparse
    // pre-scan can become stale before the source is consumed, and a path that
    // needs a GNU long-name record deliberately falls back to a dense member.
    let old_encoded_size = inventory.entries[entry_index].encoded_size;
    let old_apparent_size = inventory.entries[entry_index].apparent_size;
    let new_encoded_size = written.encoded_size;
    let new_apparent_size = written.apparent_size;
    let encoded_bytes = inventory
        .limits
        .encoded_bytes
        .checked_sub(old_encoded_size)
        .and_then(|remaining| remaining.checked_add(new_encoded_size))
        .ok_or_else(|| {
            MicrosandboxError::Custom("archive encoded size limit invariant failed".into())
        })?;
    let apparent_bytes = inventory
        .limits
        .apparent_bytes
        .checked_sub(old_apparent_size)
        .and_then(|remaining| remaining.checked_add(new_apparent_size))
        .ok_or_else(|| {
            MicrosandboxError::Custom("archive apparent size limit invariant failed".into())
        })?;

    // Commit the member and aggregate replacements together only after every checked calculation
    // succeeds, so an invalid precomputed inventory cannot leave a partially updated descriptor.
    let entry = &mut inventory.entries[entry_index];
    entry.encoded_size = new_encoded_size;
    entry.apparent_size = new_apparent_size;
    entry.sparse_ranges = written.sparse_ranges;
    entry.transport_integrity = Some(written.transport_integrity);
    inventory.limits.encoded_bytes = encoded_bytes;
    inventory.limits.apparent_bytes = apparent_bytes;
    Ok(())
}

/// Construct the stable member hash prefix. Length-prefixing text and binding
/// both sizes plus the exact sparse map keeps unlike archive records from
/// sharing a byte representation.
fn archive_transport_hasher(
    kind: &str,
    path: &str,
    encoded_size: u64,
    apparent_size: u64,
    sparse_ranges: &[(u64, u64)],
) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ARCHIVE_MEMBER_TRANSPORT_DOMAIN);
    update_transport_text(&mut hasher, kind);
    update_transport_text(&mut hasher, path);
    hasher.update(&encoded_size.to_le_bytes());
    hasher.update(&apparent_size.to_le_bytes());
    hasher.update(&(sparse_ranges.len() as u64).to_le_bytes());
    for (offset, len) in sparse_ranges {
        hasher.update(&offset.to_le_bytes());
        hasher.update(&len.to_le_bytes());
    }
    hasher
}

fn update_transport_text(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn finish_archive_transport(hasher: blake3::Hasher) -> ArchiveTransportIntegrity {
    ArchiveTransportIntegrity {
        algorithm: ARCHIVE_MEMBER_TRANSPORT_ALGORITHM.into(),
        digest: format!("blake3:{}", hasher.finalize().to_hex()),
    }
}

async fn archive_encoded_size(path: &Path) -> MicrosandboxResult<u64> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let metadata = std::fs::metadata(&path)?;
        let encoded = ExtentMap::scan(&path)?
            .as_ref()
            .and_then(tar_sparse_map)
            .map(|map| map.archived)
            .unwrap_or(metadata.len());
        Ok::<_, std::io::Error>(encoded)
    })
    .await
    .map_err(|error| MicrosandboxError::Custom(format!("archive size task: {error}")))?
    .map_err(Into::into)
}

fn require_json_safe_size(size: u64, path: &str) -> MicrosandboxResult<()> {
    if size > MAX_JSON_SAFE_INTEGER {
        return Err(MicrosandboxError::Custom(format!(
            "archive entry size exceeds JSON safe integer at {path}"
        )));
    }
    Ok(())
}

fn archive_temp_path(out: &Path) -> MicrosandboxResult<PathBuf> {
    let name = out
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| MicrosandboxError::Custom("archive path has no UTF-8 filename".into()))?;
    Ok(out.with_file_name(format!(
        ".{name}.tmp.{}.{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    )))
}

/// Append one file, as an old-GNU sparse entry when it has holes so
/// only allocated extents are read, dense otherwise.
async fn append_artifact_file<W>(
    builder: &mut Builder<W>,
    path: &Path,
    name: &str,
    kind: &str,
) -> MicrosandboxResult<WrittenArchiveMember>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    if let Some(integrity) = try_append_sparse(builder, path, name, kind).await? {
        return Ok(integrity);
    }

    let metadata = tokio::fs::metadata(path).await?;
    if !metadata.is_file() {
        return Err(MicrosandboxError::Custom(format!(
            "archive source is not a regular file: {}",
            path.display()
        )));
    }
    let size = metadata.len();
    let mut header = Header::new_gnu();
    header.set_metadata_in_mode(&metadata, HeaderMode::Complete);
    header.set_size(size);
    header.set_cksum();

    let file = tokio::fs::File::open(path).await?;
    let mut source = TransportHashingReader {
        inner: file,
        hasher: archive_transport_hasher(kind, name, size, size, &[]),
        bytes_read: 0,
    };
    builder.append_data(&mut header, name, &mut source).await?;
    if source.bytes_read != size {
        return Err(MicrosandboxError::Custom(format!(
            "archive source changed while reading {name}: expected {size} bytes, read {}",
            source.bytes_read
        )));
    }
    Ok(WrittenArchiveMember {
        encoded_size: size,
        apparent_size: size,
        transport_integrity: finish_archive_transport(source.hasher),
        sparse_ranges: Vec::new(),
    })
}

/// Append `path` as an old-GNU sparse entry if it has holes. Returns `false` without writing anything when the file is better served by the dense path (no holes, empty, extents
/// not enumerable on this filesystem, or a name too long for the fixed GNU header path field).
async fn try_append_sparse<W>(
    builder: &mut Builder<W>,
    path: &Path,
    name: &str,
    kind: &str,
) -> MicrosandboxResult<Option<WrittenArchiveMember>>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    use tokio_tar::GnuExtSparseHeader;

    let meta = tokio::fs::metadata(path).await?;
    if !meta.is_file() {
        return Ok(None);
    }
    let map = {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || ExtentMap::scan(&path))
            .await
            .map_err(|e| MicrosandboxError::Custom(format!("snapshot export scan task: {e}")))??
    };
    let Some(map) = map.as_ref().and_then(tar_sparse_map) else {
        return Ok(None);
    };

    let mut header = Header::new_gnu();
    header.set_metadata_in_mode(&meta, HeaderMode::Complete);
    if header.set_path(name).is_err() {
        // Needs a GNU long-name entry; the dense path emits one.
        return Ok(None);
    }
    header.set_entry_type(EntryType::GNUSparse);
    header.set_size(map.archived);
    let entries = map.entries();
    {
        let gnu = header
            .as_gnu_mut()
            .expect("Header::new_gnu produces a GNU header");
        write_tar_numeric(&mut gnu.realsize, map.len);
        for (slot, (offset, numbytes)) in gnu.sparse.iter_mut().zip(entries.iter()) {
            write_tar_numeric(&mut slot.offset, *offset);
            write_tar_numeric(&mut slot.numbytes, *numbytes);
        }
        if entries.len() > GNU_HEADER_SPARSE_SLOTS {
            gnu.isextended[0] = 1;
        }
    }
    header.set_cksum();

    // Header, extended sparse blocks, data segments, block padding —
    // all plain 512-byte tar records, written straight to the
    // builder's inner writer between entries.
    let dst = builder.get_mut();
    dst.write_all(header.as_bytes()).await?;

    let mut rest = &entries[entries.len().min(GNU_HEADER_SPARSE_SLOTS)..];
    while !rest.is_empty() {
        let mut ext = GnuExtSparseHeader::new();
        let take = rest.len().min(GNU_EXT_SPARSE_SLOTS);
        for (slot, (offset, numbytes)) in ext.sparse.iter_mut().zip(&rest[..take]) {
            write_tar_numeric(&mut slot.offset, *offset);
            write_tar_numeric(&mut slot.numbytes, *numbytes);
        }
        rest = &rest[take..];
        if !rest.is_empty() {
            ext.isextended[0] = 1;
        }
        dst.write_all(ext.as_bytes()).await?;
    }

    let mut file = tokio::fs::File::open(path).await?;
    let mut written: u64 = 0;
    let mut transport = archive_transport_hasher(kind, name, map.archived, map.len, &entries);
    let mut buffer = vec![0u8; 1024 * 1024];
    for (offset, numbytes) in &map.segments {
        file.seek(std::io::SeekFrom::Start(*offset)).await?;
        let mut remaining = *numbytes;
        while remaining > 0 {
            let wanted = remaining.min(buffer.len() as u64) as usize;
            let read = file.read(&mut buffer[..wanted]).await?;
            if read == 0 {
                return Err(MicrosandboxError::Custom(format!(
                    "archive source truncated during export: extent at {offset} expected {numbytes} bytes"
                )));
            }
            transport.update(&buffer[..read]);
            dst.write_all(&buffer[..read]).await?;
            written += read as u64;
            remaining -= read as u64;
        }
    }
    debug_assert_eq!(written, map.archived);

    let pad = (TAR_BLOCK - written % TAR_BLOCK) % TAR_BLOCK;
    if pad > 0 {
        dst.write_all(&[0u8; TAR_BLOCK as usize][..pad as usize])
            .await?;
    }
    Ok(Some(WrittenArchiveMember {
        encoded_size: map.archived,
        apparent_size: map.len,
        transport_integrity: finish_archive_transport(transport),
        sparse_ranges: map
            .entries()
            .into_iter()
            .map(|(offset, length)| [offset, length])
            .collect(),
    }))
}

/// Round an [`ExtentMap`]'s byte extents outward to tar blocks and merge runs that touch: sparse readers require every data run before the last to be a multiple of 512. `None`
/// means "archive it dense" — an empty or hole-free file, where a regular entry is equivalent and stays readable by older importers.
fn tar_sparse_map(map: &ExtentMap) -> Option<SparseMap> {
    let len = map.len;
    if len == 0 {
        return None;
    }

    let mut segments: Vec<(u64, u64)> = Vec::new();
    for (data_start, data_len) in &map.extents {
        let data_end = data_start + data_len;
        let seg_start = data_start - data_start % TAR_BLOCK;
        let seg_end = data_end
            .div_ceil(TAR_BLOCK)
            .saturating_mul(TAR_BLOCK)
            .min(len);
        match segments.last_mut() {
            Some((prev_start, prev_len)) if seg_start <= *prev_start + *prev_len => {
                let prev_end = *prev_start + *prev_len;
                if seg_end > prev_end {
                    *prev_len = seg_end - *prev_start;
                }
            }
            _ => segments.push((seg_start, seg_end - seg_start)),
        }
    }

    if segments.as_slice() == [(0, len)] {
        return None;
    }

    let archived = segments.iter().map(|(_, sz)| sz).sum();
    Some(SparseMap {
        len,
        archived,
        segments,
    })
}

/// Encode `value` into a 12-byte tar numeric field: zero-padded octal
/// with a NUL terminator when it fits (what GNU tar writes), otherwise
/// GNU base-256 (high bit set, big-endian binary).
fn write_tar_numeric(field: &mut [u8; 12], value: u64) {
    const OCTAL_MAX: u64 = 0o77777777777; // 11 octal digits
    if value <= OCTAL_MAX {
        let octal = format!("{value:011o}");
        field[..11].copy_from_slice(octal.as_bytes());
        field[11] = 0;
    } else {
        field.fill(0);
        field[0] = 0x80;
        field[4..].copy_from_slice(&value.to_be_bytes());
    }
}

/// Walk the archive's 512-byte records directly. The grammar is closed — regular files, directories, and old-GNU sparse entries at fixed depths, produced by our own exporter — so
/// a small owned walker replaces `tokio_tar::Archive` and lets sparse entries restore map-driven instead of through the library's opaque unpack.
async fn unpack_archive<R>(
    reader: R,
    snapshots_dir: &Path,
    cache_dir: &Path,
) -> MicrosandboxResult<UnpackedArchive>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut reader = BufReader::with_capacity(256 * 1024, reader);
    let mut manifest_dirs: Vec<PathBuf> = Vec::new();
    let mut observed_files: HashMap<String, ObservedArchiveEntry> = HashMap::new();
    let mut extraction_targets = HashSet::new();
    let mut inventory_path = None;
    let mut pending_long_name: Option<PathBuf> = None;
    let mut block = [0u8; TAR_BLOCK as usize];

    loop {
        if !read_record(&mut reader, &mut block).await? {
            if pending_long_name.is_some() {
                return Err(MicrosandboxError::Custom(
                    "archive ended after a GNU long-name record".into(),
                ));
            }
            // Clean EOF without the two-zero-record terminator; accept,
            // matching the previous reader's tolerance.
            break;
        }
        if block.iter().all(|&b| b == 0) {
            if pending_long_name.is_some() {
                return Err(MicrosandboxError::Custom(
                    "archive ended after a GNU long-name record".into(),
                ));
            }
            // End-of-archive marker. Tolerate EOF right after; anything
            // non-zero next means the stream is corrupt.
            if read_record(&mut reader, &mut block).await? && !block.iter().all(|&b| b == 0) {
                return Err(MicrosandboxError::Custom(
                    "archive contains a lone zero record inside the entry stream".into(),
                ));
            }
            break;
        }

        let mut header = Header::new_old();
        header.as_mut_bytes().copy_from_slice(&block);
        verify_header_checksum(&header)?;

        let entry_type = header.entry_type();
        let header_path = header.path()?.into_owned();
        if entry_type == EntryType::GNULongName {
            if pending_long_name.is_some() || header_path != Path::new("././@LongLink") {
                return Err(MicrosandboxError::Custom(
                    "archive contains an invalid GNU long-name record".into(),
                ));
            }
            let size = header.entry_size()?;
            if size == 0 || size > 16 * 1024 {
                return Err(MicrosandboxError::Custom(
                    "archive GNU long name exceeds the size limit".into(),
                ));
            }
            let size = usize::try_from(size).map_err(|_| {
                MicrosandboxError::Custom("archive GNU long name exceeds host limits".into())
            })?;
            let mut encoded = vec![0u8; size];
            reader.read_exact(&mut encoded).await?;
            discard_exact(&mut reader, tar_pad(size as u64)).await?;
            if encoded.last() != Some(&0) || encoded[..encoded.len() - 1].contains(&0) {
                return Err(MicrosandboxError::Custom(
                    "archive GNU long name is not a single NUL-terminated path".into(),
                ));
            }
            encoded.pop();
            let name = String::from_utf8(encoded).map_err(|_| {
                MicrosandboxError::Custom("archive GNU long name is not UTF-8".into())
            })?;
            pending_long_name = Some(PathBuf::from(name));
            continue;
        }
        let path_in_archive = pending_long_name.take().unwrap_or(header_path);

        // Reject suspicious paths (path traversal, absolute).
        if path_in_archive.is_absolute()
            || path_in_archive
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(MicrosandboxError::Custom(format!(
                "archive contains unsafe path: {}",
                path_in_archive.display()
            )));
        }
        validate_archive_entry_type(entry_type, &path_in_archive)?;

        let components = normal_utf8_components(&path_in_archive)?;
        if entry_type == EntryType::Directory {
            validate_archive_directory(&components, &path_in_archive)?;
            let size = header.entry_size()?;
            if size != 0 {
                return Err(MicrosandboxError::Custom(format!(
                    "archive directory has a non-empty body: {}",
                    path_in_archive.display()
                )));
            }
            skip_entry_data(&mut reader, size).await?;
            continue;
        }
        let (target, descriptor, inventory) = match components.as_slice() {
            ["archive.json"] => (snapshots_dir.join(".archive.json"), false, true),
            ["snapshots", snapshot_id, name]
                if microsandbox_image::snapshot::SnapshotId::new(*snapshot_id).is_ok()
                    && *name == DESCRIPTOR_FILENAME =>
            {
                (snapshots_dir.join(snapshot_id).join(name), true, false)
            }
            ["snapshots", snapshot_id, name]
                if microsandbox_image::snapshot::SnapshotId::new(*snapshot_id).is_ok()
                    && *name == super::metadata::METADATA_FILENAME =>
            {
                (snapshots_dir.join(snapshot_id).join(name), false, false)
            }
            ["layers", name] if valid_archive_layer_filename(name) => (
                snapshots_dir.join(".archive-layers").join(name),
                false,
                false,
            ),
            ["checkpoints", snapshot_id, "checkpoint.json"]
                if microsandbox_image::snapshot::SnapshotId::new(*snapshot_id).is_ok() =>
            {
                (
                    snapshots_dir
                        .join(snapshot_id)
                        .join(CHECKPOINT_DIRECTORY)
                        .join("checkpoint.json"),
                    false,
                    false,
                )
            }
            [
                "checkpoints",
                snapshot_id,
                "objects",
                "sha256",
                shard,
                object,
            ] if microsandbox_image::snapshot::SnapshotId::new(*snapshot_id).is_ok()
                && valid_checkpoint_object_path(shard, object) =>
            {
                (
                    snapshots_dir
                        .join(snapshot_id)
                        .join(CHECKPOINT_DIRECTORY)
                        .join("objects")
                        .join("sha256")
                        .join(shard)
                        .join(object),
                    false,
                    false,
                )
            }
            ["checkpoints", snapshot_id, "layers", name]
                if microsandbox_image::snapshot::SnapshotId::new(*snapshot_id).is_ok()
                    && valid_checkpoint_layer_filename(name) =>
            {
                (
                    snapshots_dir
                        .join(snapshot_id)
                        .join(CHECKPOINT_DIRECTORY)
                        .join("layers")
                        .join(name),
                    false,
                    false,
                )
            }
            ["snapshots", digest, name]
                if valid_archive_digest_hex(digest) && *name == DESCRIPTOR_FILENAME =>
            {
                (snapshots_dir.join(digest).join(name), true, false)
            }
            ["files", digest, name]
                if valid_archive_digest_hex(digest) && *name == "upper.ext4" =>
            {
                (snapshots_dir.join(digest).join(name), false, false)
            }
            ["images", kind, name]
                if is_supported_cache_file(kind, name) && valid_archive_filename(name) =>
            {
                (cache_dir.join(kind).join(name), false, false)
            }
            ["cache", kind, name] if is_supported_cache_file(kind, name) => {
                (cache_dir.join(kind).join(name), false, false)
            }
            [prefix, name]
                if valid_legacy_prefix(prefix)
                    && matches!(*name, V066_DESCRIPTOR_FILENAME | "upper.ext4") =>
            {
                (
                    snapshots_dir.join(prefix).join(name),
                    *name == V066_DESCRIPTOR_FILENAME,
                    false,
                )
            }
            _ => {
                return Err(MicrosandboxError::Custom(format!(
                    "archive contains unsupported path: {}",
                    path_in_archive.display()
                )));
            }
        };

        // Tar member names are portable paths. Re-encode their parsed components
        // instead of displaying a native Path, which would put `\\` into the
        // inventory key on Windows.
        let archive_path = portable_archive_path(&path_in_archive)?;
        if observed_files.contains_key(&archive_path) {
            return Err(MicrosandboxError::Custom(format!(
                "archive contains duplicate entry: {archive_path}"
            )));
        }
        if !extraction_targets.insert(target.clone()) {
            return Err(MicrosandboxError::Custom(format!(
                "archive entries map to the same extraction target: {archive_path}"
            )));
        }

        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let entry_size = header.entry_size()?;
        let kind = archive_member_kind(&components);
        let observation = match entry_type {
            EntryType::Directory => unreachable!("directories were handled above"),
            EntryType::GNUSparse => {
                let integrity = unpack_sparse_entry(
                    &mut reader,
                    &header,
                    entry_size,
                    &target,
                    kind,
                    &archive_path,
                )
                .await?;
                apply_entry_mode(&header, &target).await?;
                integrity
            }
            // Regular / Continuous — the only other types validation lets through.
            _ => {
                let integrity =
                    unpack_dense_entry(&mut reader, entry_size, &target, kind, &archive_path)
                        .await?;
                apply_entry_mode(&header, &target).await?;
                integrity
            }
        };
        let apparent_size = tokio::fs::metadata(&target).await?.len();
        observed_files.insert(
            archive_path,
            ObservedArchiveEntry {
                encoded_size: entry_size,
                apparent_size,
                sparse_ranges: observation.sparse_ranges,
                transport_integrity: observation.transport_integrity,
            },
        );

        if descriptor && let Some(parent) = target.parent() {
            manifest_dirs.push(parent.to_path_buf());
        }
        if inventory {
            inventory_path = Some(target);
        }
    }

    let inventory = if let Some(path) = inventory_path {
        let inventory =
            validate_archive_inventory(&path, &observed_files, snapshots_dir, cache_dir).await?;
        tokio::fs::remove_file(path).await?;
        inventory
    } else {
        None
    };
    Ok(UnpackedArchive {
        manifest_dirs,
        head: inventory.as_ref().map(|inventory| inventory.head.clone()),
        inventory,
    })
}

/// Read one 512-byte tar record. `Ok(false)` on clean EOF at a record boundary; a partial record is corruption.
async fn read_record<R>(
    reader: &mut R,
    block: &mut [u8; TAR_BLOCK as usize],
) -> MicrosandboxResult<bool>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut filled = 0usize;
    while filled < block.len() {
        let n = reader.read(&mut block[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(false);
            }
            return Err(MicrosandboxError::Custom(
                "archive truncated mid-record".into(),
            ));
        }
        filled += n;
    }
    Ok(true)
}

/// Verify a header's recorded checksum: sum of the record's bytes with the checksum field itself read as spaces. Accept both the unsigned sum (what everything modern writes,
/// including our exporter) and the legacy signed-byte sum some historic implementations produced.
fn verify_header_checksum(header: &Header) -> MicrosandboxResult<()> {
    let bytes = header.as_bytes();
    let recorded = header.cksum().map_err(|e| {
        MicrosandboxError::Custom(format!("archive header checksum unreadable: {e}"))
    })?;

    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, byte) in bytes.iter().enumerate() {
        let value = if (148..156).contains(&i) { b' ' } else { *byte };
        unsigned += value as u64;
        signed += (value as i8) as i64;
    }
    if recorded as u64 == unsigned || recorded as i64 == signed {
        Ok(())
    } else {
        Err(MicrosandboxError::Custom(
            "archive header checksum mismatch".into(),
        ))
    }
}

/// Discard an entry's data plus its block padding.
async fn skip_entry_data<R>(reader: &mut R, size: u64) -> MicrosandboxResult<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    discard_exact(reader, size + tar_pad(size)).await
}

/// Discard exactly `count` bytes from the stream.
async fn discard_exact<R>(reader: &mut R, count: u64) -> MicrosandboxResult<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let discarded =
        tokio::io::copy(&mut (&mut *reader).take(count), &mut tokio::io::sink()).await?;
    if discarded != count {
        return Err(MicrosandboxError::Custom(
            "archive truncated mid-entry".into(),
        ));
    }
    Ok(())
}

/// Bytes of zero padding that follow `size` bytes of entry data.
fn tar_pad(size: u64) -> u64 {
    (TAR_BLOCK - size % TAR_BLOCK) % TAR_BLOCK
}

/// Stream a dense entry's bytes into `target`.
async fn unpack_dense_entry<R>(
    reader: &mut R,
    size: u64,
    target: &Path,
    kind: &str,
    archive_path: &str,
) -> MicrosandboxResult<WrittenArchiveMember>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::File::create(target).await?;
    let mut source = TransportHashingReader {
        inner: (&mut *reader).take(size),
        hasher: archive_transport_hasher(kind, archive_path, size, size, &[]),
        bytes_read: 0,
    };
    let copied = tokio::io::copy(&mut source, &mut file).await?;
    if copied != size {
        return Err(MicrosandboxError::Custom(
            "archive truncated mid-entry".into(),
        ));
    }
    file.flush().await?;
    let TransportHashingReader { hasher, .. } = source;
    discard_exact(reader, tar_pad(size)).await?;
    Ok(WrittenArchiveMember {
        encoded_size: size,
        apparent_size: size,
        transport_integrity: finish_archive_transport(hasher),
        sparse_ranges: Vec::new(),
    })
}

/// Restore an old-GNU sparse entry map-driven: parse the sparse map (inline slots plus chained extended records), enforce its invariants, then copy each data run straight off the
/// wire to its logical offset. Hole bytes are never in the stream and never written; [`extent::mark_sparse`] / [`extent::punch_hole_aligned`] keep them unallocated on filesystems
/// that need telling.
async fn unpack_sparse_entry<R>(
    reader: &mut R,
    header: &Header,
    archived: u64,
    target: &Path,
    kind: &str,
    archive_path: &str,
) -> MicrosandboxResult<WrittenArchiveMember>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    use tokio_tar::GnuExtSparseHeader;

    let gnu = header.as_gnu().ok_or_else(|| {
        MicrosandboxError::Custom("sparse entry does not carry a GNU header".into())
    })?;
    let realsize = gnu
        .real_size()
        .map_err(|e| MicrosandboxError::Custom(format!("sparse entry realsize unreadable: {e}")))?;

    let mut map: Vec<(u64, u64)> = Vec::new();
    let mut push_slot = |slot: &tokio_tar::GnuSparseHeader| -> MicrosandboxResult<()> {
        if slot.is_empty() {
            return Ok(());
        }
        let offset = slot
            .offset()
            .map_err(|e| MicrosandboxError::Custom(format!("sparse map slot unreadable: {e}")))?;
        let numbytes = slot
            .length()
            .map_err(|e| MicrosandboxError::Custom(format!("sparse map slot unreadable: {e}")))?;
        map.push((offset, numbytes));
        Ok(())
    };
    for slot in &gnu.sparse {
        push_slot(slot)?;
    }
    let mut extended = gnu.is_extended();
    let mut block = [0u8; TAR_BLOCK as usize];
    while extended {
        if !read_record(reader, &mut block).await? {
            return Err(MicrosandboxError::Custom(
                "archive truncated inside a sparse map".into(),
            ));
        }
        let mut ext = GnuExtSparseHeader::new();
        ext.as_mut_bytes().copy_from_slice(&block);
        for slot in &ext.sparse {
            push_slot(slot)?;
        }
        extended = ext.is_extended();
    }

    // The same invariants GNU tar's readers enforce: runs sorted and
    // non-overlapping, every run before the last 512-aligned, run bytes
    // sum to the entry size, and the map ends exactly at realsize.
    let mut logical_end: u64 = 0;
    let mut consumed: u64 = 0;
    for (offset, numbytes) in &map {
        if *numbytes != 0 && !consumed.is_multiple_of(TAR_BLOCK) {
            return Err(MicrosandboxError::Custom(
                "sparse map data run not aligned to 512-byte record".into(),
            ));
        }
        if *offset < logical_end {
            return Err(MicrosandboxError::Custom(
                "sparse map runs out of order or overlapping".into(),
            ));
        }
        logical_end = offset.checked_add(*numbytes).ok_or_else(|| {
            MicrosandboxError::Custom("sparse map run overflows file size".into())
        })?;
        consumed = consumed.checked_add(*numbytes).ok_or_else(|| {
            MicrosandboxError::Custom("sparse map bytes overflow entry size".into())
        })?;
    }
    if logical_end != realsize {
        return Err(MicrosandboxError::Custom(
            "sparse map does not end at the entry's realsize".into(),
        ));
    }
    if consumed != archived {
        return Err(MicrosandboxError::Custom(
            "sparse map bytes disagree with the entry size".into(),
        ));
    }

    let std_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(target)?;
    // Allocation-only optimizations: content is correct without them,
    // so a filesystem that rejects either just loads dense.
    let _ = extent::mark_sparse(&std_file);
    std_file.set_len(realsize)?;
    let mut file = tokio::fs::File::from_std(std_file);
    let mut transport = archive_transport_hasher(kind, archive_path, archived, realsize, &map);

    for (offset, numbytes) in &map {
        if *numbytes == 0 {
            continue;
        }
        file.seek(std::io::SeekFrom::Start(*offset)).await?;
        let mut source = TransportHashingReader {
            inner: (&mut *reader).take(*numbytes),
            hasher: transport,
            bytes_read: 0,
        };
        let copied = tokio::io::copy(&mut source, &mut file).await?;
        transport = source.hasher;
        if copied != *numbytes {
            return Err(MicrosandboxError::Custom(
                "archive truncated mid-entry".into(),
            ));
        }
    }
    file.flush().await?;
    discard_exact(reader, tar_pad(archived)).await?;

    // APFS keeps nothing sparse on its own — punch the holes the map
    // describes. No-op on other platforms.
    if cfg!(target_os = "macos") {
        let std_file = file.into_std().await;
        let mut prev_end: u64 = 0;
        for (offset, numbytes) in &map {
            if *numbytes == 0 {
                continue;
            }
            if *offset > prev_end {
                let _ = extent::punch_hole_aligned(&std_file, prev_end, offset - prev_end);
            }
            prev_end = offset + numbytes;
        }
        if realsize > prev_end {
            let _ = extent::punch_hole_aligned(&std_file, prev_end, realsize - prev_end);
        }
    }

    Ok(WrittenArchiveMember {
        encoded_size: archived,
        apparent_size: realsize,
        transport_integrity: finish_archive_transport(transport),
        sparse_ranges: map
            .into_iter()
            .map(|(offset, length)| [offset, length])
            .collect(),
    })
}

/// Apply the entry's recorded permission bits to the restored file.
async fn apply_entry_mode(header: &Header, target: &Path) -> MicrosandboxResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = header.mode().map_err(|e| {
            MicrosandboxError::Custom(format!("archive header mode unreadable: {e}"))
        })?;
        tokio::fs::set_permissions(target, std::fs::Permissions::from_mode(mode & 0o7777)).await?;
    }
    #[cfg(not(unix))]
    {
        let _ = (header, target);
    }
    Ok(())
}

fn validate_archive_entry_type(entry_type: EntryType, path: &Path) -> MicrosandboxResult<()> {
    match entry_type {
        EntryType::Regular
        | EntryType::Continuous
        | EntryType::GNUSparse
        | EntryType::Directory => Ok(()),
        _ => Err(MicrosandboxError::Custom(format!(
            "archive contains unsupported entry type at {}",
            path.display()
        ))),
    }
}

fn validate_archive_directory(components: &[&str], path: &Path) -> MicrosandboxResult<()> {
    let valid = match components {
        ["snapshots" | "layers" | "files" | "images" | "cache" | "checkpoints"] => true,
        ["snapshots", snapshot_id] => {
            microsandbox_image::snapshot::SnapshotId::new(*snapshot_id).is_ok()
                || valid_archive_digest_hex(snapshot_id)
        }
        ["files", digest] => valid_archive_digest_hex(digest),
        ["checkpoints", snapshot_id]
        | ["checkpoints", snapshot_id, "objects"]
        | ["checkpoints", snapshot_id, "objects", "sha256"]
        | ["checkpoints", snapshot_id, "layers"] => {
            microsandbox_image::snapshot::SnapshotId::new(*snapshot_id).is_ok()
        }
        ["checkpoints", snapshot_id, "objects", "sha256", shard] => {
            microsandbox_image::snapshot::SnapshotId::new(*snapshot_id).is_ok()
                && shard.len() == 2
                && shard
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }
        ["images" | "cache", kind] => is_supported_cache_dir(kind),
        [prefix] => valid_legacy_prefix(prefix),
        _ => false,
    };
    if !valid {
        return Err(MicrosandboxError::Custom(format!(
            "archive contains unsupported directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn archive_member_kind(components: &[&str]) -> &'static str {
    match components {
        ["archive.json"] => "archive-inventory",
        ["snapshots", _, name] if *name == super::metadata::METADATA_FILENAME => {
            "snapshot-metadata"
        }
        ["snapshots", _, _] => "snapshot-descriptor",
        ["layers", _] => "file-payload",
        ["files", _, _] => "file-payload",
        ["checkpoints", _, "checkpoint.json"] => "checkpoint-root",
        ["checkpoints", _, "objects", "sha256", _, _] => "checkpoint-object",
        ["checkpoints", _, "layers", _] => "checkpoint-disk-layer",
        ["images" | "cache", "manifests", _] => "image-metadata",
        ["images" | "cache", _, _] => "image-object",
        [_, V066_DESCRIPTOR_FILENAME] => "legacy-snapshot-descriptor",
        [_, "upper.ext4"] => "legacy-file-payload",
        _ => "unknown",
    }
}

fn valid_archive_digest_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_legacy_prefix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "archive.json"
        && value != "snapshots"
        && value != "layers"
        && value != "files"
        && value != "images"
        && value != "cache"
        && value != "checkpoints"
}

fn valid_archive_filename(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && value != "." && value != ".."
}

fn valid_archive_layer_filename(value: &str) -> bool {
    let Some((id, extension)) = value.rsplit_once('.') else {
        return false;
    };
    microsandbox_image::snapshot::DiskLayerId::new(id).is_ok()
        && matches!(extension, "raw" | "qcow2")
}

fn valid_checkpoint_object_path(shard: &str, object: &str) -> bool {
    valid_archive_digest_hex(object) && shard == &object[..2]
}

fn valid_checkpoint_layer_filename(value: &str) -> bool {
    let Some((identity, format)) = value.rsplit_once('.') else {
        return false;
    };
    !identity.is_empty()
        && identity.len() <= 128
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && matches!(format, "raw" | "qcow2")
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

async fn validate_archive_inventory(
    path: &Path,
    observed: &HashMap<String, ObservedArchiveEntry>,
    snapshots_dir: &Path,
    cache_dir: &Path,
) -> MicrosandboxResult<Option<ArchiveInventory>> {
    const MAX_INVENTORY_BYTES: u64 = 4 * 1024 * 1024;
    let metadata = tokio::fs::metadata(path).await?;
    if metadata.len() > MAX_INVENTORY_BYTES {
        return Err(MicrosandboxError::Custom(
            "archive inventory exceeds the size limit".into(),
        ));
    }
    let bytes = tokio::fs::read(path).await?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        MicrosandboxError::Custom(format!("archive inventory parse failed: {error}"))
    })?;
    if value.get("schema").and_then(serde_json::Value::as_u64) == Some(1) {
        let inventory: ReleasedArchiveInventory =
            serde_json::from_value(value).map_err(|error| {
                MicrosandboxError::Custom(format!(
                    "released archive inventory parse failed: {error}"
                ))
            })?;
        validate_released_archive_inventory(&bytes, &inventory, observed, snapshots_dir, cache_dir)
            .await?;
        return Ok(None);
    }
    let inventory: ArchiveInventory = serde_json::from_value(value).map_err(|error| {
        MicrosandboxError::Custom(format!("archive inventory parse failed: {error}"))
    })?;
    let canonical = serde_json::to_vec(&inventory).map_err(|error| {
        MicrosandboxError::Custom(format!("archive inventory serialize failed: {error}"))
    })?;
    if canonical != bytes {
        return Err(MicrosandboxError::Custom(
            "archive inventory is not canonical".into(),
        ));
    }
    if inventory.schema != "microsandbox.snapshot-archive/1" {
        return Err(MicrosandboxError::Custom(
            "unsupported archive inventory schema or artifact".into(),
        ));
    }
    if inventory.completeness != "boot-complete" {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(format!(
                "snapshot archive completeness {} is not supported",
                inventory.completeness
            )),
        ));
    }
    let requires_transport = match inventory.requires.as_slice() {
        [] => false,
        [requirement] if requirement == ARCHIVE_MEMBER_TRANSPORT_ALGORITHM => true,
        _ => {
            return Err(MicrosandboxError::unsupported(
                Operation::SnapshotOps,
                UnsupportedReason::NotAvailable(format!(
                    "snapshot archive requires unsupported extensions: {:?}",
                    inventory.requires
                )),
            ));
        }
    };
    if inventory
        .suggested_name
        .as_deref()
        .is_some_and(|name| name.is_empty() || name.len() > 255 || name.contains(['/', '\\']))
    {
        return Err(MicrosandboxError::Custom(
            "archive suggested_name is invalid".into(),
        ));
    }

    let mut prior_snapshot = None;
    let mut snapshot_map = HashMap::new();
    let mut descriptor_digests = HashMap::new();
    for snapshot in &inventory.members {
        microsandbox_image::snapshot::SnapshotId::new(&snapshot.snapshot_id)
            .map_err(|error| MicrosandboxError::Custom(error.to_string()))?;
        validate_sha256(&snapshot.descriptor_digest, "archive descriptor_digest")?;
        if prior_snapshot.is_some_and(|prior: &String| prior >= &snapshot.snapshot_id) {
            return Err(MicrosandboxError::Custom(
                "archive snapshots are not strictly sorted".into(),
            ));
        }
        let expected = format!("snapshots/{}/{DESCRIPTOR_FILENAME}", snapshot.snapshot_id);
        if snapshot.descriptor_path != expected {
            return Err(MicrosandboxError::Custom(format!(
                "archive snapshot descriptor path mismatch for {}",
                snapshot.snapshot_id
            )));
        }
        snapshot_map.insert(
            snapshot.snapshot_id.clone(),
            snapshot.descriptor_path.clone(),
        );
        descriptor_digests.insert(
            snapshot.snapshot_id.clone(),
            snapshot.descriptor_digest.clone(),
        );
        prior_snapshot = Some(&snapshot.snapshot_id);
    }
    if !snapshot_map.contains_key(&inventory.head) {
        return Err(MicrosandboxError::Custom(
            "archive head is not exactly one listed snapshot".into(),
        ));
    }

    let mut expected_paths = HashSet::new();
    let mut descriptor_entries = HashMap::new();
    let mut prior_path: Option<&str> = None;
    for entry in &inventory.entries {
        if prior_path.is_some_and(|prior| prior.as_bytes() >= entry.path.as_bytes()) {
            return Err(MicrosandboxError::Custom(
                "archive entries are not strictly sorted".into(),
            ));
        }
        prior_path = Some(&entry.path);
        if !entry.included {
            if observed.contains_key(&entry.path) {
                return Err(MicrosandboxError::Custom(format!(
                    "omitted archive entry is physically present: {}",
                    entry.path
                )));
            }
            continue;
        }
        if !expected_paths.insert(entry.path.clone()) {
            return Err(MicrosandboxError::Custom(format!(
                "duplicate inventory path: {}",
                entry.path
            )));
        }
        let Some(observed_entry) = observed.get(&entry.path) else {
            return Err(MicrosandboxError::Custom(format!(
                "inventoried entry is missing: {}",
                entry.path
            )));
        };
        if observed_entry.encoded_size != entry.encoded_size
            || observed_entry.apparent_size != entry.apparent_size
            || observed_entry.sparse_ranges != entry.sparse_ranges
        {
            return Err(MicrosandboxError::Custom(format!(
                "archive entry size or sparse map mismatch: {}",
                entry.path
            )));
        }
        match &entry.transport_integrity {
            Some(expected) => {
                validate_archive_transport(expected, &entry.path)?;
                if *expected != observed_entry.transport_integrity {
                    return Err(MicrosandboxError::Custom(format!(
                        "archive member transport integrity mismatch: {}",
                        entry.path
                    )));
                }
            }
            None if requires_transport => {
                return Err(MicrosandboxError::Custom(format!(
                    "archive member is missing required transport integrity: {}",
                    entry.path
                )));
            }
            None => {}
        }
        // File-payload integrity belongs to the snapshot descriptor and is
        // deliberately explicit, even when an old descriptor calls its
        // algorithm plain `sha256`. Descriptor and image entry hashes are
        // archive-level bindings and remain mandatory here.
        if entry.kind != "file-payload"
            && let Some(UpperIntegrity::Sha256 { digest }) = &entry.integrity
        {
            let target = inventory_entry_target(&entry.path, snapshots_dir, cache_dir)?;
            let actual = format!("sha256:{}", hex::encode(file_sha256(&target).await?));
            if actual != *digest {
                return Err(MicrosandboxError::Custom(format!(
                    "archive entry integrity mismatch: {}",
                    entry.path
                )));
            }
        }
        if entry.kind == "snapshot-descriptor" {
            let owner = entry.owner_snapshot.as_deref().ok_or_else(|| {
                MicrosandboxError::Custom("snapshot descriptor has no owner".into())
            })?;
            if !matches!(
                (&entry.integrity, descriptor_digests.get(owner)),
                (Some(UpperIntegrity::Sha256 { digest }), Some(expected)) if digest == expected.as_str()
            ) {
                return Err(MicrosandboxError::Custom(format!(
                    "snapshot descriptor identity mismatch: {}",
                    entry.path
                )));
            }
            descriptor_entries.insert(owner.to_string(), entry.path.clone());
        }
    }
    let physical: HashSet<String> = observed
        .keys()
        .filter(|entry| entry.as_str() != "archive.json")
        .cloned()
        .collect();
    if physical != expected_paths {
        return Err(MicrosandboxError::Custom(
            "archive contains a non-inventoried file".into(),
        ));
    }
    if descriptor_entries != snapshot_map {
        return Err(MicrosandboxError::Custom(
            "archive snapshot descriptor inventory is incomplete".into(),
        ));
    }
    Ok(Some(inventory))
}

async fn validate_released_archive_inventory(
    original_bytes: &[u8],
    inventory: &ReleasedArchiveInventory,
    observed: &HashMap<String, ObservedArchiveEntry>,
    snapshots_dir: &Path,
    cache_dir: &Path,
) -> MicrosandboxResult<()> {
    let canonical = serde_json::to_vec(inventory).map_err(|error| {
        MicrosandboxError::Custom(format!(
            "released archive inventory serialize failed: {error}"
        ))
    })?;
    if canonical != original_bytes {
        return Err(MicrosandboxError::Custom(
            "released archive inventory is not canonical".into(),
        ));
    }
    if inventory.schema != 1 || inventory.artifact != "snapshot-archive" {
        return Err(MicrosandboxError::Custom(
            "unsupported released archive inventory schema or artifact".into(),
        ));
    }
    if inventory.completeness != "boot-complete" {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(format!(
                "snapshot archive completeness {} is not supported",
                inventory.completeness
            )),
        ));
    }
    if !inventory.protection_requirements.is_empty() {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(
                "released archive protection requirements are not supported".into(),
            ),
        ));
    }
    let requires_transport = match inventory.requires.as_slice() {
        [] => false,
        [requirement] if requirement == ARCHIVE_MEMBER_TRANSPORT_ALGORITHM => true,
        _ => {
            return Err(MicrosandboxError::unsupported(
                Operation::SnapshotOps,
                UnsupportedReason::NotAvailable(format!(
                    "snapshot archive requires unsupported extensions: {:?}",
                    inventory.requires
                )),
            ));
        }
    };
    if inventory
        .suggested_name
        .as_deref()
        .is_some_and(|name| name.is_empty() || name.len() > 255 || name.contains(['/', '\\']))
    {
        return Err(MicrosandboxError::Custom(
            "archive suggested_name is invalid".into(),
        ));
    }

    let mut prior_snapshot: Option<&str> = None;
    let mut snapshot_map = HashMap::new();
    for snapshot in &inventory.snapshots {
        validate_sha256(&snapshot.snapshot_id, "archive snapshot_id")?;
        if prior_snapshot.is_some_and(|prior| prior >= snapshot.snapshot_id.as_str()) {
            return Err(MicrosandboxError::Custom(
                "archive snapshots are not strictly sorted".into(),
            ));
        }
        let expected = format!(
            "snapshots/{}/{DESCRIPTOR_FILENAME}",
            digest_hex(&snapshot.snapshot_id)?
        );
        if snapshot.descriptor != expected {
            return Err(MicrosandboxError::Custom(format!(
                "archive snapshot descriptor path mismatch for {}",
                snapshot.snapshot_id
            )));
        }
        snapshot_map.insert(snapshot.snapshot_id.clone(), snapshot.descriptor.clone());
        prior_snapshot = Some(&snapshot.snapshot_id);
    }
    if !snapshot_map.contains_key(&inventory.head) {
        return Err(MicrosandboxError::Custom(
            "archive head is not exactly one listed snapshot".into(),
        ));
    }

    let mut expected_paths = HashSet::new();
    let mut descriptor_entries = HashMap::new();
    let mut prior_path: Option<&str> = None;
    for entry in &inventory.entries {
        if prior_path.is_some_and(|prior| prior.as_bytes() >= entry.path.as_bytes()) {
            return Err(MicrosandboxError::Custom(
                "archive entries are not strictly sorted".into(),
            ));
        }
        prior_path = Some(&entry.path);
        if !entry.included {
            if observed.contains_key(&entry.path) {
                return Err(MicrosandboxError::Custom(format!(
                    "omitted archive entry is physically present: {}",
                    entry.path
                )));
            }
            continue;
        }
        if !expected_paths.insert(entry.path.clone()) {
            return Err(MicrosandboxError::Custom(format!(
                "duplicate inventory path: {}",
                entry.path
            )));
        }
        let Some(observed_entry) = observed.get(&entry.path) else {
            return Err(MicrosandboxError::Custom(format!(
                "inventoried entry is missing: {}",
                entry.path
            )));
        };
        if observed_entry.encoded_size != entry.encoded_size
            || observed_entry.apparent_size != entry.apparent_size
        {
            return Err(MicrosandboxError::Custom(format!(
                "archive entry size mismatch: {}",
                entry.path
            )));
        }
        match &entry.transport_integrity {
            Some(expected) => {
                validate_archive_transport(expected, &entry.path)?;
                if *expected != observed_entry.transport_integrity {
                    return Err(MicrosandboxError::Custom(format!(
                        "archive member transport integrity mismatch: {}",
                        entry.path
                    )));
                }
            }
            None if requires_transport => {
                return Err(MicrosandboxError::Custom(format!(
                    "archive member is missing required transport integrity: {}",
                    entry.path
                )));
            }
            None => {}
        }
        if entry.kind != "file-payload"
            && let Some(UpperIntegrity::Sha256 { digest }) = &entry.integrity
        {
            let target = inventory_entry_target(&entry.path, snapshots_dir, cache_dir)?;
            let actual = format!("sha256:{}", hex::encode(file_sha256(&target).await?));
            if actual != *digest {
                return Err(MicrosandboxError::Custom(format!(
                    "archive entry integrity mismatch: {}",
                    entry.path
                )));
            }
        }
        if entry.kind == "snapshot-descriptor" {
            let owner = entry.owner_snapshot.as_deref().ok_or_else(|| {
                MicrosandboxError::Custom("snapshot descriptor has no owner".into())
            })?;
            if !matches!(
                &entry.integrity,
                Some(UpperIntegrity::Sha256 { digest }) if digest == owner
            ) {
                return Err(MicrosandboxError::Custom(format!(
                    "snapshot descriptor identity mismatch: {}",
                    entry.path
                )));
            }
            descriptor_entries.insert(owner.to_string(), entry.path.clone());
        }
    }
    let physical: HashSet<String> = observed
        .keys()
        .filter(|entry| entry.as_str() != "archive.json")
        .cloned()
        .collect();
    if physical != expected_paths {
        return Err(MicrosandboxError::Custom(
            "archive contains a non-inventoried file".into(),
        ));
    }
    if descriptor_entries != snapshot_map {
        return Err(MicrosandboxError::Custom(
            "archive snapshot descriptor inventory is incomplete".into(),
        ));
    }
    Ok(())
}

fn validate_archive_transport(
    integrity: &ArchiveTransportIntegrity,
    path: &str,
) -> MicrosandboxResult<()> {
    if integrity.algorithm != ARCHIVE_MEMBER_TRANSPORT_ALGORITHM
        || !integrity.digest.starts_with("blake3:")
        || integrity.digest.len() != "blake3:".len() + 64
        || !integrity.digest["blake3:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MicrosandboxError::Custom(format!(
            "invalid archive member transport integrity: {path}"
        )));
    }
    Ok(())
}

fn inventory_entry_target(
    archive_path: &str,
    snapshots_dir: &Path,
    cache_dir: &Path,
) -> MicrosandboxResult<PathBuf> {
    let path = Path::new(archive_path);
    let components = normal_utf8_components(path)?;
    match components.as_slice() {
        ["snapshots", snapshot_id, name]
            if microsandbox_image::snapshot::SnapshotId::new(*snapshot_id).is_ok() =>
        {
            Ok(snapshots_dir.join(snapshot_id).join(name))
        }
        ["layers", name] => Ok(snapshots_dir.join(".archive-layers").join(name)),
        ["checkpoints", snapshot_id, "checkpoint.json"]
            if microsandbox_image::snapshot::SnapshotId::new(*snapshot_id).is_ok() =>
        {
            Ok(snapshots_dir
                .join(snapshot_id)
                .join(CHECKPOINT_DIRECTORY)
                .join("checkpoint.json"))
        }
        [
            "checkpoints",
            snapshot_id,
            "objects",
            "sha256",
            shard,
            object,
        ] if microsandbox_image::snapshot::SnapshotId::new(*snapshot_id).is_ok()
            && valid_checkpoint_object_path(shard, object) =>
        {
            Ok(snapshots_dir
                .join(snapshot_id)
                .join(CHECKPOINT_DIRECTORY)
                .join("objects")
                .join("sha256")
                .join(shard)
                .join(object))
        }
        ["checkpoints", snapshot_id, "layers", name]
            if microsandbox_image::snapshot::SnapshotId::new(*snapshot_id).is_ok()
                && valid_checkpoint_layer_filename(name) =>
        {
            Ok(snapshots_dir
                .join(snapshot_id)
                .join(CHECKPOINT_DIRECTORY)
                .join("layers")
                .join(name))
        }
        ["snapshots", digest, name] if valid_archive_digest_hex(digest) => {
            Ok(snapshots_dir.join(digest).join(name))
        }
        ["files", digest, name] if valid_archive_digest_hex(digest) => {
            Ok(snapshots_dir.join(digest).join(name))
        }
        ["images", kind, name] if is_supported_cache_file(kind, name) => {
            Ok(cache_dir.join(kind).join(name))
        }
        _ => Err(MicrosandboxError::Custom(format!(
            "invalid inventoried archive path: {archive_path}"
        ))),
    }
}

async fn materialize_inventory_layers(
    inventory: &ArchiveInventory,
    snapshots_dir: &Path,
) -> MicrosandboxResult<()> {
    let shared_layers = snapshots_dir.join(".archive-layers");
    for member in &inventory.members {
        let artifact_dir = snapshots_dir.join(&member.snapshot_id);
        let descriptor_bytes = tokio::fs::read(artifact_dir.join(DESCRIPTOR_FILENAME)).await?;
        let descriptor = microsandbox_image::snapshot::Manifest::from_bytes(&descriptor_bytes)
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
        let SnapshotState::File(file) = descriptor.state else {
            continue;
        };
        for layer in &file.layers {
            let relative = file.layer_path(layer);
            let source = shared_layers.join(
                relative
                    .file_name()
                    .expect("canonical layer path has a filename"),
            );
            let target = artifact_dir.join(&relative);
            if let Some(parent) = target.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let source_clone = source.clone();
            let target_clone = target.clone();
            tokio::task::spawn_blocking(move || {
                microsandbox_utils::copy::fast_copy(&source_clone, &target_clone)
            })
            .await
            .map_err(|error| {
                MicrosandboxError::Custom(format!("archive layer copy task: {error}"))
            })??;
        }
    }
    if shared_layers.exists() {
        tokio::fs::remove_dir_all(shared_layers).await?;
    }
    Ok(())
}

fn validate_inventory_snapshot_bindings(
    inventory: &ArchiveInventory,
    imported: &[Snapshot],
) -> MicrosandboxResult<()> {
    let snapshots: HashMap<&str, &Snapshot> = imported
        .iter()
        .map(|snapshot| (snapshot.id().as_str(), snapshot))
        .collect();
    if snapshots.len() != inventory.members.len() {
        return Err(MicrosandboxError::Custom(
            "archive snapshot set does not match its inventory".into(),
        ));
    }
    let mut checkpoint_entries = HashMap::new();
    for snapshot in &snapshots {
        if let SnapshotState::Checkpoint(state) = &snapshot.1.manifest().state {
            for member in checkpoint_archive_members(
                snapshot.0,
                &snapshot.1.path().join(CHECKPOINT_DIRECTORY),
                &state.checkpoint_root,
            )? {
                checkpoint_entries.insert(
                    member.archive_path,
                    (snapshot.0.to_string(), member.kind.to_string()),
                );
            }
        }
    }
    for member in &inventory.members {
        let Some(snapshot) = snapshots.get(member.snapshot_id.as_str()) else {
            return Err(MicrosandboxError::Custom(format!(
                "archive descriptor identity does not match {}",
                member.snapshot_id
            )));
        };
        if snapshot.digest() != member.descriptor_digest {
            return Err(MicrosandboxError::Custom(format!(
                "archive descriptor digest does not match {}",
                member.snapshot_id
            )));
        }
    }
    for entry in inventory.entries.iter().filter(|entry| entry.included) {
        match entry.kind.as_str() {
            "snapshot-descriptor" => {}
            "snapshot-metadata" => {
                let owner = entry.owner_snapshot.as_deref().ok_or_else(|| {
                    MicrosandboxError::Custom("snapshot metadata has no owner snapshot".into())
                })?;
                if !snapshots.contains_key(owner)
                    || entry.path
                        != format!("snapshots/{owner}/{}", super::metadata::METADATA_FILENAME)
                {
                    return Err(MicrosandboxError::Custom(format!(
                        "snapshot metadata binding is invalid: {}",
                        entry.path
                    )));
                }
            }
            "file-payload" => {
                let owner = entry.owner_snapshot.as_deref().ok_or_else(|| {
                    MicrosandboxError::Custom("file payload has no owner snapshot".into())
                })?;
                let snapshot = snapshots.get(owner).ok_or_else(|| {
                    MicrosandboxError::Custom(format!(
                        "file payload owner is not in archive: {owner}"
                    ))
                })?;
                let SnapshotState::File(file) = &snapshot.manifest().state else {
                    return Err(MicrosandboxError::Custom(format!(
                        "checkpoint snapshot has a file payload entry: {owner}"
                    )));
                };
                let mut matching_layer = None;
                for layer in &file.layers {
                    if portable_archive_path(&file.layer_path(layer))? == entry.path {
                        matching_layer = Some(layer);
                        break;
                    }
                }
                if matching_layer.is_none()
                    || matching_layer.and_then(|layer| layer.payload.integrity.as_ref())
                        != entry.integrity.as_ref()
                {
                    return Err(MicrosandboxError::Custom(format!(
                        "file payload binding disagrees with descriptor: {}",
                        entry.path
                    )));
                }
            }
            "checkpoint-root" | "checkpoint-object" | "checkpoint-disk-layer" => {
                let owner = entry.owner_snapshot.as_deref().ok_or_else(|| {
                    MicrosandboxError::Custom(
                        "checkpoint closure member has no owner snapshot".into(),
                    )
                })?;
                let Some((expected_owner, expected_kind)) = checkpoint_entries.get(&entry.path)
                else {
                    return Err(MicrosandboxError::Custom(format!(
                        "checkpoint closure member is not referenced: {}",
                        entry.path
                    )));
                };
                if owner != expected_owner || entry.kind != *expected_kind {
                    return Err(MicrosandboxError::Custom(format!(
                        "checkpoint closure member binding is invalid: {}",
                        entry.path
                    )));
                }
            }
            "image-metadata" | "image-object" => {
                if entry.owner_snapshot.is_some()
                    || !matches!(&entry.integrity, Some(UpperIntegrity::Sha256 { .. }))
                {
                    return Err(MicrosandboxError::Custom(format!(
                        "invalid image entry binding: {}",
                        entry.path
                    )));
                }
            }
            kind => {
                return Err(MicrosandboxError::unsupported(
                    Operation::SnapshotOps,
                    UnsupportedReason::NotAvailable(format!(
                        "snapshot archive entry kind {kind} is not supported"
                    )),
                ));
            }
        }
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> MicrosandboxResult<()> {
    digest_hex(value)
        .map(|_| ())
        .map_err(|_| MicrosandboxError::Custom(format!("{field} is not a lowercase sha256 digest")))
}

fn normal_utf8_components(path: &Path) -> MicrosandboxResult<Vec<&str>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or_else(|| {
                    MicrosandboxError::Custom(format!(
                        "archive contains non-utf8 path: {}",
                        path.display()
                    ))
                })?;
                components.push(part);
            }
            _ => {
                return Err(MicrosandboxError::Custom(format!(
                    "archive contains unsafe path: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(components)
}

/// Encode a logical archive path independently of the host path separator.
fn portable_archive_path(path: &Path) -> MicrosandboxResult<String> {
    let components = normal_utf8_components(path)?;
    if components.is_empty()
        || components
            .iter()
            .any(|component| component.is_empty() || component.contains(['/', '\\']))
    {
        return Err(MicrosandboxError::Custom(format!(
            "archive path is not portable: {}",
            path.display()
        )));
    }
    Ok(components.join("/"))
}

fn is_supported_cache_dir(kind: &str) -> bool {
    matches!(kind, "manifests" | "layers" | "fsmeta" | "vmdk")
}

fn is_supported_cache_file(kind: &str, file: &str) -> bool {
    match kind {
        "manifests" => file.ends_with(".json"),
        "layers" | "fsmeta" => file.ends_with(".erofs"),
        "vmdk" => file.ends_with(".vmdk"),
        _ => false,
    }
}

async fn verify_imported_snapshots(
    local: &LocalBackend,
    manifest_dirs: &[PathBuf],
) -> MicrosandboxResult<Vec<Snapshot>> {
    if manifest_dirs.is_empty() {
        return Err(MicrosandboxError::Custom(
            "archive contained no snapshot manifest".into(),
        ));
    }

    let mut seen = HashSet::new();
    let mut snapshots = Vec::new();
    for dir in manifest_dirs {
        if !seen.insert(dir.clone()) {
            continue;
        }
        snapshots.push(store::open_snapshot(local, dir.to_string_lossy().as_ref()).await?);
    }

    if snapshots.is_empty() {
        return Err(MicrosandboxError::Custom(
            "archive contained no snapshot manifest".into(),
        ));
    }
    Ok(snapshots)
}

fn select_head_snapshot(snapshots: &[Snapshot]) -> MicrosandboxResult<usize> {
    let imported_ids: HashSet<&str> = snapshots.iter().map(|snap| snap.id().as_str()).collect();
    let parent_ids: HashSet<&str> = snapshots
        .iter()
        .filter_map(|snap| {
            snap.manifest()
                .parent
                .as_ref()
                .map(|parent| parent.as_str())
        })
        .filter(|parent| imported_ids.contains(parent))
        .collect();

    let heads: Vec<usize> = snapshots
        .iter()
        .enumerate()
        .filter(|(_, snap)| !parent_ids.contains(snap.id().as_str()))
        .map(|(index, _)| index)
        .collect();
    match heads.as_slice() {
        [head] => Ok(*head),
        [] => Err(MicrosandboxError::Custom(
            "archive parent graph has no head".into(),
        )),
        _ => Err(MicrosandboxError::Custom(
            "archive parent graph has multiple heads".into(),
        )),
    }
}

async fn ensure_promote_targets_available(stage: &Path, dest: &Path) -> MicrosandboxResult<()> {
    let mut entries = tokio::fs::read_dir(stage).await?;
    while let Some(entry) = entries.next_entry().await? {
        let target = dest.join(entry.file_name());
        if tokio::fs::symlink_metadata(&target).await.is_ok() {
            return Err(MicrosandboxError::SnapshotAlreadyExists(
                target.display().to_string(),
            ));
        }
    }
    Ok(())
}

async fn promote_stage(stage: &Path, dest: &Path) -> MicrosandboxResult<()> {
    let mut entries = tokio::fs::read_dir(stage).await?;
    while let Some(entry) = entries.next_entry().await? {
        let target = dest.join(entry.file_name());
        tokio::fs::rename(entry.path(), target).await?;
    }
    Ok(())
}

async fn install_staged_cache(
    cache_stage: &Path,
    cache_dir: &Path,
    manifest: &microsandbox_image::snapshot::Manifest,
) -> MicrosandboxResult<()> {
    if !contains_files(cache_stage)? {
        return Ok(());
    }

    let image_ref: microsandbox_image::Reference =
        manifest.image.reference.parse().map_err(|e| {
            MicrosandboxError::Custom(format!("invalid snapshot image reference: {e}"))
        })?;
    let pinned_digest: microsandbox_image::Digest =
        manifest.image.manifest_digest.parse().map_err(|e| {
            MicrosandboxError::Custom(format!("invalid snapshot image digest: {e}"))
        })?;
    let staged_cache = microsandbox_image::GlobalCache::new_async(cache_stage).await?;
    let _real_cache = microsandbox_image::GlobalCache::new_async(cache_dir).await?;
    let metadata = staged_cache
        .read_image_metadata_async(&image_ref)
        .await?
        .ok_or_else(|| {
            MicrosandboxError::Custom(format!(
                "snapshot image cache metadata missing for {}",
                manifest.image.reference
            ))
        })?;
    validate_cached_metadata(manifest, &metadata)?;

    let expected_files =
        expected_cache_files(&staged_cache, &image_ref, &metadata, &pinned_digest)?;
    ensure_only_expected_cache_files(cache_stage, &expected_files)?;
    ensure_cache_targets_compatible(&expected_files, cache_stage, cache_dir).await?;

    let metadata_path = staged_cache.image_metadata_path(&image_ref);
    for source in expected_files.iter().filter(|path| **path != metadata_path) {
        install_cache_file(source, cache_stage, cache_dir).await?;
    }
    install_cache_file(&metadata_path, cache_stage, cache_dir).await?;

    Ok(())
}

fn validate_cached_metadata(
    manifest: &microsandbox_image::snapshot::Manifest,
    metadata: &microsandbox_image::CachedImageMetadata,
) -> MicrosandboxResult<()> {
    if metadata.manifest_digest != manifest.image.manifest_digest {
        return Err(MicrosandboxError::Custom(format!(
            "snapshot image metadata digest mismatch: snapshot={}, cache={}",
            manifest.image.manifest_digest, metadata.manifest_digest
        )));
    }
    // Registry metadata stores the selected platform manifest bytes, while `manifest_digest` can
    // legitimately identify the parent OCI index used to pin a multi-platform image. The equality
    // check above binds the cache entry to the snapshot; hashing these different objects against
    // one another rejects valid `--with-image` archives.
    verify_sha256_digest(
        metadata.raw_config_json.as_bytes(),
        &metadata.config_digest,
        "image config",
    )?;
    for layer in &metadata.layers {
        let _: microsandbox_image::Digest = layer
            .digest
            .parse()
            .map_err(|e| MicrosandboxError::Custom(format!("invalid cached layer digest: {e}")))?;
        let _: microsandbox_image::Digest = layer
            .diff_id
            .parse()
            .map_err(|e| MicrosandboxError::Custom(format!("invalid cached layer diff_id: {e}")))?;
    }
    Ok(())
}

fn verify_sha256_digest(bytes: &[u8], digest: &str, label: &str) -> MicrosandboxResult<()> {
    let Some(expected) = digest.strip_prefix("sha256:") else {
        return Err(MicrosandboxError::Custom(format!(
            "{label} digest must use sha256: {digest}"
        )));
    };
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual = hex::encode(hasher.finalize());
    if actual != expected {
        return Err(MicrosandboxError::Custom(format!(
            "{label} digest mismatch: expected sha256:{expected}, got sha256:{actual}"
        )));
    }
    Ok(())
}

fn expected_cache_files(
    cache: &microsandbox_image::GlobalCache,
    image_ref: &microsandbox_image::Reference,
    metadata: &microsandbox_image::CachedImageMetadata,
    manifest_digest: &microsandbox_image::Digest,
) -> MicrosandboxResult<HashSet<PathBuf>> {
    let mut expected = HashSet::new();
    let metadata_path = cache.image_metadata_path(image_ref);
    if !metadata_path.is_file() {
        return Err(MicrosandboxError::Custom(format!(
            "missing staged image metadata: {}",
            metadata_path.display()
        )));
    }
    expected.insert(metadata_path);

    let fsmeta = cache.fsmeta_erofs_path(manifest_digest);
    if !cache.is_fsmeta_materialized(manifest_digest) {
        return Err(MicrosandboxError::Custom(format!(
            "missing staged fsmeta artifact: {}",
            fsmeta.display()
        )));
    }
    expected.insert(fsmeta);

    let vmdk = cache.vmdk_path(manifest_digest);
    if !cache.is_vmdk_materialized(manifest_digest) {
        return Err(MicrosandboxError::Custom(format!(
            "missing staged VMDK artifact: {}",
            vmdk.display()
        )));
    }
    expected.insert(vmdk);

    for layer in &metadata.layers {
        let diff_id: microsandbox_image::Digest = layer
            .diff_id
            .parse()
            .map_err(|e| MicrosandboxError::Custom(format!("invalid cached layer diff_id: {e}")))?;
        let layer_path = cache.layer_erofs_path(&diff_id);
        if !cache.is_layer_materialized(&diff_id) {
            return Err(MicrosandboxError::Custom(format!(
                "missing staged layer artifact: {}",
                layer_path.display()
            )));
        }
        expected.insert(layer_path);
    }

    Ok(expected)
}

fn ensure_only_expected_cache_files(
    cache_stage: &Path,
    expected_files: &HashSet<PathBuf>,
) -> MicrosandboxResult<()> {
    let expected_relative = expected_files
        .iter()
        .map(|path| {
            path.strip_prefix(cache_stage)
                .map(Path::to_path_buf)
                .map_err(|_| {
                    MicrosandboxError::Custom(format!(
                        "staged cache path escaped stage: {}",
                        path.display()
                    ))
                })
        })
        .collect::<MicrosandboxResult<HashSet<_>>>()?;
    for file in collect_files(cache_stage)? {
        let relative = file
            .strip_prefix(cache_stage)
            .map(Path::to_path_buf)
            .map_err(|_| {
                MicrosandboxError::Custom(format!(
                    "staged cache path escaped stage: {}",
                    file.display()
                ))
            })?;
        if !expected_relative.contains(&relative) {
            return Err(MicrosandboxError::Custom(format!(
                "archive contains unexpected cache artifact: {}",
                relative.display()
            )));
        }
    }
    Ok(())
}

async fn ensure_cache_targets_compatible(
    sources: &HashSet<PathBuf>,
    cache_stage: &Path,
    cache_dir: &Path,
) -> MicrosandboxResult<()> {
    for source in sources {
        let target = cache_install_target(source, cache_stage, cache_dir)?;
        ensure_cache_target_compatible(source, &target).await?;
    }
    Ok(())
}

async fn install_cache_file(
    source: &Path,
    cache_stage: &Path,
    cache_dir: &Path,
) -> MicrosandboxResult<()> {
    let target = cache_install_target(source, cache_stage, cache_dir)?;
    if tokio::fs::symlink_metadata(&target).await.is_ok() {
        ensure_cache_target_compatible(source, &target).await?;
        return Ok(());
    }
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::rename(source, target).await?;
    Ok(())
}

fn cache_install_target(
    source: &Path,
    cache_stage: &Path,
    cache_dir: &Path,
) -> MicrosandboxResult<PathBuf> {
    let relative = source.strip_prefix(cache_stage).map_err(|_| {
        MicrosandboxError::Custom(format!(
            "staged cache path escaped stage: {}",
            source.display()
        ))
    })?;
    Ok(cache_dir.join(relative))
}

async fn ensure_cache_target_compatible(source: &Path, target: &Path) -> MicrosandboxResult<()> {
    let Ok(metadata) = tokio::fs::symlink_metadata(target).await else {
        return Ok(());
    };
    if !metadata.file_type().is_file() {
        return Err(MicrosandboxError::Custom(format!(
            "cache target is not a regular file: {}",
            target.display()
        )));
    }
    if metadata.len() != tokio::fs::metadata(source).await?.len()
        || file_sha256(target).await? != file_sha256(source).await?
    {
        return Err(MicrosandboxError::Custom(format!(
            "cache target already exists with different content: {}",
            target.display()
        )));
    }
    Ok(())
}

async fn file_sha256(path: &Path) -> MicrosandboxResult<[u8; 32]> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

fn contains_files(path: &Path) -> MicrosandboxResult<bool> {
    Ok(!collect_files(path)?.is_empty())
}

fn collect_files(path: &Path) -> MicrosandboxResult<Vec<PathBuf>> {
    let mut files = Vec::new();
    if !path.exists() {
        return Ok(files);
    }
    collect_files_inner(path, &mut files)?;
    Ok(files)
}

fn collect_files_inner(path: &Path, files: &mut Vec<PathBuf>) -> MicrosandboxResult<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_files_inner(&entry.path(), files)?;
        } else if file_type.is_file() {
            files.push(entry.path());
        } else {
            return Err(MicrosandboxError::Custom(format!(
                "unsupported staged cache file type: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

fn push_required_cache_file(
    cache_files: &mut Vec<(PathBuf, String)>,
    path: &Path,
    archive_dir: &str,
) -> MicrosandboxResult<()> {
    if !path.is_file() {
        return Err(MicrosandboxError::Custom(format!(
            "required image cache artifact missing: {}",
            path.display()
        )));
    }
    cache_files.push((
        path.to_path_buf(),
        format!("images/{archive_dir}/{}", file_name_str(path)?),
    ));
    Ok(())
}

fn digest_hex(digest: &str) -> MicrosandboxResult<&str> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(MicrosandboxError::Custom(format!(
            "snapshot identity is not sha256: {digest}"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MicrosandboxError::Custom(format!(
            "snapshot identity is malformed: {digest}"
        )));
    }
    Ok(hex)
}

async fn replace_archive(temp_out: &Path, out: &Path) -> MicrosandboxResult<()> {
    #[cfg(windows)]
    {
        let source = temp_out
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<_>>();
        let destination = out
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<_>>();

        // SAFETY: Both paths are live, NUL-terminated UTF-16 buffers for the
        // duration of the call. The temp file is created beside the target,
        // so replacement stays on one volume and remains atomic.
        let replaced = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if replaced == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }

    #[cfg(not(windows))]
    tokio::fs::rename(temp_out, out).await?;

    Ok(())
}

fn file_name_str(p: &Path) -> MicrosandboxResult<String> {
    p.file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            MicrosandboxError::Custom(format!("non-utf8 cache filename: {}", p.display()))
        })
}

async fn resolve_parent_artifact(
    local: &LocalBackend,
    parent_id: &str,
) -> MicrosandboxResult<PathBuf> {
    if let Some(handle) = store::lookup_by_digest(local, parent_id).await? {
        return Ok(handle.artifact_path);
    }
    Err(MicrosandboxError::SnapshotNotFound(format!(
        "parent {parent_id} not in local index; ship it alongside or re-save with --with-parents"
    )))
}

//--------------------------------------------------------------------------------------------------
// Functions: Fuzzing Support
//--------------------------------------------------------------------------------------------------

/// Entry point for the archive-walker fuzz target (`sdk/rust/fuzz`): run the full import unpack over arbitrary bytes into throwaway directories. Errors are the expected outcome
/// for malformed input; only panics, overflows, or hangs count as findings.
#[cfg(feature = "fuzzing")]
pub async fn fuzz_unpack_archive(data: &[u8]) {
    let Ok(snapshots) = tempfile::tempdir() else {
        return;
    };
    let Ok(cache) = tempfile::tempdir() else {
        return;
    };
    let _ = unpack_archive(data, snapshots.path(), cache.path()).await;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_image::checkpoint::{
        CaptureIntent, CheckpointManifest, ContentRef, DiskGenerationManifest, DiskLayerRef,
        LocalObjectStore, MemoryCaptureMode, MemoryExtent, MemoryExtentContent, MemoryManifest,
        sparse_file_integrity,
    };
    use microsandbox_image::snapshot::{
        CheckpointSnapshotState, DiskLayer, DiskLayerId, FileSnapshotState, ImageRef,
        LayerFileKind, LayerPayload, Manifest, SCHEMA, SnapshotCapture, SnapshotConsistency,
        SnapshotFormat, SnapshotId, SnapshotScope, SnapshotState,
    };

    use super::*;

    #[test]
    fn digest_hex_rejects_uppercase_identity() {
        let uppercase = format!("sha256:{}", "A".repeat(64));
        assert!(digest_hex(&uppercase).is_err());
    }

    #[test]
    fn cached_platform_manifest_accepts_parent_index_digest() {
        let index_digest = format!("sha256:{}", "a".repeat(64));
        let raw_config_json = "{}".to_string();
        let config_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(raw_config_json.as_bytes()))
        );
        let manifest = Manifest {
            schema: SCHEMA.into(),
            snapshot_id: SnapshotId::new("snap_00000000000000000000000000000001").unwrap(),
            scope: SnapshotScope::Disk,
            state: SnapshotState::File(FileSnapshotState {
                disk_format: SnapshotFormat::Raw,
                filesystem: "ext4".into(),
                virtual_size: 0,
                head: DiskLayerId::new("layer_00000000000000000000000000000001").unwrap(),
                layers: Vec::new(),
            }),
            capture: SnapshotCapture {
                created_at: "2026-09-02T00:00:00Z".into(),
                source_lineage: None,
                source_checkpoint: None,
                consistency: SnapshotConsistency::CrashConsistent,
            },
            image: ImageRef {
                reference: "docker.io/library/alpine:latest".into(),
                manifest_digest: index_digest.clone(),
            },
            parent: None,
            extensions: BTreeMap::new(),
            requires: Vec::new(),
        };
        let metadata = microsandbox_image::CachedImageMetadata {
            manifest_digest: index_digest,
            config_digest,
            raw_manifest_json: r#"{"schemaVersion":2,"layers":[]}"#.into(),
            raw_config_json,
            config: microsandbox_image::ImageConfig::default(),
            layers: Vec::new(),
        };

        validate_cached_metadata(&manifest, &metadata).unwrap();
    }

    #[test]
    fn released_archive_entry_without_transport_integrity_stays_canonical() {
        let released = br#"{"path":"files/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/upper.ext4","owner_snapshot":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"file-payload","included":true,"encoded_size":5,"apparent_size":5,"integrity":null}"#;

        let entry: ReleasedArchiveEntry = serde_json::from_slice(released).unwrap();
        assert_eq!(entry.transport_integrity, None);
        assert_eq!(serde_json::to_vec(&entry).unwrap(), released);
    }

    #[test]
    fn archive_paths_always_use_portable_separators() {
        let path = PathBuf::from("layers").join("layer_00000000000000000000000000000001.raw");

        assert_eq!(
            portable_archive_path(&path).unwrap(),
            "layers/layer_00000000000000000000000000000001.raw"
        );
    }

    #[tokio::test]
    async fn replace_archive_overwrites_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let temp_out = directory.path().join("bundle.tar.zst.tmp");
        let out = directory.path().join("bundle.tar.zst");
        std::fs::write(&temp_out, b"new archive").unwrap();
        std::fs::write(&out, b"old archive").unwrap();

        replace_archive(&temp_out, &out).await.unwrap();

        assert_eq!(std::fs::read(&out).unwrap(), b"new archive");
        assert!(!temp_out.exists());
    }

    #[tokio::test]
    async fn direct_archive_capture_and_child_restore_do_not_install_snapshot_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("home");
        let source = directory.path().join("upper.ext4");
        let archive = directory.path().join("snapshot.tar.zst");
        let child_stage = directory.path().join("child");
        let payload = b"direct archive payload";
        std::fs::write(&source, payload).unwrap();

        let snapshot_id = SnapshotId::new("snap_00000000000000000000000000000001").unwrap();
        let layer_id = DiskLayerId::new("layer_00000000000000000000000000000001").unwrap();
        let manifest = Manifest {
            schema: SCHEMA.into(),
            snapshot_id: snapshot_id.clone(),
            scope: SnapshotScope::Disk,
            state: SnapshotState::File(FileSnapshotState {
                disk_format: SnapshotFormat::Raw,
                filesystem: "ext4".into(),
                virtual_size: payload.len() as u64,
                head: layer_id.clone(),
                layers: vec![DiskLayer {
                    layer_id,
                    format: SnapshotFormat::Raw,
                    virtual_size: payload.len() as u64,
                    backing: None,
                    payload: LayerPayload {
                        file_kind: LayerFileKind::Regular,
                        integrity: None,
                    },
                }],
            }),
            capture: SnapshotCapture {
                created_at: "2026-08-29T00:00:00Z".into(),
                source_lineage: Some("test-box".into()),
                source_checkpoint: None,
                consistency: SnapshotConsistency::CrashConsistent,
            },
            image: ImageRef {
                reference: "docker.io/library/alpine:3.20".into(),
                manifest_digest:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000001".into(),
            },
            parent: None,
            extensions: BTreeMap::new(),
            requires: Vec::new(),
        };
        let local = LocalBackend::builder().home(&home).build().await.unwrap();

        save_direct_file_snapshot(
            &manifest,
            &BTreeMap::new(),
            "test-snapshot",
            &source,
            &archive,
            false,
            false,
        )
        .await
        .unwrap();
        let restored = materialize_archive_for_child(&local, &archive, &child_stage, false)
            .await
            .unwrap();

        assert_eq!(restored.manifest.snapshot_id, snapshot_id);
        assert_eq!(
            std::fs::read(child_stage.join("upper.ext4")).unwrap(),
            payload
        );
        assert!(!child_stage.join(snapshot_id.as_str()).exists());
        assert!(!home.join("snapshots").join(snapshot_id.as_str()).exists());
    }

    #[tokio::test]
    async fn checkpoint_archive_round_trips_without_an_installed_intermediate() {
        use std::io::{Seek, Write};

        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("home");
        let source = directory.path().join("checkpoint-source");
        let archive = directory.path().join("checkpoint.tar.zst");
        let child_stage = directory.path().join("child");
        let store = LocalObjectStore::open(&source).unwrap();
        let memory_bytes = b"checkpoint-memory";
        let memory_object = store.put_bytes(memory_bytes).unwrap();
        let memory = MemoryManifest {
            schema: "microsandbox.memory/1".into(),
            architecture: std::env::consts::ARCH.into(),
            guest_page_size: 4096,
            topology_generation: 1,
            generation: 1,
            capture_mode: MemoryCaptureMode::Full,
            pause_generation: 11,
            extents: vec![MemoryExtent {
                start: 0,
                length: memory_bytes.len() as u64,
                content: MemoryExtentContent::Object(ContentRef {
                    object: memory_object,
                    object_offset: 0,
                }),
            }],
        };
        let memory_id = store
            .put_bytes(&memory.to_canonical_bytes().unwrap())
            .unwrap();
        let execution_id = store.put_bytes(b"execution").unwrap();
        let layers = source.join("layers");
        std::fs::create_dir(&layers).unwrap();
        let layer_id = "layer_00000000000000000000000000000001";
        let source_layer = layers.join(format!("{layer_id}.qcow2"));
        let mut layer_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&source_layer)
            .unwrap();
        microsandbox_utils::extent::mark_sparse(&layer_file).unwrap();
        layer_file.set_len(4 * 1024 * 1024).unwrap();
        layer_file.write_all(b"QFI\xfbcheckpoint-head").unwrap();
        layer_file
            .seek(std::io::SeekFrom::Start(2 * 1024 * 1024))
            .unwrap();
        layer_file.write_all(b"allocated-data").unwrap();
        layer_file.sync_all().unwrap();
        microsandbox_utils::extent::punch_hole_aligned(&layer_file, 4096, 2 * 1024 * 1024 - 4096)
            .unwrap();
        microsandbox_utils::extent::punch_hole_aligned(
            &layer_file,
            2 * 1024 * 1024 + 4096,
            2 * 1024 * 1024 - 4096,
        )
        .unwrap();
        layer_file.sync_all().unwrap();
        drop(layer_file);

        // The canonical checkpoint qcow member is one byte too long for the
        // fixed GNU header path field. It therefore exercises dense long-name
        // fallback even though the source itself has a sparse extent map.
        let archive_layer_path =
            format!("checkpoints/snap_00000000000000000000000000000002/layers/{layer_id}.qcow2");
        assert_eq!(archive_layer_path.len(), 101);
        assert!(
            archive_encoded_size(&source_layer).await.unwrap() < 4 * 1024 * 1024,
            "test source must remain sparse so dense fallback changes the encoded size"
        );
        let layer_integrity = sparse_file_integrity(&source_layer).unwrap();
        let disk = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: "vol_test".into(),
            generation: 1,
            layers: vec![DiskLayerRef {
                layer_id: layer_id.into(),
                format: "qcow2".into(),
                virtual_size: 4 * 1024 * 1024,
                predecessor: None,
                integrity_root: layer_integrity.root,
            }],
            head: layer_id.into(),
            pause_generation: 11,
        };
        let disk_id = store
            .put_bytes(&disk.to_canonical_bytes().unwrap())
            .unwrap();
        let checkpoint = CheckpointManifest {
            schema: "microsandbox.checkpoint/1".into(),
            checkpoint_id: "checkpoint_archive".into(),
            capture_intent: CaptureIntent::FullSnapshot,
            architecture: std::env::consts::ARCH.into(),
            pause_generation: 11,
            execution_state: execution_id,
            memory: memory_id,
            disks: vec![disk_id],
            devices: Vec::new(),
            resources: Vec::new(),
            requires: Vec::new(),
        };
        let checkpoint_bytes = checkpoint.to_canonical_bytes().unwrap();
        let checkpoint_root = ObjectId::from_bytes(&checkpoint_bytes).unwrap();
        std::fs::write(source.join("checkpoint.json"), checkpoint_bytes).unwrap();
        let snapshot_id = SnapshotId::new("snap_00000000000000000000000000000002").unwrap();
        let manifest = Manifest {
            schema: SCHEMA.into(),
            snapshot_id: snapshot_id.clone(),
            scope: SnapshotScope::Full,
            state: SnapshotState::Checkpoint(CheckpointSnapshotState {
                checkpoint_id: checkpoint.checkpoint_id,
                checkpoint_root: checkpoint_root.to_string(),
                restore_intents: vec!["clone".into(), "resume".into()],
                requirements_summary: BTreeMap::from([
                    ("vcpus".into(), serde_json::Value::from(1)),
                    ("max_vcpus".into(), serde_json::Value::from(1)),
                    ("memory_mib".into(), serde_json::Value::from(128)),
                    ("max_memory_mib".into(), serde_json::Value::from(128)),
                ]),
            }),
            capture: SnapshotCapture {
                created_at: "2026-09-01T00:00:00Z".into(),
                source_lineage: Some("test-box".into()),
                source_checkpoint: Some("checkpoint_archive".into()),
                consistency: SnapshotConsistency::ApplicationConsistent,
            },
            image: ImageRef {
                reference: "docker.io/library/alpine:3.20".into(),
                manifest_digest:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000002".into(),
            },
            parent: None,
            extensions: BTreeMap::new(),
            requires: Vec::new(),
        };
        let local = LocalBackend::builder().home(&home).build().await.unwrap();

        save_direct_checkpoint_snapshot(
            &manifest,
            &BTreeMap::new(),
            "checkpoint-archive",
            &source,
            &archive,
            false,
            false,
        )
        .await
        .unwrap();
        std::fs::remove_dir_all(&source).unwrap();
        let restored = materialize_archive_for_child(&local, &archive, &child_stage, false)
            .await
            .unwrap();

        assert_eq!(restored.manifest.snapshot_id, snapshot_id);
        assert!(restored.checkpoint_restore.is_some());
        assert_eq!(restored.upper_layers.len(), 2);
        assert!(child_stage.join(".checkpoint-restore").exists());
        assert!(!child_stage.join(snapshot_id.as_str()).exists());
        assert!(!home.join("snapshots").join(snapshot_id.as_str()).exists());

        let disk_child_stage = directory.path().join("disk-child");
        let disk_restored =
            materialize_archive_for_child(&local, &archive, &disk_child_stage, true)
                .await
                .unwrap();
        assert!(disk_restored.checkpoint_restore.is_none());
        assert_eq!(disk_restored.upper_layers.len(), 2);
        assert!(!disk_child_stage.join(".checkpoint-restore").exists());

        let loaded = load_snapshot(&local, &archive, None).await.unwrap();
        assert_eq!(loaded.id(), snapshot_id.as_str());
        assert_eq!(loaded.state_kind(), "checkpoint");
        assert!(
            loaded
                .path()
                .join(CHECKPOINT_DIRECTORY)
                .join("checkpoint.json")
                .is_file()
        );

        let resaved = directory.path().join("checkpoint-resaved.tar.zst");
        save_snapshot(
            &local,
            loaded.path().to_string_lossy().as_ref(),
            &resaved,
            SaveOpts::default(),
        )
        .await
        .unwrap();
        let second_destination = directory.path().join("second-import");
        let reloaded = load_snapshot(&local, &resaved, Some(&second_destination))
            .await
            .unwrap();
        assert_eq!(reloaded.id(), snapshot_id.as_str());
        assert!(
            reloaded
                .path()
                .join(CHECKPOINT_DIRECTORY)
                .join("checkpoint.json")
                .is_file()
        );
    }
}
