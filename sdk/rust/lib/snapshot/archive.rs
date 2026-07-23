//! Snapshot save / load via `.tar.zst` bundles.
//!
//! Default archive format is zstd-compressed tar. Regular files with holes, notably the sparse `upper.ext4` whose logical size is the configured upper cap rather than the data
//! written, are stored as old-GNU sparse entries (type `S`): only allocated extents are read and archived, so save cost scales with the data a sandbox actually wrote instead of
//! the upper layer's logical size. Dense files keep plain regular entries. Plain `.tar` archives are also accepted on load.
//!
//! Load walks the tar records itself rather than going through `tokio_tar::Archive`: the entry grammar is closed (regular files, directories, and old-GNU sparse entries at fixed
//! depths, produced by our own save path), and owning the walk lets sparse entries be restored map-driven: data runs copied straight off the wire, holes never written and kept
//! unallocated per platform ([`extent::mark_sparse`] on NTFS, [`extent::punch_hole_aligned`] on APFS). `tokio_tar` remains the header codec and the dense-entry writer.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use async_compression::tokio::bufread::ZstdDecoder;
use async_compression::tokio::write::ZstdEncoder;
use microsandbox_image::snapshot::migration::V066_DESCRIPTOR_FILENAME;
use microsandbox_image::snapshot::{
    DESCRIPTOR_FILENAME, MAX_JSON_SAFE_INTEGER, SnapshotState, UpperIntegrity,
};
use microsandbox_utils::extent::{self, ExtentMap};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio_tar::{Builder, EntryType, Header};

use crate::backend::LocalBackend;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Snapshot, SnapshotHandle, store};

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
    schema: u32,
    artifact: String,
    head: String,
    suggested_name: Option<String>,
    completeness: String,
    with_parents: bool,
    with_image: bool,
    snapshots: Vec<ArchiveSnapshot>,
    entries: Vec<ArchiveEntry>,
    protection_requirements: Vec<serde_json::Value>,
    extensions: BTreeMap<String, serde_json::Value>,
    requires: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveSnapshot {
    snapshot_id: String,
    descriptor: String,
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
    integrity: UpperIntegrity,
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
    // Collect the artifact dirs we need to ship: the head snapshot
    // and (optionally) all ancestors via parent_digest.
    let head = store::open_snapshot(local, name_or_path).await?;
    head.verify().await?;
    let mut parents: Vec<Snapshot> = Vec::new();

    if opts.with_parents {
        let mut current = head.manifest().parent.clone();
        while let Some(parent_digest) = current {
            let parent_path = resolve_parent_artifact(local, &parent_digest).await?;
            let parent =
                store::open_snapshot(local, parent_path.to_string_lossy().as_ref()).await?;
            parent.verify().await?;
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
    let write_result: MicrosandboxResult<()> = async {
        if opts.plain_tar {
            let mut builder = Builder::new(out_file);
            write_archive_entries(&mut builder, &snapshots, &cache_files, &head, &opts).await?;
            let mut inner = builder.into_inner().await?;
            tokio::io::AsyncWriteExt::shutdown(&mut inner).await?;
        } else {
            let writer = ZstdEncoder::new(out_file);
            let mut builder = Builder::new(writer);
            write_archive_entries(&mut builder, &snapshots, &cache_files, &head, &opts).await?;
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
    let durable = tokio::fs::OpenOptions::new()
        .read(true)
        .open(&temp_out)
        .await?;
    durable.sync_all().await?;
    tokio::fs::rename(&temp_out, out).await?;
    #[cfg(unix)]
    if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::File::open(parent)?.sync_all()?;
    }

    Ok(())
}

/// Unpack an archive into `dest` (defaults to the configured snapshots
/// dir). Image-cache entries (`cache/...`) are routed into the global
/// cache. Returns a handle for the head (last-listed) snapshot.
pub(super) async fn load_snapshot(
    local: &LocalBackend,
    archive: &Path,
    dest: Option<&Path>,
) -> MicrosandboxResult<SnapshotHandle> {
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

    if unpacked.inventory.is_none() {
        super::migration::normalize_staged(local.db().await?, &unpacked.manifest_dirs).await?;
    }
    let imported = verify_imported_snapshots(local, &unpacked.manifest_dirs).await?;
    if let Some(inventory) = unpacked.inventory.as_ref() {
        validate_inventory_snapshot_bindings(inventory, &imported)?;
    }
    let head_index = match unpacked.head.as_deref() {
        Some(head) => imported
            .iter()
            .position(|snapshot| snapshot.digest() == head)
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

    ensure_promote_targets_available(snapshot_stage.path(), &snapshots_dir).await?;
    install_staged_cache(cache_stage.path(), &cache_dir, &head_manifest).await?;
    promote_stage(snapshot_stage.path(), &snapshots_dir).await?;

    let snap = store::open_snapshot(local, head_path.to_string_lossy().as_ref()).await?;

    // Index this and any sibling artifacts that landed in the dest dir.
    let _ = store::reindex_dir(local, &snapshots_dir).await;

    let (state_kind, format, fstype, checkpoint_manifest_digest, size_bytes) =
        match &snap.manifest().state {
            SnapshotState::File(state) => (
                "file".to_string(),
                Some(state.format),
                Some(state.fstype.clone()),
                None,
                Some(state.upper.size_bytes),
            ),
            SnapshotState::Checkpoint(state) => (
                "checkpoint".to_string(),
                None,
                None,
                Some(state.manifest.clone()),
                None,
            ),
        };
    Ok(SnapshotHandle {
        digest: snap.digest().to_string(),
        name: snap
            .path()
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string()),
        parent_digest: snap.manifest().parent.clone(),
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
        created_at: chrono::DateTime::parse_from_rfc3339(&snap.manifest().created_at)
            .map(|d| d.naive_utc())
            .unwrap_or_else(|_| chrono::Utc::now().naive_utc()),
        artifact_path: snap.path().to_path_buf(),
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
    let inventory = build_archive_inventory(snapshots, cache_files, head, opts).await?;
    let inventory_bytes = serde_json::to_vec(&inventory).map_err(|error| {
        MicrosandboxError::Custom(format!("serialize archive inventory: {error}"))
    })?;
    append_bytes(builder, "archive.json", &inventory_bytes).await?;

    // The inventory is also the write allowlist. Never sweep artifact
    // directories: migration backups, locks, journals and unknown files are
    // intentionally not exportable.
    for snapshot in snapshots {
        let hex = digest_hex(snapshot.digest())?;
        let descriptor = snapshot.path().join(DESCRIPTOR_FILENAME);
        append_artifact_file(
            builder,
            &descriptor,
            format!("snapshots/{hex}/{DESCRIPTOR_FILENAME}"),
        )
        .await?;
        if let SnapshotState::File(file) = &snapshot.manifest().state {
            append_artifact_file(
                builder,
                &snapshot.path().join(&file.upper.file),
                format!("files/{hex}/{}", file.upper.file),
            )
            .await?;
        }
    }
    for (path, archive_name) in cache_files {
        append_artifact_file(builder, path, archive_name.clone()).await?;
    }
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
    opts: &SaveOpts,
) -> MicrosandboxResult<ArchiveInventory> {
    let mut snapshot_members = Vec::with_capacity(snapshots.len());
    let mut entries = Vec::new();
    for snapshot in snapshots {
        let hex = digest_hex(snapshot.digest())?;
        let descriptor_path = format!("snapshots/{hex}/{DESCRIPTOR_FILENAME}");
        let descriptor_size = tokio::fs::metadata(snapshot.path().join(DESCRIPTOR_FILENAME))
            .await?
            .len();
        require_json_safe_size(descriptor_size, &descriptor_path)?;
        snapshot_members.push(ArchiveSnapshot {
            snapshot_id: snapshot.digest().to_string(),
            descriptor: descriptor_path.clone(),
        });
        entries.push(ArchiveEntry {
            path: descriptor_path,
            owner_snapshot: Some(snapshot.digest().to_string()),
            kind: "snapshot-descriptor".into(),
            included: true,
            encoded_size: descriptor_size,
            apparent_size: descriptor_size,
            integrity: UpperIntegrity {
                algorithm: "sha256".into(),
                digest: snapshot.digest().to_string(),
            },
        });

        if let SnapshotState::File(file) = &snapshot.manifest().state {
            let path = snapshot.path().join(&file.upper.file);
            let archive_path = format!("files/{hex}/{}", file.upper.file);
            let encoded_size = archive_encoded_size(&path).await?;
            require_json_safe_size(encoded_size, &archive_path)?;
            require_json_safe_size(file.upper.size_bytes, &archive_path)?;
            entries.push(ArchiveEntry {
                path: archive_path,
                owner_snapshot: Some(snapshot.digest().to_string()),
                kind: "file-payload".into(),
                included: true,
                encoded_size,
                apparent_size: file.upper.size_bytes,
                integrity: file.upper.integrity.clone(),
            });
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
            integrity: UpperIntegrity {
                algorithm: "sha256".into(),
                digest,
            },
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
    Ok(ArchiveInventory {
        schema: 1,
        artifact: "snapshot-archive".into(),
        head: head.digest().to_string(),
        suggested_name,
        completeness: "boot-complete".into(),
        with_parents: opts.with_parents,
        with_image: opts.with_image,
        snapshots: snapshot_members,
        entries,
        protection_requirements: Vec::new(),
        extensions: BTreeMap::new(),
        requires: Vec::new(),
    })
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
    name: String,
) -> MicrosandboxResult<()>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    if try_append_sparse(builder, path, &name).await? {
        return Ok(());
    }
    builder.append_path_with_name(path, name).await?;
    Ok(())
}

const TAR_BLOCK: u64 = 512;

// Sparse-map slots inline in a GNU header / per extended sparse block.
const GNU_HEADER_SPARSE_SLOTS: usize = 4;
const GNU_EXT_SPARSE_SLOTS: usize = 21;

/// Append `path` as an old-GNU sparse entry if it has holes. Returns `false` without writing anything when the file is better served by the dense path (no holes, empty, extents
/// not enumerable on this filesystem, or a name too long for the fixed GNU header path field).
async fn try_append_sparse<W>(
    builder: &mut Builder<W>,
    path: &Path,
    name: &str,
) -> MicrosandboxResult<bool>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    use tokio_tar::{GnuExtSparseHeader, HeaderMode};

    let meta = tokio::fs::metadata(path).await?;
    if !meta.is_file() {
        return Ok(false);
    }
    let map = {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || ExtentMap::scan(&path))
            .await
            .map_err(|e| MicrosandboxError::Custom(format!("snapshot export scan task: {e}")))??
    };
    let Some(map) = map.as_ref().and_then(tar_sparse_map) else {
        return Ok(false);
    };

    let mut header = Header::new_gnu();
    header.set_metadata_in_mode(&meta, HeaderMode::Complete);
    if header.set_path(name).is_err() {
        // Needs a GNU long-name entry; the dense path emits one.
        return Ok(false);
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
    for (offset, numbytes) in &map.segments {
        file.seek(std::io::SeekFrom::Start(*offset)).await?;
        let mut segment = (&mut file).take(*numbytes);
        let copied = tokio::io::copy(&mut segment, dst).await?;
        if copied != *numbytes {
            return Err(MicrosandboxError::Custom(format!(
                "upper file truncated during export: extent at {offset} expected {numbytes} bytes, read {copied}"
            )));
        }
        written += copied;
    }
    debug_assert_eq!(written, map.archived);

    let pad = (TAR_BLOCK - written % TAR_BLOCK) % TAR_BLOCK;
    if pad > 0 {
        dst.write_all(&[0u8; TAR_BLOCK as usize][..pad as usize])
            .await?;
    }
    Ok(true)
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
    let mut observed_files: HashMap<String, (u64, u64)> = HashMap::new();
    let mut extraction_targets = HashSet::new();
    let mut inventory_path = None;
    let mut block = [0u8; TAR_BLOCK as usize];

    loop {
        if !read_record(&mut reader, &mut block).await? {
            // Clean EOF without the two-zero-record terminator; accept,
            // matching the previous reader's tolerance.
            break;
        }
        if block.iter().all(|&b| b == 0) {
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
        let path_in_archive = header.path()?.into_owned();

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
            ["snapshots", hex, name]
                if valid_archive_digest_hex(hex) && *name == DESCRIPTOR_FILENAME =>
            {
                (snapshots_dir.join(hex).join(name), true, false)
            }
            ["files", hex, name]
                if valid_archive_digest_hex(hex) && valid_archive_filename(name) =>
            {
                (snapshots_dir.join(hex).join(name), false, false)
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

        let archive_path = path_in_archive.to_string_lossy().into_owned();
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
        match entry_type {
            EntryType::Directory => unreachable!("directories were handled above"),
            EntryType::GNUSparse => {
                unpack_sparse_entry(&mut reader, &header, entry_size, &target).await?;
                apply_entry_mode(&header, &target).await?;
            }
            // Regular / Continuous — the only other types validation lets through.
            _ => {
                unpack_dense_entry(&mut reader, entry_size, &target).await?;
                apply_entry_mode(&header, &target).await?;
            }
        }
        let apparent_size = tokio::fs::metadata(&target).await?.len();
        observed_files.insert(archive_path, (entry_size, apparent_size));

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
        Some(inventory)
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
async fn unpack_dense_entry<R>(reader: &mut R, size: u64, target: &Path) -> MicrosandboxResult<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::File::create(target).await?;
    let copied = tokio::io::copy(&mut (&mut *reader).take(size), &mut file).await?;
    if copied != size {
        return Err(MicrosandboxError::Custom(
            "archive truncated mid-entry".into(),
        ));
    }
    file.flush().await?;
    discard_exact(reader, tar_pad(size)).await
}

/// Restore an old-GNU sparse entry map-driven: parse the sparse map (inline slots plus chained extended records), enforce its invariants, then copy each data run straight off the
/// wire to its logical offset. Hole bytes are never in the stream and never written; [`extent::mark_sparse`] / [`extent::punch_hole_aligned`] keep them unallocated on filesystems
/// that need telling.
async fn unpack_sparse_entry<R>(
    reader: &mut R,
    header: &Header,
    archived: u64,
    target: &Path,
) -> MicrosandboxResult<()>
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

    for (offset, numbytes) in &map {
        if *numbytes == 0 {
            continue;
        }
        file.seek(std::io::SeekFrom::Start(*offset)).await?;
        let copied = tokio::io::copy(&mut (&mut *reader).take(*numbytes), &mut file).await?;
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

    Ok(())
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
        ["snapshots" | "files" | "images" | "cache"] => true,
        ["snapshots" | "files", hex] => valid_archive_digest_hex(hex),
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
        && value != "files"
        && value != "images"
        && value != "cache"
}

fn valid_archive_filename(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && value != "." && value != ".."
}

async fn validate_archive_inventory(
    path: &Path,
    observed: &HashMap<String, (u64, u64)>,
    snapshots_dir: &Path,
    cache_dir: &Path,
) -> MicrosandboxResult<ArchiveInventory> {
    const MAX_INVENTORY_BYTES: u64 = 4 * 1024 * 1024;
    let metadata = tokio::fs::metadata(path).await?;
    if metadata.len() > MAX_INVENTORY_BYTES {
        return Err(MicrosandboxError::Custom(
            "archive inventory exceeds the size limit".into(),
        ));
    }
    let bytes = tokio::fs::read(path).await?;
    let inventory: ArchiveInventory = serde_json::from_slice(&bytes).map_err(|error| {
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
    if inventory.schema != 1 || inventory.artifact != "snapshot-archive" {
        return Err(MicrosandboxError::Custom(
            "unsupported archive inventory schema or artifact".into(),
        ));
    }
    if inventory.completeness != "boot-complete" {
        return Err(MicrosandboxError::Unsupported {
            feature: format!("snapshot archive completeness {}", inventory.completeness),
            available_when: "metadata-only archive bindings are implemented".into(),
        });
    }
    if !inventory.requires.is_empty() {
        return Err(MicrosandboxError::Unsupported {
            feature: format!("snapshot archive requirements {:?}", inventory.requires),
            available_when: "all required archive extensions are supported".into(),
        });
    }
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
    for snapshot in &inventory.snapshots {
        validate_sha256(&snapshot.snapshot_id, "archive snapshot_id")?;
        if prior_snapshot.is_some_and(|prior: &String| prior >= &snapshot.snapshot_id) {
            return Err(MicrosandboxError::Custom(
                "archive snapshots are not strictly sorted".into(),
            ));
        }
        let hex = digest_hex(&snapshot.snapshot_id)?;
        let expected = format!("snapshots/{hex}/{DESCRIPTOR_FILENAME}");
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
        let Some((encoded, apparent)) = observed.get(&entry.path) else {
            return Err(MicrosandboxError::Custom(format!(
                "inventoried entry is missing: {}",
                entry.path
            )));
        };
        if *encoded != entry.encoded_size || *apparent != entry.apparent_size {
            return Err(MicrosandboxError::Custom(format!(
                "archive entry size mismatch: {}",
                entry.path
            )));
        }
        if entry.integrity.algorithm == "sha256" {
            let target = inventory_entry_target(&entry.path, snapshots_dir, cache_dir)?;
            let actual = format!("sha256:{}", hex::encode(file_sha256(&target).await?));
            if actual != entry.integrity.digest {
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
            if entry.integrity.algorithm != "sha256" || entry.integrity.digest != owner {
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
    Ok(inventory)
}

fn inventory_entry_target(
    archive_path: &str,
    snapshots_dir: &Path,
    cache_dir: &Path,
) -> MicrosandboxResult<PathBuf> {
    let path = Path::new(archive_path);
    let components = normal_utf8_components(path)?;
    match components.as_slice() {
        ["snapshots", hex, name] if valid_archive_digest_hex(hex) => {
            Ok(snapshots_dir.join(hex).join(name))
        }
        ["files", hex, name] if valid_archive_digest_hex(hex) => {
            Ok(snapshots_dir.join(hex).join(name))
        }
        ["images", kind, name] if is_supported_cache_file(kind, name) => {
            Ok(cache_dir.join(kind).join(name))
        }
        _ => Err(MicrosandboxError::Custom(format!(
            "invalid inventoried archive path: {archive_path}"
        ))),
    }
}

fn validate_inventory_snapshot_bindings(
    inventory: &ArchiveInventory,
    imported: &[Snapshot],
) -> MicrosandboxResult<()> {
    let snapshots: HashMap<&str, &Snapshot> = imported
        .iter()
        .map(|snapshot| (snapshot.digest(), snapshot))
        .collect();
    if snapshots.len() != inventory.snapshots.len() {
        return Err(MicrosandboxError::Custom(
            "archive snapshot set does not match its inventory".into(),
        ));
    }
    for member in &inventory.snapshots {
        if !snapshots.contains_key(member.snapshot_id.as_str()) {
            return Err(MicrosandboxError::Custom(format!(
                "archive descriptor digest does not match {}",
                member.snapshot_id
            )));
        }
    }
    for entry in inventory.entries.iter().filter(|entry| entry.included) {
        match entry.kind.as_str() {
            "snapshot-descriptor" => {}
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
                let expected_path = format!("files/{}/{}", digest_hex(owner)?, file.upper.file);
                if entry.path != expected_path || entry.integrity != file.upper.integrity {
                    return Err(MicrosandboxError::Custom(format!(
                        "file payload binding disagrees with descriptor: {}",
                        entry.path
                    )));
                }
            }
            "image-metadata" | "image-object" => {
                if entry.owner_snapshot.is_some() || entry.integrity.algorithm != "sha256" {
                    return Err(MicrosandboxError::Custom(format!(
                        "invalid image entry binding: {}",
                        entry.path
                    )));
                }
            }
            kind => {
                return Err(MicrosandboxError::Unsupported {
                    feature: format!("snapshot archive entry kind {kind}"),
                    available_when: "the archive entry provider is implemented".into(),
                });
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
        let snap = store::open_snapshot(local, dir.to_string_lossy().as_ref()).await?;
        snap.verify().await?;
        snapshots.push(snap);
    }

    if snapshots.is_empty() {
        return Err(MicrosandboxError::Custom(
            "archive contained no snapshot manifest".into(),
        ));
    }
    Ok(snapshots)
}

fn select_head_snapshot(snapshots: &[Snapshot]) -> MicrosandboxResult<usize> {
    let imported_digests: HashSet<&str> = snapshots.iter().map(|snap| snap.digest()).collect();
    let parent_digests: HashSet<&str> = snapshots
        .iter()
        .filter_map(|snap| snap.manifest().parent.as_deref())
        .filter(|parent| imported_digests.contains(parent))
        .collect();

    let heads: Vec<usize> = snapshots
        .iter()
        .enumerate()
        .filter(|(_, snap)| !parent_digests.contains(snap.digest()))
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
    verify_sha256_digest(
        metadata.raw_manifest_json.as_bytes(),
        &metadata.manifest_digest,
        "raw manifest",
    )?;
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
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MicrosandboxError::Custom(format!(
            "snapshot identity is malformed: {digest}"
        )));
    }
    Ok(hex)
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
    parent_digest: &str,
) -> MicrosandboxResult<PathBuf> {
    if let Some(handle) = store::lookup_by_digest(local, parent_digest).await? {
        return Ok(handle.artifact_path);
    }
    Err(MicrosandboxError::SnapshotNotFound(format!(
        "parent {parent_digest} not in local index; ship it alongside or re-save with --with-parents"
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
