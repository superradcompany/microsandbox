//! Snapshot export / import via `.tar.zst` bundles.
//!
//! Default archive format is zstd-compressed tar. Regular files with
//! holes — notably the sparse `upper.ext4`, whose logical size is the
//! configured upper cap rather than the data written — are stored as
//! old-GNU sparse entries (type `S`): only allocated extents are read
//! and archived, so export cost scales with the data a sandbox
//! actually wrote instead of the upper layer's logical size. Dense
//! files keep plain regular entries, and the image tar ingest module
//! already handles gzip/zstd detection on the read side. Plain `.tar`
//! archives are also accepted on import.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use async_compression::tokio::bufread::ZstdDecoder;
use async_compression::tokio::write::ZstdEncoder;
use microsandbox_image::snapshot::MANIFEST_FILENAME;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio_tar::{Archive, Builder, EntryType};

use crate::backend::LocalBackend;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Snapshot, SnapshotHandle, store};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for [`super::Snapshot::export`].
#[derive(Debug, Clone, Default)]
pub struct ExportOpts {
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
}

/// Allocation map of a sparse file, in tar-block granularity.
#[cfg(unix)]
struct SparseMap {
    /// Logical (apparent) file size.
    len: u64,
    /// Sum of segment lengths = the tar header `size` field.
    archived: u64,
    /// Sorted `(offset, length)` data segments, 512-aligned except the
    /// final one, which may end at an unaligned `len`.
    segments: Vec<(u64, u64)>,
}

#[cfg(unix)]
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
pub(super) async fn export_snapshot(
    local: &LocalBackend,
    name_or_path: &str,
    out: &Path,
    opts: ExportOpts,
) -> MicrosandboxResult<()> {
    // Collect the artifact dirs we need to ship: the head snapshot
    // and (optionally) all ancestors via parent_digest.
    let head = store::open_snapshot(local, name_or_path).await?;
    head.verify().await?;
    let head_prefix = digest_prefix(head.digest());
    let mut parent_dirs: Vec<(PathBuf, String)> = Vec::new();

    if opts.with_parents {
        let mut current = head.manifest().parent.clone();
        while let Some(parent_digest) = current {
            let parent_path = resolve_parent_artifact(local, &parent_digest).await?;
            let parent =
                store::open_snapshot(local, parent_path.to_string_lossy().as_ref()).await?;
            parent.verify().await?;
            let prefix = digest_prefix(parent.digest());
            parent_dirs.push((parent.path().to_path_buf(), prefix));
            current = parent.manifest().parent.clone();
        }
    }
    parent_dirs.reverse();

    let mut dirs: Vec<(PathBuf, String)> = parent_dirs;
    dirs.push((head.path().to_path_buf(), head_prefix));

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
    let out_file = tokio::fs::File::create(out).await?;
    if opts.plain_tar {
        let mut builder = Builder::new(out_file);
        write_archive_entries(&mut builder, &dirs, &cache_files).await?;
        let mut inner = builder.into_inner().await?;
        tokio::io::AsyncWriteExt::shutdown(&mut inner).await?;
    } else {
        let writer = ZstdEncoder::new(out_file);
        let mut builder = Builder::new(writer);
        write_archive_entries(&mut builder, &dirs, &cache_files).await?;
        let mut inner = builder.into_inner().await?;
        tokio::io::AsyncWriteExt::shutdown(&mut inner).await?;
    }

    Ok(())
}

/// Unpack an archive into `dest` (defaults to the configured snapshots
/// dir). Image-cache entries (`cache/...`) are routed into the global
/// cache. Returns a handle for the head (last-listed) snapshot.
pub(super) async fn import_snapshot(
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
        unpack_archive(decoder, snapshot_stage.path(), cache_stage.path()).await?
    } else {
        unpack_archive(buf, snapshot_stage.path(), cache_stage.path()).await?
    };

    let imported = verify_imported_snapshots(local, &unpacked.manifest_dirs).await?;
    let head_index = select_head_snapshot(&imported)?;
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

    let format = match snap.manifest().format {
        microsandbox_image::snapshot::SnapshotFormat::Raw => super::SnapshotFormat::Raw,
        microsandbox_image::snapshot::SnapshotFormat::Qcow2 => super::SnapshotFormat::Qcow2,
    };
    Ok(SnapshotHandle {
        digest: snap.digest().to_string(),
        name: snap
            .path()
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string()),
        parent_digest: snap.manifest().parent.clone(),
        image_ref: snap.manifest().image.reference.clone(),
        format,
        size_bytes: Some(snap.manifest().upper.size_bytes),
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
    dirs: &[(PathBuf, String)],
    cache_files: &[(PathBuf, String)],
) -> MicrosandboxResult<()>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    for (dir, prefix) in dirs {
        // Append manifest first so import can recognize the layout
        // even on a truncated read.
        let manifest_src = dir.join(MANIFEST_FILENAME);
        if manifest_src.exists() {
            builder
                .append_path_with_name(&manifest_src, format!("{prefix}/{MANIFEST_FILENAME}"))
                .await?;
        }
        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name
                .to_str()
                .ok_or_else(|| MicrosandboxError::Custom("non-utf8 artifact filename".into()))?;
            if name_str == MANIFEST_FILENAME {
                continue;
            }
            append_artifact_file(builder, &path, format!("{prefix}/{name_str}")).await?;
        }
    }
    for (path, archive_name) in cache_files {
        append_artifact_file(builder, path, archive_name.clone()).await?;
    }
    Ok(())
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
    #[cfg(unix)]
    if try_append_sparse(builder, path, &name).await? {
        return Ok(());
    }
    builder.append_path_with_name(path, name).await?;
    Ok(())
}

#[cfg(unix)]
const TAR_BLOCK: u64 = 512;

// Sparse-map slots inline in a GNU header / per extended sparse block.
#[cfg(unix)]
const GNU_HEADER_SPARSE_SLOTS: usize = 4;
#[cfg(unix)]
const GNU_EXT_SPARSE_SLOTS: usize = 21;

/// Append `path` as an old-GNU sparse entry if it has holes. Returns
/// `false` without writing anything when the file is better served by
/// the dense path (no holes, empty, no `SEEK_DATA` support, or a name
/// too long for the fixed GNU header path field).
#[cfg(unix)]
async fn try_append_sparse<W>(
    builder: &mut Builder<W>,
    path: &Path,
    name: &str,
) -> MicrosandboxResult<bool>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    use tokio_tar::{GnuExtSparseHeader, Header, HeaderMode};

    let meta = tokio::fs::metadata(path).await?;
    if !meta.is_file() {
        return Ok(false);
    }
    let map = {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || scan_sparse_map(&path))
            .await
            .map_err(|e| MicrosandboxError::Custom(format!("snapshot export scan task: {e}")))??
    };
    let Some(map) = map else {
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

/// Walk `path`'s allocation map with `SEEK_DATA`/`SEEK_HOLE` (same
/// idiom as `snapshot::verify`). `None` means "archive it dense".
#[cfg(unix)]
fn scan_sparse_map(path: &Path) -> std::io::Result<Option<SparseMap>> {
    use std::os::unix::io::AsRawFd;

    let file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    let fd = file.as_raw_fd();

    let mut segments: Vec<(u64, u64)> = Vec::new();
    let mut off: i64 = 0;
    while (off as u64) < len {
        let data_start = unsafe { libc::lseek(fd, off, libc::SEEK_DATA) };
        if data_start < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                // No more data past this offset: trailing hole.
                Some(libc::ENXIO) => break,
                // Filesystem doesn't implement the seek flags — treat
                // the file as dense rather than failing the export.
                // ENOTSUP and EOPNOTSUPP are distinct on macOS / BSDs.
                Some(libc::EINVAL) | Some(libc::ENOTSUP) => return Ok(None),
                #[cfg(not(target_os = "linux"))]
                Some(libc::EOPNOTSUPP) => return Ok(None),
                _ => return Err(err),
            }
        }
        let data_end = unsafe { libc::lseek(fd, data_start, libc::SEEK_HOLE) };
        if data_end < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let data_end = (data_end as u64).min(len);
        let data_start = data_start as u64;
        if data_end <= data_start {
            break;
        }

        // Round to tar blocks and merge segments that touch: sparse
        // readers require every data run before the last to be a
        // multiple of 512.
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

        off = data_end as i64;
    }

    // No holes: a regular entry is equivalent and stays readable by
    // older importers.
    if segments.as_slice() == [(0, len)] {
        return Ok(None);
    }

    let archived = segments.iter().map(|(_, sz)| sz).sum();
    Ok(Some(SparseMap {
        len,
        archived,
        segments,
    }))
}

/// Encode `value` into a 12-byte tar numeric field: zero-padded octal
/// with a NUL terminator when it fits (what GNU tar writes), otherwise
/// GNU base-256 (high bit set, big-endian binary).
#[cfg(unix)]
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

async fn unpack_archive<R>(
    reader: R,
    snapshots_dir: &Path,
    cache_dir: &Path,
) -> MicrosandboxResult<UnpackedArchive>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut archive = Archive::new(reader);
    let mut entries = archive.entries()?;
    let mut manifest_dirs: Vec<PathBuf> = Vec::new();

    while let Some(entry) = tokio_stream_next(&mut entries).await? {
        let mut entry = entry?;
        let path_in_archive = entry.path()?.into_owned();
        let entry_type = entry.header().entry_type();

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

        let is_cache_entry = path_in_archive.starts_with("cache");
        if is_cache_entry {
            validate_cache_archive_path(&path_in_archive, entry_type)?;
        } else {
            validate_snapshot_archive_path(&path_in_archive, entry_type)?;
        }

        let dest_root = if is_cache_entry {
            cache_dir.to_path_buf()
        } else {
            snapshots_dir.to_path_buf()
        };
        let target = if is_cache_entry {
            // Strip the leading "cache" component since it's already
            // implied by `cache_dir`.
            let stripped = path_in_archive
                .strip_prefix("cache")
                .map_err(|_| MicrosandboxError::Custom("malformed cache path".into()))?;
            dest_root.join(stripped)
        } else {
            dest_root.join(&path_in_archive)
        };

        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        entry.unpack(&target).await?;

        if path_in_archive
            .file_name()
            .and_then(|s| s.to_str())
            .map(|n| n == MANIFEST_FILENAME)
            .unwrap_or(false)
            && !is_cache_entry
            && let Some(parent) = target.parent()
        {
            manifest_dirs.push(parent.to_path_buf());
        }
    }

    Ok(UnpackedArchive { manifest_dirs })
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

fn validate_snapshot_archive_path(path: &Path, entry_type: EntryType) -> MicrosandboxResult<()> {
    let components = normal_utf8_components(path)?;
    let valid = match entry_type {
        EntryType::Directory => components.len() == 1,
        EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => components.len() == 2,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(MicrosandboxError::Custom(format!(
            "archive contains unsupported snapshot path: {}",
            path.display()
        )))
    }
}

fn validate_cache_archive_path(path: &Path, entry_type: EntryType) -> MicrosandboxResult<()> {
    let components = normal_utf8_components(path)?;
    let valid = match (entry_type, components.as_slice()) {
        (EntryType::Directory, ["cache"]) => true,
        (EntryType::Directory, ["cache", kind]) => is_supported_cache_dir(kind),
        (
            EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse,
            ["cache", kind, file],
        ) => is_supported_cache_file(kind, file),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(MicrosandboxError::Custom(format!(
            "archive contains unsupported cache path: {}",
            path.display()
        )))
    }
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

    snapshots
        .iter()
        .enumerate()
        .rev()
        .find(|(_, snap)| !parent_digests.contains(snap.digest()))
        .map(|(index, _)| index)
        .ok_or_else(|| MicrosandboxError::Custom("archive contained no head snapshot".into()))
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
        format!("cache/{archive_dir}/{}", file_name_str(path)?),
    ));
    Ok(())
}

async fn tokio_stream_next<S>(s: &mut S) -> MicrosandboxResult<Option<S::Item>>
where
    S: futures::stream::Stream + Unpin,
{
    use futures::stream::StreamExt;
    Ok(s.next().await)
}

fn digest_prefix(digest: &str) -> String {
    digest
        .strip_prefix("sha256:")
        .map(|h| format!("sha256-{}", &h[..h.len().min(16)]))
        .unwrap_or_else(|| digest.replace(':', "-").chars().take(20).collect())
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
        "parent {parent_digest} not in local index; ship it alongside or re-export with --with-parents"
    )))
}
