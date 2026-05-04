//! Snapshot export / import via `.tar.zst` bundles.
//!
//! Default archive format is zstd-compressed tar — sparse files
//! collapse cleanly under zstd, and `tar_ingest.rs` already handles
//! gzip/zstd detection on the read side. Plain `.tar` archives are
//! also accepted on import.

use std::path::{Path, PathBuf};

use async_compression::tokio::bufread::ZstdDecoder;
use async_compression::tokio::write::ZstdEncoder;
use microsandbox_image::snapshot::MANIFEST_FILENAME;
use tokio::io::BufReader;
use tokio_tar::{Archive, Builder};

use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Snapshot, SnapshotHandle, store};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for [`Snapshot::export`].
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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Bundle a snapshot artifact (and optionally its ancestors / image
/// cache) into an archive at `out`.
pub(super) async fn export_snapshot(
    name_or_path: &str,
    out: &Path,
    opts: ExportOpts,
) -> MicrosandboxResult<()> {
    // Collect the artifact dirs we need to ship: the head snapshot
    // and (optionally) all ancestors via parent_digest.
    let head = Snapshot::open(name_or_path).await?;
    head.verify().await?;
    let mut dirs: Vec<(PathBuf, String)> = Vec::new();
    let head_prefix = digest_prefix(head.digest());
    dirs.push((head.path().to_path_buf(), head_prefix));

    if opts.with_parents {
        let mut current = head.manifest().parent.clone();
        while let Some(parent_digest) = current {
            let parent_path = resolve_parent_artifact(&parent_digest).await?;
            let parent = Snapshot::open(parent_path.to_string_lossy().as_ref()).await?;
            parent.verify().await?;
            let prefix = digest_prefix(parent.digest());
            dirs.push((parent.path().to_path_buf(), prefix));
            current = parent.manifest().parent.clone();
        }
    }

    // Optional image cache bundling.
    let mut cache_files: Vec<(PathBuf, String)> = Vec::new();
    if opts.with_image {
        let cache_dir = crate::config::config().cache_dir();
        let img_digest_str = head.manifest().image.manifest_digest.clone();
        let img_digest: microsandbox_image::Digest = img_digest_str
            .parse()
            .map_err(|e| MicrosandboxError::Custom(format!("invalid image digest: {e}")))?;
        let cache = microsandbox_image::GlobalCache::new_async(&cache_dir).await?;

        let vmdk = cache.vmdk_path(&img_digest);
        if vmdk.exists() {
            cache_files.push((
                vmdk.clone(),
                format!("cache/vmdk/{}", file_name_str(&vmdk)?),
            ));
        }
        // Best-effort: walk fsmeta + layers dirs and ship anything
        // referenced by the VMDK descriptor. For now, ship all files
        // in the cache subdirs that match the image digest's
        // dependent layers.
        for entry in std::fs::read_dir(cache_dir.join("fsmeta"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let path = entry.path();
            cache_files.push((
                path.clone(),
                format!("cache/fsmeta/{}", file_name_str(&path)?),
            ));
        }
        for entry in std::fs::read_dir(cache_dir.join("layers"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let path = entry.path();
            cache_files.push((
                path.clone(),
                format!("cache/layers/{}", file_name_str(&path)?),
            ));
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
    archive: &Path,
    dest: Option<&Path>,
) -> MicrosandboxResult<SnapshotHandle> {
    let snapshots_dir = match dest {
        Some(d) => d.to_path_buf(),
        None => crate::config::config().snapshots_dir(),
    };
    tokio::fs::create_dir_all(&snapshots_dir).await?;
    let cache_dir = crate::config::config().cache_dir();

    // Detect compression from the magic bytes. `tar_ingest.rs:34-37`
    // does the same dance — keep our copy minimal here.
    let bytes = tokio::fs::read(archive).await?;
    let cursor = std::io::Cursor::new(bytes);
    let buf = BufReader::new(cursor);

    let head_dir = if archive
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_lowercase)
        .as_deref()
        == Some("zst")
        || archive
            .file_name()
            .and_then(|s| s.to_str())
            .map(|n| n.ends_with(".tar.zst"))
            .unwrap_or(false)
    {
        let decoder = ZstdDecoder::new(buf);
        unpack_archive(decoder, &snapshots_dir, &cache_dir).await?
    } else {
        unpack_archive(buf, &snapshots_dir, &cache_dir).await?
    };

    let head_path = head_dir.ok_or_else(|| {
        MicrosandboxError::Custom("archive contained no snapshot manifest".into())
    })?;
    let snap = Snapshot::open(head_path.to_string_lossy().as_ref()).await?;
    snap.verify().await?;

    // Index this and any sibling artifacts that landed in the dest dir.
    let _ = Snapshot::reindex(&snapshots_dir).await;

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
            builder
                .append_path_with_name(&path, format!("{prefix}/{name_str}"))
                .await?;
        }
    }
    for (path, archive_name) in cache_files {
        builder.append_path_with_name(path, archive_name).await?;
    }
    Ok(())
}

async fn unpack_archive<R>(
    reader: R,
    snapshots_dir: &Path,
    cache_dir: &Path,
) -> MicrosandboxResult<Option<PathBuf>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut archive = Archive::new(reader);
    let mut entries = archive.entries()?;
    let mut last_snapshot_dir: Option<PathBuf> = None;

    while let Some(entry) = tokio_stream_next(&mut entries).await? {
        let mut entry = entry?;
        let path_in_archive = entry.path()?.into_owned();

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

        let dest_root = if path_in_archive.starts_with("cache") {
            cache_dir.to_path_buf()
        } else {
            snapshots_dir.to_path_buf()
        };
        let target = if path_in_archive.starts_with("cache") {
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
            && !path_in_archive.starts_with("cache")
            && let Some(parent) = target.parent()
        {
            last_snapshot_dir = Some(parent.to_path_buf());
        }
    }

    Ok(last_snapshot_dir)
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

async fn resolve_parent_artifact(parent_digest: &str) -> MicrosandboxResult<PathBuf> {
    if let Some(handle) = store::lookup_by_digest(parent_digest).await? {
        return Ok(handle.artifact_path);
    }
    Err(MicrosandboxError::SnapshotNotFound(format!(
        "parent {parent_digest} not in local index; ship it alongside or re-export with --with-parents"
    )))
}
