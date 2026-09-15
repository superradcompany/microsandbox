//! Clone an existing snapshot's upper layer into a new snapshot artifact.
//!
//! Unlike `--compact` on [`Snapshot::create`], this never mutates the source snapshot in place:
//! punching holes changes the raw bytes of the upper image (stale-but-freed garbage -> logical
//! zero), so if the source recorded Merkle integrity, an in-place compaction would change that
//! digest and, with it, the snapshot's own content digest -- breaking any child snapshot's
//! `parent_digest` reference. Writing to a new name sidesteps this entirely: it's a fresh
//! `snapshot.json` with its own digest from the start, so integrity (if the source had it) is
//! simply recomputed fresh, and the source snapshot and anything referencing it are untouched.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::Utc;
use microsandbox_image::snapshot::{
    DEFAULT_UPPER_FILE, DESCRIPTOR_FILENAME, FileSnapshotState, Manifest, SnapshotFormat,
    SnapshotScope, SnapshotState, UpperLayer,
};

use crate::backend::LocalBackend;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::create::{prepare_upper, resolve_destination};
use super::store::{index_upsert, open_snapshot};
use super::Snapshot;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for [`clone_snapshot`].
#[derive(Debug, Clone, Default)]
pub struct CloneOpts {
    /// Parent directory to create the new artifact in. `None` = the default snapshots directory.
    pub dest_dir: Option<PathBuf>,

    /// User-supplied labels for the new snapshot. Not inherited from the source.
    pub labels: Vec<(String, String)>,

    /// Overwrite an existing artifact at the destination.
    pub force: bool,

    /// Deallocate host storage for blocks the guest ext4 filesystem has already freed, while
    /// cloning. Opt-in: never changes guest-visible content, only host disk usage, and never
    /// fails the clone if compaction itself fails.
    pub compact: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn clone_snapshot(
    local: &LocalBackend,
    source: &str,
    new_name: &str,
    opts: CloneOpts,
) -> MicrosandboxResult<Snapshot> {
    let CloneOpts {
        dest_dir,
        labels,
        force,
        compact,
    } = opts;

    // Validate the destination before touching the source, same ordering
    // rationale as sandbox-sourced creation.
    let dest_dir = resolve_destination(local, new_name, dest_dir)?;
    if dest_dir.exists() && !force {
        return Err(MicrosandboxError::SnapshotAlreadyExists(
            dest_dir.display().to_string(),
        ));
    }

    let src = open_snapshot(local, source).await?;
    let unsupported = src.manifest().unsupported_requires();
    if !unsupported.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "snapshot '{source}' requires extensions this binary doesn't understand ({}); refusing to clone",
            unsupported.join(", ")
        )));
    }
    let src_state = src.manifest().state.as_file().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "snapshot '{source}' is not a file-state snapshot; only disk snapshots can be cloned"
        ))
    })?;
    if src_state.format != SnapshotFormat::Raw || src_state.fstype != "ext4" {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "snapshot '{source}' is not a raw ext4 snapshot; cloning only supports raw ext4 uppers"
        )));
    }
    let src_upper = src.path().join(&src_state.upper.file);
    let record_integrity = src_state.upper.integrity.is_some();

    // Same staged-then-promoted layout as sandbox-sourced creation.
    let parent_dir = dest_dir
        .parent()
        .ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!(
                "snapshot destination has no parent directory: {}",
                dest_dir.display()
            ))
        })?
        .to_path_buf();
    tokio::fs::create_dir_all(&parent_dir).await?;
    let staging_dir = parent_dir.join(format!(".{new_name}.staging"));
    if staging_dir.exists() {
        tokio::fs::remove_dir_all(&staging_dir).await?;
    }
    tokio::fs::create_dir_all(&staging_dir).await?;

    let built = build_cloned_artifact(&staging_dir, &src, &src_upper, labels, record_integrity, compact).await;
    let (digest, manifest) = match built {
        Ok(v) => v,
        Err(e) => {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(e);
        }
    };

    if dest_dir.exists() {
        tokio::fs::remove_dir_all(&dest_dir).await?;
    }
    if let Err(e) = tokio::fs::rename(&staging_dir, &dest_dir).await {
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        return Err(e.into());
    }

    if let Err(e) = index_upsert(local, &dest_dir, &digest, &manifest).await {
        tracing::warn!(error = %e, snapshot = %digest, "snapshot_index upsert failed");
    }

    Ok(Snapshot::from_parts(dest_dir, digest, manifest))
}

/// Build the cloned artifact contents into `dir`. Pure staging: the caller promotes or
/// discards the directory. Always recomputes integrity fresh when the source had it — a
/// brand-new `snapshot.json` from a fresh digest, so there's no stale-digest hazard the way
/// there would be compacting in place.
async fn build_cloned_artifact(
    dir: &std::path::Path,
    src: &Snapshot,
    src_upper: &std::path::Path,
    labels: Vec<(String, String)>,
    record_integrity: bool,
    compact: bool,
) -> MicrosandboxResult<(String, Manifest)> {
    let (_dst_upper, copied_len, integrity) =
        prepare_upper(dir, src_upper, record_integrity, compact).await?;

    let mut label_map: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in labels {
        label_map.insert(k, v);
    }

    let src_manifest = src.manifest();
    let manifest = Manifest {
        schema: src_manifest.schema,
        artifact: src_manifest.artifact.clone(),
        scope: SnapshotScope::Disk,
        created_at: Utc::now().to_rfc3339(),
        parent: Some(src.digest().to_string()),
        image: src_manifest.image.clone(),
        source_sandbox: src_manifest.source_sandbox.clone(),
        state: SnapshotState::File(FileSnapshotState {
            format: SnapshotFormat::Raw,
            fstype: "ext4".into(),
            upper: UpperLayer {
                file: DEFAULT_UPPER_FILE.into(),
                size_bytes: copied_len,
                integrity,
            },
        }),
        labels: label_map,
        extensions: BTreeMap::new(),
        requires: src_manifest.requires.clone(),
    };
    manifest.validate()?;
    let canonical = manifest
        .to_canonical_bytes()
        .map_err(|e| MicrosandboxError::Custom(format!("manifest serialize: {e}")))?;
    let digest = manifest
        .digest()
        .map_err(|e| MicrosandboxError::Custom(format!("manifest digest: {e}")))?;

    // Atomic descriptor write: stage as `.tmp`, fsync, rename.
    let manifest_path = dir.join(DESCRIPTOR_FILENAME);
    let tmp_path = dir.join(format!("{DESCRIPTOR_FILENAME}.tmp"));
    tokio::fs::write(&tmp_path, &canonical).await?;
    let tmp_path_for_sync = tmp_path.clone();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&tmp_path_for_sync)?;
        f.sync_all()?;
        Ok(())
    })
    .await
    .map_err(|e| MicrosandboxError::Custom(format!("snapshot fsync task: {e}")))??;
    tokio::fs::rename(&tmp_path, &manifest_path).await?;

    Ok((digest, manifest))
}
