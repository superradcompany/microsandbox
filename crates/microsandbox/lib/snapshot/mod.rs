//! Disk snapshot creation, inspection, and consumption.
//!
//! A snapshot is a self-describing, content-addressed directory on
//! disk. It captures a stopped sandbox's writable upper layer plus
//! the metadata needed to pin the immutable lower (image). The
//! artifact is the source of truth; the local DB index is just a
//! cache of "snapshots I happen to know about on this machine."
//!
//! See `planning/microsandbox/implementation/snapshots.md` for the
//! full design. Today snapshots are stopped-sandbox / raw-format only;
//! the manifest schema and DB columns are forward-compatible with
//! qcow2 backing chains landing later.

mod archive;
mod create;
mod store;
mod verify;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

use std::path::{Path, PathBuf};

use crate::MicrosandboxResult;

/// A snapshot artifact on disk.
///
/// Returned by [`Snapshot::create`] and [`Snapshot::open`]. The
/// directory at [`path()`](Snapshot::path) holds the canonical
/// `manifest.json` and the captured upper file.
#[derive(Debug, Clone)]
pub struct Snapshot {
    path: PathBuf,
    digest: String,
    manifest: Manifest,
}

/// Where to place a new snapshot artifact.
///
/// `Name` resolves under the configured `snapshots_dir` (default
/// `~/.microsandbox/snapshots/<name>`); `Path` writes to an explicit
/// directory anywhere the user has access.
#[derive(Debug, Clone)]
pub enum SnapshotDestination {
    /// Bare name resolved under the default snapshots directory.
    Name(String),
    /// Explicit absolute or relative path to the artifact directory.
    Path(PathBuf),
}

/// Inputs to [`Snapshot::create`].
#[derive(Debug, Clone)]
pub struct SnapshotConfig {
    /// Name of the source sandbox. Must be stopped.
    pub source_sandbox: String,
    /// Where to write the artifact.
    pub destination: SnapshotDestination,
    /// User-supplied labels (sorted in canonical form).
    pub labels: Vec<(String, String)>,
    /// Overwrite an existing artifact at the destination.
    pub force: bool,
    /// Compute and record upper-layer content integrity at creation time.
    ///
    /// Disabled by default so dense uppers do not make snapshot creation
    /// unexpectedly linear in file size.
    pub record_integrity: bool,
}

/// Builder for [`SnapshotConfig`].
pub struct SnapshotBuilder {
    source_sandbox: String,
    destination: Option<SnapshotDestination>,
    labels: Vec<(String, String)>,
    force: bool,
    record_integrity: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Snapshot {
    /// Start configuring a new snapshot of `source_sandbox`.
    pub fn builder(source_sandbox: impl Into<String>) -> SnapshotBuilder {
        SnapshotBuilder {
            source_sandbox: source_sandbox.into(),
            destination: None,
            labels: Vec::new(),
            force: false,
            record_integrity: false,
        }
    }

    /// Create a snapshot artifact from a stopped sandbox.
    ///
    /// Writes `manifest.json` and the captured `upper.ext4` into the
    /// destination directory atomically (manifest renamed last). On
    /// success, also upserts a row into the local `snapshot_index`
    /// cache; index failures are logged but do not fail the call —
    /// the artifact is the source of truth.
    pub async fn create(config: SnapshotConfig) -> MicrosandboxResult<Self> {
        create::create_snapshot(config).await
    }

    /// Open an existing snapshot artifact by path or bare name.
    ///
    /// Bare names (no path separator) resolve under the default
    /// snapshots directory; anything else is treated as a path.
    /// This is a fast metadata operation: it verifies the manifest
    /// structure, recomputes the manifest digest, and checks that the
    /// upper file exists with the recorded size. It does not read the
    /// full upper contents.
    pub async fn open(path_or_name: impl AsRef<str>) -> MicrosandboxResult<Self> {
        store::open_snapshot(path_or_name.as_ref()).await
    }

    /// Verify recorded content integrity for this snapshot, if present.
    pub async fn verify(&self) -> MicrosandboxResult<SnapshotVerifyReport> {
        verify::verify_snapshot(self).await
    }

    /// Path to the artifact directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Canonical content digest of this snapshot's manifest
    /// (`sha256:hex`). This is the snapshot's identity.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Parsed manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Apparent size of the captured upper layer in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.manifest.upper.size_bytes
    }

    /// Get a handle by digest, name, or path from the local index.
    pub async fn get(name_or_digest: &str) -> MicrosandboxResult<SnapshotHandle> {
        store::get_handle(name_or_digest).await
    }

    /// List indexed snapshots from the local DB cache.
    ///
    /// External-path snapshots booted by full path are not in the
    /// index and won't appear here; use [`list_dir`](Self::list_dir)
    /// to enumerate artifacts on disk directly.
    pub async fn list() -> MicrosandboxResult<Vec<SnapshotHandle>> {
        store::list_indexed().await
    }

    /// Walk a directory and parse each subdirectory's manifest. Does
    /// not touch the index. Skips entries that don't look like
    /// snapshot artifacts.
    pub async fn list_dir(dir: impl AsRef<Path>) -> MicrosandboxResult<Vec<Snapshot>> {
        store::list_dir(dir.as_ref()).await
    }

    /// Remove a snapshot artifact (by path or name) and its index row.
    ///
    /// Refuses if the snapshot has indexed children, unless `force`
    /// is set. The artifact directory is deleted on success.
    pub async fn remove(path_or_name: &str, force: bool) -> MicrosandboxResult<()> {
        store::remove_snapshot(path_or_name, force).await
    }

    /// Rebuild the local index from the artifacts in `dir`. Returns
    /// the number of artifacts indexed.
    pub async fn reindex(dir: impl AsRef<Path>) -> MicrosandboxResult<usize> {
        store::reindex_dir(dir.as_ref()).await
    }

    /// Bundle a snapshot into a `.tar.zst` archive.
    pub async fn export(
        name_or_path: &str,
        out: &Path,
        opts: archive::ExportOpts,
    ) -> MicrosandboxResult<()> {
        archive::export_snapshot(name_or_path, out, opts).await
    }

    /// Unpack a snapshot archive (`.tar.zst` or `.tar`) into the
    /// snapshots dir, registering anything found in the index.
    pub async fn import(
        archive_path: &Path,
        dest: Option<&Path>,
    ) -> MicrosandboxResult<SnapshotHandle> {
        archive::import_snapshot(archive_path, dest).await
    }
}

/// Lightweight handle backed by an index row.
///
/// Returned by [`Snapshot::list`]. Use [`open`](SnapshotHandle::open)
/// to read the artifact metadata, and [`Snapshot::verify`] for explicit
/// content verification.
#[derive(Debug, Clone)]
pub struct SnapshotHandle {
    pub(crate) digest: String,
    pub(crate) name: Option<String>,
    pub(crate) parent_digest: Option<String>,
    pub(crate) image_ref: String,
    pub(crate) format: SnapshotFormat,
    pub(crate) size_bytes: Option<u64>,
    pub(crate) created_at: chrono::NaiveDateTime,
    pub(crate) artifact_path: PathBuf,
}

impl SnapshotHandle {
    /// Manifest digest (`sha256:hex`) — canonical identity.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Name alias (None for digest-only entries).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Parent snapshot's digest, or `None` for a root.
    pub fn parent_digest(&self) -> Option<&str> {
        self.parent_digest.as_deref()
    }

    /// Image reference the snapshot was taken from.
    pub fn image_ref(&self) -> &str {
        &self.image_ref
    }

    /// On-disk format of the upper.
    pub fn format(&self) -> SnapshotFormat {
        self.format
    }

    /// Apparent size of the upper file at index time.
    pub fn size_bytes(&self) -> Option<u64> {
        self.size_bytes
    }

    /// Snapshot creation time (from manifest).
    pub fn created_at(&self) -> chrono::NaiveDateTime {
        self.created_at
    }

    /// Local artifact directory path.
    pub fn path(&self) -> &Path {
        &self.artifact_path
    }

    /// Open the underlying artifact metadata.
    pub async fn open(&self) -> MicrosandboxResult<Snapshot> {
        Snapshot::open(self.artifact_path.to_string_lossy().as_ref()).await
    }

    /// Remove this snapshot. See [`Snapshot::remove`].
    pub async fn remove(&self, force: bool) -> MicrosandboxResult<()> {
        Snapshot::remove(&self.digest, force).await
    }
}

impl SnapshotBuilder {
    /// Place the artifact at the given path or under the default
    /// snapshots directory by name.
    pub fn destination(mut self, dest: SnapshotDestination) -> Self {
        self.destination = Some(dest);
        self
    }

    /// Convenience: use a bare name resolved under the default
    /// snapshots directory.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.destination = Some(SnapshotDestination::Name(name.into()));
        self
    }

    /// Convenience: write the artifact to an explicit path.
    pub fn path(mut self, path: impl Into<PathBuf>) -> Self {
        self.destination = Some(SnapshotDestination::Path(path.into()));
        self
    }

    /// Add a user label.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push((key.into(), value.into()));
        self
    }

    /// Overwrite an existing artifact at the destination.
    pub fn force(mut self) -> Self {
        self.force = true;
        self
    }

    /// Compute and record upper-layer content integrity during creation.
    pub fn record_integrity(mut self) -> Self {
        self.record_integrity = true;
        self
    }

    /// Build the [`SnapshotConfig`].
    pub fn build(self) -> MicrosandboxResult<SnapshotConfig> {
        let destination = self.destination.ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(
                "snapshot builder requires a destination (.name() or .path())".into(),
            )
        })?;
        Ok(SnapshotConfig {
            source_sandbox: self.source_sandbox,
            destination,
            labels: self.labels,
            force: self.force,
            record_integrity: self.record_integrity,
        })
    }

    /// Build and execute the snapshot in one step.
    pub async fn create(self) -> MicrosandboxResult<Snapshot> {
        Snapshot::create(self.build()?).await
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use archive::ExportOpts;
pub use microsandbox_image::snapshot::{
    ImageRef, MANIFEST_FILENAME, Manifest, SnapshotFormat, UpperIntegrity, UpperLayer,
};
pub use verify::{SnapshotVerifyReport, UpperVerifyStatus};

//--------------------------------------------------------------------------------------------------
// Internal — used by submodules
//--------------------------------------------------------------------------------------------------

impl Snapshot {
    pub(crate) fn from_parts(path: PathBuf, digest: String, manifest: Manifest) -> Self {
        Self {
            path,
            digest,
            manifest,
        }
    }
}
