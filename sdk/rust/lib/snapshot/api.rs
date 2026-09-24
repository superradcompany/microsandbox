//! Backend-neutral snapshot values, references, and lifecycle operations.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(feature = "local")]
use super::DiskLayer;
use super::{
    HeadUpdate, LoadOpts, Manifest, SaveOpts, SnapshotConfig, SnapshotCopyBuilder, SnapshotFormat,
    SnapshotId, SnapshotScope, SnapshotState, SnapshotVerifyReport,
};
use crate::MicrosandboxResult;
use crate::backend::Backend;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A backend-neutral disk or full execution snapshot.
///
/// Returned by [`Snapshot::create`] and [`Snapshot::open`]. The snapshot keeps
/// its originating backend internally, so follow-up operations do not require
/// backend-specific user code.
#[derive(Clone)]
pub struct Snapshot {
    pub(crate) backend: Arc<dyn Backend>,
    pub(crate) reference: SnapshotReference,
    pub(crate) digest: String,
    pub(crate) manifest: Manifest,
    pub(crate) reported_size_bytes: Option<u64>,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) head_update: Option<HeadUpdate>,
    #[cfg(feature = "local")]
    pub(crate) previous_upper: Option<PathBuf>,
}

/// A backend-neutral reference used to open, remove, or restore a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotReference {
    /// Compatibility input interpreted automatically by the active backend.
    Auto(String),
    /// Stable identifier resolved by the selected backend.
    Id(String),
    /// Path resolved in the selected backend's filesystem namespace.
    Path(String),
}

/// Builder for [`SnapshotConfig`].
///
/// Constructed via [`Snapshot::builder`]. The snapshot name is fixed at
/// construction; the source sandbox is set with
/// [`from_sandbox`](Self::from_sandbox) and is required.
pub struct SnapshotBuilder {
    guest_flush: super::GuestFlush,
    name: String,
    group: Option<String>,
    source_sandbox: Option<String>,
    dest_dir: Option<PathBuf>,
    labels: Vec<(String, String)>,
    force: bool,
    record_integrity: bool,
    full: bool,
}

/// Lightweight handle backed by a backend snapshot listing.
///
/// Returned by [`Snapshot::list`]. Use [`open`](SnapshotHandle::open)
/// to read the artifact metadata, and [`Snapshot::verify`] for explicit
/// local content verification.
#[derive(Clone)]
pub struct SnapshotHandle {
    pub(crate) backend: Arc<dyn Backend>,
    pub(crate) reference: SnapshotReference,
    pub(crate) local_path: Option<PathBuf>,
    pub(crate) snapshot_id: String,
    pub(crate) group: Option<String>,
    pub(crate) head_update: Option<HeadUpdate>,
    pub(crate) digest: String,
    pub(crate) name: Option<String>,
    pub(crate) parent_digest: Option<String>,
    pub(crate) scope: SnapshotScope,
    pub(crate) image_ref: String,
    pub(crate) state_kind: String,
    pub(crate) format: Option<SnapshotFormat>,
    pub(crate) fstype: Option<String>,
    pub(crate) checkpoint_manifest_digest: Option<String>,
    pub(crate) size_bytes: Option<u64>,
    pub(crate) locality: String,
    pub(crate) availability: String,
    pub(crate) migration_state: String,
    pub(crate) migration_error_code: Option<String>,
    pub(crate) created_at: chrono::NaiveDateTime,
}

/// Result of direct sandbox-to-archive capture.
///
/// No installed snapshot directory or index row is created.
#[derive(Debug, Clone)]
pub struct SnapshotArchive {
    path: PathBuf,
    digest: String,
    manifest: Manifest,
    labels: BTreeMap<String, String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Snapshot {
    /// Start configuring a snapshot named `name` using the active backend.
    ///
    /// The source sandbox is required:
    /// `Snapshot::builder("clean").from_sandbox("box").create()`.
    ///
    /// Without a destination, local snapshots use the default snapshot store
    /// and cloud snapshots use managed storage. A destination selects a local
    /// parent directory or a directory on the cloud host volume.
    pub fn builder(name: impl Into<String>) -> SnapshotBuilder {
        SnapshotBuilder {
            guest_flush: super::GuestFlush::Auto,
            name: name.into(),
            group: None,
            source_sandbox: None,
            dest_dir: None,
            labels: Vec::new(),
            force: false,
            record_integrity: false,
            full: false,
        }
    }

    /// Capture a snapshot using the active backend.
    ///
    /// Local capture preserves the source lifecycle and supports full execution state.
    ///
    /// Cloud creation waits for the asynchronous control-plane operation and
    /// returns the completed resource.
    pub async fn create(config: SnapshotConfig) -> MicrosandboxResult<Self> {
        let backend = crate::backend::default_backend();
        backend.snapshots().create(backend.clone(), config).await
    }

    /// Open an existing snapshot by a backend-relative string reference.
    ///
    /// Local values accept names or artifact paths. Cloud values accept
    /// managed ids/names or host-volume paths.
    pub async fn open(path_or_name: impl AsRef<str>) -> MicrosandboxResult<Self> {
        let reference = SnapshotReference::Auto(path_or_name.as_ref().to_string());
        Self::open_ref(reference).await
    }

    /// Open a snapshot through its backend-neutral reference.
    pub async fn open_ref(reference: impl Into<SnapshotReference>) -> MicrosandboxResult<Self> {
        let backend = crate::backend::default_backend();
        let reference = reference.into();
        backend.snapshots().open(backend.clone(), reference).await
    }

    /// Stable reference that can seed another sandbox on the same backend.
    pub fn reference(&self) -> SnapshotReference {
        self.reference.clone()
    }

    /// Digest of the source artifact descriptor (`sha256:hex`).
    ///
    /// Cloud artifacts retain their wire descriptor digest; hashing the normalized
    /// SDK manifest is not equivalent to hashing that source descriptor.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Canonical local descriptor or a normalized view of the cloud wire descriptor.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Backend-reported stored payload size in bytes.
    ///
    /// Locally this is the guest-visible root-disk capacity. Cloud host-volume
    /// snapshots report the upper-file size; managed snapshots report archive size.
    pub fn size_bytes(&self) -> Option<u64> {
        self.reported_size_bytes.or_else(|| {
            self.manifest
                .state
                .as_file()
                .map(|state| state.virtual_size)
        })
    }

    /// Local artifact directory for this snapshot.
    ///
    /// Cloud backends return [`crate::MicrosandboxError::Unsupported`] because
    /// managed and host-volume artifacts are not paths on the client host.
    /// Use [`Self::reference`] for backend-neutral restore and lifecycle calls.
    pub fn path(&self) -> MicrosandboxResult<&Path> {
        self.backend.snapshots().path(&self.reference)
    }

    /// Closed state variant carried by the descriptor.
    pub fn state(&self) -> &SnapshotState {
        &self.manifest.state
    }

    /// Get a handle by the active backend's public snapshot identifier.
    pub async fn get(name_or_digest: &str) -> MicrosandboxResult<SnapshotHandle> {
        let backend = crate::backend::default_backend();
        backend
            .snapshots()
            .get(backend.clone(), name_or_digest)
            .await
    }

    /// List snapshots visible through the active backend.
    pub async fn list() -> MicrosandboxResult<Vec<SnapshotHandle>> {
        let backend = crate::backend::default_backend();
        backend.snapshots().list(backend.clone()).await
    }

    /// Remove a snapshot by a backend-relative string reference.
    pub async fn remove(path_or_name: &str, force: bool) -> MicrosandboxResult<()> {
        let reference = SnapshotReference::Auto(path_or_name.to_string());
        Self::remove_ref(reference, force).await
    }

    /// Remove a snapshot through its backend-neutral reference.
    pub async fn remove_ref(
        reference: impl Into<SnapshotReference>,
        force: bool,
    ) -> MicrosandboxResult<()> {
        let backend = crate::backend::default_backend();
        let reference = reference.into();
        backend
            .snapshots()
            .remove(backend.clone(), reference, force)
            .await
    }
}

impl Snapshot {
    /// Verify this snapshot's recorded integrity.
    ///
    /// This artifact-file operation is currently local-only. Other backends
    /// return [`crate::MicrosandboxError::Unsupported`].
    pub async fn verify(&self) -> MicrosandboxResult<SnapshotVerifyReport> {
        self.backend.snapshots().verify(self).await
    }

    /// Configure a new archive containing this snapshot's disk data and
    /// replacement explicit-snapshot metadata.
    ///
    /// The source snapshot is unchanged. This artifact-file operation is
    /// currently local-only and supports disk state; export full state with `save_to`.
    /// Other backends return [`crate::MicrosandboxError::Unsupported`] from
    /// [`SnapshotCopyBuilder::save`].
    pub fn copy_to(&self, output_archive_path: impl Into<PathBuf>) -> SnapshotCopyBuilder {
        SnapshotCopyBuilder::new(self.clone(), output_archive_path.into())
    }

    /// Bundle this snapshot into a `.tar.zst` archive.
    ///
    /// The operation uses the backend retained when this snapshot was opened
    /// or created. This artifact-file operation is currently local-only; other
    /// backends return [`crate::MicrosandboxError::Unsupported`].
    pub async fn save_to(&self, out: &Path, opts: SaveOpts) -> MicrosandboxResult<()> {
        self.backend
            .snapshots()
            .save(self.reference(), out, opts)
            .await
    }

    /// Walk a local directory and parse each snapshot artifact.
    ///
    /// This artifact-file operation is currently local-only. Other backends
    /// return [`crate::MicrosandboxError::Unsupported`].
    pub async fn list_dir(dir: impl AsRef<Path>) -> MicrosandboxResult<Vec<Snapshot>> {
        let backend = crate::backend::default_backend();
        backend
            .snapshots()
            .list_dir(backend.clone(), dir.as_ref().to_path_buf())
            .await
    }

    /// Rebuild the local snapshot index from artifacts in `dir`.
    ///
    /// This maintenance operation is currently local-only. Other backends
    /// return [`crate::MicrosandboxError::Unsupported`].
    pub async fn reindex(dir: impl AsRef<Path>) -> MicrosandboxResult<usize> {
        let backend = crate::backend::default_backend();
        backend
            .snapshots()
            .reindex(Some(dir.as_ref().to_path_buf()))
            .await
    }

    /// Rebuild the active backend's default snapshot index.
    ///
    /// This is the no-directory form used by SDKs whose existing `reindex`
    /// method accepts an optional path. Unsupported backends return
    /// [`crate::MicrosandboxError::Unsupported`].
    #[doc(hidden)]
    pub async fn reindex_default() -> MicrosandboxResult<usize> {
        let backend = crate::backend::default_backend();
        backend.snapshots().reindex(None).await
    }

    /// Bundle a snapshot into a `.tar.zst` archive.
    ///
    /// This artifact-file operation is currently local-only. Other backends
    /// return [`crate::MicrosandboxError::Unsupported`].
    pub async fn save(name_or_path: &str, out: &Path, opts: SaveOpts) -> MicrosandboxResult<()> {
        let backend = crate::backend::default_backend();
        let reference = SnapshotReference::Auto(name_or_path.to_string());
        backend.snapshots().save(reference, out, opts).await
    }

    /// Unpack a snapshot archive into the active backend's snapshot store.
    ///
    /// This artifact-file operation is currently local-only. Other backends
    /// return [`crate::MicrosandboxError::Unsupported`].
    pub async fn load(
        archive_path: &Path,
        dest: Option<&Path>,
    ) -> MicrosandboxResult<SnapshotHandle> {
        let backend = crate::backend::default_backend();
        backend
            .snapshots()
            .load(backend.clone(), archive_path, dest)
            .await
    }
}

impl SnapshotReference {
    /// Build a compatibility reference interpreted automatically by the backend.
    pub fn auto(value: impl Into<String>) -> Self {
        Self::Auto(value.into())
    }

    /// Build a stable backend-resolved identifier reference.
    pub fn id(id: impl Into<String>) -> Self {
        Self::Id(id.into())
    }

    /// Build a path reference in the selected backend's filesystem namespace.
    pub fn path(path: impl Into<String>) -> Self {
        Self::Path(path.into())
    }

    /// Stable string value accepted by the matching backend's restore APIs.
    pub fn value(&self) -> &str {
        match self {
            Self::Auto(value) | Self::Id(value) | Self::Path(value) => value,
        }
    }

    /// Storage kind carried by this reference.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Auto(_) => "auto",
            Self::Id(_) => "id",
            Self::Path(_) => "path",
        }
    }
}

impl SnapshotHandle {
    /// Digest of the source artifact descriptor (`sha256:hex`).
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Name alias (None for digest-only entries).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Parent snapshot's portable identity, or `None` for a root.
    pub fn parent_digest(&self) -> Option<&str> {
        self.parent_digest.as_deref()
    }

    /// Snapshot payload scope.
    pub fn scope(&self) -> SnapshotScope {
        self.scope
    }

    /// Image reference the snapshot was taken from.
    pub fn image_ref(&self) -> &str {
        &self.image_ref
    }

    /// Stable file/checkpoint state discriminant.
    pub fn state_kind(&self) -> &str {
        &self.state_kind
    }

    /// On-disk format for file state.
    pub fn format(&self) -> Option<SnapshotFormat> {
        self.format
    }

    /// Filesystem type for file state.
    pub fn fstype(&self) -> Option<&str> {
        self.fstype.as_deref()
    }

    /// Checkpoint manifest digest for checkpoint state.
    pub fn checkpoint_manifest_digest(&self) -> Option<&str> {
        self.checkpoint_manifest_digest.as_deref()
    }

    /// Backend-reported stored payload size, when known.
    pub fn size_bytes(&self) -> Option<u64> {
        self.size_bytes
    }

    /// Whether payload state is embedded or provider-linked.
    pub fn locality(&self) -> &str {
        &self.locality
    }

    /// Current local availability projection.
    pub fn availability(&self) -> &str {
        &self.availability
    }

    /// Adjacent-release migration status for this indexed artifact.
    pub fn migration_state(&self) -> &str {
        &self.migration_state
    }

    /// Stable migration failure code when migration is blocked.
    pub fn migration_error_code(&self) -> Option<&str> {
        self.migration_error_code.as_deref()
    }

    /// Snapshot creation time (from manifest).
    pub fn created_at(&self) -> chrono::NaiveDateTime {
        self.created_at
    }

    /// Stable reference that can seed another sandbox on the same backend.
    pub fn reference(&self) -> SnapshotReference {
        self.reference.clone()
    }

    /// Local artifact directory for this snapshot handle.
    ///
    /// Cloud backends return [`crate::MicrosandboxError::Unsupported`] because
    /// managed and host-volume artifacts are not paths on the client host.
    /// Use [`Self::reference`] for backend-neutral restore and lifecycle calls.
    pub fn path(&self) -> MicrosandboxResult<&Path> {
        self.local_path
            .as_deref()
            .ok_or_else(|| crate::MicrosandboxError::local_only(crate::Operation::SnapshotOps))
    }

    /// Open the underlying artifact metadata.
    pub async fn open(&self) -> MicrosandboxResult<Snapshot> {
        self.backend
            .snapshots()
            .open(self.backend.clone(), self.reference())
            .await
    }

    /// Remove this snapshot. See [`Snapshot::remove`].
    pub async fn remove(&self, force: bool) -> MicrosandboxResult<()> {
        self.backend
            .snapshots()
            .remove(self.backend.clone(), self.reference(), force)
            .await
    }

    /// Bundle this snapshot into a `.tar.zst` archive.
    ///
    /// The operation uses the backend retained by this handle. This
    /// artifact-file operation is currently local-only; other backends return
    /// [`crate::MicrosandboxError::Unsupported`].
    pub async fn save_to(&self, out: &Path, opts: SaveOpts) -> MicrosandboxResult<()> {
        self.backend
            .snapshots()
            .save(self.reference(), out, opts)
            .await
    }
}

impl SnapshotBuilder {
    /// Set the source sandbox to snapshot. Required.
    pub fn from_sandbox(mut self, source_sandbox: impl Into<String>) -> Self {
        self.source_sandbox = Some(source_sandbox.into());
        self
    }

    /// Store under this parent directory instead of managed/default storage.
    ///
    /// Cloud destinations are relative to the organization's host volume.
    pub fn dest_dir(mut self, dest_dir: impl Into<PathBuf>) -> Self {
        self.dest_dir = Some(dest_dir.into());
        self
    }

    /// Add a user label.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push((key.into(), value.into()));
        self
    }

    /// Request replacement where the backend supports it.
    ///
    /// Local grouped captures are immutable and reject this option.
    pub fn force(mut self) -> Self {
        self.force = true;
        self
    }

    /// Record persistent file integrity while creating the snapshot.
    ///
    /// Integrity is disabled by default so ordinary local capture does not
    /// add a second full payload pass. Explicit verification reports
    /// `NotRecorded` for snapshots created without this option.
    pub fn record_integrity(mut self) -> Self {
        self.record_integrity = true;
        self
    }

    /// Capture full local VM execution state, including memory and devices.
    ///
    /// Backends without full capture support return `Unsupported`.
    pub fn full(mut self) -> Self {
        self.full = true;
        self
    }

    /// Select optional guest writeback before capture. Mandatory storage barriers remain.
    /// Auto requires flushing for live disk-only capture, but not full execution capture.
    pub fn guest_flush(mut self, policy: super::GuestFlush) -> Self {
        self.guest_flush = policy;
        self
    }

    /// Build the [`SnapshotConfig`].
    pub fn build(self) -> MicrosandboxResult<SnapshotConfig> {
        let source_sandbox = self.source_sandbox.ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(
                "snapshot builder requires a source sandbox; set from_sandbox before create".into(),
            )
        })?;
        Ok(SnapshotConfig {
            guest_flush: self.guest_flush,
            name: self.name,
            group: self.group,
            dest_dir: self.dest_dir,
            source_sandbox,
            labels: self.labels,
            force: self.force,
            record_integrity: self.record_integrity,
            full: self.full,
        })
    }

    /// Build and execute the snapshot in one step.
    pub async fn create(self) -> MicrosandboxResult<Snapshot> {
        Snapshot::create(self.build()?).await
    }
}

impl Snapshot {
    /// Stable portable identity, independent of the descriptor digest.
    ///
    /// Cloud legacy descriptors use the released legacy-import identity mapping;
    /// use `reference()` for the actual backend resource identifier.
    pub fn id(&self) -> &SnapshotId {
        &self.manifest.snapshot_id
    }
    /// Labels are local metadata and do not alter descriptor identity.
    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }
    /// Group publication outcome for a newly installed capture.
    pub fn head_update(&self) -> Option<&HeadUpdate> {
        self.head_update.as_ref()
    }
    /// Capture directly to an archive without installing an intermediate artifact.
    pub async fn create_archive(
        config: SnapshotConfig,
        out: impl AsRef<Path>,
        plain_tar: bool,
    ) -> MicrosandboxResult<SnapshotArchive> {
        let backend = crate::backend::default_backend();
        backend
            .snapshots()
            .create_archive(config, out.as_ref(), plain_tar)
            .await
    }
    /// Import an archive with an explicit dependency base.
    pub async fn load_with_base(
        path: &Path,
        dest: Option<&Path>,
        base: &str,
    ) -> MicrosandboxResult<SnapshotHandle> {
        Self::load_with_options(
            path,
            LoadOpts {
                dest: dest.map(Path::to_path_buf),
                base: Some(base.into()),
                ..Default::default()
            },
        )
        .await
    }
    /// Import into a local group with explicit dependency and head policy.
    pub async fn load_with_options(
        path: &Path,
        opts: LoadOpts,
    ) -> MicrosandboxResult<SnapshotHandle> {
        let mut handles = Self::load_many(&[path.to_path_buf()], opts).await?;
        Ok(handles.remove(0))
    }
    /// Validate all inputs before publication and return their heads in input order.
    pub async fn load_many(
        paths: &[PathBuf],
        opts: LoadOpts,
    ) -> MicrosandboxResult<Vec<SnapshotHandle>> {
        let backend = crate::backend::default_backend();
        backend
            .snapshots()
            .load_many(backend.clone(), paths, opts)
            .await
    }
    /// Read a group head, or explicitly select a qualified member.
    pub async fn group_head(selector: &str) -> MicrosandboxResult<HeadUpdate> {
        crate::backend::default_backend()
            .snapshots()
            .group_head(selector)
            .await
    }
    #[cfg(feature = "local")]
    /// Resolve a local physical layer, including the released flat-artifact binding.
    pub fn layer_path(&self, layer: &DiskLayer) -> MicrosandboxResult<PathBuf> {
        let path = self.path()?;
        let canonical = path.join(microsandbox_types::snapshot::layer_path(
            &layer.layer_id,
            layer.format,
        ));
        Ok(if canonical.exists() {
            canonical
        } else if let Some(path) = &self.previous_upper {
            path.clone()
        } else if self
            .manifest
            .state
            .as_file()
            .is_some_and(|file| file.layers.len() == 1)
            && path.join("upper.ext4").exists()
        {
            path.join("upper.ext4")
        } else {
            canonical
        })
    }
}

impl SnapshotHandle {
    /// Stable portable identity.
    pub fn id(&self) -> &str {
        &self.snapshot_id
    }
    /// Local group containing this installed copy.
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }
    /// Group publication outcome when imported.
    pub fn head_update(&self) -> Option<&HeadUpdate> {
        self.head_update.as_ref()
    }
}

impl SnapshotBuilder {
    /// Select the destination local snapshot group.
    pub fn group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }
    /// Capture directly to an archive.
    pub async fn create_archive(
        self,
        out: impl AsRef<Path>,
        plain_tar: bool,
    ) -> MicrosandboxResult<SnapshotArchive> {
        Snapshot::create_archive(self.build()?, out, plain_tar).await
    }
}

impl SnapshotArchive {
    /// Stable identity of the archived snapshot.
    pub fn id(&self) -> &SnapshotId {
        &self.manifest.snapshot_id
    }

    /// SHA-256 digest of the canonical descriptor.
    pub fn descriptor_digest(&self) -> &str {
        &self.digest
    }

    /// Published archive path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Parsed snapshot descriptor.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Labels stored alongside the archived descriptor.
    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }
}

impl SnapshotArchive {
    #[cfg(feature = "local")]
    pub(crate) fn from_parts(
        path: PathBuf,
        digest: String,
        manifest: Manifest,
        labels: BTreeMap<String, String>,
    ) -> Self {
        Self {
            path,
            digest,
            manifest,
            labels,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Snapshot")
            .field("reference", &self.reference)
            .field("digest", &self.digest)
            .field("manifest", &self.manifest)
            .finish()
    }
}

impl fmt::Debug for SnapshotHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotHandle")
            .field("reference", &self.reference)
            .field("digest", &self.digest)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl From<&Snapshot> for SnapshotReference {
    fn from(snapshot: &Snapshot) -> Self {
        snapshot.reference()
    }
}

impl From<&SnapshotHandle> for SnapshotReference {
    fn from(snapshot: &SnapshotHandle) -> Self {
        snapshot.reference()
    }
}
