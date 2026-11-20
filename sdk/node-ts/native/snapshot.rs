use std::collections::HashMap;
use std::path::PathBuf;

use microsandbox::snapshot::{
    HeadUpdateReason, LoadOpts as RustLoadOpts, SaveOpts as RustSaveOpts,
};
use microsandbox::{
    Checkpoint as RustSnapshot, SnapshotArchive as RustSnapshotArchive,
    SnapshotFormat as RustSnapshotFormat, SnapshotScope as RustSnapshotScope,
    UpperIntegrity as RustUpperIntegrity, UpperVerifyStatus as RustUpperVerifyStatus,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;
use crate::snapshot_copy_builder::JsSnapshotCopyBuilder;
use crate::storage::{StorageItemUsageJs, item_to_js};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A backend-neutral snapshot artifact.
#[napi(js_name = "Snapshot")]
pub struct JsSnapshot {
    inner: RustSnapshot,
}

/// Result of direct sandbox-to-archive capture.
#[napi(js_name = "SnapshotArchive")]
pub struct JsSnapshotArchive {
    inner: RustSnapshotArchive,
}

/// One loaded descriptor observation used to project state without repeated backend lookups.
#[napi(js_name = "SnapshotMetadata")]
pub struct JsSnapshotMetadata {
    inner: microsandbox::snapshot::Manifest,
}

/// Options for `Snapshot.save()` and instance `saveTo()` methods.
#[derive(Default)]
#[napi(object, js_name = "SaveOpts")]
pub struct JsSaveOpts {
    /// Explicit archive reader target: current or 0.7.8.
    pub compatibility: Option<String>,
    /// Walk the parent chain and include each ancestor in the archive.
    pub with_parents: Option<bool>,
    /// Bundle the OCI image cache for offline transport.
    pub with_image: Option<bool>,
    /// Skip zstd compression and write a plain `.tar`.
    pub plain_tar: Option<bool>,
    /// Base snapshot or standalone archive supplying reusable disk layers and RAM objects.
    pub since: Option<String>,
    /// Newest N immutable disk layers to include.
    pub last_layers: Option<f64>,
}

/// Options for importing one or more archives into a snapshot group.
#[derive(Default)]
#[napi(object, js_name = "LoadOpts")]
pub struct JsLoadOpts {
    /// Parent directory containing snapshot groups.
    pub dest: Option<String>,
    /// External snapshot or standalone archive for dependencies absent from the batch/group.
    pub base: Option<String>,
    /// Destination group (generated when omitted).
    pub group: Option<String>,
    /// Select the unique imported tip even when it is not a fast-forward.
    pub set_head: Option<bool>,
    /// Maximum logical bytes imported.
    pub maximum_disk_bytes: Option<f64>,
}

/// Outcome of reading or selecting a snapshot group's head.
#[napi(object)]
pub struct HeadUpdate {
    pub group: String,
    pub previous: Option<String>,
    pub head: Option<String>,
    pub reason: String,
    pub changed: bool,
}

/// Result of `Snapshot.verify()`.
///
/// `upperKind` is `"notRecorded"` when integrity is absent or `"verified"`
/// when the recorded value matched. The other fields carry that binding.
#[napi(object, js_name = "SnapshotVerifyReport")]
pub struct JsSnapshotVerifyReport {
    pub digest: String,
    pub path: String,
    pub upper_kind: String,
    pub upper_algorithm: Option<String>,
    pub upper_digest: Option<String>,
    /// Verified composite-checkpoint root, when the artifact is full.
    pub checkpoint_root: Option<String>,
    /// Coverage of every required payload, independent of the head-only upper projection.
    pub coverage_kind: String,
    pub unrecorded: Vec<String>,
}

/// Options for `Snapshot.remove()` (instance and static).
#[derive(Default)]
#[napi(object, js_name = "SnapshotRemoveOptions")]
pub struct JsSnapshotRemoveOpts {
    pub force: Option<bool>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsSnapshot {
    /// Advertise support before an older provider can ignore the requested limit.
    #[napi]
    pub fn supports_import_budget() -> bool {
        true
    }

    /// Consume destination options; the receiver always selects the source and backend.
    ///
    /// # Safety
    /// The destination builder is consumed before suspension and must not be reused.
    #[napi]
    pub async unsafe fn spawn_sandbox_with_builder(
        &self,
        builder: &mut crate::restore_builder::JsRestoreBuilder,
    ) -> Result<crate::sandbox::Sandbox> {
        let options = builder.take_inner()?;
        Ok(crate::sandbox::Sandbox::from_rust(
            self.inner
                .spawn_sandbox_with(|_| options)
                .await
                .map_err(to_napi_error)?,
        ))
    }

    /// Consume destination options and return progress for the receiver-selected source.
    ///
    /// # Safety
    /// The destination builder is consumed before suspension and must not be reused.
    #[napi]
    pub async unsafe fn spawn_sandbox_with_progress_builder(
        &self,
        builder: &mut crate::restore_builder::JsRestoreBuilder,
    ) -> Result<crate::sandbox_builder::JsPullProgressCreate> {
        let options = builder.take_inner()?;
        let (progress, task) = self
            .inner
            .spawn_sandbox_with_progress_with(|_| options)
            .await
            .map_err(to_napi_error)?;
        Ok(crate::sandbox_builder::JsPullProgressCreate {
            stream: crate::pull_progress::JsPullProgressStream::from_creation(progress),
            abort: task.abort_handle(),
            task: std::sync::Arc::new(tokio::sync::Mutex::new(Some(task))),
        })
    }

    /// Return the retained destination without selecting a new one.
    #[napi]
    pub fn context(&self) -> Result<crate::context::JsContext> {
        Ok(crate::context::JsContext {
            inner: self.inner.context().clone_shared(),
        })
    }

    //----------------------------------------------------------------------------------------------
    // Static management
    //----------------------------------------------------------------------------------------------

    #[napi]
    pub async fn open(path_or_name: String) -> Result<JsSnapshot> {
        let snap = RustSnapshot::open(&path_or_name)
            .await
            .map_err(to_napi_error)?;
        Ok(JsSnapshot::from_rust(snap))
    }

    #[napi]
    pub async fn get(name_or_digest: String) -> Result<JsSnapshot> {
        let h = RustSnapshot::get(&name_or_digest)
            .await
            .map_err(to_napi_error)?;
        Ok(JsSnapshot::from_rust(h))
    }

    #[napi]
    pub async fn list() -> Result<Vec<JsSnapshot>> {
        let handles = RustSnapshot::list().await.map_err(to_napi_error)?;
        Ok(handles.into_iter().map(JsSnapshot::from_rust).collect())
    }

    #[napi(js_name = "remove")]
    pub async fn remove_static(
        path_or_name: String,
        opts: Option<JsSnapshotRemoveOpts>,
    ) -> Result<()> {
        let force = opts.and_then(|o| o.force).unwrap_or(false);
        RustSnapshot::remove_by_reference(&path_or_name, force)
            .await
            .map_err(to_napi_error)
    }

    #[napi(ts_return_type = "Promise<Snapshot>")]
    pub fn load<'env>(
        env: &'env Env,
        archive: String,
        dest: Option<String>,
        base: Option<String>,
    ) -> Result<PromiseRaw<'env, JsSnapshot>> {
        let prepared = microsandbox::snapshot::PreparedSnapshotImport::new(
            vec![archive.into()],
            RustLoadOpts {
                dest: dest.map(Into::into),
                base,
                ..Default::default()
            },
        );
        env.spawn_future(async move {
            Ok(JsSnapshot::from_rust(
                prepared
                    .map_err(to_napi_error)?
                    .legacy_checkpoint()
                    .await
                    .map_err(to_napi_error)?,
            ))
        })
    }

    #[napi(js_name = "loadWithOptions", ts_return_type = "Promise<Snapshot>")]
    pub fn load_with_options<'env>(
        env: &'env Env,
        archive: String,
        opts: Option<JsLoadOpts>,
    ) -> Result<PromiseRaw<'env, JsSnapshot>> {
        let opts = opts.unwrap_or_default();
        let prepared = microsandbox::snapshot::PreparedSnapshotImport::new(
            vec![archive.into()],
            RustLoadOpts {
                dest: opts.dest.map(Into::into),
                base: opts.base,
                group: opts.group,
                set_head: opts.set_head.unwrap_or(false),
                maximum_disk_bytes: opts
                    .maximum_disk_bytes
                    .map(|value| crate::numeric::safe_integer(value, "maximumDiskBytes"))
                    .transpose()?,
            },
        );
        env.spawn_future(async move {
            Ok(JsSnapshot::from_rust(
                prepared
                    .map_err(to_napi_error)?
                    .checkpoint()
                    .await
                    .map_err(to_napi_error)?,
            ))
        })
    }

    /// Import archives together, retaining their call-time path interpretation.
    #[napi(js_name = "loadMany", ts_return_type = "Promise<Snapshot[]>")]
    pub fn load_many<'env>(
        env: &'env Env,
        archives: Vec<String>,
        opts: Option<JsLoadOpts>,
    ) -> Result<PromiseRaw<'env, Vec<JsSnapshot>>> {
        let opts = opts.unwrap_or_default();
        let prepared = microsandbox::snapshot::PreparedSnapshotImport::new(
            archives.into_iter().map(Into::into).collect(),
            RustLoadOpts {
                dest: opts.dest.map(Into::into),
                base: opts.base,
                group: opts.group,
                set_head: opts.set_head.unwrap_or(false),
                maximum_disk_bytes: opts
                    .maximum_disk_bytes
                    .map(|value| crate::numeric::safe_integer(value, "maximumDiskBytes"))
                    .transpose()?,
            },
        );
        env.spawn_future(async move {
            Ok(prepared
                .map_err(to_napi_error)?
                .checkpoints()
                .await
                .map_err(to_napi_error)?
                .into_iter()
                .map(JsSnapshot::from_rust)
                .collect())
        })
    }

    /// Preserve the legacy selector while the read-only collection method stays separate.
    #[napi(js_name = "groupHead")]
    pub async fn select_group_head(selector: String) -> Result<HeadUpdate> {
        let context = microsandbox::configured_context();
        let update = context
            .snapshot_ops()
            .group_head_selector(&selector)
            .await
            .map_err(to_napi_error)?;
        Ok(head_update_to_js(&update))
    }

    #[napi(js_name = "readGroupHead")]
    pub async fn read_group_head(group: String) -> Result<Option<String>> {
        RustSnapshot::group_head(&group)
            .await
            .map(|head| head.map(|id| id.to_string()))
            .map_err(to_napi_error)
    }

    #[napi(js_name = "setGroupHead")]
    pub async fn set_group_head(group: String, id: String) -> Result<HeadUpdate> {
        let id = parse_snapshot_id(id)?;
        let update = RustSnapshot::set_group_head(&group, &id)
            .await
            .map_err(to_napi_error)?;
        Ok(head_update_to_js(&update))
    }

    /// Deprecated: use `reference`. Throws when no local filesystem path exists.
    #[napi(getter)]
    pub fn path(&self) -> Result<String> {
        self.inner
            .path()
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(to_napi_error)
    }

    #[napi(getter)]
    pub fn reference(&self) -> String {
        self.inner.reference().value().to_owned()
    }

    #[napi(getter, ts_return_type = "'id' | 'path'")]
    pub fn reference_kind(&self) -> &'static str {
        self.inner.reference().kind()
    }

    #[napi(getter)]
    pub fn head_update(&self) -> Option<HeadUpdate> {
        self.inner.head_update().map(head_update_to_js)
    }
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    #[napi(getter)]
    pub fn digest(&self) -> String {
        self.inner.digest().to_string()
    }

    #[napi(getter)]
    pub fn size_bytes(&self) -> Option<BigInt> {
        self.inner.size_bytes().map(BigInt::from)
    }

    #[napi(getter)]
    pub fn image_ref(&self) -> String {
        self.inner.image_ref().to_string()
    }

    #[napi(getter)]
    pub fn state_kind(&self) -> String {
        self.inner.state_kind().as_str().into()
    }

    #[napi(getter)]
    pub fn format(&self) -> Option<String> {
        self.inner.format().map(|format| format_str(format).into())
    }

    #[napi(getter)]
    pub fn fstype(&self) -> Option<String> {
        self.inner.fstype().map(str::to_string)
    }

    #[napi(getter)]
    pub fn checkpoint_manifest_digest(&self) -> Option<String> {
        self.inner.checkpoint_manifest_digest().map(str::to_string)
    }
    #[napi(getter)]
    pub fn parent(&self) -> Option<String> {
        self.inner.parent_digest().map(str::to_owned)
    }

    #[napi(getter, ts_return_type = "'disk' | 'full'")]
    pub fn scope(&self) -> String {
        format_scope(self.inner.scope()).into()
    }
    #[napi(getter)]
    pub fn created_at(&self) -> String {
        self.inner.created_at().and_utc().to_rfc3339()
    }

    #[napi(getter)]
    pub fn group(&self) -> Option<String> {
        self.inner.group().map(str::to_string)
    }

    #[napi(getter)]
    pub fn name(&self) -> Option<String> {
        self.inner.name().map(|s| s.to_string())
    }

    #[napi(getter)]
    pub fn parent_digest(&self) -> Option<String> {
        self.inner.parent_digest().map(|s| s.to_string())
    }

    #[napi(getter)]
    pub fn locality(&self) -> String {
        self.inner.locality().into()
    }

    #[napi(getter)]
    pub fn availability(&self) -> String {
        self.inner.availability().into()
    }

    #[napi(getter)]
    pub fn migration_state(&self) -> String {
        self.inner.migration_state().into()
    }

    #[napi(getter)]
    pub fn migration_error_code(&self) -> Option<String> {
        self.inner.migration_error_code().map(str::to_string)
    }
    /// Full normalized descriptor document; the wire descriptor digest remains `digest`.
    #[napi]
    pub async fn manifest(&self) -> Result<String> {
        let manifest = self.inner.manifest().await.map_err(to_napi_error)?;
        serde_json::to_string(&manifest).map_err(|error| Error::from_reason(error.to_string()))
    }

    /// A fresh descriptor observation. It is safe to retain this value as a snapshot of metadata.
    #[napi]
    pub async fn metadata(&self) -> Result<JsSnapshotMetadata> {
        let inner = self.inner.manifest().await.map_err(to_napi_error)?;
        Ok(JsSnapshotMetadata { inner })
    }

    #[napi]
    pub async fn labels(&self) -> Result<HashMap<String, String>> {
        Ok(self
            .inner
            .labels()
            .await
            .map_err(to_napi_error)?
            .into_iter()
            .collect())
    }

    #[napi]
    pub async fn destroy(&self, opts: Option<JsSnapshotRemoveOpts>) -> Result<()> {
        let force = opts.and_then(|o| o.force).unwrap_or(false);
        self.inner.destroy(force).await.map_err(to_napi_error)
    }
}

#[napi]
impl JsSnapshot {
    /// Walk `dir` and parse each snapshot artifact within it.
    #[napi(js_name = "listDir")]
    pub async fn list_dir(dir: String) -> Result<Vec<JsSnapshot>> {
        let snapshots = RustSnapshot::list_dir(PathBuf::from(dir))
            .await
            .map_err(to_napi_error)?;
        Ok(snapshots.into_iter().map(JsSnapshot::from_rust).collect())
    }

    /// Rebuild the backend snapshot index from artifacts in `dir`.
    #[napi]
    pub async fn reindex(dir: Option<String>) -> Result<u32> {
        let n = match dir {
            Some(path) => RustSnapshot::reindex(PathBuf::from(path)).await,
            None => RustSnapshot::reindex_default().await,
        };
        let n = n.map_err(to_napi_error)?;
        Ok(n as u32)
    }

    /// Bundle a snapshot into a `.tar.zst` archive.
    #[napi]
    pub async fn save(name_or_path: String, out: String, opts: Option<JsSaveOpts>) -> Result<()> {
        RustSnapshot::save_by_reference(
            &name_or_path,
            &PathBuf::from(out),
            save_opts_to_rust(opts)?,
        )
        .await
        .map_err(to_napi_error)
    }

    /// Bundle this snapshot into a `.tar.zst` archive.
    #[napi(js_name = "saveTo")]
    pub async fn save_to(&self, out: String, opts: Option<JsSaveOpts>) -> Result<()> {
        let snapshot = self.inner.clone();
        snapshot
            .save_to(&PathBuf::from(out), save_opts_to_rust(opts)?)
            .await
            .map_err(to_napi_error)
    }

    /// Configure a new archive containing this snapshot's disk data and
    /// replacement labels and integrity metadata.
    /// Returns an unsupported-operation error when artifact archives are unavailable.
    #[napi(js_name = "copyTo")]
    pub fn copy_to(&self, output_archive_path: String) -> JsSnapshotCopyBuilder {
        JsSnapshotCopyBuilder::from_rust(self.inner.copy_to(output_archive_path))
    }

    /// Remove this exact retained checkpoint and serialize its operation-owned result.
    #[napi(js_name = "removeCheckpoint")]
    pub async fn remove_checkpoint(&self, force: bool) -> Result<String> {
        let checkpoint = self.inner.clone();
        let result = checkpoint
            .remove_with(|options| if force { options.force() } else { options })
            .await
            .map_err(to_napi_error)?;
        serde_json::to_string(&result).map_err(|error| napi::Error::from_reason(error.to_string()))
    }

    /// Verify this snapshot's recorded payload integrity.
    #[napi]
    pub async fn verify(&self) -> Result<JsSnapshotVerifyReport> {
        let snapshot = self.inner.clone();
        let report = snapshot.verify().await.map_err(to_napi_error)?;
        Ok(verify_report_to_js(report))
    }

    /// Observe this artifact's storage through its captured backend.
    #[napi(js_name = "storageUsage")]
    pub async fn storage_usage(&self) -> Result<StorageItemUsageJs> {
        let report = self.inner.storage_usage().await.map_err(to_napi_error)?;
        Ok(item_to_js(report))
    }
}

#[napi]
impl JsSnapshotArchive {
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    #[napi(getter)]
    pub fn descriptor_digest(&self) -> String {
        self.inner.descriptor_digest().to_string()
    }

    #[napi(getter)]
    pub fn path(&self) -> String {
        self.inner.path().display().to_string()
    }
}

impl JsSnapshotArchive {
    pub(crate) fn from_rust(inner: RustSnapshotArchive) -> Self {
        Self { inner }
    }
}

impl JsSnapshot {
    /// Wrap a Rust `Snapshot`. Used by `SnapshotBuilder.create()` and
    /// the `Sandbox.snapshot{,_to}` paths.
    pub fn from_rust(inner: RustSnapshot) -> Self {
        Self { inner }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Explicit export options must not be silently ignored by an older native library.
#[napi]
pub fn snapshot_archive_compatibility_targets() -> Vec<String> {
    vec!["current".into(), "0.7.8".into()]
}

fn format_str(f: RustSnapshotFormat) -> &'static str {
    match f {
        RustSnapshotFormat::Raw => "raw",
        RustSnapshotFormat::Qcow2 => "qcow2",
    }
}

fn save_opts_to_rust(opts: Option<JsSaveOpts>) -> Result<RustSaveOpts> {
    let opts = opts.unwrap_or_default();
    Ok(RustSaveOpts {
        compatibility: opts
            .compatibility
            .as_deref()
            .unwrap_or("current")
            .parse()
            .map_err(to_napi_error)?,
        with_parents: opts.with_parents.unwrap_or(false),
        with_image: opts.with_image.unwrap_or(false),
        plain_tar: opts.plain_tar.unwrap_or(false),
        since: opts.since,
        last_layers: crate::sandbox::checked_layer_count(opts.last_layers)?,
    })
}

fn format_scope(scope: RustSnapshotScope) -> &'static str {
    match scope {
        RustSnapshotScope::Disk => "disk",
        RustSnapshotScope::Full => "full",
    }
}

pub(crate) fn parse_snapshot_id(id: String) -> Result<microsandbox::snapshot::SnapshotId> {
    microsandbox::snapshot::SnapshotId::new(id).map_err(|e| {
        to_napi_error(microsandbox::MicrosandboxError::InvalidConfig(
            e.to_string(),
        ))
    })
}

pub(crate) fn head_update_to_js(update: &microsandbox::snapshot::HeadUpdate) -> HeadUpdate {
    // Match the stable serde spelling without losing the closed reason variants.
    let reason = match update.reason {
        HeadUpdateReason::Initialized => "initialized",
        HeadUpdateReason::FastForwarded => "fast_forwarded",
        HeadUpdateReason::Selected => "selected",
        HeadUpdateReason::Unchanged => "unchanged",
        HeadUpdateReason::Diverged => "diverged",
        HeadUpdateReason::UnknownAncestry => "unknown_ancestry",
        HeadUpdateReason::AmbiguousCandidates => "ambiguous_candidates",
        HeadUpdateReason::Cleared => "cleared",
        HeadUpdateReason::ParentSelected => "parent_selected",
    };
    HeadUpdate {
        group: update.group.clone(),
        previous: update.previous.clone(),
        head: update.head.clone(),
        reason: reason.into(),
        changed: update.changed,
    }
}

fn verify_report_to_js(
    report: microsandbox::snapshot::SnapshotVerifyReport,
) -> JsSnapshotVerifyReport {
    let (coverage_kind, unrecorded) = match report.coverage {
        microsandbox::snapshot::SnapshotVerifyCoverage::Complete => ("complete", Vec::new()),
        microsandbox::snapshot::SnapshotVerifyCoverage::Incomplete { unrecorded } => (
            "incomplete",
            unrecorded
                .into_iter()
                .map(|path| path.display().to_string())
                .collect(),
        ),
    };
    let checkpoint_root = report.checkpoint.map(|checkpoint| checkpoint.root);
    let (kind, algorithm, digest) = match report.upper {
        RustUpperVerifyStatus::NotRecorded => ("notRecorded".to_string(), None, None),
        RustUpperVerifyStatus::Verified { algorithm, digest } => {
            ("verified".to_string(), Some(algorithm), Some(digest))
        }
    };
    JsSnapshotVerifyReport {
        digest: report.digest,
        path: report.path.display().to_string(),
        upper_kind: kind,
        upper_algorithm: algorithm,
        upper_digest: digest,
        checkpoint_root,
        coverage_kind: coverage_kind.into(),
        unrecorded,
    }
}

// Suppress dead_code for the unused-in-tests fields (napi-rs registers
// them at the codegen level which `cargo test` doesn't see).
#[cfg(test)]
#[allow(dead_code)]
fn _exports_used() {
    let _ = format_str;
}

#[napi]
impl JsSnapshotMetadata {
    #[napi(getter)]
    pub fn image_ref(&self) -> String {
        self.inner.image.reference.clone()
    }

    #[napi(getter)]
    pub fn image_manifest_digest(&self) -> String {
        self.inner.image.manifest_digest.clone()
    }

    #[napi(getter)]
    pub fn state_kind(&self) -> String {
        self.inner.state.kind().into()
    }

    #[napi(getter)]
    pub fn format(&self) -> Option<String> {
        self.inner
            .state
            .as_file()
            .map(|state| format_str(state.disk_format).into())
    }

    #[napi(getter)]
    pub fn fstype(&self) -> Option<String> {
        self.inner
            .state
            .as_file()
            .map(|state| state.filesystem.clone())
    }

    #[napi(getter)]
    pub fn upper_file(&self) -> Option<String> {
        self.inner
            .state
            .as_file()
            .and_then(|state| state.head_layer().ok().map(|layer| state.layer_path(layer)))
            .map(|path| path.to_string_lossy().into_owned())
    }

    #[napi(getter)]
    pub fn upper_integrity_algorithm(&self) -> Option<String> {
        self.inner
            .state
            .as_file()
            .and_then(|state| state.head_layer().ok())
            .and_then(|layer| layer.payload.integrity.as_ref())
            .map(|integrity| integrity.algorithm().into())
    }

    #[napi(getter)]
    pub fn upper_integrity_digest(&self) -> Option<String> {
        self.inner
            .state
            .as_file()
            .and_then(|state| state.head_layer().ok())
            .and_then(|layer| layer.payload.integrity.as_ref())
            .map(|integrity| integrity.value().into())
    }

    #[napi(getter)]
    pub fn upper_integrity_logical_size(&self) -> Option<BigInt> {
        self.inner
            .state
            .as_file()
            .and_then(|state| state.head_layer().ok())
            .and_then(|layer| layer.payload.integrity.as_ref())
            .and_then(|integrity| match integrity {
                RustUpperIntegrity::FileMerkleBlake3V1 { logical_size, .. } => {
                    Some(BigInt::from(*logical_size))
                }
                _ => None,
            })
    }

    #[napi(getter)]
    pub fn upper_integrity_leaf_size(&self) -> Option<u32> {
        self.inner
            .state
            .as_file()
            .and_then(|state| state.head_layer().ok())
            .and_then(|layer| layer.payload.integrity.as_ref())
            .and_then(|integrity| match integrity {
                RustUpperIntegrity::FileMerkleBlake3V1 { leaf_size, .. } => Some(*leaf_size),
                _ => None,
            })
    }

    #[napi(getter)]
    pub fn checkpoint_id(&self) -> Option<String> {
        self.inner
            .state
            .as_checkpoint()
            .map(|state| state.checkpoint_id.clone())
    }

    #[napi(getter)]
    pub fn checkpoint_manifest_digest(&self) -> Option<String> {
        self.inner
            .state
            .as_checkpoint()
            .map(|state| state.checkpoint_root.clone())
    }

    #[napi(getter)]
    pub fn parent(&self) -> Option<String> {
        self.inner.parent.as_ref().map(ToString::to_string)
    }

    #[napi(getter, ts_return_type = "'disk' | 'full'")]
    pub fn scope(&self) -> String {
        format_scope(self.inner.scope).into()
    }

    #[napi(getter)]
    pub fn created_at(&self) -> String {
        self.inner.capture.created_at.clone()
    }

    #[napi(getter)]
    pub fn source_sandbox(&self) -> Option<String> {
        self.inner.capture.source_lineage.clone()
    }
    #[napi(getter)]
    pub fn size_bytes(&self) -> Option<BigInt> {
        self.inner
            .state
            .as_file()
            .map(|state| BigInt::from(state.virtual_size))
    }
}
