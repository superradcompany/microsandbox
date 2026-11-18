//! Native group handles retain their backend and return operation-owned capture results.

use std::collections::HashMap;
use std::path::PathBuf;

use microsandbox::snapshot::GuestFlush;
use microsandbox::{Snapshot as RustGroup, SnapshotCaptureOptions};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;
use crate::snapshot::{JsHeadUpdate, JsSnapshot, JsSnapshotHandle, head_update_to_js};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A named snapshot history, separate from an immutable checkpoint.
#[napi(js_name = "SnapshotGroup")]
pub struct JsSnapshotGroup {
    inner: RustGroup,
}

/// Initial or subsequent capture controls. Source selection belongs to the receiver.
#[derive(Default)]
#[napi(object, js_name = "SnapshotCaptureOptions")]
pub struct JsSnapshotCaptureOptions {
    pub name: Option<String>,
    pub dest_dir: Option<String>,
    pub full: Option<bool>,
    pub record_integrity: Option<bool>,
    pub guest_flush: Option<String>,
    pub labels: Option<HashMap<String, String>>,
}

/// A newly created group and its exact initial checkpoint.
#[napi(object, object_from_js = false, js_name = "SnapshotCreateResult")]
pub struct JsSnapshotCreateResult {
    pub snapshot: JsSnapshotGroup,
    pub checkpoint: JsSnapshot,
    pub head_update: JsHeadUpdate,
}

/// The exact member and head outcome of one capture.
#[napi(object, object_from_js = false, js_name = "CheckpointCaptureResult")]
pub struct JsCheckpointCaptureResult {
    pub checkpoint: JsSnapshot,
    pub head_update: JsHeadUpdate,
}

/// A committed archive batch, including reused members and deferred cleanup.
#[napi(object, object_from_js = false, js_name = "SnapshotImportResult")]
pub struct JsSnapshotImportResult {
    pub operation_id: String,
    pub snapshot: JsSnapshotGroup,
    pub checkpoints: Vec<JsSnapshotHandle>,
    pub added: Vec<String>,
    pub reused: Vec<String>,
    pub head_update: JsHeadUpdate,
    pub warnings: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsSnapshotGroup {
    /// Observe metadata and source association without selecting a checkpoint for execution.
    #[napi]
    pub async fn inspect_json(&self) -> Result<String> {
        let info = self.inner.inspect().await.map_err(to_napi_error)?;
        serde_json::to_string(&info).map_err(|error| to_napi_error(error.into()))
    }

    /// Return the committed member set and head outcome without a later catalog read.
    #[napi]
    pub async fn remove_group(&self) -> Result<String> {
        let result = self.inner.remove().await.map_err(to_napi_error)?;
        serde_json::to_string(&result).map_err(|error| to_napi_error(error.into()))
    }

    /// Internal JSON transport preserves nested per-member results without flattening errors.
    #[napi]
    pub async fn verify_json(&self) -> Result<String> {
        let report = self.inner.verify().await.map_err(to_napi_error)?;
        serde_json::to_string(&report).map_err(|error| to_napi_error(error.into()))
    }

    #[napi(
        ts_args_type = "group: string, archives: string[], opts?: LoadOpts",
        ts_return_type = "Promise<SnapshotImportResult>"
    )]
    pub fn load<'env>(
        env: &'env Env,
        group: String,
        archives: Vec<String>,
        opts: Option<crate::snapshot::JsLoadOpts>,
    ) -> Result<PromiseRaw<'env, JsSnapshotImportResult>> {
        let opts = opts.unwrap_or_default();
        // Own and anchor inputs on the JS thread, before spawning any async work.
        let prepared = (|| -> Result<_> {
            if opts
                .group
                .as_deref()
                .is_some_and(|selected| selected != group)
            {
                return Err(to_napi_error(
                    microsandbox::MicrosandboxError::InvalidConfig(
                        "import options cannot select a different destination group".into(),
                    ),
                ));
            }
            microsandbox::snapshot::PreparedSnapshotImport::new(
                archives.into_iter().map(PathBuf::from).collect(),
                microsandbox::snapshot::LoadOpts {
                    dest: opts.dest.map(PathBuf::from),
                    base: opts.base,
                    group: None,
                    set_head: opts.set_head.unwrap_or(false),
                },
            )
            .map_err(to_napi_error)
        })();
        env.spawn_future(async move {
            let result = prepared?.group(group).await.map_err(to_napi_error)?;
            Ok(JsSnapshotImportResult {
                operation_id: result.operation_id,
                snapshot: Self::from_rust(result.snapshot),
                checkpoints: result
                    .checkpoints
                    .into_iter()
                    .map(JsSnapshotHandle::from_rust)
                    .collect(),
                added: result.added.into_iter().map(|id| id.to_string()).collect(),
                reused: result.reused.into_iter().map(|id| id.to_string()).collect(),
                head_update: head_update_to_js(&result.head_update),
                warnings: result.warnings,
            })
        })
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

    /// Open a local directory, anchoring it before scheduling native work.
    #[napi]
    pub fn open<'env>(env: &'env Env, path: String) -> Result<PromiseRaw<'env, Self>> {
        let pending = RustGroup::open(path);
        env.spawn_future(async move {
            Ok(Self {
                inner: pending.await.map_err(to_napi_error)?,
            })
        })
    }

    #[napi(factory)]
    pub async fn get(name: String) -> Result<Self> {
        Ok(Self {
            inner: RustGroup::get(name).await.map_err(to_napi_error)?,
        })
    }

    #[napi]
    pub async fn list() -> Result<Vec<JsSnapshotGroup>> {
        Ok(RustGroup::list()
            .await
            .map_err(to_napi_error)?
            .into_iter()
            .map(Self::from_rust)
            .collect())
    }

    #[napi(getter)]
    pub fn name(&self) -> String {
        self.inner.name().into()
    }

    #[napi]
    pub async fn head(&self) -> Result<Option<JsSnapshot>> {
        Ok(self
            .inner
            .head()
            .await
            .map_err(to_napi_error)?
            .map(JsSnapshot::from_rust))
    }

    #[napi]
    pub async fn checkpoints(&self) -> Result<Vec<JsSnapshotHandle>> {
        Ok(self
            .inner
            .checkpoints()
            .await
            .map_err(to_napi_error)?
            .into_iter()
            .map(JsSnapshotHandle::from_rust)
            .collect())
    }

    #[napi]
    pub async fn get_checkpoint(&self, member: String) -> Result<JsSnapshot> {
        Ok(JsSnapshot::from_rust(
            self.inner
                .get_checkpoint(member)
                .await
                .map_err(to_napi_error)?,
        ))
    }

    #[napi]
    pub async fn set_head(&self, member: String) -> Result<JsHeadUpdate> {
        Ok(head_update_to_js(
            &self.inner.set_head(member).await.map_err(to_napi_error)?,
        ))
    }

    #[napi]
    pub async fn clear_head(&self) -> Result<JsHeadUpdate> {
        Ok(head_update_to_js(
            &self.inner.clear_head().await.map_err(to_napi_error)?,
        ))
    }

    #[napi]
    pub async fn checkpoint(
        &self,
        options: Option<JsSnapshotCaptureOptions>,
    ) -> Result<JsCheckpointCaptureResult> {
        let options = capture_options(options.unwrap_or_default())?;
        let result = self
            .inner
            .checkpoint_with(|_| options)
            .await
            .map_err(to_napi_error)?;
        Ok(JsCheckpointCaptureResult {
            checkpoint: JsSnapshot::from_rust(result.checkpoint),
            head_update: head_update_to_js(&result.head_update),
        })
    }

    #[napi]
    pub async fn spawn_sandbox(&self) -> Result<crate::sandbox::Sandbox> {
        Ok(crate::sandbox::Sandbox::from_rust(
            self.inner.spawn_sandbox().await.map_err(to_napi_error)?,
        ))
    }
}

impl JsSnapshotGroup {
    pub(crate) fn from_rust(inner: RustGroup) -> Self {
        Self { inner }
    }
}

impl JsSnapshotCreateResult {
    pub(crate) fn from_rust(result: microsandbox::SnapshotCreateResult) -> Self {
        Self {
            snapshot: JsSnapshotGroup::from_rust(result.snapshot),
            checkpoint: JsSnapshot::from_rust(result.checkpoint),
            head_update: head_update_to_js(&result.head_update),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn capture_options(options: JsSnapshotCaptureOptions) -> Result<SnapshotCaptureOptions> {
    capture_options_for_backend(options, false)
}

/// Call before spawning the future. Group checkpoint destinations are fixed by the receiver;
/// new histories additionally anchor local caller paths without resolving cloud paths here.
pub(crate) fn capture_options_for_backend(
    options: JsSnapshotCaptureOptions,
    local: bool,
) -> Result<SnapshotCaptureOptions> {
    let mut result = SnapshotCaptureOptions::default();
    if let Some(name) = options.name {
        result = result.name(name);
    }
    if let Some(dest) = options.dest_dir {
        let destination = if local {
            std::path::absolute(dest).map_err(|error| to_napi_error(error.into()))?
        } else {
            PathBuf::from(dest)
        };
        result = result.dest_dir(destination);
    }
    if options.full.unwrap_or(false) {
        result = result.full();
    }
    if options.record_integrity.unwrap_or(false) {
        result = result.record_integrity();
    }
    if let Some(policy) = options.guest_flush {
        result = result.guest_flush(match policy.as_str() {
            "auto" => GuestFlush::Auto,
            "required" => GuestFlush::Required,
            "skip" => GuestFlush::Skip,
            _ => {
                return Err(napi::Error::from_reason(
                    "guestFlush must be auto, required, or skip",
                ));
            }
        });
    }
    for (key, value) in options.labels.unwrap_or_default() {
        result = result.label(key, value);
    }
    Ok(result)
}
