//! Native context objects own the destination used by collections and builders.

use std::sync::Arc;

use napi::Result;
use napi_derive::napi;

use crate::{
    error::to_napi_error,
    sandbox::{JsSandboxPage, Sandbox, sandbox_page_to_js},
    sandbox_builder::JsSandboxBuilder,
    snapshot::{HeadUpdate, JsSnapshot, head_update_to_js, parse_snapshot_id},
    snapshot_builder::JsSnapshotBuilder,
    types::SandboxListOptions,
    volume::JsVolume,
    volume_builder::JsVolumeBuilder,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An explicit shared destination. Construction never changes global selection.
#[napi(js_name = "Context")]
pub struct JsContext {
    pub(crate) inner: Arc<dyn microsandbox::Context>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsContext {
    /// Snapshot destination selection is captured before the restore builder escapes.
    #[napi]
    pub fn sandbox_restore(
        &self,
        snapshot: String,
        kind: Option<String>,
    ) -> Result<crate::restore_builder::JsRestoreBuilder> {
        let reference = match kind.as_deref() {
            None | Some("auto") => microsandbox::SnapshotReference::auto(snapshot),
            Some("id") => microsandbox::SnapshotReference::id(snapshot),
            Some("path") => microsandbox::SnapshotReference::path(snapshot),
            Some(_) => return Err(napi::Error::from_reason("unknown snapshot reference kind")),
        };
        Ok(crate::restore_builder::JsRestoreBuilder::from_builder(
            self.inner.sandboxes().restore_ref(reference),
        ))
    }

    #[napi(constructor)]
    pub fn new(options_json: String) -> Result<Self> {
        Ok(Self {
            inner: microsandbox::context::from_options_json(&options_json)
                .map_err(to_napi_error)?,
        })
    }

    /// Derive inside the retained provider; credentials never cross back into JavaScript.
    #[napi]
    pub fn derive_remote(&self, options_json: String) -> Result<Self> {
        Ok(Self {
            inner: microsandbox::context::derive_remote_from_options_json(
                self.inner.as_ref(),
                &options_json,
            )
            .map_err(to_napi_error)?,
        })
    }

    /// Metadata belongs to this context, never a newly resolved default.
    #[napi(getter)]
    pub fn info_json(&self) -> Result<String> {
        serde_json::to_string(&self.inner.info().map_err(to_napi_error)?)
            .map_err(|error| napi::Error::from_reason(error.to_string()))
    }

    #[napi(getter)]
    pub fn kind(&self) -> &'static str {
        match self.inner.kind() {
            microsandbox::context::ContextKind::Local => "local",
            microsandbox::context::ContextKind::Remote => "remote",
        }
    }

    #[napi]
    pub fn sandbox_builder(&self, name: String) -> JsSandboxBuilder {
        let builder = self.inner.sandboxes().builder(&name);
        JsSandboxBuilder::from_builder(name, builder)
    }

    #[napi]
    pub async fn sandbox_get(&self, name: String) -> Result<Sandbox> {
        self.inner
            .sandboxes()
            .get(&name)
            .await
            .map(Sandbox::from_rust)
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn sandbox_get_running(&self, name: String) -> Result<Sandbox> {
        self.inner
            .sandboxes()
            .get_running(&name)
            .await
            .map(Sandbox::from_rust)
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn sandbox_start(&self, name: String, detached: bool) -> Result<Sandbox> {
        let record = self
            .inner
            .sandbox_ops()
            .get(self.inner.clone(), &name)
            .await
            .map_err(to_napi_error)?;
        let result = if detached {
            record.start_detached().await
        } else {
            record.start().await
        };
        result.map(Sandbox::from_rust).map_err(to_napi_error)
    }

    #[napi]
    pub async fn sandbox_list(&self, options: Option<SandboxListOptions>) -> Result<JsSandboxPage> {
        self.inner
            .sandboxes()
            .list_with(|mut list| {
                if let Some(options) = options {
                    if let Some(limit) = options.limit {
                        list = list.limit(limit);
                    }
                    if let Some(cursor) = options.cursor {
                        list = list.cursor(cursor);
                    }
                    if let Some(labels) = options.labels {
                        list = list.labels(labels);
                    }
                }
                list
            })
            .await
            .map(sandbox_page_to_js)
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn sandbox_remove(&self, name: String) -> Result<()> {
        self.inner
            .sandbox_ops()
            .remove(self.inner.clone(), &name)
            .await
            .map_err(to_napi_error)
    }

    #[napi]
    pub fn volume_builder(&self, name: String) -> JsVolumeBuilder {
        let builder = self.inner.volumes().builder(&name);
        JsVolumeBuilder::from_builder(name, builder)
    }

    #[napi]
    pub async fn volume_get(&self, name: String) -> Result<JsVolume> {
        self.inner
            .volumes()
            .get(&name)
            .await
            .map(JsVolume::from_rust)
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn volume_get_default(&self) -> Result<JsVolume> {
        self.inner
            .volumes()
            .get_default()
            .await
            .map(JsVolume::from_rust)
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn volume_list(&self) -> Result<Vec<JsVolume>> {
        self.inner
            .volumes()
            .list()
            .await
            .map(|values| values.into_iter().map(JsVolume::from_rust).collect())
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn volume_remove(&self, name: String) -> Result<()> {
        self.inner
            .volumes()
            .remove(&name)
            .await
            .map_err(to_napi_error)
    }

    #[napi]
    pub fn snapshot_builder(&self, name: String) -> JsSnapshotBuilder {
        let builder = self.inner.checkpoints().builder(&name);
        JsSnapshotBuilder::from_builder(name, builder)
    }

    #[napi]
    pub async fn snapshot_group_head(&self, group: String) -> Result<Option<String>> {
        self.inner
            .checkpoints()
            .group_head(&group)
            .await
            .map(|head| head.map(|id| id.to_string()))
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn snapshot_set_group_head(&self, group: String, id: String) -> Result<HeadUpdate> {
        let id = parse_snapshot_id(id)?;
        let update = self
            .inner
            .checkpoints()
            .set_group_head(&group, &id)
            .await
            .map_err(to_napi_error)?;
        Ok(head_update_to_js(&update))
    }

    #[napi]
    pub async fn snapshot_group_get(
        &self,
        name: String,
    ) -> Result<crate::snapshot_group::JsSnapshotGroup> {
        self.inner
            .snapshots()
            .get(&name)
            .await
            .map(crate::snapshot_group::JsSnapshotGroup::from_rust)
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn snapshot_group_list(&self) -> Result<Vec<crate::snapshot_group::JsSnapshotGroup>> {
        Ok(self
            .inner
            .snapshots()
            .list()
            .await
            .map_err(to_napi_error)?
            .into_iter()
            .map(crate::snapshot_group::JsSnapshotGroup::from_rust)
            .collect())
    }

    #[napi(ts_return_type = "Promise<SnapshotGroup>")]
    pub fn snapshot_group_open<'env>(
        &self,
        env: &'env napi::Env,
        path: String,
    ) -> Result<napi::bindgen_prelude::PromiseRaw<'env, crate::snapshot_group::JsSnapshotGroup>>
    {
        let pending = self.inner.snapshots().open(path);
        env.spawn_future(async move {
            Ok(crate::snapshot_group::JsSnapshotGroup::from_rust(
                pending.await.map_err(to_napi_error)?,
            ))
        })
    }

    #[napi(
        ts_args_type = "group: string, archives: string[], opts?: LoadOpts",
        ts_return_type = "Promise<SnapshotImportResult>"
    )]
    pub fn snapshot_group_load<'env>(
        &self,
        env: &'env napi::Env,
        group: String,
        archives: Vec<String>,
        opts: Option<crate::snapshot::JsLoadOpts>,
    ) -> Result<
        napi::bindgen_prelude::PromiseRaw<'env, crate::snapshot_group::JsSnapshotImportResult>,
    > {
        crate::snapshot_group::load_in(env, self.inner.snapshots(), group, archives, opts)
    }

    #[napi]
    pub async fn snapshot_get(&self, reference: String) -> Result<JsSnapshot> {
        self.inner
            .checkpoints()
            .get(&reference)
            .await
            .map(JsSnapshot::from_rust)
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn snapshot_list(&self) -> Result<Vec<JsSnapshot>> {
        self.inner
            .checkpoints()
            .list()
            .await
            .map(|values| values.into_iter().map(JsSnapshot::from_rust).collect())
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn snapshot_remove(&self, reference: String, force: bool) -> Result<()> {
        self.inner
            .checkpoints()
            .remove(reference, force)
            .await
            .map_err(to_napi_error)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve configuration without starting a VM or making a remote request.
#[napi]
pub fn configured_context() -> Result<JsContext> {
    Ok(JsContext {
        inner: microsandbox::resolve_context().map_err(to_napi_error)?,
    })
}
