//! Retained persistent resources for Go. Releasing a registration never deletes storage.

use super::{FfiError, Handle, cstr, run_c};
use microsandbox::{Checkpoint as Snapshot, Volume};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    os::raw::{c_char, c_uchar},
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) enum Resource {
    Volume(Volume),
    Snapshot(Box<Snapshot>),
}
type Registry = RwLock<HashMap<Handle, Arc<Resource>>>;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: String,
    #[serde(default)]
    args: Value,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Resource {
    // Keep lightweight volume registrations small despite snapshot metadata size.
    pub(super) fn snapshot(snapshot: Snapshot) -> Self {
        Self::Snapshot(Box::new(snapshot))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

pub(super) fn register(resource: Resource) -> Result<Value, FfiError> {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut value = match &resource {
        Resource::Volume(volume) => {
            let mut value: Value = serde_json::from_str(&super::volume_handle_json(volume))
                .map_err(|e| FfiError::internal(e.to_string()))?;
            value["id"] = json!(volume.id().as_str());
            value
        }
        Resource::Snapshot(snapshot) => super::snapshot_handle_json(snapshot),
    };
    let handle = NEXT.fetch_add(1, Ordering::Relaxed);
    registry()
        .write()
        .map_err(|_| FfiError::internal("persistent resource registry lock poisoned"))?
        .insert(handle, Arc::new(resource));
    value["handle"] = json!(handle);
    Ok(value)
}

/// Borrow an exact checkpoint across the two Go receiver interfaces without looking it up by name.
pub(super) fn checkpoint(handle: Handle) -> Result<Snapshot, FfiError> {
    let registry = registry()
        .read()
        .map_err(|_| FfiError::internal("persistent resource registry lock poisoned"))?;
    match registry.get(&handle).map(Arc::as_ref) {
        Some(Resource::Snapshot(snapshot)) => Ok(snapshot.as_ref().clone()),
        _ => Err(FfiError::invalid_handle(handle)),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_resource_release(handle: Handle) {
    if let Ok(mut registry) = registry().write() {
        registry.remove(&handle);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_resource_operation(
    cancel_id: u64,
    handle: Handle,
    request: *const c_char,
    buf: *mut c_uchar,
    len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, len, || {
        let resource = registry()
            .read()
            .map_err(|_| FfiError::internal("persistent resource registry lock poisoned"))?
            .get(&handle)
            .cloned()
            .ok_or_else(|| FfiError::invalid_handle(handle))?;
        let request: Request = serde_json::from_str(&unsafe { cstr(request) }?)
            .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
        Ok(Box::pin(async move {
            match resource.as_ref() {
                Resource::Volume(volume) => match request.operation.as_str() {
                    "info" => serde_json::to_string(&volume.info().await?)
                        .map_err(|e| FfiError::internal(e.to_string())),
                    "destroy" => {
                        volume.destroy().await?;
                        Ok(json!({"ok":true}).to_string())
                    }
                    op if op.starts_with("fs_") => {
                        super::volume_fs::dispatch_volume(volume, &op[3..], &request.args).await
                    }
                    _ => Err(FfiError::invalid_argument("unknown volume operation")),
                },
                Resource::Snapshot(snapshot) => match request.operation.as_str() {
                    "info" => {
                        let context = snapshot.context().clone_shared();
                        let current = context.checkpoints().open_ref(snapshot.reference()).await?;
                        // Released index rows may use the descriptor digest as their public ID.
                        // Compare the unchanged descriptor, then retain the selected public identity.
                        if current.digest() != snapshot.digest() {
                            return Err(FfiError::invalid_argument("snapshot identity changed"));
                        }
                        let mut value = super::snapshot_handle_json(&current);
                        value["id"] = json!(snapshot.id());
                        value["created_at"] = json!(current.created_at().and_utc());
                        Ok(value.to_string())
                    }
                    "metadata" => Ok(super::snapshot_json(snapshot).await?.to_string()),
                    "manifest" => serde_json::to_string(&snapshot.manifest().await?)
                        .map_err(|e| FfiError::internal(e.to_string())),
                    "destroy" => {
                        snapshot
                            .destroy(request.args["force"].as_bool().unwrap_or(false))
                            .await?;
                        Ok(json!({"ok":true}).to_string())
                    }
                    "save" => {
                        let out = request.args["path"].as_str().ok_or_else(|| {
                            FfiError::invalid_argument("missing archive output path")
                        })?;
                        let opts: super::SnapshotSaveOptsJson =
                            serde_json::from_value(request.args["options"].clone())
                                .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
                        snapshot
                            .save_to(
                                std::path::Path::new(out),
                                microsandbox::snapshot::SaveOpts {
                                    compatibility: opts.compatibility,
                                    since: opts.since,
                                    last_layers: opts.last_layers,
                                    with_parents: opts.with_parents,
                                    with_image: opts.with_image,
                                    plain_tar: opts.plain_tar,
                                },
                            )
                            .await?;
                        Ok(json!({"ok":true}).to_string())
                    }
                    "copy" => {
                        let out = request.args["path"].as_str().ok_or_else(|| {
                            FfiError::invalid_argument("missing archive output path")
                        })?;
                        let opts: super::SnapshotCopyOpts =
                            serde_json::from_value(request.args["options"].clone())
                                .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
                        snapshot
                            .copy_to(out)
                            .labels(opts.labels.into_iter().collect())
                            .record_integrity(opts.record_integrity)
                            .save()
                            .await?;
                        Ok(json!({"ok":true}).to_string())
                    }
                    "verify" => Ok(super::verify_report_json(snapshot.verify().await?).to_string()),
                    _ => Err(FfiError::invalid_argument("unknown snapshot operation")),
                },
            }
        }))
    })
}
