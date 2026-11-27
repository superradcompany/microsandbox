//! Explicit Go destinations. Registry entries retain provider state, never ambient scope.

use super::{FfiError, Handle, cstr, run_c};
use microsandbox::Context;
use std::{
    collections::HashMap,
    os::raw::{c_char, c_uchar},
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type ContextRegistry = RwLock<HashMap<Handle, Arc<dyn Context>>>;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    filter: Option<super::SandboxListOpts>,
    #[serde(default)]
    args: serde_json::Value,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Derivation {
    base_handle: u64,
    overrides: serde_json::Value,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn registry() -> &'static ContextRegistry {
    static REGISTRY: OnceLock<ContextRegistry> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

pub(super) fn get(handle: Handle) -> Result<Arc<dyn Context>, FfiError> {
    registry()
        .read()
        .map_err(|_| FfiError::internal("context registry lock poisoned"))?
        .get(&handle)
        .cloned()
        .ok_or_else(|| FfiError::invalid_handle(handle))
}

/// Creation is local configuration capture, not a remote lookup or runtime launch.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_context_create(
    cancel_id: u64,
    options: *const c_char,
    buf: *mut c_uchar,
    len: usize,
) -> *mut c_char {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let published = Arc::new(AtomicU64::new(0));
    let publication = published.clone();
    let result = run_c(cancel_id, buf, len, || {
        let json = unsafe { cstr(options) }?;
        let value: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| FfiError::invalid_argument(e.to_string()))?;
        if value == serde_json::json!({"selection": "kind"}) {
            let kind = microsandbox::context::configured_provider_kind()?;
            return Ok(Box::pin(async move { Ok(kind.as_str().to_owned()) }));
        }
        let context = if value == serde_json::json!({"selection": "configured"}) {
            microsandbox::context::resolve_default_backend()?
        } else if value.get("baseHandle").is_some() {
            let request: Derivation = serde_json::from_value(value)
                .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
            let base = get(request.base_handle)?;
            microsandbox::context::derive_remote_from_options_json(
                base.as_ref(),
                &request.overrides.to_string(),
            )?
        } else {
            microsandbox::context::from_options_json(&json)?
        };
        Ok(Box::pin(async move {
            let kind = match context.kind() {
                microsandbox::ContextKind::Local => "local",
                microsandbox::ContextKind::Remote => "remote",
            };
            let info = context.info()?;
            let handle = NEXT.fetch_add(1, Ordering::Relaxed);
            registry()
                .write()
                .map_err(|_| FfiError::internal("context registry lock poisoned"))?
                .insert(handle, context);
            publication.store(handle, Ordering::Release);
            Ok(serde_json::json!({"handle":handle,"kind":kind,"info":info}).to_string())
        }))
    });
    if !result.is_null() {
        msb_context_release(published.load(Ordering::Acquire));
    }
    result
}

/// Release the registry reference. Existing collections and native resources retain their Arcs.
#[unsafe(no_mangle)]
pub extern "C" fn msb_context_release(handle: Handle) {
    if let Ok(mut registry) = registry().write() {
        registry.remove(&handle);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_context_operation(
    cancel_id: u64,
    handle: Handle,
    request: *const c_char,
    buf: *mut c_uchar,
    len: usize,
) -> *mut c_char {
    let published = Arc::new(Mutex::new(Vec::new()));
    let publication = published.clone();
    let persistent = Arc::new(Mutex::new(Vec::new()));
    let persistent_publication = persistent.clone();
    let result = run_c(cancel_id, buf, len, || {
        let context = get(handle)?;
        let request: Request = serde_json::from_str(&unsafe { cstr(request) }?)
            .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
        Ok(Box::pin(async move {
            if request.operation.starts_with("volume_")
                || request.operation.starts_with("snapshot_")
            {
                return persistent_operation(context, request, persistent_publication).await;
            }
            let sandboxes = context.sandboxes();
            if request.operation == "sandbox_remove" {
                sandboxes.remove(&request.name).await?;
                return Ok(r#"{"ok":true}"#.into());
            }
            let (resources, cursor) = match request.operation.as_str() {
                "sandbox_get" => (vec![sandboxes.get(&request.name).await?], None),
                "sandbox_get_running" => (vec![sandboxes.get_running(&request.name).await?], None),
                "sandbox_start" => (vec![sandboxes.start(&request.name).await?], None),
                "sandbox_start_detached" => {
                    (vec![sandboxes.start_detached(&request.name).await?], None)
                }
                "sandbox_list" => {
                    let query = super::resource::list_query(request.filter.unwrap_or_default())?;
                    let page = sandboxes.list_with(|_| query).await?;
                    (page.sandboxes, page.next_cursor)
                }
                _ => return Err(FfiError::invalid_argument("unknown context operation")),
            };
            let mut entries = Vec::with_capacity(resources.len());
            for sandbox in resources {
                let id = sandbox.id().to_string();
                let name = sandbox.name().to_owned();
                let kind = sandbox.context_kind().as_str();
                let handle = super::register(sandbox)?;
                publication
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(handle);
                entries.push(
                    serde_json::json!({"handle":handle,"id":id,"name":name,"backend_kind":kind}),
                );
            }
            Ok(serde_json::json!({"sandboxes":entries,"next_cursor":cursor}).to_string())
        }))
    });
    // Neither a short output buffer nor cancellation may orphan owning resources.
    if !result.is_null() {
        for handle in published
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            let _ = super::remove(handle);
        }
        for handle in persistent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            super::persistent_resource::msb_resource_release(handle);
        }
    }
    result
}

async fn persistent_operation(
    context: Arc<dyn Context>,
    request: Request,
    publication: Arc<Mutex<Vec<Handle>>>,
) -> Result<String, FfiError> {
    use super::persistent_resource::Resource;
    let resources = match request.operation.as_str() {
        "volume_get" => vec![Resource::Volume(
            context.volumes().get(&request.name).await?,
        )],
        "volume_get_default" => vec![Resource::Volume(context.volumes().get_default().await?)],
        "volume_list" => context
            .volumes()
            .list()
            .await?
            .into_iter()
            .map(Resource::Volume)
            .collect(),
        "volume_remove" => {
            context.volumes().remove(&request.name).await?;
            Vec::new()
        }
        "volume_create" => {
            let opts: super::VolumeCreateOpts = serde_json::from_value(request.args)
                .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
            let mut builder = context.volumes().builder(request.name);
            builder = match super::parse_volume_kind(&opts.kind)? {
                microsandbox::volume::VolumeKind::Directory => builder.directory(),
                microsandbox::volume::VolumeKind::Disk => builder.disk(),
            };
            if opts.size_mib > 0 {
                builder = builder.size(opts.size_mib);
            }
            if opts.quota_mib > 0 {
                builder = builder.quota(opts.quota_mib);
            }
            for (key, value) in opts.labels {
                builder = builder.label(key, value);
            }
            vec![Resource::Volume(builder.create().await?)]
        }
        "snapshot_get" => vec![Resource::snapshot(
            context.checkpoints().get(&request.name).await?,
        )],
        "snapshot_open" => vec![Resource::snapshot(
            context.checkpoints().open(&request.name).await?,
        )],
        "snapshot_list" => context
            .checkpoints()
            .list()
            .await?
            .into_iter()
            .map(Resource::snapshot)
            .collect(),
        "snapshot_remove" => {
            context
                .checkpoints()
                .remove(
                    &request.name,
                    request.args["force"].as_bool().unwrap_or(false),
                )
                .await?;
            Vec::new()
        }
        "snapshot_list_dir" => context
            .snapshot_ops()
            .list_dir(context.clone(), request.name.into())
            .await?
            .into_iter()
            .map(Resource::snapshot)
            .collect(),
        "snapshot_load" => {
            let opts: super::SnapshotLoadOptsJson =
                serde_json::from_value(request.args["options"].clone())
                    .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
            let archives: Vec<std::path::PathBuf> =
                serde_json::from_value(request.args["archives"].clone())
                    .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
            context
                .snapshot_ops()
                .load_many(
                    context.clone(),
                    &archives,
                    microsandbox::snapshot::LoadOpts {
                        dest: opts.dest,
                        base: opts.base,
                        group: opts.group,
                        set_head: opts.set_head,
                        maximum_disk_bytes: opts.maximum_disk_bytes,
                    },
                )
                .await?
                .into_iter()
                .map(Resource::snapshot)
                .collect()
        }
        "snapshot_reindex" => {
            let directory = if request.name.is_empty() {
                None
            } else {
                Some(request.name.into())
            };
            return Ok(
                serde_json::json!({"count":context.snapshot_ops().reindex(directory).await?})
                    .to_string(),
            );
        }
        "snapshot_read_group_head" => {
            let head = context.checkpoints().group_head(&request.name).await?;
            return Ok(serde_json::json!(head.map(|id| id.to_string())).to_string());
        }
        "snapshot_set_group_head" => {
            let id = request.args["id"]
                .as_str()
                .ok_or_else(|| FfiError::invalid_argument("missing snapshot ID"))?;
            let id = microsandbox::snapshot::SnapshotId::new(id)
                .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
            let update = context
                .checkpoints()
                .set_group_head(&request.name, &id)
                .await?;
            return serde_json::to_string(&update).map_err(|e| FfiError::internal(e.to_string()));
        }
        // Previous Go SDKs use this operation for both selector forms.
        "snapshot_group_head" => {
            return serde_json::to_string(
                &context
                    .snapshot_ops()
                    .group_head_selector(&request.name)
                    .await?,
            )
            .map_err(|e| FfiError::internal(e.to_string()));
        }
        "snapshot_create_archive" => {
            let opts: super::SnapshotCreateOpts =
                serde_json::from_value(request.args["options"].clone())
                    .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
            let out = request.args["path"]
                .as_str()
                .ok_or_else(|| FfiError::invalid_argument("missing archive output path"))?;
            let config =
                super::snapshot_builder_in(context.clone(), request.name, opts)?.build()?;
            let archive = context
                .snapshot_ops()
                .create_archive(
                    config,
                    std::path::Path::new(out),
                    request.args["plain_tar"].as_bool().unwrap_or(false),
                )
                .await?;
            return Ok(serde_json::json!({"id":archive.id(),"descriptor_digest":archive.descriptor_digest(),"path":archive.path()}).to_string());
        }
        "snapshot_create" => {
            let opts: super::SnapshotCreateOpts = serde_json::from_value(request.args)
                .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
            vec![Resource::snapshot(
                super::snapshot_builder_in(context, request.name, opts)?
                    .create()
                    .await?,
            )]
        }
        _ => {
            return Err(FfiError::invalid_argument(
                "unknown persistent collection operation",
            ));
        }
    };
    let mut entries = Vec::with_capacity(resources.len());
    for resource in resources {
        let entry = super::persistent_resource::register(resource)?;
        publication
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(entry["handle"].as_u64().expect("resource registration"));
        entries.push(entry);
    }
    Ok(serde_json::json!({"resources":entries}).to_string())
}
