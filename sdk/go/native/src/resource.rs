//! Unified resource operations use registered receivers, preserving their context and owner.

use std::{
    os::raw::{c_char, c_uchar},
    sync::{Arc, Mutex},
};

use microsandbox::{Sandbox, SandboxListBuilder};

use super::{FfiError, Handle, SandboxListOpts, cstr, get, register, remove, run_c};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Wait against the registered receiver, retaining destination and ownership.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_resource_wait_for_status(
    cancel_id: u64,
    handle: Handle,
    status: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sandbox = get(handle)?;
        let status = super::parse_sandbox_status(&unsafe { cstr(status) }?)?;
        Ok(Box::pin(async move {
            sandbox.wait_for_status(status).await?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

pub(super) fn list_query(opts: SandboxListOpts) -> Result<SandboxListBuilder, FfiError> {
    let mut query = SandboxListBuilder::default();
    if let Some(limit) = opts.limit {
        if !(1..=microsandbox::sandbox::MAX_SANDBOX_LIST_LIMIT).contains(&limit) {
            return Err(FfiError::invalid_argument(
                "sandbox list limit is out of range",
            ));
        }
        query = query.limit(limit);
    }
    if let Some(cursor) = opts.cursor {
        query = query.cursor(cursor);
    }
    Ok(query.labels(opts.labels))
}

/// Receiver-based operations never resolve the current ambient destination.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_resource_operation(
    cancel_id: u64,
    handle: Handle,
    operation: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let published = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let publication = published.clone();
    let persistent = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let persistent_publication = persistent.clone();
    let result = run_c(cancel_id, buf, buf_len, || {
        let sandbox = get(handle)?;
        let operation = unsafe { cstr(operation) }?;
        let (operation, options, name) = if operation.starts_with('{') {
            let value: serde_json::Value = serde_json::from_str(&operation)
                .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
            let op = value["operation"]
                .as_str()
                .ok_or_else(|| FfiError::invalid_argument("missing operation"))?
                .to_owned();
            let opts: super::SandboxHandleLifecycleOpts =
                serde_json::from_value(value["options"].clone())
                    .map_err(|e| FfiError::invalid_argument(e.to_string()))?;
            (
                op,
                opts,
                value["name"].as_str().unwrap_or_default().to_owned(),
            )
        } else {
            (
                operation,
                super::SandboxHandleLifecycleOpts::default(),
                String::new(),
            )
        };
        Ok(Box::pin(async move {
            match operation.as_str() {
                "ensure_running" => {
                    sandbox.ensure_running().await?;
                    Ok(r#"{"ok":true}"#.into())
                }
                "snapshot" => {
                    // This operation is part of the released single-artifact ABI.
                    let snapshot = sandbox.checkpoint(&name).await?;
                    let entry = super::persistent_resource::register(
                        super::persistent_resource::Resource::snapshot(snapshot),
                    )?;
                    persistent_publication.store(
                        entry["handle"].as_u64().expect("resource registration"),
                        std::sync::atomic::Ordering::Release,
                    );
                    Ok(serde_json::json!({"resources":[entry]}).to_string())
                }
                "destroy" => {
                    let mut opts = microsandbox::sandbox::DestroyOptions {
                        force: options.force,
                        ..Default::default()
                    };
                    if let Some(ms) = options.timeout_ms {
                        opts.timeout = std::time::Duration::from_millis(ms);
                    }
                    sandbox.destroy_with(opts).await?;
                    Ok(r#"{"ok":true}"#.into())
                }
                "restart" => {
                    let mut opts = microsandbox::sandbox::RestartOptions {
                        force: options.force,
                        detached: options.detached,
                        ..Default::default()
                    };
                    if let Some(ms) = options.timeout_ms {
                        opts.timeout = std::time::Duration::from_millis(ms);
                    }
                    let restarted = sandbox.restart_with(opts).await?;
                    let id = restarted.id().to_string();
                    let name = restarted.name().to_owned();
                    let kind = restarted.context_kind().as_str();
                    let handle = register(restarted)?;
                    publication.store(handle, std::sync::atomic::Ordering::Release);
                    Ok(serde_json::json!({"handle":handle,"id":id,"name":name,"backend_kind":kind}).to_string())
                }
                "info" => serde_json::to_string(&sandbox.info().await?)
                    .map_err(|error| FfiError::internal(error.to_string())),
                "config" => serde_json::to_string(&sandbox.config().await?)
                    .map_err(|error| FfiError::internal(error.to_string())),
                _ => Err(FfiError::invalid_argument(
                    "unknown sandbox resource operation",
                )),
            }
        }))
    });
    if !result.is_null() {
        let _ = remove(published.load(std::sync::atomic::Ordering::Acquire));
        super::persistent_resource::msb_resource_release(
            persistent.load(std::sync::atomic::Ordering::Acquire),
        );
    }
    result
}

/// Resource listing has a distinct symbol so older metadata consumers keep their ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_resource_list(
    cancel_id: u64,
    filter_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let published = Arc::new(Mutex::new(Vec::new()));
    let publication = published.clone();
    let result = run_c(cancel_id, buf, buf_len, || {
        let filter = unsafe { cstr(filter_json) }?;
        let opts: SandboxListOpts = serde_json::from_str(&filter)
            .map_err(|error| FfiError::invalid_argument(error.to_string()))?;
        let query = list_query(opts)?;
        // Capture destination before handing work to the native runtime.
        let context = microsandbox::context::configured_context();
        let sandboxes = Sandbox::ctx(context.as_ref());
        Ok(Box::pin(async move {
            let page = sandboxes.list_with(|_| query).await?;
            let mut resources = Vec::with_capacity(page.sandboxes.len());
            for sandbox in page.sandboxes {
                let name = sandbox.name().to_owned();
                let id = sandbox.id().to_string();
                let backend = sandbox.context_kind().as_str();
                let handle = register(sandbox)?;
                // Keep every allocation recoverable until the whole page reaches Go.
                publication
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(handle);
                resources.push(serde_json::json!({
                    "handle": handle, "id": id, "name": name, "backend_kind": backend,
                }));
            }
            Ok(
                serde_json::json!({"sandboxes":resources,"next_cursor":page.next_cursor})
                    .to_string(),
            )
        }))
    });
    if !result.is_null() {
        for handle in published
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .drain(..)
        {
            let _ = remove(handle);
        }
    }
    result
}
