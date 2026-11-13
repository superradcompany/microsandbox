//! Service bindings delegate every request, validation and outcome to the Rust SDK.
//!
//! Each Service returned to Go owns a handle to its Rust `Service`, so later operations use the
//! backend that returned it. Go releases the handle with `msb_service_close`.

use std::collections::HashMap;
use std::os::raw::{c_char, c_uchar};
use std::sync::{
    OnceLock, RwLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use microsandbox::{
    ChangeState, CloudService, CloudServiceTarget, CloudUpdateServiceRequest, MicrosandboxError,
    Operation, Service, ServiceError,
};

use crate::{FfiError, cancel_unregister, cstr, error_kind, run, run_c};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The largest whole millisecond count that fits Go's `time.Duration`, an i64 nanosecond count.
const GO_DURATION_MAX_MILLIS: u64 = i64::MAX as u64 / 1_000_000;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct CreateRequest {
    slug: String,
    target: CloudServiceTarget,
}

#[derive(serde::Deserialize)]
struct ListRequest {
    sandbox: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(serde::Serialize)]
struct PageJson {
    services: Vec<ServiceJson>,
    next_cursor: Option<String>,
}

#[derive(serde::Serialize)]
struct ServiceJson {
    handle: u64,
    #[serde(flatten)]
    info: CloudService,
}

/// Service change failure details carried in the FFI error JSON.
#[derive(serde::Serialize)]
pub(crate) struct ServiceErrorDetails {
    slug: String,
    reason: &'static str,
    retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_message: Option<String>,
}

/// Which action endpoint a Service call takes.
#[derive(Clone, Copy)]
enum Action {
    Enable,
    Disable,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create a Service from `{"slug", "target"}` JSON and return it once committed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_service_create(
    cancel_id: u64,
    request_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let request: CreateRequest = serde_json::from_str(&unsafe { cstr(request_json) }?)
            .map_err(|error| {
                FfiError::invalid_argument(format!("invalid service create request: {error}"))
                    .with_change(ChangeState::Unchanged)
            })?;
        Ok(Box::pin(async move {
            let service = Service::builder(request.slug)
                .target(request.target.sandbox, request.target.port)
                .create()
                .await
                .map_err(change_error)?;
            service_json(service)
        }))
    })
}

/// Get a Service by slug.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_service_get(
    cancel_id: u64,
    slug: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let slug = unsafe { cstr(slug) }?;
        Ok(Box::pin(async move {
            let service = Service::get(&slug).await.map_err(FfiError::from)?;
            service_json(service)
        }))
    })
}

/// List one page of Services from `{"sandbox", "cursor", "limit"}` JSON.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_service_list(
    cancel_id: u64,
    options_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let options: ListRequest =
            serde_json::from_str(&unsafe { cstr(options_json) }?).map_err(|error| {
                FfiError::invalid_argument(format!("invalid service list options: {error}"))
            })?;
        Ok(Box::pin(async move {
            let page = Service::list_with(|list| {
                let mut list = list;
                if let Some(sandbox) = options.sandbox {
                    list = list.sandbox(sandbox);
                }
                if let Some(cursor) = options.cursor {
                    list = list.cursor(cursor);
                }
                if let Some(limit) = options.limit {
                    list = list.limit(limit);
                }
                list
            })
            .await
            .map_err(FfiError::from)?;

            let page = PageJson {
                services: page
                    .services
                    .into_iter()
                    .map(register_service)
                    .collect::<Result<Vec<_>, _>>()?,
                next_cursor: page.next_cursor,
            };
            serde_json::to_string(&page).map_err(|error| FfiError::internal(error.to_string()))
        }))
    })
}

/// Send one target change and return the Service once committed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_service_update(
    cancel_id: u64,
    handle: u64,
    request_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let request: CloudUpdateServiceRequest =
            serde_json::from_str(&unsafe { cstr(request_json) }?).map_err(|error| {
                FfiError::invalid_argument(format!("invalid service update request: {error}"))
                    .with_change(ChangeState::Unchanged)
            })?;
        Ok(Box::pin(async move {
            let service = service_for_change(handle)?
                .update(|mut update| {
                    if let Some(target) = request.target {
                        update = update.target(target.sandbox, target.port);
                    }
                    update
                })
                .await
                .map_err(change_error)?;
            service_json(service)
        }))
    })
}

/// Enable a Service and return it once committed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_service_enable(
    cancel_id: u64,
    handle: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    service_action(cancel_id, handle, buf, buf_len, Action::Enable)
}

/// Disable a Service and return it once committed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_service_disable(
    cancel_id: u64,
    handle: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    service_action(cancel_id, handle, buf, buf_len, Action::Disable)
}

/// Remove a Service and release the slug.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_service_remove(
    cancel_id: u64,
    handle: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            service_for_change(handle)?
                .remove()
                .await
                .map_err(change_error)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

/// Get a Service through the backend retained by its handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_service_refresh(
    cancel_id: u64,
    handle: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let service = service_for_handle(handle)?
                .refresh()
                .await
                .map_err(FfiError::from)?;
            service_json(service)
        }))
    })
}

/// Release a Service handle. The Service itself is not changed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_service_close(
    cancel_id: u64,
    handle: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    cancel_unregister(cancel_id);
    run(buf, buf_len, || {
        services()
            .write()
            .map_err(|_| FfiError::internal("service registry lock poisoned"))?
            .remove(&handle);
        Ok(r#"{"ok":true}"#.into())
    })
}

/// Whether `op` is a Service operation, which the local backend refuses as cloud-only.
pub(crate) fn is_service_operation(op: Operation) -> bool {
    matches!(
        op,
        Operation::ServiceCreate
            | Operation::ServiceGet
            | Operation::ServiceList
            | Operation::ServiceUpdate
            | Operation::ServiceEnable
            | Operation::ServiceDisable
            | Operation::ServiceRemove
    )
}

pub(crate) fn error_details(error: &MicrosandboxError) -> Option<Box<ServiceErrorDetails>> {
    let MicrosandboxError::Service { slug, error } = error else {
        return None;
    };
    let (reason, retry_after, raw_code, raw_status, raw_message) = match error {
        ServiceError::QuotaExceeded => ("service_quota_exceeded", None, None, None, None),
        ServiceError::SandboxLimitExceeded => {
            ("sandbox_service_limit_exceeded", None, None, None, None)
        }
        ServiceError::Conflict => ("service_conflict", None, None, None, None),
        ServiceError::Detached => ("service_detached", None, None, None, None),
        ServiceError::TargetUnreachable { retry_after } => {
            ("target_unreachable", *retry_after, None, None, None)
        }
        ServiceError::TargetNotRunning => ("sandbox_not_running", None, None, None, None),
        ServiceError::ChangesPaused { retry_after } => {
            ("service_changes_paused", *retry_after, None, None, None)
        }
        ServiceError::OutcomeUnknown => ("outcome_unknown", None, None, None, None),
        ServiceError::Other {
            code,
            status,
            message,
        } => (
            "other",
            None,
            Some(code.clone()),
            Some(*status),
            Some(message.clone()),
        ),
        // `ServiceError` is non-exhaustive, so newer reasons retain a stable fallback.
        _ => ("other", None, None, None, None),
    };
    Some(Box::new(ServiceErrorDetails {
        slug: slug.clone(),
        reason,
        retry_after_ms: retry_after.map(go_duration_millis),
        raw_code,
        raw_status,
        raw_message,
    }))
}

fn go_duration_millis(wait: Duration) -> u64 {
    wait.as_millis().min(GO_DURATION_MAX_MILLIS.into()) as u64
}

fn change_error(error: MicrosandboxError) -> FfiError {
    let changed = error.changed();
    FfiError::from(error).with_change(changed)
}

fn service_json(service: Service) -> Result<String, FfiError> {
    serde_json::to_string(&register_service(service)?)
        .map_err(|error| FfiError::internal(error.to_string()))
}

fn services() -> &'static RwLock<HashMap<u64, Service>> {
    static SERVICES: OnceLock<RwLock<HashMap<u64, Service>>> = OnceLock::new();
    SERVICES.get_or_init(|| RwLock::new(HashMap::new()))
}

fn register_service(service: Service) -> Result<ServiceJson, FfiError> {
    static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let info = cloud_service(&service);
    services()
        .write()
        .map_err(|_| FfiError::internal("service registry lock poisoned"))?
        .insert(handle, service);
    Ok(ServiceJson { handle, info })
}

fn service_for_handle(handle: u64) -> Result<Service, FfiError> {
    services()
        .read()
        .map_err(|_| FfiError::internal("service registry lock poisoned"))?
        .get(&handle)
        .cloned()
        .ok_or_else(|| {
            FfiError::new(
                error_kind::INVALID_HANDLE,
                format!("unknown service handle: {handle}"),
            )
        })
}

/// Look up the Service for a change; an unknown handle fails before any request.
fn service_for_change(handle: u64) -> Result<Service, FfiError> {
    service_for_handle(handle).map_err(|error| error.with_change(ChangeState::Unchanged))
}

fn service_action(
    cancel_id: u64,
    handle: u64,
    buf: *mut c_uchar,
    buf_len: usize,
    action: Action,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let service = service_for_change(handle)?;
            let service = match action {
                Action::Enable => service.enable().await,
                Action::Disable => service.disable().await,
            }
            .map_err(change_error)?;
            service_json(service)
        }))
    })
}

fn cloud_service(service: &Service) -> CloudService {
    CloudService {
        slug: service.slug().to_string(),
        url: service.url().to_string(),
        status: service.status(),
        target: service.target(),
        created_at: service.created_at(),
        updated_at: service.updated_at(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn service_errors_carry_reason_wait_and_change_state() {
        let sandbox_limit = MicrosandboxError::Service {
            slug: "my-app".into(),
            error: ServiceError::SandboxLimitExceeded,
        };
        let refused = MicrosandboxError::Service {
            slug: "my-app".into(),
            error: ServiceError::TargetUnreachable {
                retry_after: Some(Duration::from_secs(5)),
            },
        };
        let unknown = MicrosandboxError::Service {
            slug: "my-app".into(),
            error: ServiceError::OutcomeUnknown,
        };
        let saturated = MicrosandboxError::Service {
            slug: "my-app".into(),
            error: ServiceError::TargetUnreachable {
                retry_after: Some(Duration::from_secs(u64::MAX)),
            },
        };

        let sandbox_limit: serde_json::Value =
            serde_json::from_str(&change_error(sandbox_limit).to_json()).unwrap();
        let refused: serde_json::Value =
            serde_json::from_str(&change_error(refused).to_json()).unwrap();
        let unknown: serde_json::Value =
            serde_json::from_str(&change_error(unknown).to_json()).unwrap();
        let saturated: serde_json::Value =
            serde_json::from_str(&change_error(saturated).to_json()).unwrap();

        assert_eq!(refused["kind"], "service");
        assert_eq!(
            sandbox_limit["service"]["reason"],
            "sandbox_service_limit_exceeded"
        );
        assert_eq!(sandbox_limit["changed"], "unchanged");
        assert_eq!(refused["service"]["slug"], "my-app");
        assert_eq!(refused["service"]["reason"], "target_unreachable");
        assert_eq!(refused["service"]["retry_after_ms"], 5000);
        assert_eq!(
            saturated["service"]["retry_after_ms"],
            GO_DURATION_MAX_MILLIS
        );
        assert_eq!(refused["changed"], "unchanged");
        assert_eq!(unknown["service"]["reason"], "outcome_unknown");
        assert!(unknown["service"]["retry_after_ms"].is_null());
        assert_eq!(unknown["changed"], "unknown");
    }

    #[test]
    fn non_service_change_errors_carry_core_state() {
        let invalid = change_error(MicrosandboxError::InvalidConfig("bad target".into()));
        let unavailable = change_error(MicrosandboxError::CloudHttp {
            status: 503,
            code: Some("unavailable".into()),
            message: "try again".into(),
        });

        let invalid: serde_json::Value = serde_json::from_str(&invalid.to_json()).unwrap();
        let unavailable: serde_json::Value = serde_json::from_str(&unavailable.to_json()).unwrap();

        assert_eq!(invalid["changed"], "unchanged");
        assert_eq!(unavailable["changed"], "unknown");
    }

    #[test]
    fn other_service_errors_carry_raw_refusal_data() {
        let error = MicrosandboxError::Service {
            slug: "my-app".into(),
            error: ServiceError::Other {
                code: "slug_reserved".into(),
                status: 409,
                message: "slug is reserved".into(),
            },
        };

        let error: serde_json::Value =
            serde_json::from_str(&change_error(error).to_json()).unwrap();

        assert_eq!(error["service"]["reason"], "other");
        assert_eq!(error["service"]["raw_code"], "slug_reserved");
        assert_eq!(error["service"]["raw_status"], 409);
        assert_eq!(error["service"]["raw_message"], "slug is reserved");
    }

    #[test]
    fn missing_and_taken_slugs_keep_plain_kinds() {
        let missing = FfiError::from(MicrosandboxError::ServiceNotFound("my-app".into()));
        let taken = FfiError::from(MicrosandboxError::ServiceAlreadyExists("my-app".into()));

        assert_eq!(
            missing.to_json(),
            r#"{"kind":"service_not_found","message":"service not found: my-app"}"#
        );
        assert_eq!(
            taken.to_json(),
            r#"{"kind":"service_already_exists","message":"service slug unavailable: my-app; choose another slug"}"#
        );
    }

    #[test]
    fn only_local_service_calls_report_cloud_only() {
        let service = FfiError::from(MicrosandboxError::cloud_only(Operation::ServiceGet));
        let volume = FfiError::from(MicrosandboxError::cloud_only(Operation::VolumeGetDefault));

        assert_eq!(service.kind, error_kind::CLOUD_ONLY);
        assert_eq!(volume.kind, error_kind::UNSUPPORTED_OPERATION);
    }
}
