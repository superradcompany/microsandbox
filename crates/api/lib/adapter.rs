//! Adapter helpers over public microsandbox APIs.

use std::collections::HashMap;

use axum::http::StatusCode;
use microsandbox::{
    MicrosandboxError, Sandbox, SandboxConfig,
    sandbox::{SandboxHandle, SandboxStatus},
};

use crate::{
    dto::{DevboxCreateRequest, DevboxView},
    error::ApiError,
    ids,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create a local devbox.
pub async fn create_devbox(request: DevboxCreateRequest) -> Result<DevboxView, ApiError> {
    reject_unsupported_create_fields(&request)?;

    let id = ids::new_devbox_id();
    let metadata = request.metadata.unwrap_or_default();
    let mut builder = Sandbox::builder(&id);

    if let Some(image) = &request.image {
        builder = builder.image(image.as_str());
    }
    if let Some(env) = &request.environment_variables {
        builder = builder.envs(env.iter());
    }
    builder = builder.labels(metadata.iter());

    let sandbox = builder
        .detached(true)
        .create()
        .await
        .map_err(map_create_error)?;
    sandbox.detach().await;

    Ok(DevboxView {
        id,
        name: request.name,
        status: status_to_runloop(SandboxStatus::Running).into(),
        metadata,
    })
}

/// List local devboxes.
pub async fn list_devboxes() -> Result<Vec<DevboxView>, ApiError> {
    let handles = Sandbox::list()
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(handles.into_iter().map(devbox_view).collect())
}

/// Get a local devbox.
pub async fn get_devbox(id: &str) -> Result<DevboxView, ApiError> {
    let handle = Sandbox::get(id)
        .await
        .map_err(|_| ApiError::not_found(format!("Devbox '{id}' was not found.")))?;
    Ok(devbox_view(handle))
}

fn devbox_view(handle: SandboxHandle) -> DevboxView {
    DevboxView {
        id: handle.name().to_string(),
        name: None,
        status: status_to_runloop(handle.status()).into(),
        metadata: metadata_from_config(handle.config().ok()),
    }
}

fn metadata_from_config(config: Option<SandboxConfig>) -> HashMap<String, String> {
    config.map(|config| config.labels).unwrap_or_default()
}

fn reject_unsupported_create_fields(request: &DevboxCreateRequest) -> Result<(), ApiError> {
    if request.blueprint_id.is_some() {
        return Err(ApiError::bad_request(
            "unsupported_field",
            "blueprint_id is not supported by the local Microsandbox API POC.",
        ));
    }
    if request.blueprint_name.is_some() {
        return Err(ApiError::bad_request(
            "unsupported_field",
            "blueprint_name is not supported by the local Microsandbox API POC.",
        ));
    }
    Ok(())
}

fn map_create_error(err: MicrosandboxError) -> ApiError {
    let message = err.to_string();
    match err {
        MicrosandboxError::InvalidConfig(_) if is_image_reference_error(&message) => {
            ApiError::bad_request("invalid_image_reference", message)
        }
        MicrosandboxError::InvalidConfig(_) => ApiError::bad_request("invalid_request", message),
        MicrosandboxError::Image(_) | MicrosandboxError::ImageNotFound(_) => {
            ApiError::new(StatusCode::BAD_GATEWAY, "image_pull_failed", message)
        }
        MicrosandboxError::SandboxAlreadyExists(_) => {
            ApiError::new(StatusCode::CONFLICT, "already_exists", message)
        }
        other => ApiError::internal(other.to_string()),
    }
}

fn is_image_reference_error(message: &str) -> bool {
    message.contains("image")
        || message.contains("reference")
        || message.contains("rootfs")
        || message.contains("oci")
}

fn status_to_runloop(status: SandboxStatus) -> &'static str {
    match status {
        SandboxStatus::Running | SandboxStatus::Draining => "running",
        SandboxStatus::Stopped => "shutdown",
        SandboxStatus::Crashed => "failure",
        SandboxStatus::Paused => "suspended",
    }
}
