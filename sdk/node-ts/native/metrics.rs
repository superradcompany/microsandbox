use std::collections::HashMap;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;
use crate::sandbox::metrics_to_js;
use crate::types::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Get metrics for all running sandboxes.
#[napi]
pub async fn all_sandbox_metrics() -> Result<HashMap<String, SandboxMetrics>> {
    let backend = microsandbox::backend::default_backend();
    let local = backend.as_local().ok_or_else(|| {
        napi::Error::from_reason("all_sandbox_metrics requires a local backend".to_string())
    })?;
    let metrics = microsandbox::sandbox::all_sandbox_metrics(local)
        .await
        .map_err(to_napi_error)?;
    Ok(metrics
        .iter()
        .map(|(name, m)| (name.clone(), metrics_to_js(m)))
        .collect())
}
