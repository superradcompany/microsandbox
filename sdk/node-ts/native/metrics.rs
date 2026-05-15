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
    let metrics = microsandbox::sandbox::all_sandbox_metrics()
        .await
        .map_err(to_napi_error)?;
    Ok(metrics
        .iter()
        .map(|(name, m)| (name.clone(), metrics_to_js(m)))
        .collect())
}
