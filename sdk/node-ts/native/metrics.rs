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
    #[cfg(not(feature = "local"))]
    {
        Err(crate::error::to_napi_error(
            microsandbox::MicrosandboxError::local_only(microsandbox::Operation::AllSandboxMetrics),
        ))
    }
    #[cfg(feature = "local")]
    {
        let backend = microsandbox::context::configured_context();
        let local = backend.as_local().ok_or_else(|| {
            napi::Error::from_reason("all_sandbox_metrics requires a local backend".to_string())
        })?;
        let metrics = microsandbox::sandbox::all_sandbox_metrics_local(local)
            .await
            .map_err(to_napi_error)?;
        Ok(metrics
            .iter()
            .map(|(name, m)| (name.clone(), metrics_to_js(m)))
            .collect())
    }
}
