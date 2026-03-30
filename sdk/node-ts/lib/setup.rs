use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Check if msb and libkrunfw are installed and available.
#[napi]
pub fn is_installed() -> bool {
    microsandbox::setup::is_installed()
}

/// Download and install msb + libkrunfw to ~/.microsandbox/.
#[napi]
pub async fn install() -> Result<()> {
    microsandbox::setup::install().await.map_err(to_napi_error)
}
