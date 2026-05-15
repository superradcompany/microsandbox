use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for installing the runtime binaries.
#[napi(js_name = "Setup")]
pub struct JsSetup {
    base_dir: Option<PathBuf>,
    version: Option<String>,
    skip_verify: bool,
    force: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsSetup {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            base_dir: None,
            version: None,
            skip_verify: false,
            force: false,
        }
    }

    #[napi(js_name = "baseDir")]
    pub fn base_dir(&mut self, path: String) -> &Self {
        self.base_dir = Some(PathBuf::from(path));
        self
    }

    #[napi]
    pub fn version(&mut self, version: String) -> &Self {
        self.version = Some(version);
        self
    }

    #[napi(js_name = "skipVerify")]
    pub fn skip_verify(&mut self, enabled: bool) -> &Self {
        self.skip_verify = enabled;
        self
    }

    #[napi]
    pub fn force(&mut self, enabled: bool) -> &Self {
        self.force = enabled;
        self
    }

    #[napi]
    pub async fn install(&self) -> Result<()> {
        let skip = self.skip_verify;
        let force = self.force;
        match (self.base_dir.clone(), self.version.clone()) {
            (Some(dir), Some(v)) => microsandbox::setup::Setup::builder()
                .base_dir(dir)
                .version(v)
                .skip_verify(skip)
                .force(force)
                .build()
                .install()
                .await
                .map_err(to_napi_error),
            (Some(dir), None) => microsandbox::setup::Setup::builder()
                .base_dir(dir)
                .skip_verify(skip)
                .force(force)
                .build()
                .install()
                .await
                .map_err(to_napi_error),
            (None, Some(v)) => microsandbox::setup::Setup::builder()
                .version(v)
                .skip_verify(skip)
                .force(force)
                .build()
                .install()
                .await
                .map_err(to_napi_error),
            (None, None) => microsandbox::setup::Setup::builder()
                .skip_verify(skip)
                .force(force)
                .build()
                .install()
                .await
                .map_err(to_napi_error),
        }
    }
}

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
