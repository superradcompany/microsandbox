use std::collections::HashMap;

use microsandbox::volume::{Volume, VolumeHandle};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;
use crate::types::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A named persistent volume.
#[napi(js_name = "Volume")]
pub struct JsVolume {
    inner: Volume,
}

/// A lightweight handle to a volume from the database.
#[napi(js_name = "VolumeHandle")]
pub struct JsVolumeHandle {
    inner: VolumeHandle,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsVolume {
    /// Create a new named volume.
    #[napi(factory)]
    pub async fn create(config: VolumeConfig) -> Result<JsVolume> {
        let mut builder = Volume::builder(&config.name);
        if let Some(quota) = config.quota_mib {
            builder = builder.quota(quota);
        }
        if let Some(ref labels) = config.labels {
            for (k, v) in labels {
                builder = builder.label(k, v);
            }
        }
        let inner = builder.create().await.map_err(to_napi_error)?;
        Ok(JsVolume { inner })
    }

    /// Get a lightweight handle to an existing volume.
    #[napi]
    pub async fn get(name: String) -> Result<JsVolumeHandle> {
        let handle = Volume::get(&name).await.map_err(to_napi_error)?;
        Ok(JsVolumeHandle { inner: handle })
    }

    /// List all volumes.
    #[napi]
    pub async fn list() -> Result<Vec<VolumeInfo>> {
        let handles = Volume::list().await.map_err(to_napi_error)?;
        Ok(handles.iter().map(volume_handle_to_info).collect())
    }

    /// Remove a volume.
    #[napi(js_name = "remove")]
    pub async fn remove_static(name: String) -> Result<()> {
        Volume::remove(&name).await.map_err(to_napi_error)
    }

    /// Volume name.
    #[napi(getter)]
    pub fn name(&self) -> String {
        self.inner.name().to_string()
    }

    /// Host path of the volume.
    #[napi(getter)]
    pub fn path(&self) -> String {
        self.inner.path().to_string_lossy().to_string()
    }
}

#[napi]
impl JsVolumeHandle {
    /// Volume name.
    #[napi(getter)]
    pub fn name(&self) -> String {
        self.inner.name().to_string()
    }

    /// Size quota in MiB, if set.
    #[napi(getter)]
    pub fn quota_mib(&self) -> Option<u32> {
        self.inner.quota_mib()
    }

    /// Used bytes on disk.
    #[napi(getter)]
    pub fn used_bytes(&self) -> f64 {
        self.inner.used_bytes() as f64
    }

    /// Key-value labels.
    #[napi(getter)]
    pub fn labels(&self) -> HashMap<String, String> {
        self.inner
            .labels()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Creation timestamp as ms since epoch.
    #[napi(getter)]
    pub fn created_at(&self) -> Option<f64> {
        opt_datetime_to_ms(&self.inner.created_at())
    }

    /// Remove this volume.
    #[napi]
    pub async fn remove(&self) -> Result<()> {
        self.inner.remove().await.map_err(to_napi_error)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn volume_handle_to_info(handle: &VolumeHandle) -> VolumeInfo {
    VolumeInfo {
        name: handle.name().to_string(),
        quota_mib: handle.quota_mib(),
        used_bytes: handle.used_bytes() as f64,
        labels: handle
            .labels()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        created_at: opt_datetime_to_ms(&handle.created_at()),
    }
}
