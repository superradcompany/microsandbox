use std::collections::HashMap;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::size::Mebibytes;
use microsandbox::volume::{Volume as RustVolume, VolumeBuilder as RustVolumeBuilder};

use crate::error::to_napi_error;
use crate::volume::JsVolume;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Built volume configuration produced by `VolumeBuilder.build()`.
#[derive(Clone)]
#[napi(object, js_name = "VolumeConfig")]
pub struct JsVolumeConfig {
    pub name: String,
    pub kind: String,
    pub quota_mib: Option<u32>,
    pub capacity_mib: Option<u32>,
    pub labels: HashMap<String, String>,
}

/// Fluent builder for a named persistent volume.
#[napi(js_name = "VolumeBuilder")]
pub struct JsVolumeBuilder {
    inner: Option<RustVolumeBuilder>,
    name: String,
    kind: String,
    quota_mib: Option<u32>,
    capacity_mib: Option<u32>,
    labels: Vec<(String, String)>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsVolumeBuilder {
    #[napi(constructor)]
    pub fn new(name: String) -> Self {
        Self {
            inner: Some(RustVolumeBuilder::new(&name)),
            name,
            kind: "dir".to_string(),
            quota_mib: None,
            capacity_mib: None,
            labels: Vec::new(),
        }
    }

    /// Create a directory-backed named volume.
    #[napi]
    pub fn directory(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.directory());
        self.kind = "dir".to_string();
        self
    }

    /// Create a raw ext4 disk-backed named volume.
    #[napi]
    pub fn disk(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.disk());
        self.kind = "disk".to_string();
        self
    }

    /// Limit the volume's storage capacity (MiB). Omit for unlimited.
    #[napi]
    pub fn quota(&mut self, mib: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.quota(Mebibytes::from(mib)));
        self.quota_mib = Some(mib);
        self
    }

    /// Set disk volume capacity in MiB.
    #[napi]
    pub fn size(&mut self, mib: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.size(Mebibytes::from(mib)));
        self.capacity_mib = Some(mib);
        self
    }

    /// Attach a key-value label. May be called multiple times.
    #[napi]
    pub fn label(&mut self, key: String, value: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.label(&key, &value));
        self.labels.push((key, value));
        self
    }

    /// Snapshot the accumulated configuration.
    #[napi]
    pub fn build(&self) -> JsVolumeConfig {
        JsVolumeConfig {
            name: self.name.clone(),
            kind: self.kind.clone(),
            quota_mib: self.quota_mib,
            capacity_mib: self.capacity_mib,
            labels: self.labels.iter().cloned().collect(),
        }
    }

    /// Create the volume.
    ///
    /// # Safety
    /// `&mut self` async requires the napi-rs `unsafe` tag. We drain the
    /// inner builder synchronously before awaiting, so it's effectively
    /// safe. JS callers see a normal `create(): Promise<Volume>`.
    #[napi]
    pub async unsafe fn create(&mut self) -> Result<JsVolume> {
        let b = self
            .inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("VolumeBuilder already consumed"))?;
        let v: RustVolume = b.create().await.map_err(to_napi_error)?;
        Ok(JsVolume::from_rust(v))
    }
}

impl JsVolumeBuilder {
    fn take_inner(&mut self) -> RustVolumeBuilder {
        self.inner
            .take()
            .expect("VolumeBuilder used after consumption")
    }
}
