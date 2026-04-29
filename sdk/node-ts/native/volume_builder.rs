use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::size::Mebibytes;
use microsandbox::volume::{Volume as RustVolume, VolumeBuilder as RustVolumeBuilder};

use crate::error::to_napi_error;
use crate::volume::JsVolume;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for a named persistent volume.
#[napi(js_name = "VolumeBuilder")]
pub struct JsVolumeBuilder {
    inner: Option<RustVolumeBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsVolumeBuilder {
    #[napi(constructor)]
    pub fn new(name: String) -> Self {
        Self {
            inner: Some(RustVolumeBuilder::new(name)),
        }
    }

    /// Limit the volume's storage capacity (MiB). Omit for unlimited.
    #[napi]
    pub fn quota(&mut self, mib: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.quota(Mebibytes::from(mib)));
        self
    }

    /// Attach a key-value label. May be called multiple times.
    #[napi]
    pub fn label(&mut self, key: String, value: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.label(key, value));
        self
    }

    /// Create the volume.
    ///
    /// Marked `unsafe` only because `napi-rs` requires `&mut self` async
    /// methods to be tagged that way (a half-mutated struct could be
    /// observed mid-await). Practically it's safe: we take the inner
    /// builder synchronously before the await point, leaving an empty
    /// `Option` behind that subsequent calls reject. JS users do not see
    /// the `unsafe` marker.
    ///
    /// # Safety
    /// The await-point hazard does not apply here because we drain the
    /// inner builder before awaiting.
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
