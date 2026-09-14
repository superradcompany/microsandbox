use std::collections::{BTreeMap, HashMap};

use microsandbox::SnapshotCopyBuilder as RustSnapshotCopyBuilder;
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for copying a snapshot archive with replacement metadata.
#[napi(js_name = "SnapshotCopyBuilder")]
pub struct JsSnapshotCopyBuilder {
    inner: Option<RustSnapshotCopyBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsSnapshotCopyBuilder {
    /// Replace the copied snapshot's labels.
    #[napi]
    pub fn labels(&mut self, labels: HashMap<String, String>) -> Result<&Self> {
        let builder = self.take_inner()?;
        self.inner = Some(builder.labels(labels.into_iter().collect::<BTreeMap<_, _>>()));
        Ok(self)
    }

    /// Choose whether to calculate and record disk integrity in the copy.
    #[napi(js_name = "recordIntegrity")]
    pub fn record_integrity(&mut self, enabled: bool) -> Result<&Self> {
        let builder = self.take_inner()?;
        self.inner = Some(builder.record_integrity(enabled));
        Ok(self)
    }

    /// Write the configured snapshot archive.
    /// Returns an unsupported-operation error when artifact archives are unavailable.
    #[napi(ts_return_type = "Promise<void>")]
    pub fn save<'env>(&mut self, env: &'env Env) -> Result<PromiseRaw<'env, ()>> {
        // Consume the builder on the JS thread. The future owns its state and
        // never holds a reference to this JavaScript object.
        let builder = self.take_inner();
        env.spawn_future(async move {
            builder?.save().await.map_err(to_napi_error)?;
            Ok(())
        })
    }
}

impl JsSnapshotCopyBuilder {
    pub(crate) fn from_rust(inner: RustSnapshotCopyBuilder) -> Self {
        Self { inner: Some(inner) }
    }

    fn take_inner(&mut self) -> Result<RustSnapshotCopyBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("SnapshotCopyBuilder already consumed"))
    }
}
