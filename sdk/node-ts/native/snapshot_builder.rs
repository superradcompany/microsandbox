use microsandbox::snapshot::{Snapshot as RustSnapshot, SnapshotBuilder as RustSnapshotBuilder};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;
use crate::snapshot::JsSnapshot;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Built snapshot configuration produced by `SnapshotBuilder.build()`.
#[derive(Clone)]
#[napi(object, js_name = "SnapshotConfig")]
pub struct JsSnapshotConfig {
    pub name: String,
    pub source_sandbox: Option<String>,
    pub dest_dir: Option<String>,
    pub labels: Vec<JsSnapshotLabel>,
    pub force: bool,
    pub record_integrity: bool,
    pub resumable: bool,
}

#[derive(Clone)]
#[napi(object, js_name = "SnapshotLabel")]
pub struct JsSnapshotLabel {
    pub key: String,
    pub value: String,
}

/// Fluent builder for a snapshot. Returned by `Snapshot.builder(name)`.
/// The source sandbox is set with `fromSandbox()` and is required.
#[napi(js_name = "SnapshotBuilder")]
pub struct JsSnapshotBuilder {
    inner: Option<RustSnapshotBuilder>,
    name: String,
    source_sandbox: Option<String>,
    dest_dir: Option<String>,
    labels: Vec<(String, String)>,
    force: bool,
    record_integrity: bool,
    resumable: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsSnapshotBuilder {
    #[napi(constructor)]
    pub fn new(name: String) -> Self {
        Self {
            inner: Some(RustSnapshot::builder(&name)),
            name,
            source_sandbox: None,
            dest_dir: None,
            labels: Vec::new(),
            force: false,
            record_integrity: false,
            resumable: false,
        }
    }

    /// Create the artifact under this parent directory instead of the
    /// default snapshots store. The artifact lands at `destDir/<name>`.
    #[napi(js_name = "destDir")]
    pub fn dest_dir(&mut self, dest_dir: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.dest_dir(&dest_dir));
        self.dest_dir = Some(dest_dir);
        self
    }

    /// Set the source sandbox to snapshot. Required.
    // `from_*` normally takes no self, but napi setters mutate in place and
    // the JS-facing name `fromSandbox` is the contract.
    #[allow(clippy::wrong_self_convention)]
    #[napi(js_name = "fromSandbox")]
    pub fn from_sandbox(&mut self, source_sandbox: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.from_sandbox(source_sandbox.clone()));
        self.source_sandbox = Some(source_sandbox);
        self
    }

    /// Attach a key-value label. May be called multiple times.
    #[napi]
    pub fn label(&mut self, key: String, value: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.label(key.clone(), value.clone()));
        self.labels.push((key, value));
        self
    }

    /// Overwrite an existing artifact at the destination.
    #[napi]
    pub fn force(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.force());
        self.force = true;
        self
    }

    /// Compute and record content integrity at create time.
    #[napi(js_name = "recordIntegrity")]
    pub fn record_integrity(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.record_integrity());
        self.record_integrity = true;
        self
    }

    /// Request a future resumable snapshot.
    #[napi]
    pub fn resumable(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.resumable());
        self.resumable = true;
        self
    }

    /// Snapshot the accumulated configuration.
    #[napi]
    pub fn build(&self) -> JsSnapshotConfig {
        JsSnapshotConfig {
            name: self.name.clone(),
            source_sandbox: self.source_sandbox.clone(),
            dest_dir: self.dest_dir.clone(),
            labels: self
                .labels
                .iter()
                .map(|(k, v)| JsSnapshotLabel {
                    key: k.clone(),
                    value: v.clone(),
                })
                .collect(),
            force: self.force,
            record_integrity: self.record_integrity,
            resumable: self.resumable,
        }
    }

    /// Create the snapshot.
    ///
    /// # Safety
    /// `&mut self` async requires the napi-rs `unsafe` tag. We drain
    /// the inner builder synchronously before awaiting, so it's
    /// effectively safe. JS callers see a normal
    /// `create(): Promise<Snapshot>`.
    #[napi]
    pub async unsafe fn create(&mut self) -> Result<JsSnapshot> {
        let b = self
            .inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("SnapshotBuilder already consumed"))?;
        let snap = b.create().await.map_err(to_napi_error)?;
        Ok(JsSnapshot::from_rust(snap))
    }
}

impl JsSnapshotBuilder {
    fn take_inner(&mut self) -> RustSnapshotBuilder {
        self.inner
            .take()
            .expect("SnapshotBuilder used after consumption")
    }
}
