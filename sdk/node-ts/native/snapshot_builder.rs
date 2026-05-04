use std::path::PathBuf;

use microsandbox::snapshot::{
    Snapshot as RustSnapshot, SnapshotBuilder as RustSnapshotBuilder,
    SnapshotDestination as RustSnapshotDestination,
};
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
    pub source_sandbox: String,
    pub destination_kind: String, // "name" | "path" | "unset"
    pub destination_value: Option<String>,
    pub labels: Vec<JsSnapshotLabel>,
    pub force: bool,
    pub record_integrity: bool,
}

#[derive(Clone)]
#[napi(object, js_name = "SnapshotLabel")]
pub struct JsSnapshotLabel {
    pub key: String,
    pub value: String,
}

/// Fluent builder for a snapshot. Returned by `Snapshot.builder(name)`.
#[napi(js_name = "SnapshotBuilder")]
pub struct JsSnapshotBuilder {
    inner: Option<RustSnapshotBuilder>,
    source_sandbox: String,
    destination: Option<RustSnapshotDestination>,
    labels: Vec<(String, String)>,
    force: bool,
    record_integrity: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsSnapshotBuilder {
    #[napi(constructor)]
    pub fn new(source_sandbox: String) -> Self {
        Self {
            inner: Some(RustSnapshot::builder(&source_sandbox)),
            source_sandbox,
            destination: None,
            labels: Vec::new(),
            force: false,
            record_integrity: false,
        }
    }

    /// Set a bare name (resolved under the default snapshots dir).
    #[napi]
    pub fn name(&mut self, name: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.name(name.clone()));
        self.destination = Some(RustSnapshotDestination::Name(name));
        self
    }

    /// Set an explicit destination path.
    #[napi]
    pub fn path(&mut self, path: String) -> &Self {
        let prev = self.take_inner();
        let buf = PathBuf::from(&path);
        self.inner = Some(prev.path(buf.clone()));
        self.destination = Some(RustSnapshotDestination::Path(buf));
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

    /// Snapshot the accumulated configuration.
    #[napi]
    pub fn build(&self) -> JsSnapshotConfig {
        let (kind, value) = match &self.destination {
            Some(RustSnapshotDestination::Name(n)) => ("name".into(), Some(n.clone())),
            Some(RustSnapshotDestination::Path(p)) => {
                ("path".into(), Some(p.display().to_string()))
            }
            None => ("unset".into(), None),
        };
        JsSnapshotConfig {
            source_sandbox: self.source_sandbox.clone(),
            destination_kind: kind,
            destination_value: value,
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
