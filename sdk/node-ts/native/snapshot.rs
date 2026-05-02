use std::collections::HashMap;
use std::path::PathBuf;

use microsandbox::snapshot::ExportOpts as RustExportOpts;
use microsandbox::{
    Snapshot as RustSnapshot, SnapshotFormat as RustSnapshotFormat,
    SnapshotHandle as RustSnapshotHandle, UpperVerifyStatus as RustUpperVerifyStatus,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A snapshot artifact on disk.
#[napi(js_name = "Snapshot")]
pub struct JsSnapshot {
    inner: RustSnapshot,
}

/// Lightweight snapshot handle from the local index.
#[napi(js_name = "SnapshotHandle")]
pub struct JsSnapshotHandle {
    inner: RustSnapshotHandle,
}

/// Options for `Snapshot.export()`.
#[derive(Default)]
#[napi(object, js_name = "ExportOpts")]
pub struct JsExportOpts {
    /// Walk the parent chain and include each ancestor (no-op in v1).
    pub with_parents: Option<bool>,
    /// Bundle the OCI image cache for offline transport.
    pub with_image: Option<bool>,
    /// Skip zstd compression and write a plain `.tar`.
    pub plain_tar: Option<bool>,
}

/// Result of `Snapshot.verify()`.
///
/// `upperKind` is `"notRecorded"` when no integrity hash was stored,
/// or `"verified"` when the recorded hash matched the recomputed one.
/// `upperAlgorithm` and `upperDigest` are populated only when
/// `upperKind === "verified"`.
#[napi(object, js_name = "SnapshotVerifyReport")]
pub struct JsSnapshotVerifyReport {
    pub digest: String,
    pub path: String,
    pub upper_kind: String,
    pub upper_algorithm: Option<String>,
    pub upper_digest: Option<String>,
}

/// Options for `Snapshot.remove()` (instance and static).
#[derive(Default)]
#[napi(object, js_name = "SnapshotRemoveOptions")]
pub struct JsSnapshotRemoveOpts {
    pub force: Option<bool>,
}

/// Snapshot index info from the local DB cache.
#[napi(object, js_name = "SnapshotInfo")]
pub struct JsSnapshotInfo {
    pub digest: String,
    pub name: Option<String>,
    pub parent_digest: Option<String>,
    pub image_ref: String,
    /// `"raw"` or `"qcow2"`.
    pub format: String,
    pub size_bytes: Option<f64>,
    pub created_at: f64,
    pub path: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsSnapshot {
    //----------------------------------------------------------------------------------------------
    // Static management
    //----------------------------------------------------------------------------------------------

    #[napi]
    pub async fn open(path_or_name: String) -> Result<JsSnapshot> {
        let snap = RustSnapshot::open(&path_or_name)
            .await
            .map_err(to_napi_error)?;
        Ok(JsSnapshot::from_rust(snap))
    }

    #[napi]
    pub async fn get(name_or_digest: String) -> Result<JsSnapshotHandle> {
        let h = RustSnapshot::get(&name_or_digest)
            .await
            .map_err(to_napi_error)?;
        Ok(JsSnapshotHandle::from_rust(h))
    }

    #[napi]
    pub async fn list() -> Result<Vec<JsSnapshotInfo>> {
        let handles = RustSnapshot::list().await.map_err(to_napi_error)?;
        Ok(handles.iter().map(snapshot_handle_to_info).collect())
    }

    /// Walk `dir` and parse each subdirectory's `manifest.json`. Does
    /// not touch the local index — useful for inspecting external
    /// snapshot collections (e.g. a mounted volume of artifacts that
    /// were never imported).
    #[napi(js_name = "listDir")]
    pub async fn list_dir(dir: String) -> Result<Vec<JsSnapshot>> {
        let snapshots = RustSnapshot::list_dir(PathBuf::from(dir))
            .await
            .map_err(to_napi_error)?;
        Ok(snapshots.into_iter().map(JsSnapshot::from_rust).collect())
    }

    #[napi(js_name = "remove")]
    pub async fn remove_static(
        path_or_name: String,
        opts: Option<JsSnapshotRemoveOpts>,
    ) -> Result<()> {
        let force = opts.and_then(|o| o.force).unwrap_or(false);
        RustSnapshot::remove(&path_or_name, force)
            .await
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn reindex(dir: Option<String>) -> Result<u32> {
        let dir = match dir {
            Some(p) => PathBuf::from(p),
            None => microsandbox::config::config().snapshots_dir(),
        };
        let n = RustSnapshot::reindex(&dir).await.map_err(to_napi_error)?;
        Ok(n as u32)
    }

    #[napi]
    pub async fn export(
        name_or_path: String,
        out: String,
        opts: Option<JsExportOpts>,
    ) -> Result<()> {
        let opts = opts.unwrap_or_default();
        let rust_opts = RustExportOpts {
            with_parents: opts.with_parents.unwrap_or(false),
            with_image: opts.with_image.unwrap_or(false),
            plain_tar: opts.plain_tar.unwrap_or(false),
        };
        RustSnapshot::export(&name_or_path, &PathBuf::from(out), rust_opts)
            .await
            .map_err(to_napi_error)
    }

    #[napi(js_name = "import")]
    pub async fn import_(archive: String, dest: Option<String>) -> Result<JsSnapshotHandle> {
        let dest = dest.map(PathBuf::from);
        let h = RustSnapshot::import(&PathBuf::from(archive), dest.as_deref())
            .await
            .map_err(to_napi_error)?;
        Ok(JsSnapshotHandle::from_rust(h))
    }

    //----------------------------------------------------------------------------------------------
    // Instance accessors (mirror PyVolume's getter style)
    //----------------------------------------------------------------------------------------------

    #[napi(getter)]
    pub fn path(&self) -> String {
        self.inner.path().display().to_string()
    }

    #[napi(getter)]
    pub fn digest(&self) -> String {
        self.inner.digest().to_string()
    }

    #[napi(getter)]
    pub fn size_bytes(&self) -> BigInt {
        BigInt::from(self.inner.size_bytes())
    }

    #[napi(getter)]
    pub fn image_ref(&self) -> String {
        self.inner.manifest().image.reference.clone()
    }

    #[napi(getter)]
    pub fn image_manifest_digest(&self) -> String {
        self.inner.manifest().image.manifest_digest.clone()
    }

    #[napi(getter)]
    pub fn format(&self) -> String {
        format_str(self.inner.manifest().format).into()
    }

    #[napi(getter)]
    pub fn fstype(&self) -> String {
        self.inner.manifest().fstype.clone()
    }

    #[napi(getter)]
    pub fn parent(&self) -> Option<String> {
        self.inner.manifest().parent.clone()
    }

    #[napi(getter)]
    pub fn created_at(&self) -> String {
        self.inner.manifest().created_at.clone()
    }

    #[napi(getter)]
    pub fn labels(&self) -> HashMap<String, String> {
        self.inner
            .manifest()
            .labels
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    #[napi(getter)]
    pub fn source_sandbox(&self) -> Option<String> {
        self.inner.manifest().source_sandbox.clone()
    }

    #[napi]
    pub async fn verify(&self) -> Result<JsSnapshotVerifyReport> {
        let report = self.inner.verify().await.map_err(to_napi_error)?;
        Ok(verify_report_to_js(report))
    }
}

impl JsSnapshot {
    /// Wrap a Rust `Snapshot`. Used by `SnapshotBuilder.create()` and
    /// the `SandboxHandle.snapshot{,_to}` paths.
    pub fn from_rust(inner: RustSnapshot) -> Self {
        Self { inner }
    }
}

#[napi]
impl JsSnapshotHandle {
    #[napi(getter)]
    pub fn digest(&self) -> String {
        self.inner.digest().to_string()
    }

    #[napi(getter)]
    pub fn name(&self) -> Option<String> {
        self.inner.name().map(|s| s.to_string())
    }

    #[napi(getter)]
    pub fn parent_digest(&self) -> Option<String> {
        self.inner.parent_digest().map(|s| s.to_string())
    }

    #[napi(getter)]
    pub fn image_ref(&self) -> String {
        self.inner.image_ref().to_string()
    }

    #[napi(getter)]
    pub fn format(&self) -> String {
        format_str(self.inner.format()).into()
    }

    #[napi(getter)]
    pub fn size_bytes(&self) -> Option<BigInt> {
        self.inner.size_bytes().map(BigInt::from)
    }

    #[napi(getter)]
    pub fn created_at(&self) -> f64 {
        self.inner.created_at().and_utc().timestamp_millis() as f64
    }

    #[napi(getter)]
    pub fn path(&self) -> String {
        self.inner.path().display().to_string()
    }

    #[napi]
    pub async fn open(&self) -> Result<JsSnapshot> {
        let snap = self.inner.open().await.map_err(to_napi_error)?;
        Ok(JsSnapshot::from_rust(snap))
    }

    #[napi]
    pub async fn remove(&self, opts: Option<JsSnapshotRemoveOpts>) -> Result<()> {
        let force = opts.and_then(|o| o.force).unwrap_or(false);
        self.inner.remove(force).await.map_err(to_napi_error)
    }
}

impl JsSnapshotHandle {
    pub fn from_rust(inner: RustSnapshotHandle) -> Self {
        Self { inner }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn format_str(f: RustSnapshotFormat) -> &'static str {
    match f {
        RustSnapshotFormat::Raw => "raw",
        RustSnapshotFormat::Qcow2 => "qcow2",
    }
}

fn snapshot_handle_to_info(h: &RustSnapshotHandle) -> JsSnapshotInfo {
    JsSnapshotInfo {
        digest: h.digest().to_string(),
        name: h.name().map(|s| s.to_string()),
        parent_digest: h.parent_digest().map(|s| s.to_string()),
        image_ref: h.image_ref().to_string(),
        format: format_str(h.format()).into(),
        size_bytes: h.size_bytes().map(|n| n as f64),
        created_at: h.created_at().and_utc().timestamp_millis() as f64,
        path: h.path().display().to_string(),
    }
}

fn verify_report_to_js(
    report: microsandbox::snapshot::SnapshotVerifyReport,
) -> JsSnapshotVerifyReport {
    let (kind, algorithm, digest) = match report.upper {
        RustUpperVerifyStatus::NotRecorded => ("notRecorded".to_string(), None, None),
        RustUpperVerifyStatus::Verified { algorithm, digest } => {
            ("verified".to_string(), Some(algorithm), Some(digest))
        }
    };
    JsSnapshotVerifyReport {
        digest: report.digest,
        path: report.path.display().to_string(),
        upper_kind: kind,
        upper_algorithm: algorithm,
        upper_digest: digest,
    }
}

// Suppress dead_code for the unused-in-tests fields (napi-rs registers
// them at the codegen level which `cargo test` doesn't see).
#[cfg(test)]
#[allow(dead_code)]
fn _exports_used() {
    let _ = snapshot_handle_to_info;
    let _ = format_str;
}
