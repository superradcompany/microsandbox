use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use microsandbox::sandbox::FsEntry as RustFsEntry;
use microsandbox::sandbox::FsEntryKind as RustFsEntryKind;
use microsandbox::sandbox::FsMetadata as RustFsMetadata;
use microsandbox::volume::fs::{VolumeFs, VolumeFsReadStream, VolumeFsWriteSink};
use microsandbox::volume::{Volume, VolumeHandle};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

use crate::error::to_napi_error;
use crate::types::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[napi(js_name = "Volume")]
pub struct JsVolume {
    inner: Arc<Volume>,
}

#[napi(js_name = "VolumeHandle")]
pub struct JsVolumeHandle {
    inner: VolumeHandle,
    path: PathBuf,
}

#[napi(js_name = "VolumeFs")]
pub struct JsVolumeFs {
    path: PathBuf,
}

#[napi(async_iterator, js_name = "VolumeFsReadStream")]
pub struct JsVolumeFsReadStream {
    inner: Arc<Mutex<VolumeFsReadStream>>,
}

#[napi(js_name = "VolumeFsWriteSink")]
pub struct JsVolumeFsWriteSink {
    inner: Arc<Mutex<Option<VolumeFsWriteSink>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsVolume {
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
        Ok(JsVolume {
            inner: Arc::new(inner),
        })
    }

    #[napi]
    pub async fn get(name: String) -> Result<JsVolumeHandle> {
        let handle = Volume::get(&name).await.map_err(to_napi_error)?;
        let path = microsandbox::config::config()
            .volumes_dir()
            .join(handle.name());
        Ok(JsVolumeHandle {
            inner: handle,
            path,
        })
    }

    #[napi]
    pub async fn list() -> Result<Vec<VolumeInfo>> {
        let handles = Volume::list().await.map_err(to_napi_error)?;
        Ok(handles.iter().map(volume_handle_to_info).collect())
    }

    #[napi(js_name = "remove")]
    pub async fn remove_static(name: String) -> Result<()> {
        Volume::remove(&name).await.map_err(to_napi_error)
    }

    #[napi(getter)]
    pub fn name(&self) -> String {
        self.inner.name().to_string()
    }

    #[napi(getter)]
    pub fn path(&self) -> String {
        self.inner.path().to_string_lossy().to_string()
    }

    /// Host-side filesystem operations on this volume's directory.
    #[napi]
    pub fn fs(&self) -> JsVolumeFs {
        JsVolumeFs {
            path: self.inner.path().to_path_buf(),
        }
    }
}

impl JsVolume {
    /// Wrap a Rust `Volume`. Used by `VolumeBuilder.create()`.
    pub(crate) fn from_rust(v: Volume) -> Self {
        Self { inner: Arc::new(v) }
    }
}

#[napi]
impl JsVolumeHandle {
    #[napi(getter)]
    pub fn name(&self) -> String {
        self.inner.name().to_string()
    }

    #[napi(getter)]
    pub fn quota_mib(&self) -> Option<u32> {
        self.inner.quota_mib()
    }

    #[napi(getter)]
    pub fn used_bytes(&self) -> f64 {
        self.inner.used_bytes() as f64
    }

    #[napi(getter)]
    pub fn labels(&self) -> HashMap<String, String> {
        self.inner
            .labels()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    #[napi(getter)]
    pub fn created_at(&self) -> Option<f64> {
        opt_datetime_to_ms(&self.inner.created_at())
    }

    #[napi]
    pub async fn remove(&self) -> Result<()> {
        self.inner.remove().await.map_err(to_napi_error)
    }

    /// Host-side filesystem operations on this volume's directory.
    #[napi]
    pub fn fs(&self) -> JsVolumeFs {
        JsVolumeFs {
            path: self.path.clone(),
        }
    }
}

#[napi]
impl JsVolumeFs {
    fn make(&self) -> VolumeFs<'_> {
        VolumeFs::from_path(self.path.clone())
    }

    #[napi]
    pub async fn read(&self, path: String) -> Result<Buffer> {
        let bytes = self.make().read(&path).await.map_err(to_napi_error)?;
        Ok(bytes.to_vec().into())
    }

    #[napi]
    pub async fn read_string(&self, path: String) -> Result<String> {
        self.make()
            .read_to_string(&path)
            .await
            .map_err(to_napi_error)
    }

    #[napi(js_name = "readStream")]
    pub async fn read_stream(&self, path: String) -> Result<JsVolumeFsReadStream> {
        let stream = self
            .make()
            .read_stream(&path)
            .await
            .map_err(to_napi_error)?;
        Ok(JsVolumeFsReadStream {
            inner: Arc::new(Mutex::new(stream)),
        })
    }

    #[napi]
    pub async fn write(&self, path: String, data: Buffer) -> Result<()> {
        let bytes: Vec<u8> = data.to_vec();
        self.make()
            .write(&path, &bytes)
            .await
            .map_err(to_napi_error)
    }

    #[napi(js_name = "writeStream")]
    pub async fn write_stream(&self, path: String) -> Result<JsVolumeFsWriteSink> {
        let sink = self
            .make()
            .write_stream(&path)
            .await
            .map_err(to_napi_error)?;
        Ok(JsVolumeFsWriteSink {
            inner: Arc::new(Mutex::new(Some(sink))),
        })
    }

    #[napi]
    pub async fn list(&self, path: String) -> Result<Vec<FsEntry>> {
        let entries = self.make().list(&path).await.map_err(to_napi_error)?;
        Ok(entries.iter().map(fs_entry_to_js).collect())
    }

    #[napi]
    pub async fn mkdir(&self, path: String) -> Result<()> {
        self.make().mkdir(&path).await.map_err(to_napi_error)
    }

    #[napi]
    pub async fn remove_dir(&self, path: String) -> Result<()> {
        self.make().remove_dir(&path).await.map_err(to_napi_error)
    }

    #[napi]
    pub async fn remove(&self, path: String) -> Result<()> {
        self.make().remove(&path).await.map_err(to_napi_error)
    }

    #[napi]
    pub async fn copy(&self, from: String, to: String) -> Result<()> {
        self.make().copy(&from, &to).await.map_err(to_napi_error)
    }

    #[napi]
    pub async fn rename(&self, from: String, to: String) -> Result<()> {
        self.make().rename(&from, &to).await.map_err(to_napi_error)
    }

    #[napi]
    pub async fn stat(&self, path: String) -> Result<FsMetadata> {
        let meta = self.make().stat(&path).await.map_err(to_napi_error)?;
        Ok(fs_metadata_to_js(&meta))
    }

    #[napi]
    pub async fn exists(&self, path: String) -> Result<bool> {
        self.make().exists(&path).await.map_err(to_napi_error)
    }
}

#[napi]
impl JsVolumeFsReadStream {
    #[napi]
    pub async fn recv(&self) -> Result<Option<Buffer>> {
        let mut guard = self.inner.lock().await;
        match guard.recv().await.map_err(to_napi_error)? {
            Some(bytes) => Ok(Some(bytes.to_vec().into())),
            None => Ok(None),
        }
    }
}

#[napi]
impl AsyncGenerator for JsVolumeFsReadStream {
    type Yield = Buffer;
    type Next = ();
    type Return = ();

    fn next(
        &mut self,
        _value: Option<Self::Next>,
    ) -> impl std::future::Future<Output = Result<Option<Self::Yield>>> + Send + 'static {
        let inner = Arc::clone(&self.inner);
        async move {
            let mut guard = inner.lock().await;
            match guard.recv().await.map_err(to_napi_error)? {
                Some(bytes) => Ok(Some(bytes.to_vec().into())),
                None => Ok(None),
            }
        }
    }
}

#[napi]
impl JsVolumeFsWriteSink {
    #[napi]
    pub async fn write(&self, data: Buffer) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let sink = guard
            .as_mut()
            .ok_or_else(|| napi::Error::from_reason("write sink already closed"))?;
        sink.write(data.as_ref()).await.map_err(to_napi_error)
    }

    #[napi]
    pub async fn close(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if let Some(sink) = guard.take() {
            sink.close().await.map_err(to_napi_error)?;
        }
        Ok(())
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

fn fs_entry_kind_str(kind: &RustFsEntryKind) -> &'static str {
    match kind {
        RustFsEntryKind::File => "file",
        RustFsEntryKind::Directory => "directory",
        RustFsEntryKind::Symlink => "symlink",
        RustFsEntryKind::Other => "other",
    }
}

fn fs_entry_to_js(entry: &RustFsEntry) -> FsEntry {
    FsEntry {
        path: entry.path.clone(),
        kind: fs_entry_kind_str(&entry.kind).to_string(),
        size: entry.size as f64,
        mode: entry.mode,
        modified: entry.modified.as_ref().map(datetime_to_ms),
    }
}

fn fs_metadata_to_js(meta: &RustFsMetadata) -> FsMetadata {
    FsMetadata {
        kind: fs_entry_kind_str(&meta.kind).to_string(),
        size: meta.size as f64,
        mode: meta.mode,
        readonly: meta.readonly,
        modified: meta.modified.as_ref().map(datetime_to_ms),
        created: meta.created.as_ref().map(datetime_to_ms),
    }
}
