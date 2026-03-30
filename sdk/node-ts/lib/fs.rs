use std::sync::Arc;

use microsandbox::sandbox::{FsEntry as RustFsEntry, FsEntryKind, FsMetadata as RustFsMetadata};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

use crate::error::to_napi_error;
use crate::types::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Filesystem operations on a running sandbox (via agent protocol).
#[napi(js_name = "SandboxFs")]
pub struct JsSandboxFs {
    sandbox: Arc<Mutex<Option<microsandbox::sandbox::Sandbox>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl JsSandboxFs {
    pub fn new(sandbox: Arc<Mutex<Option<microsandbox::sandbox::Sandbox>>>) -> Self {
        Self { sandbox }
    }
}

#[napi]
impl JsSandboxFs {
    /// Read a file as a Buffer.
    #[napi]
    pub async fn read(&self, path: String) -> Result<Buffer> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let data = sb.fs().read(&path).await.map_err(to_napi_error)?;
        Ok(data.to_vec().into())
    }

    /// Read a file as a UTF-8 string.
    #[napi]
    pub async fn read_string(&self, path: String) -> Result<String> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.fs().read_to_string(&path).await.map_err(to_napi_error)
    }

    /// Write data to a file (accepts Buffer or string).
    #[napi]
    pub async fn write(&self, path: String, data: Buffer) -> Result<()> {
        let bytes: Vec<u8> = data.to_vec();
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.fs().write(&path, &bytes).await.map_err(to_napi_error)
    }

    /// List directory contents.
    #[napi]
    pub async fn list(&self, path: String) -> Result<Vec<FsEntry>> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let entries = sb.fs().list(&path).await.map_err(to_napi_error)?;
        Ok(entries.iter().map(fs_entry_to_js).collect())
    }

    /// Create a directory.
    #[napi]
    pub async fn mkdir(&self, path: String) -> Result<()> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.fs().mkdir(&path).await.map_err(to_napi_error)
    }

    /// Remove a directory.
    #[napi]
    pub async fn remove_dir(&self, path: String) -> Result<()> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.fs().remove_dir(&path).await.map_err(to_napi_error)
    }

    /// Remove a file.
    #[napi]
    pub async fn remove(&self, path: String) -> Result<()> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.fs().remove(&path).await.map_err(to_napi_error)
    }

    /// Copy a file within the sandbox.
    #[napi]
    pub async fn copy(&self, from: String, to: String) -> Result<()> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.fs().copy(&from, &to).await.map_err(to_napi_error)
    }

    /// Rename a file within the sandbox.
    #[napi]
    pub async fn rename(&self, from: String, to: String) -> Result<()> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.fs().rename(&from, &to).await.map_err(to_napi_error)
    }

    /// Get file or directory metadata.
    #[napi]
    pub async fn stat(&self, path: String) -> Result<FsMetadata> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let meta = sb.fs().stat(&path).await.map_err(to_napi_error)?;
        Ok(fs_metadata_to_js(&meta))
    }

    /// Check if a path exists.
    #[napi]
    pub async fn exists(&self, path: String) -> Result<bool> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.fs().exists(&path).await.map_err(to_napi_error)
    }

    /// Copy a file from the host into the sandbox.
    #[napi]
    pub async fn copy_from_host(&self, host_path: String, guest_path: String) -> Result<()> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.fs()
            .copy_from_host(&host_path, &guest_path)
            .await
            .map_err(to_napi_error)
    }

    /// Copy a file from the sandbox to the host.
    #[napi]
    pub async fn copy_to_host(&self, guest_path: String, host_path: String) -> Result<()> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.fs()
            .copy_to_host(&guest_path, &host_path)
            .await
            .map_err(to_napi_error)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn fs_entry_kind_str(kind: &FsEntryKind) -> &'static str {
    match kind {
        FsEntryKind::File => "file",
        FsEntryKind::Directory => "directory",
        FsEntryKind::Symlink => "symlink",
        FsEntryKind::Other => "other",
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

fn consumed_error() -> napi::Error {
    napi::Error::from_reason("Sandbox handle has been consumed (detached or removed)")
}
