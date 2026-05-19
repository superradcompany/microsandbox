use std::sync::Arc;

use microsandbox::sandbox::{
    FsEntry as RustFsEntry, FsEntryKind, FsMetadata as RustFsMetadata,
    FsReadStream as RustFsReadStream, FsWriteSink as RustFsWriteSink,
};
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

/// A streaming reader for file data from the sandbox.
///
/// Supports both manual `recv()` calls and `for await...of` iteration:
/// ```js
/// const stream = await sb.fs().readStream("/app/data.bin");
/// for await (const chunk of stream) {
///   processChunk(chunk);
/// }
/// ```
#[napi(async_iterator, js_name = "FsReadStream")]
pub struct JsFsReadStream {
    inner: Arc<Mutex<RustFsReadStream>>,
}

/// Streaming writer for guest files.
#[napi(js_name = "FsWriteSink")]
pub struct JsFsWriteSink {
    inner: Arc<Mutex<Option<RustFsWriteSink>>>,
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

    /// Read a file with streaming (~3 MiB chunks).
    #[napi(js_name = "readStream")]
    pub async fn read_stream(&self, path: String) -> Result<JsFsReadStream> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let stream = sb.fs().read_stream(&path).await.map_err(to_napi_error)?;
        Ok(JsFsReadStream {
            inner: Arc::new(Mutex::new(stream)),
        })
    }

    /// Write a file with streaming. Returns a sink the caller writes to.
    #[napi(js_name = "writeStream")]
    pub async fn write_stream(&self, path: String) -> Result<JsFsWriteSink> {
        let guard = self.sandbox.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let sink = sb.fs().write_stream(&path).await.map_err(to_napi_error)?;
        Ok(JsFsWriteSink {
            inner: Arc::new(Mutex::new(Some(sink))),
        })
    }
}

#[napi]
impl JsFsWriteSink {
    /// Write a chunk to the underlying file.
    #[napi]
    pub async fn write(&self, data: Buffer) -> Result<()> {
        let guard = self.inner.lock().await;
        let sink = guard
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason("write sink already closed"))?;
        sink.write(data.as_ref()).await.map_err(to_napi_error)
    }

    /// Flush and close the sink. Idempotent.
    #[napi]
    pub async fn close(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if let Some(sink) = guard.take() {
            sink.close().await.map_err(to_napi_error)?;
        }
        Ok(())
    }
}

#[napi]
impl JsFsReadStream {
    /// Receive the next chunk of data. Returns `null` when the stream ends.
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
impl AsyncGenerator for JsFsReadStream {
    type Yield = Buffer;
    type Next = ();
    type Return = ();

    fn next(
        &mut self,
        _value: Option<Self::Next>,
    ) -> impl Future<Output = Result<Option<Self::Yield>>> + Send + 'static {
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
