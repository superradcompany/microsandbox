//! Owned file handles remain bound to their opening connection and runtime generation.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use bytes::Bytes;

use super::{
    fs::{self, AgentFsHandle, FsEntry, FsMetadata, FsReadStream, FsSetAttrs, FsWriteSink},
    state::RuntimeSession,
};
use crate::{MicrosandboxError, MicrosandboxResult, agent::AgentClient};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An open guest file or directory bound to the connection that opened it.
///
/// It retains that run independently of the Sandbox. Explicit close reports errors;
/// dropping the last handle/stream attempts bounded best-effort close. A restart
/// never redirects this handle to the new run. Closing while a stream is active
/// may interrupt that stream; finish streams before closing when their output matters.
pub struct FsHandle {
    inner: Arc<FsHandleState>,
}

pub(super) struct FsHandleState {
    raw: AgentFsHandle,
    client: Arc<AgentClient>,
    runtime: Option<Arc<RuntimeSession>>,
    closed: AtomicBool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FsHandle {
    pub(super) fn new(
        raw: AgentFsHandle,
        client: Arc<AgentClient>,
        runtime: Option<Arc<RuntimeSession>>,
    ) -> Self {
        Self {
            inner: Arc::new(FsHandleState {
                raw,
                client,
                runtime,
                closed: AtomicBool::new(false),
            }),
        }
    }

    pub(super) async fn open(
        client: Arc<AgentClient>,
        path: String,
        options: Option<super::fs::FsOpenOptions>,
        runtime: Option<Arc<RuntimeSession>>,
    ) -> MicrosandboxResult<Self> {
        let (mut sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if sender.is_closed() {
                return;
            }
            let opening = async move {
                let raw = match options {
                    Some(options) => fs::agent::open_file(&client, &path, options).await?,
                    None => fs::agent::open_dir(&client, &path).await?,
                };
                Ok::<_, MicrosandboxError>(Self::new(raw, client, runtime))
            };
            tokio::pin!(opening);
            tokio::select! {
                result = &mut opening => { let _ = sender.send(result); }
                _ = sender.closed() => {
                    // Drain a late open response so its published file is closed
                    // even when the caller disappeared before receiving the ID.
                    // Older agents cannot cancel an open. After this bound cleanup
                    // becomes best effort and the retained run must be released.
                    let _ = tokio::time::timeout(Duration::from_secs(5), opening).await;
                }
            }
        });
        receiver.await.map_err(|_| {
            MicrosandboxError::SandboxFsOps(
                "filesystem open task ended before returning a result".into(),
            )
        })?
    }

    pub(super) fn raw(&self) -> AgentFsHandle {
        self.inner.raw
    }

    pub(super) fn transfer_close(self) {
        self.inner.closed.store(true, Ordering::Release);
    }

    /// Read bytes from this file at the selected offset.
    pub async fn read(&self, offset: u64, len: Option<u64>) -> MicrosandboxResult<Bytes> {
        self.inner.check_open()?;
        fs::agent::read_handle(self.inner.client.clone(), self.inner.raw, offset, len).await
    }

    /// Stream bytes while retaining this open file and its original run.
    pub async fn read_stream(
        &self,
        offset: u64,
        len: Option<u64>,
    ) -> MicrosandboxResult<FsReadStream> {
        self.inner.check_open()?;
        let mut stream = fs::agent::read_handle_stream(
            self.inner.client.clone(),
            self.inner.raw,
            offset,
            len,
            None,
        )
        .await?;
        stream.file = Some(self.inner.clone());
        Ok(stream)
    }

    /// Write bytes at the selected offset without changing the handle's destination.
    pub async fn write(&self, offset: u64, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        self.inner.check_open()?;
        fs::agent::write_handle(
            self.inner.client.clone(),
            self.inner.raw,
            offset,
            data.as_ref(),
        )
        .await
    }

    /// Stream writes while retaining this file and run until close or drop.
    pub async fn write_stream(
        &self,
        offset: u64,
        len: Option<u64>,
    ) -> MicrosandboxResult<FsWriteSink> {
        self.inner.check_open()?;
        let mut sink = fs::agent::write_handle_stream(
            self.inner.client.clone(),
            self.inner.raw,
            offset,
            len,
            None,
            false,
        )
        .await?;
        sink.retain_file(self.inner.clone());
        Ok(sink)
    }

    /// Read the next directory entries from this handle.
    pub async fn read_dir(&self, limit: Option<u32>) -> MicrosandboxResult<Vec<FsEntry>> {
        self.inner.check_open()?;
        fs::agent::read_dir_handle(&self.inner.client, self.inner.raw, limit).await
    }

    /// Fetch metadata from the original run.
    pub async fn stat(&self) -> MicrosandboxResult<FsMetadata> {
        self.inner.check_open()?;
        fs::agent::stat_handle(&self.inner.client, self.inner.raw).await
    }

    /// Update metadata on the original run.
    pub async fn set_stat(&self, attrs: FsSetAttrs) -> MicrosandboxResult<()> {
        self.inner.check_open()?;
        fs::agent::set_stat_handle(&self.inner.client, self.inner.raw, attrs).await
    }

    /// Close this handle, reporting any error. The value is consumed even on error.
    pub async fn close(self) -> MicrosandboxResult<()> {
        // Do not automatically retry a delivered close: the peer could have
        // already released the numeric ID before its acknowledgement was lost.
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        fs::agent::close_handle(&self.inner.client, self.inner.raw).await
    }
}

impl FsHandleState {
    fn check_open(&self) -> MicrosandboxResult<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(MicrosandboxError::SandboxFsOps(
                "filesystem handle is closed".into(),
            ));
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for FsHandleState {
    fn drop(&mut self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let Ok(executor) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let client = self.client.clone();
        let raw = self.raw;
        let runtime = self.runtime.take();
        executor.spawn(async move {
            // Only destructor cleanup has this bound. Explicit close keeps the
            // caller's ordinary cancellation/error contract.
            let _runtime = runtime;
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                fs::agent::close_handle(&client, raw),
            )
            .await;
        });
    }
}
