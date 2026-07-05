//! Filesystem operations on a running sandbox.
//!
//! [`SandboxFsOps`] provides methods to read, write, list, and manipulate files
//! inside a running sandbox. Path-style helpers dispatch through the
//! [`SandboxBackend`](crate::backend::SandboxBackend) trait. Low-level handle
//! helpers use the live local agent client because agentd scopes handles to a
//! relay client; cloud returns per-method `Unsupported` until cloud guest-fs
//! lands.

use std::{path::Path, sync::Arc};

use bytes::Bytes;
use microsandbox_protocol::{
    fs::{FsData, FsEntryInfo, FsResponse},
    message::{Message, MessageType},
};
use tokio::sync::mpsc;

use crate::{
    MicrosandboxError, MicrosandboxResult,
    agent::AgentClient,
    backend::{Backend, LocalBackend},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Filesystem operations handle for a running sandbox.
///
/// Borrows the parent [`Sandbox`](super::Sandbox)'s `Arc<dyn Backend>` + name
/// and dispatches path-style ops through the
/// [`SandboxBackend`](crate::backend::SandboxBackend) trait. Low-level handle
/// ops use the live local agent client so file and directory handles stay in
/// the same relay-client range.
pub struct SandboxFsOps<'a> {
    backend: Arc<dyn Backend>,
    client: Option<Arc<AgentClient>>,
    name: &'a str,
}

/// Agentd-side filesystem handle.
pub type FsHandle = u64;

/// A filesystem entry returned from listing or stat operations.
#[derive(Debug, Clone)]
pub struct FsEntry {
    /// Path of the entry.
    pub path: String,

    /// Kind of entry.
    pub kind: FsEntryKind,

    /// Size in bytes.
    pub size: u64,

    /// Unix permission bits.
    pub mode: u32,

    /// Owner user ID.
    pub uid: u32,

    /// Owner group ID.
    pub gid: u32,

    /// Last access time.
    pub accessed: Option<chrono::DateTime<chrono::Utc>>,

    /// Last modification time.
    pub modified: Option<chrono::DateTime<chrono::Utc>>,
}

/// Kind of filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsEntryKind {
    /// Regular file.
    File,

    /// Directory.
    Directory,

    /// Symbolic link.
    Symlink,

    /// Other (device, socket, etc.).
    Other,
}

/// Metadata about a filesystem entry.
#[derive(Debug, Clone)]
pub struct FsMetadata {
    /// Kind of entry.
    pub kind: FsEntryKind,

    /// Size in bytes.
    pub size: u64,

    /// Unix permission bits.
    pub mode: u32,

    /// Owner user ID.
    pub uid: u32,

    /// Owner group ID.
    pub gid: u32,

    /// Whether the entry is read-only.
    pub readonly: bool,

    /// Last access time.
    pub accessed: Option<chrono::DateTime<chrono::Utc>>,

    /// Last modification time.
    pub modified: Option<chrono::DateTime<chrono::Utc>>,

    /// Creation time.
    pub created: Option<chrono::DateTime<chrono::Utc>>,
}

/// A streaming reader for file data from the sandbox.
pub struct FsReadStream {
    rx: mpsc::Receiver<Message>,
    // Holds the per-call agent client alive for the duration of the stream.
    // Without this the AgentClient's reader task would be dropped after
    // `fs_read_stream` returns and `rx` would receive nothing.
    client: Option<Arc<AgentClient>>,
    close_handle: Option<FsHandle>,
}

/// A streaming writer for file data to the sandbox.
pub struct FsWriteSink {
    id: u32,
    client: Arc<AgentClient>,
    rx: mpsc::Receiver<Message>,
    close_handle: Option<FsHandle>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> SandboxFsOps<'a> {
    /// Create a new filesystem handle bound to the supplied backend + sandbox name.
    pub(crate) fn new(
        backend: Arc<dyn Backend>,
        name: &'a str,
        client: Option<Arc<AgentClient>>,
    ) -> Self {
        Self {
            backend,
            client,
            name,
        }
    }

    /// Public constructor for FFI shims that re-assemble a `SandboxFsOps` per
    /// FFI call. Most callers should use [`Sandbox::fs`](super::Sandbox::fs);
    /// low-level handle methods require that live sandbox-backed constructor.
    pub fn with_backend(backend: Arc<dyn Backend>, name: &'a str) -> Self {
        Self {
            backend,
            client: None,
            name,
        }
    }

    //----------------------------------------------------------------------------------------------
    // Read Operations
    //----------------------------------------------------------------------------------------------

    /// Read an entire file from the guest filesystem into memory.
    pub async fn read(&self, path: &str) -> MicrosandboxResult<Bytes> {
        self.backend
            .sandboxes()
            .fs_read(self.backend.clone(), self.name, path)
            .await
    }

    /// Read an entire file from the guest filesystem as a UTF-8 string.
    pub async fn read_to_string(&self, path: &str) -> MicrosandboxResult<String> {
        let data = self.read(path).await?;
        String::from_utf8(Vec::from(data))
            .map_err(|e| MicrosandboxError::SandboxFsOps(format!("invalid utf-8: {e}")))
    }

    /// Read a file with streaming.
    ///
    /// Returns an [`FsReadStream`] that yields chunks of data as they arrive.
    pub async fn read_stream(&self, path: &str) -> MicrosandboxResult<FsReadStream> {
        self.backend
            .sandboxes()
            .fs_read_stream(self.backend.clone(), self.name, path)
            .await
    }

    /// Read an entire open file handle into memory.
    pub async fn read_handle(
        &self,
        handle: FsHandle,
        offset: u64,
        len: Option<u64>,
    ) -> MicrosandboxResult<Bytes> {
        let client = self.agent_client("SandboxFsOps::read_handle")?;
        local::read_handle(client, handle, offset, len).await
    }

    /// Read an open file handle with streaming.
    pub async fn read_handle_stream(
        &self,
        handle: FsHandle,
        offset: u64,
        len: Option<u64>,
    ) -> MicrosandboxResult<FsReadStream> {
        let client = self.agent_client("SandboxFsOps::read_handle_stream")?;
        local::read_handle_stream(client, handle, offset, len, None).await
    }

    //----------------------------------------------------------------------------------------------
    // Write Operations
    //----------------------------------------------------------------------------------------------

    /// Write data to a file in the guest, creating it if it doesn't exist.
    pub async fn write(&self, path: &str, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        self.backend
            .sandboxes()
            .fs_write(
                self.backend.clone(),
                self.name,
                path,
                data.as_ref().to_vec(),
            )
            .await
    }

    /// Write with streaming.
    ///
    /// Returns an [`FsWriteSink`] for writing data in chunks. Call
    /// [`FsWriteSink::close`] when done writing.
    pub async fn write_stream(&self, path: &str) -> MicrosandboxResult<FsWriteSink> {
        self.backend
            .sandboxes()
            .fs_write_stream(self.backend.clone(), self.name, path)
            .await
    }

    /// Write data to an open file handle.
    pub async fn write_handle(
        &self,
        handle: FsHandle,
        offset: u64,
        data: impl AsRef<[u8]>,
    ) -> MicrosandboxResult<()> {
        let client = self.agent_client("SandboxFsOps::write_handle")?;
        local::write_handle(client, handle, offset, data.as_ref()).await
    }

    /// Write to an open file handle with streaming.
    pub async fn write_handle_stream(
        &self,
        handle: FsHandle,
        offset: u64,
        len: Option<u64>,
    ) -> MicrosandboxResult<FsWriteSink> {
        let client = self.agent_client("SandboxFsOps::write_handle_stream")?;
        local::write_handle_stream(client, handle, offset, len, None).await
    }

    //----------------------------------------------------------------------------------------------
    // Handle Operations
    //----------------------------------------------------------------------------------------------

    /// Open a file and return an agentd-side handle.
    pub async fn open_file(
        &self,
        path: &str,
        options: FsOpenOptions,
    ) -> MicrosandboxResult<FsHandle> {
        let client = self.agent_client("SandboxFsOps::open_file")?;
        local::open_file(&client, path, options).await
    }

    /// Open a directory and return an agentd-side handle.
    pub async fn open_dir(&self, path: &str) -> MicrosandboxResult<FsHandle> {
        let client = self.agent_client("SandboxFsOps::open_dir")?;
        local::open_dir(&client, path).await
    }

    /// Close an open file or directory handle.
    pub async fn close_handle(&self, handle: FsHandle) -> MicrosandboxResult<()> {
        let client = self.agent_client("SandboxFsOps::close_handle")?;
        local::close_handle(&client, handle).await
    }

    //----------------------------------------------------------------------------------------------
    // Directory Operations
    //----------------------------------------------------------------------------------------------

    /// List the immediate children of a directory in the guest (non-recursive).
    pub async fn list(&self, path: &str) -> MicrosandboxResult<Vec<FsEntry>> {
        self.backend
            .sandboxes()
            .fs_list(self.backend.clone(), self.name, path)
            .await
    }

    /// Read the next batch from an open directory handle.
    pub async fn read_dir_handle(
        &self,
        handle: FsHandle,
        limit: Option<u32>,
    ) -> MicrosandboxResult<Vec<FsEntry>> {
        let client = self.agent_client("SandboxFsOps::read_dir_handle")?;
        local::read_dir_handle(&client, handle, limit).await
    }

    /// Read the next batch from an open directory handle.
    ///
    /// Compatibility alias for [`read_dir_handle`](Self::read_dir_handle).
    pub async fn read_dir(
        &self,
        handle: FsHandle,
        limit: Option<u32>,
    ) -> MicrosandboxResult<Vec<FsEntry>> {
        self.read_dir_handle(handle, limit).await
    }

    /// Create a directory (and parents).
    pub async fn mkdir(&self, path: &str) -> MicrosandboxResult<()> {
        self.backend
            .sandboxes()
            .fs_mkdir(self.backend.clone(), self.name, path)
            .await
    }

    /// Remove a directory recursively.
    pub async fn remove_dir(&self, path: &str) -> MicrosandboxResult<()> {
        self.backend
            .sandboxes()
            .fs_remove(self.backend.clone(), self.name, path, true)
            .await
    }

    /// Remove an empty directory.
    pub async fn remove_empty_dir(&self, path: &str) -> MicrosandboxResult<()> {
        let local = self.local_backend("SandboxFsOps::remove_empty_dir")?;
        local::remove_dir(local, self.name, path, false).await
    }

    //----------------------------------------------------------------------------------------------
    // File Operations
    //----------------------------------------------------------------------------------------------

    /// Delete a single file. Use [`remove_dir`](Self::remove_dir) for directories.
    pub async fn remove(&self, path: &str) -> MicrosandboxResult<()> {
        self.backend
            .sandboxes()
            .fs_remove(self.backend.clone(), self.name, path, false)
            .await
    }

    /// Copy a file within the sandbox.
    pub async fn copy(&self, from: &str, to: &str) -> MicrosandboxResult<()> {
        self.backend
            .sandboxes()
            .fs_copy(self.backend.clone(), self.name, from, to)
            .await
    }

    /// Rename/move a file or directory.
    pub async fn rename(&self, from: &str, to: &str) -> MicrosandboxResult<()> {
        self.backend
            .sandboxes()
            .fs_rename(self.backend.clone(), self.name, from, to)
            .await
    }

    /// Read the target of a symbolic link.
    pub async fn read_link(&self, path: &str) -> MicrosandboxResult<String> {
        let local = self.local_backend("SandboxFsOps::read_link")?;
        local::read_link(local, self.name, path).await
    }

    /// Create a symbolic link.
    pub async fn symlink(&self, target: &str, link_path: &str) -> MicrosandboxResult<()> {
        let local = self.local_backend("SandboxFsOps::symlink")?;
        local::symlink(local, self.name, target, link_path).await
    }

    /// Resolve a path to its canonical absolute form.
    pub async fn real_path(&self, path: &str) -> MicrosandboxResult<String> {
        let local = self.local_backend("SandboxFsOps::real_path")?;
        local::real_path(local, self.name, path).await
    }

    //----------------------------------------------------------------------------------------------
    // Metadata
    //----------------------------------------------------------------------------------------------

    /// Get file/directory metadata.
    pub async fn stat(&self, path: &str) -> MicrosandboxResult<FsMetadata> {
        self.backend
            .sandboxes()
            .fs_stat(self.backend.clone(), self.name, path)
            .await
    }

    /// Get file/directory metadata, optionally following symlinks.
    pub async fn stat_with_follow(
        &self,
        path: &str,
        follow_symlink: bool,
    ) -> MicrosandboxResult<FsMetadata> {
        let local = self.local_backend("SandboxFsOps::stat_with_follow")?;
        local::stat_with_follow(local, self.name, path, follow_symlink).await
    }

    /// Update file/directory metadata.
    pub async fn set_stat(
        &self,
        path: &str,
        follow_symlink: bool,
        attrs: FsSetAttrs,
    ) -> MicrosandboxResult<()> {
        let local = self.local_backend("SandboxFsOps::set_stat")?;
        local::set_stat(local, self.name, path, follow_symlink, attrs).await
    }

    /// Get metadata for an open file or directory handle.
    pub async fn stat_handle(&self, handle: FsHandle) -> MicrosandboxResult<FsMetadata> {
        let client = self.agent_client("SandboxFsOps::stat_handle")?;
        local::stat_handle(&client, handle).await
    }

    /// Get metadata for an open file or directory handle.
    ///
    /// Compatibility alias for [`stat_handle`](Self::stat_handle).
    pub async fn fstat(&self, handle: FsHandle) -> MicrosandboxResult<FsMetadata> {
        self.stat_handle(handle).await
    }

    /// Update metadata for an open file handle.
    pub async fn set_stat_handle(
        &self,
        handle: FsHandle,
        attrs: FsSetAttrs,
    ) -> MicrosandboxResult<()> {
        let client = self.agent_client("SandboxFsOps::set_stat_handle")?;
        local::set_stat_handle(&client, handle, attrs).await
    }

    /// Update metadata for an open file handle.
    ///
    /// Compatibility alias for [`set_stat_handle`](Self::set_stat_handle).
    pub async fn fset_stat(&self, handle: FsHandle, attrs: FsSetAttrs) -> MicrosandboxResult<()> {
        self.set_stat_handle(handle, attrs).await
    }

    /// Check whether a file or directory exists at the given path in the guest.
    pub async fn exists(&self, path: &str) -> MicrosandboxResult<bool> {
        self.backend
            .sandboxes()
            .fs_exists(self.backend.clone(), self.name, path)
            .await
    }

    //----------------------------------------------------------------------------------------------
    // Host Transfer
    //----------------------------------------------------------------------------------------------

    /// Copy a file from the host into the sandbox.
    pub async fn copy_from_host(
        &self,
        host_path: impl AsRef<Path>,
        guest_path: &str,
    ) -> MicrosandboxResult<()> {
        self.backend
            .sandboxes()
            .fs_copy_from_host(
                self.backend.clone(),
                self.name,
                host_path.as_ref(),
                guest_path,
            )
            .await
    }

    /// Copy a file from the sandbox to the host.
    pub async fn copy_to_host(
        &self,
        guest_path: &str,
        host_path: impl AsRef<Path>,
    ) -> MicrosandboxResult<()> {
        self.backend
            .sandboxes()
            .fs_copy_to_host(
                self.backend.clone(),
                self.name,
                guest_path,
                host_path.as_ref(),
            )
            .await
    }

    fn local_backend(&self, method: &'static str) -> MicrosandboxResult<&LocalBackend> {
        self.backend
            .as_local()
            .ok_or_else(|| MicrosandboxError::Unsupported {
                feature: method.into(),
                available_when: "when cloud guest-fs lands".into(),
            })
    }

    fn agent_client(&self, method: &'static str) -> MicrosandboxResult<Arc<AgentClient>> {
        self.client
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| MicrosandboxError::Unsupported {
                feature: method.into(),
                available_when: self.handle_api_available_when().into(),
            })
    }

    fn handle_api_available_when(&self) -> &'static str {
        if self.backend.as_local().is_some() {
            "from Sandbox::fs() on a live local sandbox"
        } else {
            "when cloud guest-fs lands"
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: FsReadStream
//--------------------------------------------------------------------------------------------------

impl FsReadStream {
    /// Construct a read stream that closes an owned handle at EOF.
    pub(crate) fn with_client_and_close(
        rx: mpsc::Receiver<Message>,
        client: Arc<AgentClient>,
        close_handle: Option<FsHandle>,
    ) -> Self {
        Self {
            rx,
            client: Some(client),
            close_handle,
        }
    }

    /// Receive the next chunk of data.
    ///
    /// Returns `None` when the stream is complete (after `FsResponse`).
    /// Returns an error if the guest reported a failure.
    pub async fn recv(&mut self) -> MicrosandboxResult<Option<Bytes>> {
        while let Some(msg) = self.rx.recv().await {
            match msg.t {
                MessageType::FsData => {
                    let chunk: FsData = msg.payload()?;
                    if !chunk.data.is_empty() {
                        return Ok(Some(Bytes::from(chunk.data)));
                    }
                }
                MessageType::FsResponse => {
                    let resp: FsResponse = msg.payload()?;
                    let close_result = self.close_owned_handle().await;
                    if !resp.ok {
                        return Err(MicrosandboxError::SandboxFsOps(
                            resp.error.unwrap_or_else(|| "unknown error".into()),
                        ));
                    }
                    close_result?;
                    return Ok(None);
                }
                _ => {}
            }
        }
        self.close_owned_handle().await?;
        Ok(None)
    }

    /// Collect all remaining data into bytes.
    pub async fn collect(mut self) -> MicrosandboxResult<Bytes> {
        let mut data = Vec::new();
        while let Some(chunk) = self.recv().await? {
            data.extend_from_slice(&chunk);
        }
        Ok(Bytes::from(data))
    }

    async fn close_owned_handle(&mut self) -> MicrosandboxResult<()> {
        if let (Some(client), Some(handle)) = (self.client.as_ref(), self.close_handle.take()) {
            local::close_handle(client, handle).await?;
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: FsWriteSink
//--------------------------------------------------------------------------------------------------

impl FsWriteSink {
    /// Construct a write sink from raw protocol state. **Local impl only.**
    pub(crate) fn new(
        id: u32,
        client: Arc<AgentClient>,
        rx: mpsc::Receiver<Message>,
        close_handle: Option<FsHandle>,
    ) -> Self {
        Self {
            id,
            client,
            rx,
            close_handle,
        }
    }

    /// Write a chunk of data.
    pub async fn write(&self, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        let fs_data = FsData {
            data: data.as_ref().to_vec(),
        };
        self.client
            .send(self.id, MessageType::FsData, &fs_data)
            .await
            .map_err(Into::into)
    }

    /// Close the write stream (sends EOF) and wait for confirmation.
    ///
    /// This must be called to finalize the write operation. Returns an
    /// error if the guest reports a write failure.
    pub async fn close(mut self) -> MicrosandboxResult<()> {
        let eof = FsData { data: Vec::new() };
        self.client.send(self.id, MessageType::FsData, &eof).await?;

        // Wait for the terminal FsResponse from the guest.
        let result = wait_for_ok_response(&mut self.rx).await;
        let close_result = if let Some(handle) = self.close_handle.take() {
            local::close_handle(&self.client, handle).await
        } else {
            Ok(())
        };
        result?;
        close_result
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Parse a kind string from the wire protocol into an `FsEntryKind`.
fn parse_kind(s: &str) -> FsEntryKind {
    match s {
        "file" => FsEntryKind::File,
        "dir" => FsEntryKind::Directory,
        "symlink" => FsEntryKind::Symlink,
        _ => FsEntryKind::Other,
    }
}

/// Parse an optional Unix timestamp into a `DateTime<Utc>`.
fn parse_time(ts: Option<i64>) -> Option<chrono::DateTime<chrono::Utc>> {
    ts.map(|t| chrono::DateTime::from_timestamp(t, 0).unwrap_or_default())
}

/// Parse an `FsEntryInfo` into an `FsEntry`.
fn entry_info_to_fs_entry(info: FsEntryInfo) -> FsEntry {
    FsEntry {
        kind: parse_kind(&info.kind),
        accessed: parse_time(info.atime),
        modified: parse_time(info.mtime.or(info.modified)),
        path: info.path,
        size: info.size,
        mode: info.mode,
        uid: info.uid,
        gid: info.gid,
    }
}

/// Convert an `FsEntryInfo` to `FsMetadata`.
fn entry_info_to_metadata(info: &FsEntryInfo) -> FsMetadata {
    FsMetadata {
        kind: parse_kind(&info.kind),
        accessed: parse_time(info.atime),
        modified: parse_time(info.mtime.or(info.modified)),
        created: None,
        size: info.size,
        mode: info.mode,
        uid: info.uid,
        gid: info.gid,
        readonly: info.mode & 0o200 == 0,
    }
}

/// Deserialize and check a simple ok/error `FsResponse`.
fn check_response(msg: Message) -> MicrosandboxResult<()> {
    let resp: FsResponse = msg.payload()?;
    if resp.ok {
        Ok(())
    } else {
        Err(MicrosandboxError::SandboxFsOps(
            resp.error.unwrap_or_else(|| "unknown error".into()),
        ))
    }
}

/// Wait for and check a terminal `FsResponse` from a subscription channel.
async fn wait_for_ok_response(rx: &mut mpsc::Receiver<Message>) -> MicrosandboxResult<()> {
    while let Some(msg) = rx.recv().await {
        if msg.t == MessageType::FsResponse {
            return check_response(msg);
        }
    }
    Err(MicrosandboxError::SandboxFsOps(
        "channel closed before response".into(),
    ))
}

fn read_only_open_options() -> FsOpenOptions {
    FsOpenOptions {
        read: true,
        ..Default::default()
    }
}

fn write_open_options() -> FsOpenOptions {
    FsOpenOptions {
        write: true,
        create: true,
        truncate: true,
        ..Default::default()
    }
}

//--------------------------------------------------------------------------------------------------
// Module: local (free fn impls called by LocalBackend's SandboxBackend impl)
//--------------------------------------------------------------------------------------------------

pub(crate) mod local {
    //! Local guest-FS ops keyed by `(sandbox_name, path)`.
    //!
    //! Each function opens a fresh agent UDS connection (option A per the
    //! parity plan). The per-call overhead is small relative to the
    //! cross-VM I/O these calls drive and keeps the trait dispatch path
    //! stateless.

    use std::path::Path;
    use std::sync::Arc;

    use bytes::Bytes;
    use microsandbox_protocol::{
        fs::{
            FS_CHUNK_SIZE, FsData, FsOp, FsOpenOptions, FsRequest, FsResponse, FsResponseData,
            FsSetAttrs,
        },
        message::MessageType,
    };
    use tokio::io::AsyncReadExt;

    use crate::{MicrosandboxError, MicrosandboxResult, agent::AgentClient, backend::LocalBackend};

    use super::{
        FsEntry, FsHandle, FsMetadata, FsReadStream, FsWriteSink, check_response,
        entry_info_to_fs_entry, entry_info_to_metadata, wait_for_ok_response,
    };

    /// Open a fresh agent connection for the named sandbox.
    pub(crate) async fn connect_agent(
        local: &LocalBackend,
        name: &str,
    ) -> MicrosandboxResult<AgentClient> {
        connect_agent_with_timeout(local, name, std::time::Duration::from_secs(10)).await
    }

    pub(crate) async fn connect_agent_with_timeout(
        local: &LocalBackend,
        name: &str,
        timeout: std::time::Duration,
    ) -> MicrosandboxResult<AgentClient> {
        let mut last_error = None;

        for sock_path in crate::runtime::sandbox_agent_socket_path_candidates_for(local, name) {
            if !agent_endpoint_may_exist(&sock_path) {
                continue;
            }

            match AgentClient::connect_with_timeout(&sock_path, timeout).await {
                Ok(client) => return Ok(client),
                Err(error) => last_error = Some(error),
            }
        }

        match last_error {
            Some(error) => Err(error.into()),
            None => Err(MicrosandboxError::SandboxNotRunning(format!(
                "{name:?} has no agent endpoint (is it running?)"
            ))),
        }
    }

    #[cfg(unix)]
    fn agent_endpoint_may_exist(path: &std::path::Path) -> bool {
        path.exists()
    }

    #[cfg(windows)]
    fn agent_endpoint_may_exist(_path: &std::path::Path) -> bool {
        true
    }

    pub(crate) async fn open_file(
        client: &AgentClient,
        path: &str,
        options: FsOpenOptions,
    ) -> MicrosandboxResult<FsHandle> {
        let req = FsRequest {
            op: FsOp::OpenFile {
                path: path.to_string(),
                options,
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        let resp: FsResponse = resp_msg.payload()?;
        if !resp.ok {
            return Err(MicrosandboxError::SandboxFsOps(
                resp.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }
        match resp.data {
            Some(FsResponseData::Handle(handle)) => Ok(handle),
            _ => Err(MicrosandboxError::SandboxFsOps(
                "unexpected response data for open".into(),
            )),
        }
    }

    pub(crate) async fn open_dir(client: &AgentClient, path: &str) -> MicrosandboxResult<FsHandle> {
        let req = FsRequest {
            op: FsOp::OpenDir {
                path: path.to_string(),
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        let resp: FsResponse = resp_msg.payload()?;
        if !resp.ok {
            return Err(MicrosandboxError::SandboxFsOps(
                resp.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }
        match resp.data {
            Some(FsResponseData::Handle(handle)) => Ok(handle),
            _ => Err(MicrosandboxError::SandboxFsOps(
                "unexpected response data for open directory".into(),
            )),
        }
    }

    pub(crate) async fn close_handle(
        client: &AgentClient,
        handle: FsHandle,
    ) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::CloseHandle { handle },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        check_response(resp_msg)
    }

    pub(crate) async fn read_handle(
        client: Arc<AgentClient>,
        handle: FsHandle,
        offset: u64,
        len: Option<u64>,
    ) -> MicrosandboxResult<Bytes> {
        read_handle_stream(client, handle, offset, len, None)
            .await?
            .collect()
            .await
    }

    pub(crate) async fn read_handle_stream(
        client: Arc<AgentClient>,
        handle: FsHandle,
        offset: u64,
        len: Option<u64>,
        close_handle: Option<FsHandle>,
    ) -> MicrosandboxResult<FsReadStream> {
        let req = FsRequest {
            op: FsOp::Read {
                handle,
                offset,
                len,
            },
        };
        let (_id, rx) = client.stream(MessageType::FsRequest, &req).await?;

        // The stream must retain the same relay client while the handle is in
        // use; agentd rejects handle operations from a different client range.
        Ok(FsReadStream::with_client_and_close(
            rx,
            client,
            close_handle,
        ))
    }

    pub(crate) async fn write_handle(
        client: Arc<AgentClient>,
        handle: FsHandle,
        offset: u64,
        data: &[u8],
    ) -> MicrosandboxResult<()> {
        let sink =
            write_handle_stream(client, handle, offset, Some(data.len() as u64), None).await?;
        for chunk in data.chunks(FS_CHUNK_SIZE) {
            sink.write(chunk).await?;
        }
        sink.close().await
    }

    pub(crate) async fn write_handle_stream(
        client: Arc<AgentClient>,
        handle: FsHandle,
        offset: u64,
        len: Option<u64>,
        close_handle: Option<FsHandle>,
    ) -> MicrosandboxResult<FsWriteSink> {
        let req = FsRequest {
            op: FsOp::Write {
                handle,
                offset,
                len,
            },
        };
        let (id, rx) = client.stream(MessageType::FsRequest, &req).await?;
        Ok(FsWriteSink::new(id, client, rx, close_handle))
    }

    pub(crate) async fn read_dir_handle(
        client: &AgentClient,
        handle: FsHandle,
        limit: Option<u32>,
    ) -> MicrosandboxResult<Vec<FsEntry>> {
        let req = FsRequest {
            op: FsOp::ReadDir { handle, limit },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        let resp: FsResponse = resp_msg.payload()?;

        if !resp.ok {
            return Err(MicrosandboxError::SandboxFsOps(
                resp.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }

        match resp.data {
            Some(FsResponseData::List(entries)) => {
                Ok(entries.into_iter().map(entry_info_to_fs_entry).collect())
            }
            _ => Ok(Vec::new()),
        }
    }

    pub(crate) async fn stat_handle(
        client: &AgentClient,
        handle: FsHandle,
    ) -> MicrosandboxResult<FsMetadata> {
        let req = FsRequest {
            op: FsOp::FStat { handle },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        let resp: FsResponse = resp_msg.payload()?;

        if !resp.ok {
            return Err(MicrosandboxError::SandboxFsOps(
                resp.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }

        match resp.data {
            Some(FsResponseData::Stat(info)) => Ok(entry_info_to_metadata(&info)),
            _ => Err(MicrosandboxError::SandboxFsOps(
                "unexpected response data for stat handle".into(),
            )),
        }
    }

    pub(crate) async fn set_stat_handle(
        client: &AgentClient,
        handle: FsHandle,
        attrs: FsSetAttrs,
    ) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::FSetStat { handle, attrs },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        check_response(resp_msg)
    }

    pub(crate) async fn read(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<Bytes> {
        let client = connect_agent(local, name).await?;
        let handle = open_file(&client, path, super::read_only_open_options()).await?;

        let req = FsRequest {
            op: FsOp::Read {
                handle,
                offset: 0,
                len: None,
            },
        };
        let (_id, mut rx) = client.stream(MessageType::FsRequest, &req).await?;

        let mut data = Vec::new();
        while let Some(msg) = rx.recv().await {
            match msg.t {
                MessageType::FsData => {
                    let chunk: FsData = msg.payload()?;
                    data.extend_from_slice(&chunk.data);
                }
                MessageType::FsResponse => {
                    let resp: FsResponse = msg.payload()?;
                    if !resp.ok {
                        return Err(MicrosandboxError::SandboxFsOps(
                            resp.error.unwrap_or_else(|| "unknown error".into()),
                        ));
                    }
                    break;
                }
                _ => {}
            }
        }

        let close_result = close_handle(&client, handle).await;
        close_result?;
        Ok(Bytes::from(data))
    }

    pub(crate) async fn read_stream(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<FsReadStream> {
        let client = Arc::new(connect_agent(local, name).await?);
        let handle = open_file(&client, path, super::read_only_open_options()).await?;

        let req = FsRequest {
            op: FsOp::Read {
                handle,
                offset: 0,
                len: None,
            },
        };
        let (_id, rx) = client.stream(MessageType::FsRequest, &req).await?;

        // Pin the AgentClient alive inside the stream and close the
        // auto-opened file handle once the guest sends the terminal response.
        Ok(FsReadStream::with_client_and_close(
            rx,
            client,
            Some(handle),
        ))
    }

    pub(crate) async fn write(
        local: &LocalBackend,
        name: &str,
        path: &str,
        data: Vec<u8>,
    ) -> MicrosandboxResult<()> {
        let client = connect_agent(local, name).await?;
        let handle = open_file(&client, path, super::write_open_options()).await?;

        let req = FsRequest {
            op: FsOp::Write {
                handle,
                offset: 0,
                len: Some(data.len() as u64),
            },
        };
        let (id, mut rx) = client.stream(MessageType::FsRequest, &req).await?;

        for chunk in data.chunks(FS_CHUNK_SIZE) {
            let fs_data = FsData {
                data: chunk.to_vec(),
            };
            client.send(id, MessageType::FsData, &fs_data).await?;
        }

        let eof = FsData { data: Vec::new() };
        client.send(id, MessageType::FsData, &eof).await?;

        let result = wait_for_ok_response(&mut rx).await;
        let _ = close_handle(&client, handle).await;
        result
    }

    pub(crate) async fn write_stream(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<FsWriteSink> {
        let client = Arc::new(connect_agent(local, name).await?);
        let handle = open_file(&client, path, super::write_open_options()).await?;

        let req = FsRequest {
            op: FsOp::Write {
                handle,
                offset: 0,
                len: None,
            },
        };
        let (id, rx) = client.stream(MessageType::FsRequest, &req).await?;

        Ok(FsWriteSink::new(id, client, rx, Some(handle)))
    }

    pub(crate) async fn list(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<Vec<FsEntry>> {
        let client = connect_agent(local, name).await?;
        let req = FsRequest {
            op: FsOp::List {
                path: path.to_string(),
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        let resp: FsResponse = resp_msg.payload()?;

        if !resp.ok {
            return Err(MicrosandboxError::SandboxFsOps(
                resp.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }

        match resp.data {
            Some(FsResponseData::List(entries)) => {
                Ok(entries.into_iter().map(entry_info_to_fs_entry).collect())
            }
            _ => Ok(Vec::new()),
        }
    }

    pub(crate) async fn mkdir(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<()> {
        let client = connect_agent(local, name).await?;
        let req = FsRequest {
            op: FsOp::Mkdir {
                path: path.to_string(),
                mode: None,
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        check_response(resp_msg)
    }

    pub(crate) async fn remove(
        local: &LocalBackend,
        name: &str,
        path: &str,
        recursive: bool,
    ) -> MicrosandboxResult<()> {
        if recursive {
            return remove_dir(local, name, path, true).await;
        }

        let client = connect_agent(local, name).await?;
        let req = FsRequest {
            op: FsOp::Remove {
                path: path.to_string(),
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        check_response(resp_msg)
    }

    pub(crate) async fn remove_dir(
        local: &LocalBackend,
        name: &str,
        path: &str,
        recursive: bool,
    ) -> MicrosandboxResult<()> {
        let client = connect_agent(local, name).await?;
        let req = FsRequest {
            op: FsOp::RemoveDir {
                path: path.to_string(),
                recursive,
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        check_response(resp_msg)
    }

    pub(crate) async fn copy(
        local: &LocalBackend,
        name: &str,
        from: &str,
        to: &str,
    ) -> MicrosandboxResult<()> {
        let client = connect_agent(local, name).await?;
        let req = FsRequest {
            op: FsOp::Copy {
                src: from.to_string(),
                dst: to.to_string(),
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        check_response(resp_msg)
    }

    pub(crate) async fn rename(
        local: &LocalBackend,
        name: &str,
        from: &str,
        to: &str,
    ) -> MicrosandboxResult<()> {
        let client = connect_agent(local, name).await?;
        let req = FsRequest {
            op: FsOp::Rename {
                src: from.to_string(),
                dst: to.to_string(),
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        check_response(resp_msg)
    }

    pub(crate) async fn stat(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<FsMetadata> {
        stat_with_follow(local, name, path, true).await
    }

    pub(crate) async fn stat_with_follow(
        local: &LocalBackend,
        name: &str,
        path: &str,
        follow_symlink: bool,
    ) -> MicrosandboxResult<FsMetadata> {
        let client = connect_agent(local, name).await?;
        let req = FsRequest {
            op: FsOp::Stat {
                path: path.to_string(),
                follow_symlink,
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        let resp: FsResponse = resp_msg.payload()?;

        if !resp.ok {
            return Err(MicrosandboxError::SandboxFsOps(
                resp.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }

        match resp.data {
            Some(FsResponseData::Stat(info)) => Ok(entry_info_to_metadata(&info)),
            _ => Err(MicrosandboxError::SandboxFsOps(
                "unexpected response data for stat".into(),
            )),
        }
    }

    pub(crate) async fn set_stat(
        local: &LocalBackend,
        name: &str,
        path: &str,
        follow_symlink: bool,
        attrs: FsSetAttrs,
    ) -> MicrosandboxResult<()> {
        let client = connect_agent(local, name).await?;
        let req = FsRequest {
            op: FsOp::SetStat {
                path: path.to_string(),
                follow_symlink,
                attrs,
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        check_response(resp_msg)
    }

    pub(crate) async fn read_link(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<String> {
        let client = connect_agent(local, name).await?;
        let req = FsRequest {
            op: FsOp::ReadLink {
                path: path.to_string(),
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        let resp: FsResponse = resp_msg.payload()?;

        if !resp.ok {
            return Err(MicrosandboxError::SandboxFsOps(
                resp.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }

        match resp.data {
            Some(FsResponseData::Path(path)) => Ok(path),
            _ => Err(MicrosandboxError::SandboxFsOps(
                "unexpected response data for readlink".into(),
            )),
        }
    }

    pub(crate) async fn symlink(
        local: &LocalBackend,
        name: &str,
        target: &str,
        link_path: &str,
    ) -> MicrosandboxResult<()> {
        let client = connect_agent(local, name).await?;
        let req = FsRequest {
            op: FsOp::Symlink {
                target: target.to_string(),
                link_path: link_path.to_string(),
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        check_response(resp_msg)
    }

    pub(crate) async fn real_path(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<String> {
        let client = connect_agent(local, name).await?;
        let req = FsRequest {
            op: FsOp::RealPath {
                path: path.to_string(),
            },
        };
        let resp_msg = client.request(MessageType::FsRequest, &req).await?;
        let resp: FsResponse = resp_msg.payload()?;

        if !resp.ok {
            return Err(MicrosandboxError::SandboxFsOps(
                resp.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }

        match resp.data {
            Some(FsResponseData::Path(path)) => Ok(path),
            _ => Err(MicrosandboxError::SandboxFsOps(
                "unexpected response data for realpath".into(),
            )),
        }
    }

    pub(crate) async fn exists(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<bool> {
        match stat(local, name, path).await {
            Ok(_) => Ok(true),
            Err(MicrosandboxError::SandboxFsOps(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn copy_from_host(
        local: &LocalBackend,
        name: &str,
        host_path: &Path,
        guest_path: &str,
    ) -> MicrosandboxResult<()> {
        let mut file = tokio::fs::File::open(host_path).await?;
        let sink = write_stream(local, name, guest_path).await?;
        let mut buf = vec![0u8; FS_CHUNK_SIZE];
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            sink.write(&buf[..n]).await?;
        }
        sink.close().await
    }

    pub(crate) async fn copy_to_host(
        local: &LocalBackend,
        name: &str,
        guest_path: &str,
        host_path: &Path,
    ) -> MicrosandboxResult<()> {
        let data = read(local, name, guest_path).await?;
        tokio::fs::write(host_path, &data).await?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_protocol::fs::{FsOpenOptions, FsSetAttrs};
