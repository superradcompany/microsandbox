//! Filesystem operations on a running sandbox.
//!
//! [`SandboxFs`] provides methods to read, write, list, and manipulate files
//! inside a running sandbox. The handle is a thin façade that dispatches each
//! op through the [`SandboxBackend`](crate::backend::SandboxBackend) trait, so
//! local routes through agentd's `core.fs.*` messages and cloud returns
//! per-method `Unsupported` until cloud guest-fs lands.

use std::{path::Path, sync::Arc};

use bytes::Bytes;
use microsandbox_protocol::{
    fs::{FsData, FsEntryInfo, FsOpenOptions, FsResponse},
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
/// and dispatches each op through the
/// [`SandboxBackend`](crate::backend::SandboxBackend) trait. Local routes to
/// `core.fs.*` agent messages; cloud returns `Unsupported` per-method.
pub struct SandboxFs<'a> {
    backend: Arc<dyn Backend>,
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

    /// Whether the entry is read-only.
    pub readonly: bool,

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
    _client: Option<Arc<AgentClient>>,
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

impl<'a> SandboxFs<'a> {
    /// Create a new filesystem handle bound to the supplied backend + sandbox name.
    pub(crate) fn new(backend: Arc<dyn Backend>, name: &'a str) -> Self {
        Self { backend, name }
    }

    /// Public constructor for FFI shims that re-assemble a `SandboxFs` per
    /// FFI call. Most callers should use [`Sandbox::fs`](super::Sandbox::fs).
    pub fn with_backend(backend: Arc<dyn Backend>, name: &'a str) -> Self {
        Self { backend, name }
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
        let local = self.local_backend("SandboxFs::stat_with_follow")?;
        local::stat_with_follow(local, self.name, path, follow_symlink).await
    }

    /// Update file/directory metadata.
    pub async fn set_stat(
        &self,
        path: &str,
        follow_symlink: bool,
        attrs: FsSetAttrs,
    ) -> MicrosandboxResult<()> {
        let local = self.local_backend("SandboxFs::set_stat")?;
        local::set_stat(local, self.name, path, follow_symlink, attrs).await
    }

    /// Read the target of a symbolic link.
    pub async fn read_link(&self, path: &str) -> MicrosandboxResult<String> {
        let local = self.local_backend("SandboxFs::read_link")?;
        local::read_link(local, self.name, path).await
    }

    /// Create a symbolic link.
    pub async fn symlink(&self, target: &str, link_path: &str) -> MicrosandboxResult<()> {
        let local = self.local_backend("SandboxFs::symlink")?;
        local::symlink(local, self.name, target, link_path).await
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
}

//--------------------------------------------------------------------------------------------------
// Methods: FsReadStream
//--------------------------------------------------------------------------------------------------

impl FsReadStream {
    /// Construct a read stream that pins an [`AgentClient`] alive for the
    /// duration of the stream. **Local impl only.**
    pub(crate) fn with_client(rx: mpsc::Receiver<Message>, client: Arc<AgentClient>) -> Self {
        Self {
            rx,
            _client: Some(client),
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
                    if !resp.ok {
                        return Err(MicrosandboxError::SandboxFsOps(
                            resp.error.unwrap_or_else(|| "unknown error".into()),
                        ));
                    }
                    return Ok(None);
                }
                _ => {}
            }
        }
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
        if let Some(handle) = self.close_handle.take() {
            let _ = local::close_handle(&self.client, handle).await;
        }
        result
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
fn parse_modified(ts: Option<i64>) -> Option<chrono::DateTime<chrono::Utc>> {
    ts.map(|t| chrono::DateTime::from_timestamp(t, 0).unwrap_or_default())
}

/// Parse an `FsEntryInfo` into an `FsEntry`.
fn entry_info_to_fs_entry(info: FsEntryInfo) -> FsEntry {
    FsEntry {
        kind: parse_kind(&info.kind),
        modified: parse_modified(info.modified),
        path: info.path,
        size: info.size,
        mode: info.mode,
    }
}

/// Convert an `FsEntryInfo` to `FsMetadata`.
fn entry_info_to_metadata(info: &FsEntryInfo) -> FsMetadata {
    FsMetadata {
        kind: parse_kind(&info.kind),
        modified: parse_modified(info.modified),
        created: None,
        size: info.size,
        mode: info.mode,
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
            None => Err(MicrosandboxError::Runtime(format!(
                "no agent endpoint found for sandbox {name:?}"
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

    async fn open_file(
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

        // Pin the AgentClient alive inside the stream — without it the
        // reader task would drop after this fn returns and `rx` would
        // never receive any messages.
        Ok(FsReadStream::with_client(rx, client))
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
        let client = connect_agent(local, name).await?;
        let op = if recursive {
            FsOp::RemoveDir {
                path: path.to_string(),
                recursive,
            }
        } else {
            FsOp::Remove {
                path: path.to_string(),
            }
        };
        let req = FsRequest { op };
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

pub use microsandbox_protocol::fs::FsSetAttrs;
