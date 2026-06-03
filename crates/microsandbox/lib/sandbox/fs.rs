//! Filesystem operations on a running sandbox.
//!
//! [`SandboxFs`] provides methods to read, write, list, and manipulate files
//! inside a running sandbox via the `core.fs.*` protocol messages.

use std::{path::Path, sync::Arc};

use bytes::Bytes;
pub use microsandbox_protocol::fs::{FsOpenOptions, FsSetAttrs};
use microsandbox_protocol::{
    fs::{FS_CHUNK_SIZE, FsData, FsEntryInfo, FsOp, FsRequest, FsResponse, FsResponseData},
    message::{Message, MessageType},
};
use tokio::sync::mpsc;

use crate::{MicrosandboxError, MicrosandboxResult, agent::AgentClient};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Filesystem operations handle for a running sandbox.
///
/// All operations go through the agent protocol (`core.fs.*` messages),
/// which are handled by agentd inside the guest VM.
#[derive(Clone)]
pub struct SandboxFs {
    client: Arc<AgentClient>,
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
    rx: mpsc::UnboundedReceiver<Message>,
    client: Arc<AgentClient>,
    close_handle: Option<FsHandle>,
}

/// A streaming writer for file data to the sandbox.
pub struct FsWriteSink {
    id: u32,
    client: Arc<AgentClient>,
    rx: mpsc::UnboundedReceiver<Message>,
    close_handle: Option<FsHandle>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxFs {
    /// Create a new filesystem handle.
    pub fn new(client: &Arc<AgentClient>) -> Self {
        Self {
            client: Arc::clone(client),
        }
    }

    fn ensure_filesystem_supported(&self) -> MicrosandboxResult<()> {
        // Fail fast when the sandbox is too old for filesystem streaming. The
        // send path enforces the same gate; this is the early, friendlier
        // surface. Feature support is decided in one place:
        // MessageType::min_protocol_version, via AgentClient::require.
        self.client.ensure_version_compat(MessageType::FsRequest)?;
        Ok(())
    }

    //----------------------------------------------------------------------------------------------
    // Read Operations
    //----------------------------------------------------------------------------------------------

    /// Read an entire file from the guest filesystem into memory.
    pub async fn read(&self, path: &str) -> MicrosandboxResult<Bytes> {
        let handle = self.open_file(path, read_only_open_options()).await?;
        let result = self.read_handle(handle, 0, None).await;
        let close_result = self.close_handle(handle).await;
        match result {
            Ok(data) => {
                close_result?;
                Ok(data)
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    /// Read an entire file from the guest filesystem as a UTF-8 string.
    pub async fn read_to_string(&self, path: &str) -> MicrosandboxResult<String> {
        let data = self.read(path).await?;
        String::from_utf8(Vec::from(data))
            .map_err(|e| MicrosandboxError::SandboxFs(format!("invalid utf-8: {e}")))
    }

    /// Read a file with streaming.
    ///
    /// Returns an [`FsReadStream`] that yields chunks of data as they arrive.
    pub async fn read_stream(&self, path: &str) -> MicrosandboxResult<FsReadStream> {
        let handle = self.open_file(path, read_only_open_options()).await?;
        self.read_handle_stream_with_close(handle, 0, None, Some(handle))
            .await
    }

    /// Read an entire open handle into memory.
    pub async fn read_handle(
        &self,
        handle: FsHandle,
        offset: u64,
        len: Option<u64>,
    ) -> MicrosandboxResult<Bytes> {
        self.read_handle_stream(handle, offset, len)
            .await?
            .collect()
            .await
    }

    /// Read an open handle with streaming.
    pub async fn read_handle_stream(
        &self,
        handle: FsHandle,
        offset: u64,
        len: Option<u64>,
    ) -> MicrosandboxResult<FsReadStream> {
        self.read_handle_stream_with_close(handle, offset, len, None)
            .await
    }

    async fn read_handle_stream_with_close(
        &self,
        handle: FsHandle,
        offset: u64,
        len: Option<u64>,
        close_handle: Option<FsHandle>,
    ) -> MicrosandboxResult<FsReadStream> {
        self.ensure_filesystem_supported()?;
        let req = FsRequest {
            op: FsOp::Read {
                handle,
                offset,
                len,
            },
        };
        let (_id, rx) = self.client.stream(MessageType::FsRequest, &req).await?;
        Ok(FsReadStream {
            rx,
            client: Arc::clone(&self.client),
            close_handle,
        })
    }

    //----------------------------------------------------------------------------------------------
    // Write Operations
    //----------------------------------------------------------------------------------------------

    /// Write data to a file in the guest, creating it if it doesn't exist.
    pub async fn write(&self, path: &str, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        let options = FsOpenOptions {
            write: true,
            create: true,
            truncate: true,
            ..Default::default()
        };
        let handle = self.open_file(path, options).await?;
        let result = self.write_handle(handle, 0, data).await;
        let close_result = self.close_handle(handle).await;
        result?;
        close_result
    }

    /// Write with streaming.
    ///
    /// Returns an [`FsWriteSink`] for writing data in chunks. Call
    /// [`FsWriteSink::close`] when done writing.
    pub async fn write_stream(&self, path: &str) -> MicrosandboxResult<FsWriteSink> {
        let options = FsOpenOptions {
            write: true,
            create: true,
            truncate: true,
            ..Default::default()
        };
        let handle = self.open_file(path, options).await?;
        self.write_handle_stream_with_close(handle, 0, None, Some(handle))
            .await
    }

    /// Write data to an open file handle.
    pub async fn write_handle(
        &self,
        handle: FsHandle,
        offset: u64,
        data: impl AsRef<[u8]>,
    ) -> MicrosandboxResult<()> {
        let data = data.as_ref();
        let sink = self
            .write_handle_stream(handle, offset, Some(data.len() as u64))
            .await?;
        for chunk in data.chunks(FS_CHUNK_SIZE) {
            sink.write(chunk).await?;
        }
        sink.close().await
    }

    /// Write to an open file handle with streaming.
    pub async fn write_handle_stream(
        &self,
        handle: FsHandle,
        offset: u64,
        len: Option<u64>,
    ) -> MicrosandboxResult<FsWriteSink> {
        self.write_handle_stream_with_close(handle, offset, len, None)
            .await
    }

    async fn write_handle_stream_with_close(
        &self,
        handle: FsHandle,
        offset: u64,
        len: Option<u64>,
        close_handle: Option<FsHandle>,
    ) -> MicrosandboxResult<FsWriteSink> {
        self.ensure_filesystem_supported()?;
        let req = FsRequest {
            op: FsOp::Write {
                handle,
                offset,
                len,
            },
        };
        let (id, rx) = self.client.stream(MessageType::FsRequest, &req).await?;
        Ok(FsWriteSink {
            id,
            client: Arc::clone(&self.client),
            rx,
            close_handle,
        })
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
        let req = FsRequest {
            op: FsOp::OpenFile {
                path: path.to_string(),
                options,
            },
        };
        let resp = self.request_response(req).await?;
        match resp.data {
            Some(FsResponseData::Handle(handle)) => Ok(handle),
            _ => Err(MicrosandboxError::SandboxFs(
                "unexpected response data for open file".into(),
            )),
        }
    }

    /// Open a directory and return an agentd-side handle.
    pub async fn open_dir(&self, path: &str) -> MicrosandboxResult<FsHandle> {
        let req = FsRequest {
            op: FsOp::OpenDir {
                path: path.to_string(),
            },
        };
        let resp = self.request_response(req).await?;
        match resp.data {
            Some(FsResponseData::Handle(handle)) => Ok(handle),
            _ => Err(MicrosandboxError::SandboxFs(
                "unexpected response data for open directory".into(),
            )),
        }
    }

    /// Close an open file or directory handle.
    pub async fn close_handle(&self, handle: FsHandle) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::CloseHandle { handle },
        };
        self.request_ok(req).await
    }

    //----------------------------------------------------------------------------------------------
    // Directory Operations
    //----------------------------------------------------------------------------------------------

    /// List the immediate children of a directory in the guest (non-recursive).
    pub async fn list(&self, path: &str) -> MicrosandboxResult<Vec<FsEntry>> {
        let handle = self.open_dir(path).await?;
        let mut entries = Vec::new();

        loop {
            let batch = match self.read_dir(handle, None).await {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = self.close_handle(handle).await;
                    return Err(error);
                }
            };
            if batch.is_empty() {
                break;
            }
            entries.extend(batch);
        }

        self.close_handle(handle).await?;
        Ok(entries)
    }

    /// Read the next batch from an open directory handle.
    pub async fn read_dir(
        &self,
        handle: FsHandle,
        limit: Option<u32>,
    ) -> MicrosandboxResult<Vec<FsEntry>> {
        let req = FsRequest {
            op: FsOp::ReadDir { handle, limit },
        };
        let resp = self.request_response(req).await?;
        match resp.data {
            Some(FsResponseData::List(entries)) => {
                Ok(entries.into_iter().map(entry_info_to_fs_entry).collect())
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Create a directory (and parents).
    pub async fn mkdir(&self, path: &str) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::Mkdir {
                path: path.to_string(),
                mode: None,
            },
        };
        self.request_ok(req).await
    }

    /// Remove a directory recursively.
    pub async fn remove_dir(&self, path: &str) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::RemoveDir {
                path: path.to_string(),
                recursive: true,
            },
        };
        self.request_ok(req).await
    }

    /// Remove an empty directory.
    pub async fn remove_empty_dir(&self, path: &str) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::RemoveDir {
                path: path.to_string(),
                recursive: false,
            },
        };
        self.request_ok(req).await
    }

    //----------------------------------------------------------------------------------------------
    // File Operations
    //----------------------------------------------------------------------------------------------

    /// Delete a single file. Use [`remove_dir`](Self::remove_dir) for directories.
    pub async fn remove(&self, path: &str) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::Remove {
                path: path.to_string(),
            },
        };
        self.request_ok(req).await
    }

    /// Copy a file within the sandbox.
    pub async fn copy(&self, from: &str, to: &str) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::Copy {
                src: from.to_string(),
                dst: to.to_string(),
            },
        };
        self.request_ok(req).await
    }

    /// Rename/move a file or directory.
    pub async fn rename(&self, from: &str, to: &str) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::Rename {
                src: from.to_string(),
                dst: to.to_string(),
            },
        };
        self.request_ok(req).await
    }

    /// Read a symlink target.
    pub async fn read_link(&self, path: &str) -> MicrosandboxResult<String> {
        let req = FsRequest {
            op: FsOp::ReadLink {
                path: path.to_string(),
            },
        };
        let resp = self.request_response(req).await?;
        match resp.data {
            Some(FsResponseData::Path(path)) => Ok(path),
            _ => Err(MicrosandboxError::SandboxFs(
                "unexpected response data for readlink".into(),
            )),
        }
    }

    /// Create a symlink.
    pub async fn symlink(&self, target: &str, link_path: &str) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::Symlink {
                target: target.to_string(),
                link_path: link_path.to_string(),
            },
        };
        self.request_ok(req).await
    }

    /// Resolve a path to its canonical absolute form.
    pub async fn real_path(&self, path: &str) -> MicrosandboxResult<String> {
        let req = FsRequest {
            op: FsOp::RealPath {
                path: path.to_string(),
            },
        };
        let resp = self.request_response(req).await?;
        match resp.data {
            Some(FsResponseData::Path(path)) => Ok(path),
            _ => Err(MicrosandboxError::SandboxFs(
                "unexpected response data for realpath".into(),
            )),
        }
    }

    //----------------------------------------------------------------------------------------------
    // Metadata
    //----------------------------------------------------------------------------------------------

    /// Get file/directory metadata, following symlinks.
    pub async fn stat(&self, path: &str) -> MicrosandboxResult<FsMetadata> {
        self.stat_with_follow(path, true).await
    }

    /// Get file/directory metadata with explicit symlink behavior.
    pub async fn stat_with_follow(
        &self,
        path: &str,
        follow_symlink: bool,
    ) -> MicrosandboxResult<FsMetadata> {
        let req = FsRequest {
            op: FsOp::Stat {
                path: path.to_string(),
                follow_symlink,
            },
        };
        let resp = self.request_response(req).await?;
        match resp.data {
            Some(FsResponseData::Stat(info)) => Ok(entry_info_to_metadata(&info)),
            _ => Err(MicrosandboxError::SandboxFs(
                "unexpected response data for stat".into(),
            )),
        }
    }

    /// Get metadata for an open handle.
    pub async fn fstat(&self, handle: FsHandle) -> MicrosandboxResult<FsMetadata> {
        let req = FsRequest {
            op: FsOp::FStat { handle },
        };
        let resp = self.request_response(req).await?;
        match resp.data {
            Some(FsResponseData::Stat(info)) => Ok(entry_info_to_metadata(&info)),
            _ => Err(MicrosandboxError::SandboxFs(
                "unexpected response data for fstat".into(),
            )),
        }
    }

    /// Update path metadata.
    pub async fn set_stat(
        &self,
        path: &str,
        follow_symlink: bool,
        attrs: FsSetAttrs,
    ) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::SetStat {
                path: path.to_string(),
                follow_symlink,
                attrs,
            },
        };
        self.request_ok(req).await
    }

    /// Update metadata for an open handle.
    pub async fn fset_stat(&self, handle: FsHandle, attrs: FsSetAttrs) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::FSetStat { handle, attrs },
        };
        self.request_ok(req).await
    }

    /// Check whether a file or directory exists at the given path in the guest.
    pub async fn exists(&self, path: &str) -> MicrosandboxResult<bool> {
        match self.stat(path).await {
            Ok(_) => Ok(true),
            Err(MicrosandboxError::SandboxFs(_)) => Ok(false),
            Err(e) => Err(e),
        }
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
        use tokio::io::AsyncReadExt;

        let mut file = tokio::fs::File::open(host_path.as_ref()).await?;
        let sink = self.write_stream(guest_path).await?;
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

    /// Copy a file from the sandbox to the host.
    pub async fn copy_to_host(
        &self,
        guest_path: &str,
        host_path: impl AsRef<Path>,
    ) -> MicrosandboxResult<()> {
        let data = self.read(guest_path).await?;
        tokio::fs::write(host_path.as_ref(), &data).await?;
        Ok(())
    }

    async fn request_ok(&self, req: FsRequest) -> MicrosandboxResult<()> {
        let resp = self.request_response(req).await?;
        if resp.ok {
            Ok(())
        } else {
            Err(response_error(resp))
        }
    }

    async fn request_response(&self, req: FsRequest) -> MicrosandboxResult<FsResponse> {
        self.ensure_filesystem_supported()?;
        let msg = self.client.request(MessageType::FsRequest, &req).await?;
        let resp: FsResponse = msg.payload()?;
        if resp.ok {
            Ok(resp)
        } else {
            Err(response_error(resp))
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: FsReadStream
//--------------------------------------------------------------------------------------------------

impl FsReadStream {
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
                        return Err(response_error(resp));
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
        if let Some(handle) = self.close_handle.take() {
            close_handle(&self.client, handle).await?;
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: FsWriteSink
//--------------------------------------------------------------------------------------------------

impl FsWriteSink {
    /// Write a chunk of data.
    pub async fn write(&self, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        let fs_data = FsData {
            data: data.as_ref().to_vec(),
        };
        self.client
            .send(self.id, MessageType::FsData, &fs_data)
            .await?;
        Ok(())
    }

    /// Close the write stream (sends EOF) and wait for confirmation.
    ///
    /// This must be called to finalize the write operation. Returns an
    /// error if the guest reports a write failure.
    pub async fn close(mut self) -> MicrosandboxResult<()> {
        let eof = FsData { data: Vec::new() };
        self.client.send(self.id, MessageType::FsData, &eof).await?;

        let result = wait_for_ok_response(&mut self.rx).await;
        let close_result = if let Some(handle) = self.close_handle.take() {
            close_handle(&self.client, handle).await
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
        Err(response_error(resp))
    }
}

/// Wait for and check a terminal `FsResponse` from a subscription channel.
async fn wait_for_ok_response(rx: &mut mpsc::UnboundedReceiver<Message>) -> MicrosandboxResult<()> {
    while let Some(msg) = rx.recv().await {
        if msg.t == MessageType::FsResponse {
            return check_response(msg);
        }
    }
    Err(MicrosandboxError::SandboxFs(
        "channel closed before response".into(),
    ))
}

async fn close_handle(client: &Arc<AgentClient>, handle: FsHandle) -> MicrosandboxResult<()> {
    let req = FsRequest {
        op: FsOp::CloseHandle { handle },
    };
    let msg = client.request(MessageType::FsRequest, &req).await?;
    check_response(msg)
}

fn response_error(resp: FsResponse) -> MicrosandboxError {
    MicrosandboxError::SandboxFs(resp.error.unwrap_or_else(|| "unknown error".into()))
}

fn read_only_open_options() -> FsOpenOptions {
    FsOpenOptions {
        read: true,
        ..Default::default()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use microsandbox_protocol::{codec, core::Ready};
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;
    use tokio::time::Instant;

    use super::*;
    use crate::agent::AgentClientError;

    #[tokio::test]
    async fn filesystem_operations_reject_legacy_agent_protocol() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = Ready {
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            ..Default::default()
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&0u32.to_be_bytes()).await.unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client = Arc::new(
            AgentClient::connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap(),
        );
        let fs = SandboxFs::new(&client);

        match fs.stat("/").await {
            Err(MicrosandboxError::AgentClient(AgentClientError::UnsupportedOperation {
                needs: 2,
                peer: 1,
                ..
            })) => {}
            Err(error) => panic!("unexpected error: {error}"),
            Ok(_) => panic!("legacy filesystem request unexpectedly succeeded"),
        }
    }
}
