//! Filesystem operations on a running sandbox.
//!
//! [`SandboxFs`] provides methods to read, write, list, and manipulate files
//! inside a running sandbox via the `core.fs.*` protocol messages.

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use microsandbox_protocol::fs::{
    FsData, FsEntryInfo, FsOp, FsRequest, FsResponse, FsResponseData, FS_CHUNK_SIZE,
};
use microsandbox_protocol::message::{Message, MessageType};
use tokio::sync::mpsc;

use crate::MicrosandboxError;
use crate::MicrosandboxResult;
use crate::agent::AgentBridge;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Filesystem operations handle for a running sandbox.
///
/// All operations go through the agent protocol (`core.fs.*` messages),
/// which are handled by agentd inside the guest VM.
pub struct SandboxFs<'a> {
    bridge: &'a Arc<AgentBridge>,
}

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
}

/// A streaming reader for file data from the sandbox.
pub struct FsReadStream {
    rx: mpsc::UnboundedReceiver<Message>,
}

/// A streaming writer for file data to the sandbox.
pub struct FsWriteSink {
    id: u32,
    bridge: Arc<AgentBridge>,
    rx: mpsc::UnboundedReceiver<Message>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> SandboxFs<'a> {
    /// Create a new filesystem handle.
    pub(crate) fn new(bridge: &'a Arc<AgentBridge>) -> Self {
        Self { bridge }
    }

    //----------------------------------------------------------------------------------------------
    // Read Operations
    //----------------------------------------------------------------------------------------------

    /// Read a file to bytes.
    pub async fn read(&self, path: &str) -> MicrosandboxResult<Bytes> {
        let id = self.bridge.next_id();
        let mut rx = self.bridge.subscribe(id).await;

        let req = FsRequest {
            op: FsOp::Read {
                path: path.to_string(),
            },
        };
        let msg = Message::with_payload(MessageType::FsRequest, id, &req)?;
        self.bridge.send(&msg).await?;

        // Collect FsData chunks until FsResponse (terminal).
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
                        return Err(MicrosandboxError::SandboxFs(
                            resp.error.unwrap_or_else(|| "unknown error".into()),
                        ));
                    }
                    break;
                }
                _ => {}
            }
        }

        Ok(Bytes::from(data))
    }

    /// Read a file to string.
    pub async fn read_to_string(&self, path: &str) -> MicrosandboxResult<String> {
        let data = self.read(path).await?;
        String::from_utf8(Vec::from(data))
            .map_err(|e| MicrosandboxError::SandboxFs(format!("invalid utf-8: {e}")))
    }

    /// Read a file with streaming.
    ///
    /// Returns an [`FsReadStream`] that yields chunks of data as they arrive.
    pub async fn read_stream(&self, path: &str) -> MicrosandboxResult<FsReadStream> {
        let id = self.bridge.next_id();
        let rx = self.bridge.subscribe(id).await;

        let req = FsRequest {
            op: FsOp::Read {
                path: path.to_string(),
            },
        };
        let msg = Message::with_payload(MessageType::FsRequest, id, &req)?;
        self.bridge.send(&msg).await?;

        Ok(FsReadStream { rx })
    }

    //----------------------------------------------------------------------------------------------
    // Write Operations
    //----------------------------------------------------------------------------------------------

    /// Write bytes to a file.
    pub async fn write(
        &self,
        path: &str,
        data: impl AsRef<[u8]>,
    ) -> MicrosandboxResult<()> {
        let data = data.as_ref();
        let id = self.bridge.next_id();
        let mut rx = self.bridge.subscribe(id).await;

        // Send write request.
        let req = FsRequest {
            op: FsOp::Write {
                path: path.to_string(),
                mode: None,
            },
        };
        let msg = Message::with_payload(MessageType::FsRequest, id, &req)?;
        self.bridge.send(&msg).await?;

        // Send data chunks.
        for chunk in data.chunks(FS_CHUNK_SIZE) {
            let fs_data = FsData {
                data: chunk.to_vec(),
            };
            let msg = Message::with_payload(MessageType::FsData, id, &fs_data)?;
            self.bridge.send(&msg).await?;
        }

        // Send EOF.
        let eof = FsData { data: Vec::new() };
        let msg = Message::with_payload(MessageType::FsData, id, &eof)?;
        self.bridge.send(&msg).await?;

        // Wait for terminal response.
        wait_for_ok_response(&mut rx).await
    }

    /// Write with streaming.
    ///
    /// Returns an [`FsWriteSink`] for writing data in chunks. Call
    /// [`FsWriteSink::close`] when done writing.
    pub async fn write_stream(&self, path: &str) -> MicrosandboxResult<FsWriteSink> {
        let id = self.bridge.next_id();

        // Subscribe before sending to avoid race.
        let rx = self.bridge.subscribe(id).await;

        let req = FsRequest {
            op: FsOp::Write {
                path: path.to_string(),
                mode: None,
            },
        };
        let msg = Message::with_payload(MessageType::FsRequest, id, &req)?;
        self.bridge.send(&msg).await?;

        Ok(FsWriteSink {
            id,
            bridge: Arc::clone(self.bridge),
            rx,
        })
    }

    //----------------------------------------------------------------------------------------------
    // Directory Operations
    //----------------------------------------------------------------------------------------------

    /// List directory contents.
    pub async fn list(&self, path: &str) -> MicrosandboxResult<Vec<FsEntry>> {
        let req = FsRequest {
            op: FsOp::List {
                path: path.to_string(),
            },
        };
        let msg = Message::with_payload(MessageType::FsRequest, 0, &req)?;
        let resp_msg = self.bridge.request(msg).await?;
        let resp: FsResponse = resp_msg.payload()?;

        if !resp.ok {
            return Err(MicrosandboxError::SandboxFs(
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

    /// Create a directory (and parents).
    pub async fn mkdir(&self, path: &str) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::Mkdir {
                path: path.to_string(),
            },
        };
        let msg = Message::with_payload(MessageType::FsRequest, 0, &req)?;
        let resp_msg = self.bridge.request(msg).await?;
        check_response(resp_msg)
    }

    /// Remove a directory recursively.
    pub async fn remove_dir(&self, path: &str) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::RemoveDir {
                path: path.to_string(),
            },
        };
        let msg = Message::with_payload(MessageType::FsRequest, 0, &req)?;
        let resp_msg = self.bridge.request(msg).await?;
        check_response(resp_msg)
    }

    //----------------------------------------------------------------------------------------------
    // File Operations
    //----------------------------------------------------------------------------------------------

    /// Remove a file.
    pub async fn remove(&self, path: &str) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::Remove {
                path: path.to_string(),
            },
        };
        let msg = Message::with_payload(MessageType::FsRequest, 0, &req)?;
        let resp_msg = self.bridge.request(msg).await?;
        check_response(resp_msg)
    }

    /// Copy a file within the sandbox.
    pub async fn copy(&self, from: &str, to: &str) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::Copy {
                src: from.to_string(),
                dst: to.to_string(),
            },
        };
        let msg = Message::with_payload(MessageType::FsRequest, 0, &req)?;
        let resp_msg = self.bridge.request(msg).await?;
        check_response(resp_msg)
    }

    /// Rename/move a file or directory.
    pub async fn rename(&self, from: &str, to: &str) -> MicrosandboxResult<()> {
        let req = FsRequest {
            op: FsOp::Rename {
                src: from.to_string(),
                dst: to.to_string(),
            },
        };
        let msg = Message::with_payload(MessageType::FsRequest, 0, &req)?;
        let resp_msg = self.bridge.request(msg).await?;
        check_response(resp_msg)
    }

    //----------------------------------------------------------------------------------------------
    // Metadata
    //----------------------------------------------------------------------------------------------

    /// Get file/directory metadata.
    pub async fn stat(&self, path: &str) -> MicrosandboxResult<FsMetadata> {
        let req = FsRequest {
            op: FsOp::Stat {
                path: path.to_string(),
            },
        };
        let msg = Message::with_payload(MessageType::FsRequest, 0, &req)?;
        let resp_msg = self.bridge.request(msg).await?;
        let resp: FsResponse = resp_msg.payload()?;

        if !resp.ok {
            return Err(MicrosandboxError::SandboxFs(
                resp.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }

        match resp.data {
            Some(FsResponseData::Stat(info)) => Ok(entry_info_to_metadata(&info)),
            _ => Err(MicrosandboxError::SandboxFs(
                "unexpected response data for stat".into(),
            )),
        }
    }

    /// Check if a path exists.
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
        let data = tokio::fs::read(host_path.as_ref()).await?;
        self.write(guest_path, &data).await
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
                    if !resp.ok {
                        return Err(MicrosandboxError::SandboxFs(
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
    /// Write a chunk of data.
    pub async fn write(&self, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        let fs_data = FsData {
            data: data.as_ref().to_vec(),
        };
        let msg = Message::with_payload(MessageType::FsData, self.id, &fs_data)?;
        self.bridge.send(&msg).await
    }

    /// Close the write stream (sends EOF) and wait for confirmation.
    ///
    /// This must be called to finalize the write operation. Returns an
    /// error if the guest reports a write failure.
    pub async fn close(mut self) -> MicrosandboxResult<()> {
        let eof = FsData { data: Vec::new() };
        let msg = Message::with_payload(MessageType::FsData, self.id, &eof)?;
        self.bridge.send(&msg).await?;

        // Wait for the terminal FsResponse from the guest.
        wait_for_ok_response(&mut self.rx).await
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
        Err(MicrosandboxError::SandboxFs(
            resp.error.unwrap_or_else(|| "unknown error".into()),
        ))
    }
}

/// Wait for and check a terminal `FsResponse` from a subscription channel.
async fn wait_for_ok_response(
    rx: &mut mpsc::UnboundedReceiver<Message>,
) -> MicrosandboxResult<()> {
    while let Some(msg) = rx.recv().await {
        if msg.t == MessageType::FsResponse {
            return check_response(msg);
        }
    }
    Err(MicrosandboxError::SandboxFs(
        "channel closed before response".into(),
    ))
}
