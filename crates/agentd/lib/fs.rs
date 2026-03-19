//! Guest-side filesystem operation handlers.
//!
//! Handles `core.fs.*` protocol messages by performing filesystem operations
//! using `std::fs` and `tokio::fs`, then sending responses back to the host.

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use microsandbox_protocol::{
    codec::encode_to_buf,
    fs::{FS_CHUNK_SIZE, FsData, FsEntryInfo, FsOp, FsRequest, FsResponse, FsResponseData},
    message::{Message, MessageType},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

use crate::session::SessionOutput;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Tracks an in-progress streaming write operation.
pub struct FsWriteSession {
    file: tokio::fs::File,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Handles an incoming `FsRequest` message.
///
/// For simple request/response ops (stat, list, mkdir, remove, copy, rename),
/// the response is encoded directly into `out_buf`.
///
/// For streaming read, a background task is spawned that sends `FsData` chunks
/// via `session_tx`, followed by a terminal `FsResponse`.
///
/// For streaming write, a `FsWriteSession` is created and returned for the
/// caller to insert into the write sessions map.
pub async fn handle_fs_request(
    id: u32,
    req: FsRequest,
    out_buf: &mut Vec<u8>,
    session_tx: &mpsc::UnboundedSender<(u32, SessionOutput)>,
) -> Result<Option<FsWriteSession>, String> {
    match req.op {
        FsOp::Stat { path } => {
            let resp = handle_stat(&path).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::List { path } => {
            let resp = handle_list(&path).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::Read { path } => {
            let tx = session_tx.clone();
            tokio::spawn(async move {
                handle_read_stream(id, &path, &tx).await;
            });
            Ok(None)
        }
        FsOp::Write { path, mode } => match handle_write_open(&path, mode).await {
            Ok(session) => Ok(Some(session)),
            Err(e) => {
                let resp = FsResponse {
                    ok: false,
                    error: Some(e),
                    data: None,
                };
                encode_response(id, resp, out_buf)?;
                Ok(None)
            }
        },
        FsOp::Mkdir { path } => {
            let resp = handle_mkdir(&path).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::Remove { path } => {
            let resp = handle_remove(&path).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::RemoveDir { path } => {
            let resp = handle_remove_dir(&path).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::Copy { src, dst } => {
            let resp = handle_copy(&src, &dst).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::Rename { src, dst } => {
            let resp = handle_rename(&src, &dst).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
    }
}

/// Handles an incoming `FsData` message for a streaming write session.
///
/// If `data` is empty, the file is closed and a terminal `FsResponse` is sent.
/// Returns `true` if the session should be removed (EOF received).
pub async fn handle_fs_data(
    id: u32,
    data: FsData,
    session: &mut FsWriteSession,
    out_buf: &mut Vec<u8>,
) -> Result<bool, String> {
    if data.data.is_empty() {
        // EOF — flush and close the file.
        if let Err(e) = session.file.flush().await {
            let resp = FsResponse {
                ok: false,
                error: Some(format!("flush: {e}")),
                data: None,
            };
            encode_response(id, resp, out_buf)?;
            return Ok(true);
        }

        let resp = FsResponse {
            ok: true,
            error: None,
            data: None,
        };
        encode_response(id, resp, out_buf)?;
        Ok(true)
    } else {
        // Write chunk to file.
        if let Err(e) = session.file.write_all(&data.data).await {
            let resp = FsResponse {
                ok: false,
                error: Some(format!("write: {e}")),
                data: None,
            };
            encode_response(id, resp, out_buf)?;
            return Ok(true);
        }
        Ok(false)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Encode a `FsResponse` message into the output buffer.
fn encode_response(id: u32, resp: FsResponse, out_buf: &mut Vec<u8>) -> Result<(), String> {
    let msg = Message::with_payload(MessageType::FsResponse, id, &resp)
        .map_err(|e| format!("encode fs response: {e}"))?;
    encode_to_buf(&msg, out_buf).map_err(|e| format!("encode fs response frame: {e}"))?;
    Ok(())
}

/// Stat a path and return the response.
async fn handle_stat(path: &str) -> FsResponse {
    match tokio::fs::symlink_metadata(path).await {
        Ok(meta) => FsResponse {
            ok: true,
            error: None,
            data: Some(FsResponseData::Stat(metadata_to_entry_info(path, &meta))),
        },
        Err(e) => FsResponse {
            ok: false,
            error: Some(format!("stat: {e}")),
            data: None,
        },
    }
}

/// List directory contents and return the response.
async fn handle_list(path: &str) -> FsResponse {
    match tokio::fs::read_dir(path).await {
        Ok(mut dir) => {
            let mut entries = Vec::new();
            loop {
                match dir.next_entry().await {
                    Ok(Some(entry)) => {
                        let entry_path = entry.path();
                        let path_str = entry_path.to_string_lossy().to_string();
                        match tokio::fs::symlink_metadata(&entry_path).await {
                            Ok(meta) => {
                                entries.push(metadata_to_entry_info(&path_str, &meta));
                            }
                            Err(_) => {
                                // Skip entries we can't stat.
                                entries.push(FsEntryInfo {
                                    path: path_str,
                                    kind: "other".to_string(),
                                    size: 0,
                                    mode: 0,
                                    modified: None,
                                });
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        return FsResponse {
                            ok: false,
                            error: Some(format!("readdir: {e}")),
                            data: None,
                        };
                    }
                }
            }
            FsResponse {
                ok: true,
                error: None,
                data: Some(FsResponseData::List(entries)),
            }
        }
        Err(e) => FsResponse {
            ok: false,
            error: Some(format!("opendir: {e}")),
            data: None,
        },
    }
}

/// Stream file contents as `FsData` chunks, then send terminal `FsResponse`.
async fn handle_read_stream(id: u32, path: &str, tx: &mpsc::UnboundedSender<(u32, SessionOutput)>) {
    let file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) => {
            send_raw_response(id, false, Some(format!("open: {e}")), None, tx);
            return;
        }
    };

    let mut reader = tokio::io::BufReader::new(file);
    let mut chunk = vec![0u8; FS_CHUNK_SIZE];
    let mut buf = Vec::new();

    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                let data = FsData {
                    data: chunk[..n].to_vec(),
                };
                let msg = match Message::with_payload(MessageType::FsData, id, &data) {
                    Ok(msg) => msg,
                    Err(e) => {
                        send_raw_response(id, false, Some(format!("encode chunk: {e}")), None, tx);
                        return;
                    }
                };
                buf.clear();
                if let Err(e) = encode_to_buf(&msg, &mut buf) {
                    send_raw_response(
                        id,
                        false,
                        Some(format!("encode chunk frame: {e}")),
                        None,
                        tx,
                    );
                    return;
                }
                if tx.send((id, SessionOutput::Raw(buf.clone()))).is_err() {
                    return;
                }
            }
            Err(e) => {
                send_raw_response(id, false, Some(format!("read: {e}")), None, tx);
                return;
            }
        }
    }

    // Terminal success response.
    send_raw_response(id, true, None, None, tx);
}

/// Encode and send a `FsResponse` as a raw pre-encoded frame via the session channel.
fn send_raw_response(
    id: u32,
    ok: bool,
    error: Option<String>,
    data: Option<FsResponseData>,
    tx: &mpsc::UnboundedSender<(u32, SessionOutput)>,
) {
    let resp = FsResponse { ok, error, data };
    match Message::with_payload(MessageType::FsResponse, id, &resp) {
        Ok(msg) => {
            let mut buf = Vec::new();
            match encode_to_buf(&msg, &mut buf) {
                Ok(()) => {
                    let _ = tx.send((id, SessionOutput::Raw(buf)));
                }
                Err(e) => {
                    eprintln!("failed to encode fs response frame for {id}: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("failed to encode fs response for {id}: {e}");
        }
    }
}

/// Open a file for writing and return a write session.
async fn handle_write_open(path: &str, mode: Option<u32>) -> Result<FsWriteSession, String> {
    // Ensure parent directory exists.
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("mkdir parent: {e}"))?;
    }

    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .await
        .map_err(|e| format!("open for write: {e}"))?;

    // Set permissions if specified.
    if let Some(mode) = mode {
        let perms = std::fs::Permissions::from_mode(mode);
        file.set_permissions(perms)
            .await
            .map_err(|e| format!("set permissions: {e}"))?;
    }

    Ok(FsWriteSession { file })
}

/// Create a directory (and parents).
async fn handle_mkdir(path: &str) -> FsResponse {
    match tokio::fs::create_dir_all(path).await {
        Ok(()) => FsResponse {
            ok: true,
            error: None,
            data: None,
        },
        Err(e) => FsResponse {
            ok: false,
            error: Some(format!("mkdir: {e}")),
            data: None,
        },
    }
}

/// Remove a file.
async fn handle_remove(path: &str) -> FsResponse {
    match tokio::fs::remove_file(path).await {
        Ok(()) => FsResponse {
            ok: true,
            error: None,
            data: None,
        },
        Err(e) => FsResponse {
            ok: false,
            error: Some(format!("remove: {e}")),
            data: None,
        },
    }
}

/// Remove a directory recursively.
async fn handle_remove_dir(path: &str) -> FsResponse {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => FsResponse {
            ok: true,
            error: None,
            data: None,
        },
        Err(e) => FsResponse {
            ok: false,
            error: Some(format!("remove_dir: {e}")),
            data: None,
        },
    }
}

/// Copy a file within the guest.
async fn handle_copy(src: &str, dst: &str) -> FsResponse {
    // Ensure parent directory of destination exists.
    if let Some(parent) = std::path::Path::new(dst).parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = tokio::fs::create_dir_all(parent).await
    {
        return FsResponse {
            ok: false,
            error: Some(format!("mkdir parent: {e}")),
            data: None,
        };
    }

    match tokio::fs::copy(src, dst).await {
        Ok(_) => FsResponse {
            ok: true,
            error: None,
            data: None,
        },
        Err(e) => FsResponse {
            ok: false,
            error: Some(format!("copy: {e}")),
            data: None,
        },
    }
}

/// Rename/move a file or directory.
async fn handle_rename(src: &str, dst: &str) -> FsResponse {
    // Ensure parent directory of destination exists.
    if let Some(parent) = std::path::Path::new(dst).parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = tokio::fs::create_dir_all(parent).await
    {
        return FsResponse {
            ok: false,
            error: Some(format!("mkdir parent: {e}")),
            data: None,
        };
    }

    match tokio::fs::rename(src, dst).await {
        Ok(()) => FsResponse {
            ok: true,
            error: None,
            data: None,
        },
        Err(e) => FsResponse {
            ok: false,
            error: Some(format!("rename: {e}")),
            data: None,
        },
    }
}

/// Convert `std::fs::Metadata` to `FsEntryInfo`.
fn metadata_to_entry_info(path: &str, meta: &std::fs::Metadata) -> FsEntryInfo {
    let kind = if meta.is_file() {
        "file"
    } else if meta.is_dir() {
        "dir"
    } else if meta.is_symlink() {
        "symlink"
    } else {
        "other"
    };

    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64);

    FsEntryInfo {
        path: path.to_string(),
        kind: kind.to_string(),
        size: meta.len(),
        mode: meta.mode(),
        modified,
    }
}
