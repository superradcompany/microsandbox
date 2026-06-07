//! Guest-side filesystem operation handlers.
//!
//! Handles `core.fs.*` protocol messages by performing filesystem operations
//! using `std::fs` and `tokio::fs`, then sending responses back to the host.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP;
use microsandbox_protocol::codec;
use microsandbox_protocol::fs::{
    FS_CHUNK_SIZE, FsData, FsEntryInfo, FsOp, FsOpenOptions, FsRequest, FsResponse, FsResponseData,
    FsSetAttrs,
};
use microsandbox_protocol::message::{Message, MessageType};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::session::{RawActivity, RawSessionCompletion, RawSessionOutput, SessionOutput};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default maximum number of entries returned by one `ReadDir` request.
const DEFAULT_READ_DIR_LIMIT: u32 = 128;

/// Maximum number of open filesystem handles owned by one relay client.
const MAX_OPEN_HANDLES_PER_OWNER: usize = 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Mutable filesystem protocol state held by agentd.
#[derive(Default)]
pub struct FsState {
    next_handle: u64,
    handles: HashMap<u64, FsHandleEntry>,
}

/// Tracks an in-progress streaming write operation.
pub struct FsWriteSession {
    owner_id: u32,
    handle: u64,
    file: Arc<Mutex<tokio::fs::File>>,
    offset: u64,
    append: bool,
    expected_len: Option<u64>,
    written: u64,
}

/// Tracks an in-progress streaming read operation.
pub struct FsReadSession {
    owner_id: u32,
    handle: u64,
    task: JoinHandle<()>,
}

/// A filesystem stream session started by a request.
pub enum FsStreamSession {
    /// Read stream task.
    Read(FsReadSession),

    /// Write stream awaiting `FsData` chunks.
    Write(FsWriteSession),
}

enum FsHandleEntry {
    File {
        owner_id: u32,
        file: Arc<Mutex<tokio::fs::File>>,
        read: bool,
        write: bool,
        append: bool,
        path: String,
    },
    Dir {
        owner_id: u32,
        dir: Arc<Mutex<tokio::fs::ReadDir>>,
        path: String,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FsState {
    /// Close handles opened by a disconnected relay client.
    pub fn close_owner_range(&mut self, id_start: u32, id_end_exclusive: u32) {
        self.handles.retain(|_, handle| {
            let owner_id = handle.owner_id();
            owner_id < id_start || owner_id >= id_end_exclusive
        });
    }

    /// Close all handles.
    pub fn clear(&mut self) {
        self.handles.clear();
    }

    fn insert_file(
        &mut self,
        owner_id: u32,
        file: tokio::fs::File,
        read: bool,
        write: bool,
        append: bool,
        path: String,
    ) -> Result<u64, String> {
        self.enforce_owner_limit(owner_id)?;
        let handle = self.alloc_handle();
        self.handles.insert(
            handle,
            FsHandleEntry::File {
                owner_id,
                file: Arc::new(Mutex::new(file)),
                read,
                write,
                append,
                path,
            },
        );
        Ok(handle)
    }

    fn insert_dir(
        &mut self,
        owner_id: u32,
        dir: tokio::fs::ReadDir,
        path: String,
    ) -> Result<u64, String> {
        self.enforce_owner_limit(owner_id)?;
        let handle = self.alloc_handle();
        self.handles.insert(
            handle,
            FsHandleEntry::Dir {
                owner_id,
                dir: Arc::new(Mutex::new(dir)),
                path,
            },
        );
        Ok(handle)
    }

    fn close_handle(&mut self, caller_id: u32, handle: u64) -> Result<FsHandleEntry, String> {
        if let Some(entry) = self.handles.get(&handle) {
            entry.ensure_owner(handle, caller_id)?;
        }
        self.handles
            .remove(&handle)
            .ok_or_else(|| format!("invalid handle: {handle}"))
    }

    fn file(
        &self,
        caller_id: u32,
        handle: u64,
        need_read: bool,
        need_write: bool,
    ) -> Result<(Arc<Mutex<tokio::fs::File>>, bool, String), String> {
        match self.handles.get(&handle) {
            Some(FsHandleEntry::File {
                file,
                read,
                write,
                append,
                path,
                ..
            }) => {
                self.handles
                    .get(&handle)
                    .expect("entry just matched")
                    .ensure_owner(handle, caller_id)?;
                if need_read && !read {
                    return Err(format!("handle {handle} is not open for reading"));
                }
                if need_write && !write && !append {
                    return Err(format!("handle {handle} is not open for writing"));
                }
                Ok((Arc::clone(file), *append, path.clone()))
            }
            Some(FsHandleEntry::Dir { .. }) => Err(format!("handle {handle} is a directory")),
            None => Err(format!("invalid handle: {handle}")),
        }
    }

    fn dir(
        &self,
        caller_id: u32,
        handle: u64,
    ) -> Result<(Arc<Mutex<tokio::fs::ReadDir>>, String), String> {
        match self.handles.get(&handle) {
            Some(FsHandleEntry::Dir { dir, path, .. }) => {
                self.handles
                    .get(&handle)
                    .expect("entry just matched")
                    .ensure_owner(handle, caller_id)?;
                Ok((Arc::clone(dir), path.clone()))
            }
            Some(FsHandleEntry::File { .. }) => Err(format!("handle {handle} is a file")),
            None => Err(format!("invalid handle: {handle}")),
        }
    }

    fn alloc_handle(&mut self) -> u64 {
        self.next_handle = self.next_handle.wrapping_add(1).max(1);
        while self.handles.contains_key(&self.next_handle) {
            self.next_handle = self.next_handle.wrapping_add(1).max(1);
        }
        self.next_handle
    }

    fn enforce_owner_limit(&self, owner_id: u32) -> Result<(), String> {
        let count = self
            .handles
            .values()
            .filter(|entry| same_relay_client(entry.owner_id(), owner_id))
            .count();
        if count >= MAX_OPEN_HANDLES_PER_OWNER {
            return Err(format!(
                "too many open filesystem handles for relay client: {count}"
            ));
        }
        Ok(())
    }
}

impl FsHandleEntry {
    fn owner_id(&self) -> u32 {
        match self {
            Self::File { owner_id, .. } | Self::Dir { owner_id, .. } => *owner_id,
        }
    }

    fn ensure_owner(&self, handle: u64, caller_id: u32) -> Result<(), String> {
        if same_relay_client(self.owner_id(), caller_id) {
            Ok(())
        } else {
            Err(format!(
                "handle {handle} is owned by a different relay client"
            ))
        }
    }
}

impl FsReadSession {
    /// Correlation ID whose relay client owns this read stream.
    pub fn owner_id(&self) -> u32 {
        self.owner_id
    }

    /// Filesystem handle being read.
    pub fn handle(&self) -> u64 {
        self.handle
    }

    /// Abort the background read task.
    pub fn abort(self) {
        self.task.abort();
    }
}

impl FsWriteSession {
    /// Correlation ID whose relay client owns this write stream.
    pub fn owner_id(&self) -> u32 {
        self.owner_id
    }

    /// Filesystem handle being written.
    pub fn handle(&self) -> u64 {
        self.handle
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn relay_client_slot(id: u32) -> Option<u32> {
    if id == 0 {
        None
    } else {
        Some((id - 1) / AGENT_RELAY_ID_RANGE_STEP)
    }
}

fn same_relay_client(left: u32, right: u32) -> bool {
    relay_client_slot(left).is_some_and(|left| Some(left) == relay_client_slot(right))
}

/// Handles an incoming `FsRequest` message.
pub async fn handle_fs_request(
    id: u32,
    req: FsRequest,
    state: &mut FsState,
    out_buf: &mut Vec<u8>,
    session_tx: &mpsc::UnboundedSender<(u32, SessionOutput)>,
) -> Result<Option<FsStreamSession>, String> {
    match req.op {
        FsOp::RealPath { path } => {
            let resp = handle_realpath(&path).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::Stat {
            path,
            follow_symlink,
        } => {
            let resp = handle_stat(&path, follow_symlink).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::SetStat {
            path,
            follow_symlink,
            attrs,
        } => {
            let resp = handle_setstat(&path, follow_symlink, attrs).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::List { path } => {
            let resp = handle_list(&path).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::ReadLink { path } => {
            let resp = handle_readlink(&path).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::Symlink { target, link_path } => {
            let resp = handle_symlink(&target, &link_path).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::Mkdir { path, mode } => {
            let resp = handle_mkdir(&path, mode).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::Remove { path } => {
            let resp = handle_remove(&path).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::RemoveDir { path, recursive } => {
            let resp = handle_remove_dir(&path, recursive).await;
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
        FsOp::OpenFile { path, options } => {
            let resp = handle_open_file(id, state, &path, options).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::OpenDir { path } => {
            let resp = handle_open_dir(id, state, &path).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::CloseHandle { handle } => {
            let resp = handle_close_handle(id, state, handle).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::Read {
            handle,
            offset,
            len,
        } => match state.file(id, handle, true, false) {
            Ok((file, _, _)) => {
                let tx = session_tx.clone();
                let task = tokio::spawn(async move {
                    handle_read_stream(id, file, offset, len, &tx).await;
                });
                Ok(Some(FsStreamSession::Read(FsReadSession {
                    owner_id: id,
                    handle,
                    task,
                })))
            }
            Err(e) => {
                encode_response(id, error_response(format!("read: {e}")), out_buf)?;
                Ok(None)
            }
        },
        FsOp::Write {
            handle,
            offset,
            len,
        } => match state.file(id, handle, false, true) {
            Ok((file, append, _)) => Ok(Some(FsStreamSession::Write(FsWriteSession {
                owner_id: id,
                handle,
                file,
                offset,
                append,
                expected_len: len,
                written: 0,
            }))),
            Err(e) => {
                encode_response(id, error_response(format!("write: {e}")), out_buf)?;
                Ok(None)
            }
        },
        FsOp::ReadDir { handle, limit } => {
            let resp = handle_read_dir(id, state, handle, limit).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::FStat { handle } => {
            let resp = handle_fstat(id, state, handle).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
        FsOp::FSetStat { handle, attrs } => {
            let resp = handle_fsetstat(id, state, handle, attrs).await;
            encode_response(id, resp, out_buf)?;
            Ok(None)
        }
    }
}

/// Handles an incoming `FsData` message for a streaming write session.
///
/// If `data` is empty, the file is flushed and a terminal `FsResponse` is sent.
/// Returns `true` if the session should be removed (EOF received).
pub async fn handle_fs_data(
    id: u32,
    data: FsData,
    session: &mut FsWriteSession,
    out_buf: &mut Vec<u8>,
) -> Result<bool, String> {
    if data.data.is_empty() {
        if let Some(expected) = session.expected_len
            && session.written != expected
        {
            let resp = error_response(format!(
                "write length mismatch: expected {expected}, wrote {}",
                session.written
            ));
            encode_response(id, resp, out_buf)?;
            return Ok(true);
        }

        if let Some(expected) = session.expected_len {
            let next_written = session.written.saturating_add(data.data.len() as u64);
            if next_written > expected {
                let resp = error_response(format!(
                    "write length mismatch: expected {expected}, received at least {next_written}"
                ));
                encode_response(id, resp, out_buf)?;
                return Ok(true);
            }
        }

        let mut file = session.file.lock().await;
        if let Err(e) = file.flush().await {
            encode_response(id, error_response(format!("flush: {e}")), out_buf)?;
            return Ok(true);
        }

        encode_response(id, ok_response(None), out_buf)?;
        Ok(true)
    } else {
        let mut file = session.file.lock().await;
        if !session.append
            && let Err(e) = file.seek(std::io::SeekFrom::Start(session.offset)).await
        {
            encode_response(id, error_response(format!("seek: {e}")), out_buf)?;
            return Ok(true);
        }
        if let Err(e) = file.write_all(&data.data).await {
            encode_response(id, error_response(format!("write: {e}")), out_buf)?;
            return Ok(true);
        }
        session.offset = session.offset.saturating_add(data.data.len() as u64);
        session.written = session.written.saturating_add(data.data.len() as u64);
        Ok(false)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Handlers
//--------------------------------------------------------------------------------------------------

async fn handle_realpath(path: &str) -> FsResponse {
    match realpath(path).await {
        Ok(path) => ok_response(Some(FsResponseData::Path(path))),
        Err(e) => error_response(format!("realpath: {e}")),
    }
}

async fn handle_stat(path: &str, follow_symlink: bool) -> FsResponse {
    let result = if follow_symlink {
        tokio::fs::metadata(path).await
    } else {
        tokio::fs::symlink_metadata(path).await
    };

    match result {
        Ok(meta) => ok_response(Some(FsResponseData::Stat(metadata_to_entry_info(
            path, &meta,
        )))),
        Err(e) => error_response(format!("stat: {e}")),
    }
}

async fn handle_setstat(path: &str, follow_symlink: bool, attrs: FsSetAttrs) -> FsResponse {
    match apply_path_attrs(path, follow_symlink, attrs).await {
        Ok(()) => ok_response(None),
        Err(e) => error_response(format!("setstat: {e}")),
    }
}

async fn handle_list(path: &str) -> FsResponse {
    match read_all_dir(path).await {
        Ok(entries) => ok_response(Some(FsResponseData::List(entries))),
        Err(e) => error_response(format!("readdir: {e}")),
    }
}

async fn handle_readlink(path: &str) -> FsResponse {
    match tokio::fs::read_link(path).await {
        Ok(target) => ok_response(Some(FsResponseData::Path(
            target.to_string_lossy().to_string(),
        ))),
        Err(e) => error_response(format!("readlink: {e}")),
    }
}

async fn handle_symlink(target: &str, link_path: &str) -> FsResponse {
    let target = target.to_string();
    let link_path = link_path.to_string();
    match tokio::task::spawn_blocking(move || std::os::unix::fs::symlink(target, link_path)).await {
        Ok(Ok(())) => ok_response(None),
        Ok(Err(e)) => error_response(format!("symlink: {e}")),
        Err(e) => error_response(format!("symlink task: {e}")),
    }
}

async fn handle_open_file(
    id: u32,
    state: &mut FsState,
    path: &str,
    options: FsOpenOptions,
) -> FsResponse {
    let mut open_options = tokio::fs::OpenOptions::new();
    open_options
        .read(options.read)
        .write(options.write)
        .append(options.append)
        .create(options.create)
        .truncate(options.truncate)
        .create_new(options.create_new);
    if let Some(mode) = options.mode {
        open_options.mode(mode);
    }

    match open_options.open(path).await {
        Ok(file) => match state.insert_file(
            id,
            file,
            options.read,
            options.write,
            options.append,
            path.to_string(),
        ) {
            Ok(handle) => ok_response(Some(FsResponseData::Handle(handle))),
            Err(e) => error_response(format!("open: {e}")),
        },
        Err(e) => error_response(format!("open: {e}")),
    }
}

async fn handle_open_dir(id: u32, state: &mut FsState, path: &str) -> FsResponse {
    match tokio::fs::read_dir(path).await {
        Ok(dir) => match state.insert_dir(id, dir, path.to_string()) {
            Ok(handle) => ok_response(Some(FsResponseData::Handle(handle))),
            Err(e) => error_response(format!("opendir: {e}")),
        },
        Err(e) => error_response(format!("opendir: {e}")),
    }
}

async fn handle_close_handle(id: u32, state: &mut FsState, handle: u64) -> FsResponse {
    match state.close_handle(id, handle) {
        Ok(FsHandleEntry::File { file, .. }) => {
            let mut file = file.lock().await;
            match file.flush().await {
                Ok(()) => ok_response(None),
                Err(e) => error_response(format!("close: {e}")),
            }
        }
        Ok(FsHandleEntry::Dir { .. }) => ok_response(None),
        Err(e) => error_response(format!("close: {e}")),
    }
}

async fn handle_read_dir(id: u32, state: &FsState, handle: u64, limit: Option<u32>) -> FsResponse {
    let (dir, path) = match state.dir(id, handle) {
        Ok(v) => v,
        Err(e) => return error_response(format!("readdir: {e}")),
    };

    let limit = limit.unwrap_or(DEFAULT_READ_DIR_LIMIT).max(1);
    let mut dir = dir.lock().await;
    let mut entries = Vec::new();

    for _ in 0..limit {
        match dir.next_entry().await {
            Ok(Some(entry)) => {
                let entry_path = entry.path();
                let path_str = entry_path.to_string_lossy().to_string();
                match tokio::fs::symlink_metadata(&entry_path).await {
                    Ok(meta) => entries.push(metadata_to_entry_info(&path_str, &meta)),
                    Err(_) => entries.push(unknown_entry_info(&path_str)),
                }
            }
            Ok(None) => break,
            Err(e) => return error_response(format!("readdir {path}: {e}")),
        }
    }

    ok_response(Some(FsResponseData::List(entries)))
}

async fn handle_fstat(id: u32, state: &FsState, handle: u64) -> FsResponse {
    match state.handles.get(&handle) {
        Some(FsHandleEntry::File { file, path, .. }) => {
            if let Err(e) = state
                .handles
                .get(&handle)
                .expect("entry just matched")
                .ensure_owner(handle, id)
            {
                return error_response(format!("fstat: {e}"));
            }
            let file = file.lock().await;
            match file.metadata().await {
                Ok(meta) => ok_response(Some(FsResponseData::Stat(metadata_to_entry_info(
                    path, &meta,
                )))),
                Err(e) => error_response(format!("fstat: {e}")),
            }
        }
        Some(FsHandleEntry::Dir { path, .. }) => {
            if let Err(e) = state
                .handles
                .get(&handle)
                .expect("entry just matched")
                .ensure_owner(handle, id)
            {
                return error_response(format!("fstat: {e}"));
            }
            match tokio::fs::metadata(path).await {
                Ok(meta) => ok_response(Some(FsResponseData::Stat(metadata_to_entry_info(
                    path, &meta,
                )))),
                Err(e) => error_response(format!("fstat: {e}")),
            }
        }
        None => error_response(format!("fstat: invalid handle: {handle}")),
    }
}

async fn handle_fsetstat(id: u32, state: &FsState, handle: u64, attrs: FsSetAttrs) -> FsResponse {
    let (file, _, path) = match state.file(id, handle, false, false) {
        Ok(v) => v,
        Err(e) => return error_response(format!("fsetstat: {e}")),
    };

    let mut file = file.lock().await;
    match apply_file_attrs(&mut file, &path, attrs).await {
        Ok(()) => ok_response(None),
        Err(e) => error_response(format!("fsetstat: {e}")),
    }
}

async fn handle_mkdir(path: &str, mode: Option<u32>) -> FsResponse {
    match tokio::fs::create_dir_all(path).await {
        Ok(()) => {
            if let Some(mode) = mode
                && let Err(e) =
                    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await
            {
                return error_response(format!("chmod: {e}"));
            }
            ok_response(None)
        }
        Err(e) => error_response(format!("mkdir: {e}")),
    }
}

async fn handle_remove(path: &str) -> FsResponse {
    match tokio::fs::remove_file(path).await {
        Ok(()) => ok_response(None),
        Err(e) => error_response(format!("remove: {e}")),
    }
}

async fn handle_remove_dir(path: &str, recursive: bool) -> FsResponse {
    let result = if recursive {
        tokio::fs::remove_dir_all(path).await
    } else {
        tokio::fs::remove_dir(path).await
    };
    match result {
        Ok(()) => ok_response(None),
        Err(e) => error_response(format!("remove_dir: {e}")),
    }
}

async fn handle_copy(src: &str, dst: &str) -> FsResponse {
    match tokio::fs::copy(src, dst).await {
        Ok(_) => ok_response(None),
        Err(e) => error_response(format!("copy: {e}")),
    }
}

async fn handle_rename(src: &str, dst: &str) -> FsResponse {
    match tokio::fs::rename(src, dst).await {
        Ok(()) => ok_response(None),
        Err(e) => error_response(format!("rename: {e}")),
    }
}

async fn handle_read_stream(
    id: u32,
    file: Arc<Mutex<tokio::fs::File>>,
    offset: u64,
    len: Option<u64>,
    tx: &mpsc::UnboundedSender<(u32, SessionOutput)>,
) {
    let mut file = file.lock().await;
    if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
        send_raw_response(id, false, Some(format!("seek: {e}")), None, tx);
        return;
    }

    let mut remaining = len;
    let mut chunk = vec![0u8; FS_CHUNK_SIZE];
    let mut buf = Vec::new();

    loop {
        let read_len = match remaining {
            Some(0) => break,
            Some(n) => chunk.len().min(n as usize),
            None => chunk.len(),
        };

        match file.read(&mut chunk[..read_len]).await {
            Ok(0) => break,
            Ok(n) => {
                if let Some(ref mut remaining) = remaining {
                    *remaining = remaining.saturating_sub(n as u64);
                }
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
                if let Err(e) = codec::encode_to_buf(&msg, &mut buf) {
                    send_raw_response(
                        id,
                        false,
                        Some(format!("encode chunk frame: {e}")),
                        None,
                        tx,
                    );
                    return;
                }
                let output = RawSessionOutput::new(buf.clone(), RawActivity::fs_bytes(n), None);
                if tx.send((id, SessionOutput::Raw(output))).is_err() {
                    return;
                }
            }
            Err(e) => {
                send_raw_response(id, false, Some(format!("read: {e}")), None, tx);
                return;
            }
        }
    }

    send_raw_response(id, true, None, None, tx);
}

//--------------------------------------------------------------------------------------------------
// Functions: Attribute Helpers
//--------------------------------------------------------------------------------------------------

async fn apply_path_attrs(
    path: &str,
    follow_symlink: bool,
    attrs: FsSetAttrs,
) -> Result<(), String> {
    if let Some(size) = attrs.size {
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .await
            .map_err(|e| format!("open for truncate: {e}"))?;
        file.set_len(size)
            .await
            .map_err(|e| format!("set_len: {e}"))?;
    }

    if let Some(mode) = attrs.mode {
        if !follow_symlink
            && tokio::fs::symlink_metadata(path)
                .await
                .map_err(|e| format!("lstat before chmod: {e}"))?
                .file_type()
                .is_symlink()
        {
            return Err("chmod on symlink without following is not supported".into());
        }
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .await
            .map_err(|e| format!("chmod: {e}"))?;
    }

    if attrs.uid.is_some() || attrs.gid.is_some() {
        chown_path(path, follow_symlink, attrs.uid, attrs.gid)?;
    }

    if attrs.atime.is_some() || attrs.mtime.is_some() {
        set_times_path(path, follow_symlink, attrs.atime, attrs.mtime).await?;
    }

    Ok(())
}

async fn apply_file_attrs(
    file: &mut tokio::fs::File,
    path: &str,
    attrs: FsSetAttrs,
) -> Result<(), String> {
    if let Some(size) = attrs.size {
        file.set_len(size)
            .await
            .map_err(|e| format!("set_len: {e}"))?;
    }

    if let Some(mode) = attrs.mode {
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .await
            .map_err(|e| format!("chmod: {e}"))?;
    }

    if attrs.uid.is_some() || attrs.gid.is_some() {
        let uid = attrs.uid.map(|v| v as libc::uid_t).unwrap_or(!0);
        let gid = attrs.gid.map(|v| v as libc::gid_t).unwrap_or(!0);
        let rc = unsafe { libc::fchown(file.as_raw_fd(), uid, gid) };
        if rc != 0 {
            return Err(format!("fchown: {}", std::io::Error::last_os_error()));
        }
    }

    if attrs.atime.is_some() || attrs.mtime.is_some() {
        set_times_fd(file.as_raw_fd(), path, attrs.atime, attrs.mtime).await?;
    }

    Ok(())
}

fn chown_path(
    path: &str,
    follow_symlink: bool,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    let c_path = cstring_path(path)?;
    let uid = uid.map(|v| v as libc::uid_t).unwrap_or(!0);
    let gid = gid.map(|v| v as libc::gid_t).unwrap_or(!0);
    let rc = unsafe {
        if follow_symlink {
            libc::chown(c_path.as_ptr(), uid, gid)
        } else {
            libc::lchown(c_path.as_ptr(), uid, gid)
        }
    };
    if rc != 0 {
        return Err(format!("chown: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

async fn set_times_path(
    path: &str,
    follow_symlink: bool,
    atime: Option<i64>,
    mtime: Option<i64>,
) -> Result<(), String> {
    let meta = if follow_symlink {
        tokio::fs::metadata(path).await
    } else {
        tokio::fs::symlink_metadata(path).await
    }
    .map_err(|e| format!("stat before utimensat: {e}"))?;
    let times = timespecs(atime.unwrap_or(meta.atime()), mtime.unwrap_or(meta.mtime()));
    let c_path = cstring_path(path)?;
    let flags = if follow_symlink {
        0
    } else {
        libc::AT_SYMLINK_NOFOLLOW
    };
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), flags) };
    if rc != 0 {
        return Err(format!("utimensat: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

async fn set_times_fd(
    fd: std::os::fd::RawFd,
    path: &str,
    atime: Option<i64>,
    mtime: Option<i64>,
) -> Result<(), String> {
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| format!("stat before futimens: {e}"))?;
    let times = timespecs(atime.unwrap_or(meta.atime()), mtime.unwrap_or(meta.mtime()));
    let rc = unsafe { libc::futimens(fd, times.as_ptr()) };
    if rc != 0 {
        return Err(format!("futimens: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn timespecs(atime: i64, mtime: i64) -> [libc::timespec; 2] {
    [
        libc::timespec {
            tv_sec: atime as _,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: mtime as _,
            tv_nsec: 0,
        },
    ]
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn encode_response(id: u32, resp: FsResponse, out_buf: &mut Vec<u8>) -> Result<(), String> {
    let msg = Message::with_payload(MessageType::FsResponse, id, &resp)
        .map_err(|e| format!("encode fs response: {e}"))?;
    codec::encode_to_buf(&msg, out_buf).map_err(|e| format!("encode fs response frame: {e}"))?;
    Ok(())
}

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
            match codec::encode_to_buf(&msg, &mut buf) {
                Ok(()) => {
                    let output = RawSessionOutput::new(
                        buf,
                        RawActivity::guest_message(),
                        Some(RawSessionCompletion::FsRead),
                    );
                    let _ = tx.send((id, SessionOutput::Raw(output)));
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

async fn realpath(path: &str) -> Result<String, String> {
    match tokio::fs::canonicalize(path).await {
        Ok(path) => Ok(path.to_string_lossy().to_string()),
        Err(original_error) => {
            let path = Path::new(path);
            let Some(parent) = path.parent() else {
                return Err(original_error.to_string());
            };
            let parent = tokio::fs::canonicalize(parent)
                .await
                .map_err(|_| original_error.to_string())?;
            let resolved = match path.file_name() {
                Some(name) => parent.join(name),
                None => parent,
            };
            Ok(resolved.to_string_lossy().to_string())
        }
    }
}

async fn read_all_dir(path: &str) -> Result<Vec<FsEntryInfo>, String> {
    let mut dir = tokio::fs::read_dir(path)
        .await
        .map_err(|e| format!("opendir: {e}"))?;
    let mut entries = Vec::new();

    loop {
        match dir.next_entry().await {
            Ok(Some(entry)) => {
                let entry_path = entry.path();
                let path_str = entry_path.to_string_lossy().to_string();
                match tokio::fs::symlink_metadata(&entry_path).await {
                    Ok(meta) => entries.push(metadata_to_entry_info(&path_str, &meta)),
                    Err(_) => entries.push(unknown_entry_info(&path_str)),
                }
            }
            Ok(None) => break,
            Err(e) => return Err(e.to_string()),
        }
    }

    Ok(entries)
}

fn ok_response(data: Option<FsResponseData>) -> FsResponse {
    FsResponse {
        ok: true,
        error: None,
        data,
    }
}

fn error_response(error: String) -> FsResponse {
    FsResponse {
        ok: false,
        error: Some(error),
        data: None,
    }
}

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

    let mtime = Some(meta.mtime());
    let atime = Some(meta.atime());

    FsEntryInfo {
        path: path.to_string(),
        kind: kind.to_string(),
        size: meta.len(),
        mode: meta.mode(),
        modified: mtime,
        uid: meta.uid(),
        gid: meta.gid(),
        atime,
        mtime,
    }
}

fn unknown_entry_info(path: &str) -> FsEntryInfo {
    FsEntryInfo {
        path: path.to_string(),
        kind: "other".to_string(),
        size: 0,
        mode: 0,
        modified: None,
        uid: 0,
        gid: 0,
        atime: None,
        mtime: None,
    }
}

fn cstring_path(path: impl AsRef<Path>) -> Result<CString, String> {
    CString::new(path.as_ref().as_os_str().as_bytes())
        .map_err(|e| format!("path contains NUL: {e}"))
}
