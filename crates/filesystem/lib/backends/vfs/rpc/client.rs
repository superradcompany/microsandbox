//! [`RpcPathFs`] — a [`PathFs`] whose semantics live behind a [`VfsTransport`].
//!
//! Each `PathFs` call is turned into a [`VfsRequest`], sent over the transport,
//! and decoded from the [`VfsResponse`]. In production the transport is a
//! socket to the controlling (Go SDK) process; in tests it is an in-memory or
//! loopback channel. [`dispatch`] is the mirror image — the server side that
//! answers a [`VfsRequest`] from a real `PathFs` — and is shared by the Rust
//! reference server and the tests.

use std::{io, os::unix::ffi::OsStrExt, path::Path};

use serde_bytes::ByteBuf;

use super::super::{PathFs, VAttr, VDirEntry};
use super::limits::clamp_io_size;
use super::protocol::{
    GETATTR_MANY_RPC_CHUNK, MAX_IO_SIZE, MAX_READDIR_ENTRIES, MAX_READDIR_TOTAL, PROTOCOL_VERSION,
    VAttrResult, VfsRequest, VfsResponse,
};
use crate::backends::shared::platform;
use crate::{SetattrValid, statvfs64};

//--------------------------------------------------------------------------------------------------
// Transport
//--------------------------------------------------------------------------------------------------

/// A request/response channel to the process that owns the real [`PathFs`] provider.
///
/// Implementations must be `Send + Sync`: the scaffold calls the provider
/// concurrently from multiple FUSE worker threads.
pub trait VfsTransport: Send + Sync {
    /// Send one request and block for its response.
    fn call(&self, req: VfsRequest) -> io::Result<VfsResponse>;

    /// Send a `Write` request and block for its response. The default builds an
    /// owned [`VfsRequest::Write`] (in-memory transports need the decoded
    /// request to dispatch); the socket transport overrides this to serialize
    /// straight from the borrowed `data`, skipping a full copy on the hot path.
    fn call_write(&self, path: &[u8], offset: u64, data: &[u8]) -> io::Result<VfsResponse> {
        self.call(VfsRequest::Write {
            path: ByteBuf::from(path.to_vec()),
            offset,
            data: ByteBuf::from(data.to_vec()),
        })
    }

    /// Send a `GetAttr` request. Like [`call_write`](Self::call_write), the
    /// default builds an owned request for in-memory transports; the socket
    /// transport overrides this to serialize straight from the borrowed `path`.
    fn call_getattr(&self, path: &[u8]) -> io::Result<VfsResponse> {
        self.call(VfsRequest::GetAttr {
            path: ByteBuf::from(path.to_vec()),
        })
    }

    /// Send a `Read` request. See [`call_getattr`](Self::call_getattr).
    fn call_read(&self, path: &[u8], offset: u64, size: u32) -> io::Result<VfsResponse> {
        self.call(VfsRequest::Read {
            path: ByteBuf::from(path.to_vec()),
            offset,
            size,
        })
    }

    /// Send a `GetAttrMany` request. See [`call_getattr`](Self::call_getattr);
    /// the socket transport avoids copying every path into an owned `ByteBuf`.
    fn call_getattr_many(&self, paths: &[&[u8]]) -> io::Result<VfsResponse> {
        self.call(VfsRequest::GetAttrMany {
            paths: paths.iter().map(|p| ByteBuf::from(p.to_vec())).collect(),
        })
    }

    /// Protocol version reported by the peer during hello. Defaults to
    /// [`PROTOCOL_VERSION`] for in-memory / test transports.
    fn peer_protocol_version(&self) -> u32 {
        PROTOCOL_VERSION
    }
}

//--------------------------------------------------------------------------------------------------
// RpcPathFs
//--------------------------------------------------------------------------------------------------

/// A [`PathFs`] backed by a [`VfsTransport`].
pub struct RpcPathFs<T: VfsTransport> {
    transport: T,
}

impl<T: VfsTransport> RpcPathFs<T> {
    /// Wrap a transport.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Borrow the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

fn path_bytes(p: &Path) -> ByteBuf {
    ByteBuf::from(p.as_os_str().as_bytes().to_vec())
}

/// Map an unexpected (or `Err`) response to an `io::Error`.
fn unexpected(resp: VfsResponse) -> io::Error {
    match resp {
        VfsResponse::Err(errno) => io::Error::from_raw_os_error(errno),
        _ => io::Error::from_raw_os_error(libc::EIO),
    }
}

impl<T: VfsTransport> PathFs for RpcPathFs<T> {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        match self.transport.call_getattr(path.as_os_str().as_bytes())? {
            VfsResponse::Attr(a) => a.into_vattr(),
            other => Err(unexpected(other)),
        }
    }

    fn getattr_many(&self, paths: &[&Path]) -> io::Result<Vec<io::Result<VAttr>>> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let mut all = Vec::with_capacity(paths.len());
        for chunk in paths.chunks(GETATTR_MANY_RPC_CHUNK) {
            let wire_paths: Vec<&[u8]> = chunk.iter().map(|p| p.as_os_str().as_bytes()).collect();
            match self.transport.call_getattr_many(&wire_paths)? {
                VfsResponse::AttrMany(results) => {
                    if results.len() != chunk.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vfs: getattr_many returned a mismatched number of results",
                        ));
                    }
                    all.extend(results.into_iter().map(|r| match r {
                        VAttrResult::Ok(a) => a.into_vattr(),
                        VAttrResult::Err(errno) => Err(io::Error::from_raw_os_error(errno)),
                    }));
                }
                other => return Err(unexpected(other)),
            }
        }
        Ok(all)
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        let path_bytes = path_bytes(path);
        let mut all = Vec::new();
        let mut offset = 0u64;
        let mut restarts = 0u32;
        const MAX_READDIR_RESTARTS: u32 = 64;
        loop {
            match self.transport.call(VfsRequest::ReadDir {
                path: path_bytes.clone(),
                offset,
                limit: MAX_READDIR_ENTRIES as u32,
            })? {
                VfsResponse::Dir(entries) => {
                    let n = entries.len();
                    all.extend(
                        entries
                            .into_iter()
                            .map(|e| e.into_entry())
                            .collect::<io::Result<Vec<_>>>()?,
                    );
                    if all.len() > MAX_READDIR_TOTAL {
                        return Err(platform::einval());
                    }
                    if n < MAX_READDIR_ENTRIES {
                        break;
                    }
                    offset = offset.saturating_add(n as u64);
                }
                VfsResponse::Err(errno) if errno == platform::LINUX_EAGAIN && offset > 0 => {
                    restarts += 1;
                    if restarts > MAX_READDIR_RESTARTS {
                        return Err(platform::eio());
                    }
                    all.clear();
                    offset = 0;
                }
                VfsResponse::Err(errno) => return Err(io::Error::from_raw_os_error(errno)),
                other => return Err(unexpected(other)),
            }
        }
        Ok(all)
    }

    fn read(&self, path: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
        let size = clamp_io_size(size)?;
        match self
            .transport
            .call_read(path.as_os_str().as_bytes(), offset, size)?
        {
            VfsResponse::Bytes(b) => {
                // A reply longer than requested is a peer contract violation:
                // silently truncating it would drop the tail (the kernel treats
                // a full-length read as non-EOF and never re-requests the lost
                // bytes), so fail loudly instead.
                if b.len() > size as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vfs: read returned more bytes than requested",
                    ));
                }
                Ok(b.into_vec())
            }
            other => Err(unexpected(other)),
        }
    }

    fn write(&self, path: &Path, offset: u64, data: &[u8]) -> io::Result<usize> {
        if data.len() > MAX_IO_SIZE as usize {
            return Err(platform::einval());
        }
        match self
            .transport
            .call_write(path.as_os_str().as_bytes(), offset, data)?
        {
            VfsResponse::Count(n) => {
                let n = n as usize;
                if n > data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vfs: write returned more bytes than sent",
                    ));
                }
                Ok(n)
            }
            other => Err(unexpected(other)),
        }
    }

    fn create(&self, path: &Path, attr: &VAttr) -> io::Result<VAttr> {
        match self.transport.call(VfsRequest::Create {
            path: path_bytes(path),
            attr: attr.into(),
        })? {
            VfsResponse::Attr(a) => a.into_vattr(),
            other => Err(unexpected(other)),
        }
    }

    fn mkdir(&self, path: &Path, mode: u32) -> io::Result<VAttr> {
        match self.transport.call(VfsRequest::Mkdir {
            path: path_bytes(path),
            mode,
        })? {
            VfsResponse::Attr(a) => a.into_vattr(),
            other => Err(unexpected(other)),
        }
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        match self.transport.call(VfsRequest::Remove {
            path: path_bytes(path),
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn rmdir(&self, path: &Path) -> io::Result<()> {
        // Server-side Remove serializes mutating ops per connection and routes
        // directory removal through rmdir().
        self.remove(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.rename_with_flags(from, to, 0)
    }

    fn rename_with_flags(&self, from: &Path, to: &Path, flags: u32) -> io::Result<()> {
        match self.transport.call(VfsRequest::Rename {
            from: path_bytes(from),
            to: path_bytes(to),
            flags,
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn setattr(&self, path: &Path, attr: &VAttr, valid: SetattrValid) -> io::Result<VAttr> {
        match self.transport.call(VfsRequest::SetAttr {
            path: path_bytes(path),
            attr: attr.into(),
            valid: valid.bits(),
        })? {
            VfsResponse::Attr(a) => a.into_vattr(),
            other => Err(unexpected(other)),
        }
    }

    fn symlink(&self, path: &Path, target: &[u8]) -> io::Result<VAttr> {
        match self.transport.call(VfsRequest::Symlink {
            path: path_bytes(path),
            target: ByteBuf::from(target.to_vec()),
        })? {
            VfsResponse::Attr(a) => a.into_vattr(),
            other => Err(unexpected(other)),
        }
    }

    fn readlink(&self, path: &Path) -> io::Result<Vec<u8>> {
        match self.transport.call(VfsRequest::ReadLink {
            path: path_bytes(path),
        })? {
            VfsResponse::Bytes(b) => Ok(b.into_vec()),
            other => Err(unexpected(other)),
        }
    }

    fn setxattr(&self, path: &Path, name: &[u8], value: &[u8], flags: u32) -> io::Result<()> {
        match self.transport.call(VfsRequest::SetXattr {
            path: path_bytes(path),
            name: ByteBuf::from(name.to_vec()),
            value: ByteBuf::from(value.to_vec()),
            flags,
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn getxattr(&self, path: &Path, name: &[u8]) -> io::Result<Vec<u8>> {
        match self.transport.call(VfsRequest::GetXattr {
            path: path_bytes(path),
            name: ByteBuf::from(name.to_vec()),
        })? {
            VfsResponse::Bytes(b) => Ok(b.into_vec()),
            other => Err(unexpected(other)),
        }
    }

    fn listxattr(&self, path: &Path) -> io::Result<Vec<Vec<u8>>> {
        match self.transport.call(VfsRequest::ListXattr {
            path: path_bytes(path),
        })? {
            VfsResponse::Names(names) => Ok(names.into_iter().map(ByteBuf::into_vec).collect()),
            other => Err(unexpected(other)),
        }
    }

    fn removexattr(&self, path: &Path, name: &[u8]) -> io::Result<()> {
        match self.transport.call(VfsRequest::RemoveXattr {
            path: path_bytes(path),
            name: ByteBuf::from(name.to_vec()),
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn statfs(&self) -> io::Result<statvfs64> {
        match self.transport.call(VfsRequest::StatFs)? {
            VfsResponse::StatFs(s) => Ok(s.into_statvfs()),
            other => Err(unexpected(other)),
        }
    }

    fn flush(&self, path: &Path) -> io::Result<()> {
        match self.transport.call(VfsRequest::Flush {
            path: path_bytes(path),
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn fsync(&self, path: &Path, datasync: bool) -> io::Result<()> {
        match self.transport.call(VfsRequest::Fsync {
            path: path_bytes(path),
            datasync,
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn fsyncdir(&self, path: &Path) -> io::Result<()> {
        if self.transport.peer_protocol_version() < 4 {
            return Ok(());
        }
        match self.transport.call(VfsRequest::FsyncDir {
            path: path_bytes(path),
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }
}
