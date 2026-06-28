//! The VFS-op wire protocol: a request/response pair per [`super::super::PathFs`] method.
//!
//! These types cross the parent↔child process boundary that separates the Go
//! SDK (which runs the user's provider) from the `msb` runtime (which serves
//! FUSE). They are CBOR-encoded ([`to_cbor`]/[`from_cbor`]) and length-framed
//! ([`write_frame`]/[`read_frame`]).
//!
//! Paths and names are raw bytes — never UTF-8-validated strings — and errors
//! carry a **Linux** errno so they round-trip exactly as
//! [`PathFs`](super::super::PathFs) already promises.

use std::{
    io::{self, Read, Write},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::super::{NodeKind, VAttr, VDirEntry};
use crate::backends::shared::platform;
use crate::statvfs64;

//--------------------------------------------------------------------------------------------------
// Node kind <-> wire byte
//--------------------------------------------------------------------------------------------------

pub(crate) fn node_kind_to_u8(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::File => 0,
        NodeKind::Dir => 1,
        NodeKind::Symlink => 2,
        NodeKind::Char => 3,
        NodeKind::Block => 4,
        NodeKind::Fifo => 5,
        NodeKind::Socket => 6,
    }
}

pub(crate) fn node_kind_from_u8(v: u8) -> io::Result<NodeKind> {
    Ok(match v {
        0 => NodeKind::File,
        1 => NodeKind::Dir,
        2 => NodeKind::Symlink,
        3 => NodeKind::Char,
        4 => NodeKind::Block,
        5 => NodeKind::Fifo,
        6 => NodeKind::Socket,
        _ => return Err(bad_data("unknown node kind")),
    })
}

//--------------------------------------------------------------------------------------------------
// Time <-> wire
//--------------------------------------------------------------------------------------------------

// Times use the standard `timespec` floor convention shared with the Go side:
// `sec` is the floor of the instant in whole seconds and `nsec` is always in
// `[0, 1_000_000_000)`. For a pre-epoch instant like epoch-0.5s that means
// `(sec=-1, nsec=500_000_000)`, not `(sec=0, nsec=500_000_000)` — the latter is
// ambiguous (it decodes as epoch+0.5s) and disagrees with Go's `t.Unix()` /
// `t.Nanosecond()`.
fn time_to_wire(t: SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            let secs = d.as_secs() as i64;
            let nanos = d.subsec_nanos();
            if nanos == 0 {
                (-secs, 0)
            } else {
                // Floor: carry the positive sub-second remainder by borrowing a
                // whole second from the (negative) seconds field.
                (-secs - 1, 1_000_000_000 - nanos)
            }
        }
    }
}

fn wire_to_time((sec, nsec): (i64, u32)) -> SystemTime {
    if sec >= 0 {
        UNIX_EPOCH + Duration::new(sec as u64, nsec)
    } else {
        // The instant is `(-sec)` seconds before the epoch, then `nsec` forward.
        // `-sec >= 1` and `nsec < 1e9`, so the subtraction never underflows.
        UNIX_EPOCH - (Duration::new((-sec) as u64, 0) - Duration::new(0, nsec))
    }
}

//--------------------------------------------------------------------------------------------------
// Wire structs
//--------------------------------------------------------------------------------------------------

/// Wire form of [`VAttr`]. Times are `(seconds, nanos)` since the epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VAttrWire {
    /// [`NodeKind`] encoded as a byte.
    pub kind: u8,
    /// Permission bits (type bits are derived from `kind`).
    pub mode: u32,
    /// Size in bytes.
    pub size: u64,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
    /// Hard-link count; `None` lets the scaffold default it.
    pub nlink: Option<u64>,
    /// Device number for `Char`/`Block` nodes.
    pub rdev: u32,
    /// Last-access time; `None` => current time.
    pub atime: Option<(i64, u32)>,
    /// Last-modification time; `None` => current time.
    pub mtime: Option<(i64, u32)>,
    /// Last status-change time; `None` => current time.
    pub ctime: Option<(i64, u32)>,
}

impl From<&VAttr> for VAttrWire {
    fn from(a: &VAttr) -> Self {
        VAttrWire {
            kind: node_kind_to_u8(a.kind),
            mode: a.mode,
            size: a.size,
            uid: a.uid,
            gid: a.gid,
            nlink: a.nlink,
            rdev: a.rdev,
            atime: a.atime.map(time_to_wire),
            mtime: a.mtime.map(time_to_wire),
            ctime: a.ctime.map(time_to_wire),
        }
    }
}

/// One path's result inside an [`VfsResponse::AttrMany`] batch: either the
/// node's attributes or the Linux errno its getattr failed with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VAttrResult {
    /// Attributes for the path.
    Ok(VAttrWire),
    /// The path's getattr failed with this Linux errno.
    Err(i32),
}

impl VAttrWire {
    /// Convert back into a [`VAttr`], rejecting an unknown node kind.
    pub fn into_vattr(self) -> io::Result<VAttr> {
        Ok(VAttr {
            kind: node_kind_from_u8(self.kind)?,
            mode: self.mode,
            size: self.size,
            uid: self.uid,
            gid: self.gid,
            nlink: self.nlink,
            rdev: self.rdev,
            atime: self.atime.map(wire_to_time),
            mtime: self.mtime.map(wire_to_time),
            ctime: self.ctime.map(wire_to_time),
        })
    }
}

/// Wire form of [`VDirEntry`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VDirEntryWire {
    /// Entry name (a single path component).
    #[serde(with = "serde_bytes")]
    pub name: Vec<u8>,
    /// [`NodeKind`] encoded as a byte.
    pub kind: u8,
}

impl From<&VDirEntry> for VDirEntryWire {
    fn from(e: &VDirEntry) -> Self {
        VDirEntryWire {
            name: e.name.clone(),
            kind: node_kind_to_u8(e.kind),
        }
    }
}

impl VDirEntryWire {
    /// Convert back into a [`VDirEntry`].
    pub fn into_entry(self) -> io::Result<VDirEntry> {
        Ok(VDirEntry {
            name: self.name,
            kind: node_kind_from_u8(self.kind)?,
        })
    }
}

/// Wire form of the `statvfs64` fields a provider can influence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatFsWire {
    /// Filesystem block size.
    pub bsize: u64,
    /// Fragment size.
    pub frsize: u64,
    /// Total data blocks.
    pub blocks: u64,
    /// Free blocks.
    pub bfree: u64,
    /// Free blocks available to unprivileged users.
    pub bavail: u64,
    /// Total inodes.
    pub files: u64,
    /// Free inodes.
    pub ffree: u64,
    /// Maximum filename length.
    pub namemax: u64,
}

impl From<&statvfs64> for StatFsWire {
    // The `as u64` casts are no-ops where the libc fields are already u64
    // (64-bit Linux/macOS) but matter on platforms where they are narrower.
    #[allow(clippy::unnecessary_cast)]
    fn from(s: &statvfs64) -> Self {
        StatFsWire {
            bsize: s.f_bsize as u64,
            frsize: s.f_frsize as u64,
            blocks: s.f_blocks as u64,
            bfree: s.f_bfree as u64,
            bavail: s.f_bavail as u64,
            files: s.f_files as u64,
            ffree: s.f_ffree as u64,
            namemax: s.f_namemax as u64,
        }
    }
}

impl StatFsWire {
    /// Rebuild a `statvfs64` from the wire fields.
    pub fn into_statvfs(self) -> statvfs64 {
        let mut st: statvfs64 = unsafe { std::mem::zeroed() };
        st.f_bsize = self.bsize as _;
        st.f_frsize = self.frsize as _;
        st.f_blocks = self.blocks as _;
        st.f_bfree = self.bfree as _;
        st.f_bavail = self.bavail as _;
        st.f_files = self.files as _;
        st.f_ffree = self.ffree as _;
        st.f_namemax = self.namemax as _;
        st
    }
}

//--------------------------------------------------------------------------------------------------
// Requests / responses
//--------------------------------------------------------------------------------------------------

/// One variant per [`PathFs`](super::super::PathFs) method. All `path`/`name`
/// fields are raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)] // variant/field names mirror the PathFs methods 1:1
pub enum VfsRequest {
    GetAttr {
        path: ByteBuf,
    },
    GetAttrMany {
        paths: Vec<ByteBuf>,
    },
    ReadDir {
        path: ByteBuf,
        #[serde(default)]
        offset: u64,
        #[serde(default = "default_readdir_limit")]
        limit: u32,
    },
    ReadLink {
        path: ByteBuf,
    },
    Read {
        path: ByteBuf,
        offset: u64,
        size: u32,
    },
    Write {
        path: ByteBuf,
        offset: u64,
        data: ByteBuf,
    },
    Create {
        path: ByteBuf,
        attr: VAttrWire,
    },
    Mkdir {
        path: ByteBuf,
        mode: u32,
    },
    Remove {
        path: ByteBuf,
    },
    Rename {
        from: ByteBuf,
        to: ByteBuf,
        #[serde(default)]
        flags: u32,
    },
    SetAttr {
        path: ByteBuf,
        attr: VAttrWire,
        valid: u32,
    },
    Symlink {
        path: ByteBuf,
        target: ByteBuf,
    },
    SetXattr {
        path: ByteBuf,
        name: ByteBuf,
        value: ByteBuf,
        flags: u32,
    },
    GetXattr {
        path: ByteBuf,
        name: ByteBuf,
    },
    ListXattr {
        path: ByteBuf,
    },
    RemoveXattr {
        path: ByteBuf,
        name: ByteBuf,
    },
    Flush {
        path: ByteBuf,
    },
    Fsync {
        path: ByteBuf,
        #[serde(default)]
        datasync: bool,
    },
    FsyncDir {
        path: ByteBuf,
    },
    StatFs,
}

/// The reply to a [`VfsRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VfsResponse {
    /// Node attributes (getattr/create/mkdir/setattr/symlink).
    Attr(VAttrWire),
    /// Per-path attributes for a batched getattr (`getattr_many`), in request
    /// order; each entry is the path's attributes or its errno.
    AttrMany(Vec<VAttrResult>),
    /// Directory entries, excluding `.`/`..` (readdir).
    Dir(Vec<VDirEntryWire>),
    /// Raw bytes (read/readlink/getxattr).
    Bytes(ByteBuf),
    /// Extended-attribute names (listxattr).
    Names(Vec<ByteBuf>),
    /// Bytes accepted (write).
    Count(u64),
    /// Filesystem statistics (statfs).
    StatFs(StatFsWire),
    /// Success with no payload (remove/rename/setxattr/removexattr).
    Ok,
    /// Failure carrying a Linux errno.
    Err(i32),
}

//--------------------------------------------------------------------------------------------------
// Encoding + framing
//--------------------------------------------------------------------------------------------------

fn bad_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// CBOR-encode a value into a fresh buffer.
pub fn to_cbor<T: Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("CBOR encoding to a Vec cannot fail");
    buf
}

/// Encode a [`VfsRequest::Write`] directly from borrowed slices, avoiding the
/// copy of `data` into an owned `ByteBuf` that building the request value would
/// require. The byte layout is identical to `to_cbor(&VfsRequest::Write { .. })`
/// — the borrowing enum below must mirror that variant's name, field names, and
/// order (a `round_trips` test guards the equivalence).
pub fn encode_write(path: &[u8], offset: u64, data: &[u8]) -> Vec<u8> {
    #[derive(Serialize)]
    enum WriteRef<'a> {
        Write {
            #[serde(with = "serde_bytes")]
            path: &'a [u8],
            offset: u64,
            #[serde(with = "serde_bytes")]
            data: &'a [u8],
        },
    }
    to_cbor(&WriteRef::Write { path, offset, data })
}

/// Encode a [`VfsRequest::GetAttr`] from a borrowed `path`, avoiding the copy
/// into an owned `ByteBuf` that building the request value would require. Byte
/// layout is identical to `to_cbor(&VfsRequest::GetAttr { .. })` — guarded by
/// the `borrowed_request_encoders_match_owned` test.
pub fn encode_getattr(path: &[u8]) -> Vec<u8> {
    #[derive(Serialize)]
    enum Ref<'a> {
        GetAttr {
            #[serde(with = "serde_bytes")]
            path: &'a [u8],
        },
    }
    to_cbor(&Ref::GetAttr { path })
}

/// Encode a [`VfsRequest::Read`] from a borrowed `path`. See [`encode_getattr`].
pub fn encode_read(path: &[u8], offset: u64, size: u32) -> Vec<u8> {
    #[derive(Serialize)]
    enum Ref<'a> {
        Read {
            #[serde(with = "serde_bytes")]
            path: &'a [u8],
            offset: u64,
            size: u32,
        },
    }
    to_cbor(&Ref::Read { path, offset, size })
}

/// Encode a [`VfsRequest::GetAttrMany`] from borrowed paths, avoiding the
/// per-path copy into owned `ByteBuf`s that building the batch would require
/// (only a thin slice of references is allocated). See [`encode_getattr`].
pub fn encode_getattr_many(paths: &[&[u8]]) -> Vec<u8> {
    #[derive(Serialize)]
    enum Ref<'a> {
        GetAttrMany { paths: &'a [&'a serde_bytes::Bytes] },
    }
    let wire: Vec<&serde_bytes::Bytes> = paths.iter().map(|p| serde_bytes::Bytes::new(p)).collect();
    to_cbor(&Ref::GetAttrMany { paths: &wire })
}

/// CBOR-decode a value from bytes.
pub fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    ciborium::from_reader(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Decode a [`VfsRequest`] and reject oversize batches/payloads before dispatch.
pub fn decode_request(bytes: &[u8]) -> io::Result<VfsRequest> {
    prevalidate_request_cbor(bytes)?;
    let mut reader = std::io::Cursor::new(bytes);
    let req: VfsRequest = ciborium::from_reader(&mut reader)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if reader.position() as usize != bytes.len() {
        return Err(platform::einval());
    }
    validate_request_limits(&req)?;
    super::dispatch::validate_request_paths(&req)?;
    Ok(req)
}

/// Map a decode/validation failure to the Linux errno sent on the wire.
pub fn decode_error_errno(err: &io::Error) -> i32 {
    err.raw_os_error().unwrap_or(libc::EINVAL)
}

/// Reject oversize `GetAttrMany` batches and `Write` payloads before allocating
/// the full decoded request.
fn prevalidate_request_cbor(bytes: &[u8]) -> io::Result<()> {
    let mut reader = CborReader::new(bytes);
    let map_len = reader.read_map_len()?;
    if map_len != 1 {
        return Err(platform::einval());
    }
    let tag = reader.read_text()?;
    match tag.as_str() {
        "GetAttrMany" => prevalidate_getattr_many(&mut reader),
        "Write" => prevalidate_write(&mut reader),
        "SetXattr" => prevalidate_setxattr(&mut reader),
        _ => Ok(()),
    }
}

fn prevalidate_getattr_many(reader: &mut CborReader<'_>) -> io::Result<()> {
    let inner_len = reader.read_map_len()?;
    if inner_len != 1 {
        return Err(platform::einval());
    }
    let key = reader.read_text()?;
    if key != "paths" {
        return Err(platform::einval());
    }
    let n = reader.read_array_len()?;
    if n > MAX_BATCH_PATHS {
        return Err(platform::einval());
    }
    let mut total_bytes = 0usize;
    for _ in 0..n {
        let path_len = reader.read_bytes_len()?;
        total_bytes = total_bytes.saturating_add(path_len);
        if total_bytes > MAX_BATCH_PATH_BYTES {
            return Err(platform::einval());
        }
    }
    Ok(())
}

fn prevalidate_write(reader: &mut CborReader<'_>) -> io::Result<()> {
    let inner_len = reader.read_map_len()?;
    for _ in 0..inner_len {
        let key = reader.read_text()?;
        match key.as_str() {
            "data" => {
                let len = reader.read_bytes_len()?;
                if len > MAX_IO_SIZE as usize {
                    return Err(platform::einval());
                }
            }
            "path" => {
                reader.read_bytes_len()?;
            }
            "offset" => {
                reader.read_u64()?;
            }
            _ => return Err(platform::einval()),
        }
    }
    Ok(())
}

fn prevalidate_setxattr(reader: &mut CborReader<'_>) -> io::Result<()> {
    let inner_len = reader.read_map_len()?;
    for _ in 0..inner_len {
        let key = reader.read_text()?;
        match key.as_str() {
            "value" => {
                let len = reader.read_bytes_len()?;
                if len > MAX_XATTR_VALUE {
                    return Err(platform::einval());
                }
            }
            "path" | "name" => {
                reader.read_bytes_len()?;
            }
            "flags" => {
                reader.read_u64()?;
            }
            _ => return Err(platform::einval()),
        }
    }
    Ok(())
}

struct CborReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take_byte(&mut self) -> io::Result<u8> {
        let b = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "vfs: truncated CBOR"))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_additional_info(&mut self, initial: u8) -> io::Result<u64> {
        let ai = initial & 0x1f;
        match ai {
            n @ 0..=23 => Ok(u64::from(n)),
            24 => Ok(u64::from(self.take_byte()?)),
            25 => {
                let b0 = self.take_byte()?;
                let b1 = self.take_byte()?;
                Ok(u64::from(b0) << 8 | u64::from(b1))
            }
            26 => {
                let mut buf = [0u8; 4];
                for slot in &mut buf {
                    *slot = self.take_byte()?;
                }
                Ok(u64::from(u32::from_be_bytes(buf)))
            }
            27 => {
                let mut buf = [0u8; 8];
                for slot in &mut buf {
                    *slot = self.take_byte()?;
                }
                Ok(u64::from_be_bytes(buf))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vfs: unsupported CBOR additional info",
            )),
        }
    }

    fn read_definite_len(&mut self, major: u8) -> io::Result<usize> {
        let initial = self.take_byte()?;
        if initial >> 5 != major {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vfs: unexpected CBOR major type",
            ));
        }
        self.read_additional_info(initial)?
            .try_into()
            .map_err(|_| platform::einval())
    }

    fn read_text(&mut self) -> io::Result<String> {
        let len = self.read_definite_len(3)?;
        let end = self.pos.checked_add(len).ok_or(platform::einval())?;
        if end > self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "vfs: truncated CBOR text",
            ));
        }
        let s = std::str::from_utf8(&self.bytes[self.pos..end])
            .map_err(|_| platform::einval())?
            .to_string();
        self.pos = end;
        Ok(s)
    }

    fn read_bytes_len(&mut self) -> io::Result<usize> {
        let len = self.read_definite_len(2)?;
        let end = self.pos.checked_add(len).ok_or(platform::einval())?;
        if end > self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "vfs: truncated CBOR bytes",
            ));
        }
        self.pos = end;
        Ok(len)
    }

    fn read_u64(&mut self) -> io::Result<u64> {
        let initial = self.take_byte()?;
        if initial >> 5 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vfs: expected unsigned CBOR integer",
            ));
        }
        self.read_additional_info(initial)
    }

    fn read_map_len(&mut self) -> io::Result<usize> {
        self.read_definite_len(5)
    }

    fn read_array_len(&mut self) -> io::Result<usize> {
        self.read_definite_len(4)
    }
}

/// Reject wire requests whose declared sizes exceed protocol limits.
pub fn validate_request_limits(req: &VfsRequest) -> io::Result<()> {
    match req {
        VfsRequest::GetAttrMany { paths } => {
            if paths.len() > MAX_BATCH_PATHS {
                return Err(platform::einval());
            }
            let total_bytes: usize = paths.iter().map(|p| p.len()).sum();
            if total_bytes > MAX_BATCH_PATH_BYTES {
                return Err(platform::einval());
            }
            Ok(())
        }
        VfsRequest::Read { size, .. } if *size > MAX_IO_SIZE => Err(platform::einval()),
        VfsRequest::Write { data, .. } if data.len() > MAX_IO_SIZE as usize => {
            Err(platform::einval())
        }
        VfsRequest::ReadDir { limit, .. }
            if *limit != 0 && *limit as usize > MAX_READDIR_ENTRIES =>
        {
            Err(platform::einval())
        }
        VfsRequest::Symlink { target, .. } if target.len() > MAX_SYMLINK_TARGET => {
            Err(platform::enametoolong())
        }
        VfsRequest::SetXattr { value, .. } if value.len() > MAX_XATTR_VALUE => {
            Err(platform::einval())
        }
        _ => Ok(()),
    }
}

/// The wire-protocol version, exchanged once via the [`write_hello`] /
/// [`read_hello`] handshake at channel open. Because the `msb` runtime binary
/// and the Go SDK ship as independently-versioned artifacts, a skew would
/// otherwise surface as an opaque decode error mid-stream; the handshake makes
/// it fail loudly and immediately instead.
///
/// Version 2 added the batched `GetAttrMany` request / `AttrMany` response.
/// Version 3 added `Flush` and `Fsync`.
/// Version 4 added `FsyncDir` to invalidate paginated `ReadDir` cache entries.
pub const PROTOCOL_VERSION: u32 = 4;

/// Magic prefix identifying the microsandbox VFS protocol in a hello frame.
const HELLO_MAGIC: [u8; 4] = *b"MVFS";

/// Write the 8-byte hello: the 4-byte `HELLO_MAGIC` then [`PROTOCOL_VERSION`]
/// as a big-endian `u32`. The channel *requester* (child `RpcPathFs`) writes
/// its hello first and then reads the peer's; the *responder* (the Go
/// `vfs.Serve` loop) reads first and then writes — so the exchange never
/// deadlocks.
pub fn write_hello<W: Write>(w: &mut W) -> io::Result<()> {
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&HELLO_MAGIC);
    buf[4..].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    w.write_all(&buf)?;
    w.flush()
}

/// Read and validate a hello written by [`write_hello`], returning the peer's
/// protocol version. Errors on a bad magic or an incompatible version.
pub fn read_hello<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    if buf[..4] != HELLO_MAGIC {
        return Err(bad_data("vfs: bad protocol magic"));
    }
    let version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if !is_supported_protocol_version(version) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "vfs: unsupported protocol version {version} (supported {} and {})",
                PROTOCOL_VERSION,
                PROTOCOL_VERSION.saturating_sub(1)
            ),
        ));
    }
    Ok(version)
}

/// Whether a peer's hello version is compatible with this implementation.
fn is_supported_protocol_version(version: u32) -> bool {
    version == PROTOCOL_VERSION || version == PROTOCOL_VERSION.saturating_sub(1)
}

/// Maximum bytes per read/write payload (matches the FUSE BIG_WRITES default).
pub const MAX_IO_SIZE: u32 = 128 * 1024;

/// Maximum paths in a single `GetAttrMany` batch.
pub const MAX_BATCH_PATHS: usize = 4096;

/// Conservative path count per `GetAttrMany` RPC so encoded `AttrMany`
/// responses stay within [`MAX_FRAME_LEN`]. The wire allows up to
/// [`MAX_BATCH_PATHS`], but large successful batches can exceed the frame
/// budget; callers should chunk at this limit instead.
pub const GETATTR_MANY_RPC_CHUNK: usize = 256;

/// Maximum total path bytes in one `GetAttrMany` request.
pub const MAX_BATCH_PATH_BYTES: usize = 256 * 1024;

/// Maximum size of a single framed message. Sized for a full `GetAttrMany` batch
/// plus CBOR overhead while keeping a corrupt or hostile length prefix from
/// forcing multi-megabyte allocations (see `maxFrameLen` in `sdk/go/vfs/protocol.go`).
pub const MAX_FRAME_LEN: u32 = 2 * 1024 * 1024;

/// Maximum directory entries returned in one `ReadDir` response.
pub const MAX_READDIR_ENTRIES: usize = 4096;

/// Maximum directory entries materialized for one logical listing (all pages).
pub const MAX_READDIR_TOTAL: usize = 1 << 20;

/// Maximum distinct directory paths cached per VFS connection for paginated
/// `ReadDir`. Keep in sync with `maxReaddirCachePaths` in `sdk/go/vfs/protocol.go`.
pub const MAX_READDIR_CACHE_PATHS: usize = 64;

/// Maximum refetch attempts when directory-cache generation races during pagination.
/// Keep in sync with `maxReaddirFetchRetries` in `sdk/go/vfs/protocol.go`.
pub const MAX_READDIR_FETCH_RETRIES: u32 = 64;

/// Maximum symlink target length accepted on the wire.
pub(crate) const MAX_SYMLINK_TARGET: usize = 4096;

/// Maximum extended-attribute value length accepted on the wire.
const MAX_XATTR_VALUE: usize = 64 * 1024;

fn default_readdir_limit() -> u32 {
    MAX_READDIR_ENTRIES as u32
}

/// Write a frame: a big-endian `u32` payload length, a big-endian `u64`
/// `request_id`, then the CBOR payload. The id lets a future multiplexed
/// transport match responses to in-flight requests; the current serialized
/// transport still stamps and echoes it. Frames assume a byte stream
/// (`SOCK_STREAM`): the two-step read below is incompatible with `SOCK_SEQPACKET`
/// message boundaries.
pub fn write_frame<W: Write>(w: &mut W, request_id: u64, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|&n| n <= MAX_FRAME_LEN)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "vfs frame too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&request_id.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// Read a single frame written by [`write_frame`], returning its `request_id`
/// and CBOR payload.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<(u64, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vfs frame too large",
        ));
    }
    let mut id_buf = [0u8; 8];
    r.read_exact(&mut id_buf)?;
    let request_id = u64::from_be_bytes(id_buf);
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok((request_id, buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_round_trips_including_pre_epoch_subsecond() {
        for t in [
            UNIX_EPOCH,
            UNIX_EPOCH + Duration::new(1_000, 500_000_000),
            UNIX_EPOCH - Duration::from_millis(500), // epoch - 0.5s (the buggy case)
            UNIX_EPOCH - Duration::new(1, 500_000_000), // epoch - 1.5s
            UNIX_EPOCH - Duration::new(2, 0),        // exact whole second before epoch
        ] {
            assert_eq!(wire_to_time(time_to_wire(t)), t, "time round-trip mismatch");
        }
    }

    #[test]
    fn node_kind_rejects_out_of_range_byte() {
        assert!(node_kind_from_u8(6).is_ok()); // Socket, the largest valid kind
        assert!(node_kind_from_u8(7).is_err());
    }

    #[test]
    fn validate_request_limits_rejects_oversized_batch() {
        use serde_bytes::ByteBuf;

        let paths: Vec<ByteBuf> = (0..=MAX_BATCH_PATHS)
            .map(|i| ByteBuf::from(format!("/p{i}").into_bytes()))
            .collect();
        assert!(validate_request_limits(&VfsRequest::GetAttrMany { paths }).is_err());
    }

    #[test]
    fn validate_request_limits_rejects_oversized_getattr_many_path_bytes() {
        use serde_bytes::ByteBuf;

        let paths = vec![ByteBuf::from(vec![b'a'; MAX_BATCH_PATH_BYTES + 1])];
        assert!(validate_request_limits(&VfsRequest::GetAttrMany { paths }).is_err());
    }

    #[test]
    fn validate_request_limits_rejects_oversized_symlink_and_xattr() {
        use serde_bytes::ByteBuf;

        assert!(
            validate_request_limits(&VfsRequest::Symlink {
                path: ByteBuf::from(b"/a".to_vec()),
                target: ByteBuf::from(vec![b'x'; MAX_SYMLINK_TARGET + 1]),
            })
            .is_err()
        );
        assert!(
            validate_request_limits(&VfsRequest::SetXattr {
                path: ByteBuf::from(b"/a".to_vec()),
                name: ByteBuf::from(b"user.foo".to_vec()),
                value: ByteBuf::from(vec![0u8; MAX_XATTR_VALUE + 1]),
                flags: 0,
            })
            .is_err()
        );
    }

    #[test]
    fn max_frame_len_bounds_write_payload() {
        let oversized = vec![0u8; MAX_FRAME_LEN as usize + 1];
        assert!(write_frame(&mut Vec::new(), 1, &oversized).is_err());
    }

    #[test]
    fn prevalidate_request_cbor_rejects_oversized_write_before_decode() {
        use serde_bytes::ByteBuf;

        let req = VfsRequest::Write {
            path: ByteBuf::from(b"/a".to_vec()),
            offset: 0,
            data: ByteBuf::from(vec![0u8; MAX_IO_SIZE as usize + 1]),
        };
        let bytes = to_cbor(&req);
        assert!(prevalidate_request_cbor(&bytes).is_err());
    }

    #[test]
    fn max_readdir_page_fits_in_frame_limit() {
        let entries: Vec<VDirEntryWire> = (0..MAX_READDIR_ENTRIES)
            .map(|_| VDirEntryWire {
                name: vec![b'x'; 255],
                kind: 0, // File
            })
            .collect();
        let payload = to_cbor(&VfsResponse::Dir(entries));
        assert!(
            payload.len() <= MAX_FRAME_LEN as usize,
            "max-size ReadDir page encoded to {} bytes (limit {})",
            payload.len(),
            MAX_FRAME_LEN
        );
    }

    #[test]
    fn encode_write_matches_owned_request() {
        // The borrowed fast path must produce byte-identical CBOR to building
        // and encoding an owned VfsRequest::Write — otherwise the two encodings
        // would silently drift.
        let path = b"/some/file";
        let data = b"hello world payload";
        let owned = to_cbor(&VfsRequest::Write {
            path: ByteBuf::from(path.to_vec()),
            offset: 42,
            data: ByteBuf::from(data.to_vec()),
        });
        assert_eq!(owned, encode_write(path, 42, data));
    }

    #[test]
    fn decode_request_rejects_oversized_getattr_many_before_full_decode() {
        use serde_bytes::ByteBuf;

        let paths: Vec<ByteBuf> = (0..=MAX_BATCH_PATHS)
            .map(|i| ByteBuf::from(format!("/p{i}").into_bytes()))
            .collect();
        let bytes = to_cbor(&VfsRequest::GetAttrMany { paths });
        let err = decode_request(&bytes).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn flush_and_fsync_round_trip() {
        use serde_bytes::ByteBuf;

        let flush = to_cbor(&VfsRequest::Flush {
            path: ByteBuf::from(b"/f".to_vec()),
        });
        let req: VfsRequest = from_cbor(&flush).unwrap();
        assert!(matches!(req, VfsRequest::Flush { .. }));

        let fsync = to_cbor(&VfsRequest::Fsync {
            path: ByteBuf::from(b"/f".to_vec()),
            datasync: true,
        });
        let req: VfsRequest = from_cbor(&fsync).unwrap();
        match req {
            VfsRequest::Fsync { datasync, .. } => assert!(datasync),
            _ => panic!("expected Fsync"),
        }

        let fsyncdir = to_cbor(&VfsRequest::FsyncDir {
            path: ByteBuf::from(b"/d".to_vec()),
        });
        let req: VfsRequest = from_cbor(&fsyncdir).unwrap();
        assert!(matches!(req, VfsRequest::FsyncDir { .. }));
    }

    #[test]
    fn decode_request_rejects_trailing_cbor_bytes() {
        let mut bytes = to_cbor(&VfsRequest::GetAttr {
            path: ByteBuf::from(b"/a".to_vec()),
        });
        bytes.push(0x00);
        let err = decode_request(&bytes).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn borrowed_request_encoders_match_owned() {
        // Each borrowed fast-path encoder must produce byte-identical CBOR to
        // building and encoding the owned VfsRequest, or the two would drift.
        let path = b"/dir/file";
        assert_eq!(
            encode_getattr(path),
            to_cbor(&VfsRequest::GetAttr {
                path: ByteBuf::from(path.to_vec()),
            })
        );
        assert_eq!(
            encode_read(path, 7, 4096),
            to_cbor(&VfsRequest::Read {
                path: ByteBuf::from(path.to_vec()),
                offset: 7,
                size: 4096,
            })
        );
        let (a, b): (&[u8], &[u8]) = (b"/a", b"/bb");
        assert_eq!(
            encode_getattr_many(&[a, b]),
            to_cbor(&VfsRequest::GetAttrMany {
                paths: vec![ByteBuf::from(a.to_vec()), ByteBuf::from(b.to_vec())],
            })
        );
    }
}
