//! Tests for the RPC-backed provider.
//!
//! The same [`InMemoryFs`] reference backend used by the direct scaffold tests
//! is driven here *through* `RpcPathFs`, over both an in-memory transport and a
//! real loopback `UnixStream`, proving the request/response mapping behaves
//! identically to an in-process provider — all in userspace, no VM.

use std::{
    ffi::CString,
    io,
    os::unix::net::UnixStream,
    path::Path,
    sync::{Arc, Mutex},
    thread,
};

use serde_bytes::ByteBuf;

use super::super::test_backend::{InMemoryFs, MockReader, MockWriter};
use super::super::{NodeKind, PathFs, VAttr, VDirEntry, VirtualFs};
use super::*;
use crate::{Context, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply};

//--------------------------------------------------------------------------------------------------
// Transports under test
//--------------------------------------------------------------------------------------------------

/// Answers requests synchronously from an in-process `InMemoryFs` — the
/// simplest possible "other side".
struct InMemoryTransport {
    provider: Arc<InMemoryFs>,
    state: Mutex<DispatchState>,
}

impl VfsTransport for InMemoryTransport {
    fn call(&self, req: VfsRequest) -> io::Result<VfsResponse> {
        let guard = self.state.lock().unwrap();
        Ok(dispatch_with_state(self.provider.as_ref(), req, &guard))
    }
}

//--------------------------------------------------------------------------------------------------
// Harness
//--------------------------------------------------------------------------------------------------

fn ctx() -> Context {
    Context {
        uid: 0,
        gid: 0,
        pid: 1,
    }
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn mem_fs() -> VirtualFs<RpcPathFs<InMemoryTransport>> {
    let transport = InMemoryTransport {
        provider: Arc::new(InMemoryFs::new()),
        state: Mutex::new(DispatchState::default()),
    };
    let fs = VirtualFs::new(RpcPathFs::new(transport)).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs
}

fn create<P: super::super::PathFs>(fs: &VirtualFs<P>, parent: u64, name: &str) -> (Entry, u64) {
    let (entry, handle, _) = fs
        .create(
            ctx(),
            parent,
            &cstr(name),
            0o644,
            false,
            libc::O_RDWR as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    (entry, handle.unwrap())
}

fn write<P: super::super::PathFs>(
    fs: &VirtualFs<P>,
    ino: u64,
    handle: u64,
    data: &[u8],
    offset: u64,
) -> io::Result<usize> {
    let mut reader = MockReader::new(data.to_vec());
    fs.write(
        ctx(),
        ino,
        handle,
        &mut reader,
        data.len() as u32,
        offset,
        None,
        false,
        false,
        0,
    )
}

fn read<P: super::super::PathFs>(
    fs: &VirtualFs<P>,
    ino: u64,
    handle: u64,
    size: u32,
    offset: u64,
) -> io::Result<Vec<u8>> {
    let mut writer = MockWriter::new();
    let n = fs.read(ctx(), ino, handle, &mut writer, size, offset, None, 0)?;
    let mut data = writer.buf;
    data.truncate(n);
    Ok(data)
}

fn readdir_names<P: super::super::PathFs>(fs: &VirtualFs<P>, ino: u64) -> Vec<String> {
    let (handle, _) = fs.opendir(ctx(), ino, 0).unwrap();
    let handle = handle.unwrap();
    let entries = fs.readdir(ctx(), ino, handle, 65536, 0).unwrap();
    let mut names: Vec<String> = entries
        .iter()
        .map(|e| String::from_utf8_lossy(e.name).to_string())
        .filter(|n| n != "." && n != "..")
        .collect();
    fs.releasedir(ctx(), ino, 0, handle).unwrap();
    names.sort();
    names
}

//--------------------------------------------------------------------------------------------------
// Protocol round-trip
//--------------------------------------------------------------------------------------------------

#[test]
fn request_cbor_round_trips() {
    use serde_bytes::ByteBuf;
    let reqs = [
        VfsRequest::GetAttr {
            path: ByteBuf::from(b"/a".to_vec()),
        },
        VfsRequest::Read {
            path: ByteBuf::from(b"/a".to_vec()),
            offset: 42,
            size: 100,
        },
        VfsRequest::Write {
            path: ByteBuf::from(b"/a".to_vec()),
            offset: 0,
            data: ByteBuf::from(b"\x00\xffbytes".to_vec()),
        },
        VfsRequest::StatFs,
        VfsRequest::FsyncDir {
            path: ByteBuf::from(b"/d".to_vec()),
        },
    ];
    for req in reqs {
        let decoded: VfsRequest = from_cbor(&to_cbor(&req)).unwrap();
        assert_eq!(decoded, req);
    }
}

#[test]
fn response_cbor_round_trips() {
    use serde_bytes::ByteBuf;
    let resps = [
        VfsResponse::Attr(VAttrWire {
            kind: 1,
            mode: 0o755,
            size: 0,
            uid: 7,
            gid: 9,
            nlink: Some(2),
            rdev: 0,
            atime: Some((123, 456)),
            mtime: None,
            ctime: Some((-5, 0)),
        }),
        VfsResponse::Bytes(ByteBuf::from(b"\x00\x01\x02".to_vec())),
        VfsResponse::Count(11),
        VfsResponse::Ok,
        VfsResponse::Err(libc::ENOENT),
    ];
    for resp in resps {
        let decoded: VfsResponse = from_cbor(&to_cbor(&resp)).unwrap();
        assert_eq!(decoded, resp);
    }
}

//--------------------------------------------------------------------------------------------------
// In-memory transport: full DynFileSystem surface through RpcPathFs
//--------------------------------------------------------------------------------------------------

#[test]
fn create_write_read_roundtrip_over_rpc() {
    let fs = mem_fs();
    let (entry, handle) = create(&fs, 1, "f.txt");
    assert_eq!(
        write(&fs, entry.inode, handle, b"hello world", 0).unwrap(),
        11
    );
    let data = read(&fs, entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"hello world");
}

#[test]
fn read_at_offset_over_rpc() {
    let fs = mem_fs();
    let (entry, handle) = create(&fs, 1, "f.txt");
    write(&fs, entry.inode, handle, b"hello world", 0).unwrap();
    let data = read(&fs, entry.inode, handle, 5, 6).unwrap();
    assert_eq!(&data[..], b"world");
}

#[test]
fn lookup_missing_is_enoent_over_rpc() {
    let fs = mem_fs();
    let err = fs.lookup(ctx(), 1, &cstr("nope")).err().unwrap();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
}

#[test]
fn mkdir_and_readdir_over_rpc() {
    let fs = mem_fs();
    let dir = fs
        .mkdir(ctx(), 1, &cstr("d"), 0o755, 0, Extensions::default())
        .unwrap();
    create(&fs, dir.inode, "a.txt");
    create(&fs, dir.inode, "b.txt");
    assert_eq!(readdir_names(&fs, dir.inode), vec!["a.txt", "b.txt"]);
}

#[test]
fn rename_over_rpc() {
    let fs = mem_fs();
    let (entry, handle) = create(&fs, 1, "old.txt");
    write(&fs, entry.inode, handle, b"payload", 0).unwrap();
    fs.rename(ctx(), 1, &cstr("old.txt"), 1, &cstr("new.txt"), 0)
        .unwrap();
    assert_eq!(
        fs.lookup(ctx(), 1, &cstr("old.txt"))
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    assert_eq!(
        fs.lookup(ctx(), 1, &cstr("new.txt")).unwrap().attr.st_size,
        7
    );
}

#[test]
fn setattr_truncate_over_rpc() {
    let fs = mem_fs();
    let (entry, handle) = create(&fs, 1, "f.txt");
    write(&fs, entry.inode, handle, b"0123456789", 0).unwrap();
    let mut attr: crate::stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 4;
    let (st, _) = fs
        .setattr(ctx(), entry.inode, attr, None, crate::SetattrValid::SIZE)
        .unwrap();
    assert_eq!(st.st_size, 4);
    assert_eq!(
        &read(&fs, entry.inode, handle, 1024, 0).unwrap()[..],
        b"0123"
    );
}

#[test]
fn symlink_readlink_over_rpc() {
    let fs = mem_fs();
    let entry = fs
        .symlink(
            ctx(),
            &cstr("target/path"),
            1,
            &cstr("link"),
            Extensions::default(),
        )
        .unwrap();
    assert_eq!(
        &fs.readlink(ctx(), entry.inode).unwrap()[..],
        b"target/path"
    );
}

#[test]
fn xattr_over_rpc() {
    let fs = mem_fs();
    let (entry, _) = create(&fs, 1, "f.txt");
    fs.setxattr(ctx(), entry.inode, &cstr("user.tag"), b"value", 0)
        .unwrap();
    match fs
        .getxattr(ctx(), entry.inode, &cstr("user.tag"), 64)
        .unwrap()
    {
        GetxattrReply::Value(v) => assert_eq!(&v[..], b"value"),
        GetxattrReply::Count(_) => panic!("expected value"),
    }
    fs.removexattr(ctx(), entry.inode, &cstr("user.tag"))
        .unwrap();
    // The wire — and the guest — always speak Linux errno; ENODATA is 61 on
    // Linux even when the host (e.g. macOS) numbers it differently. The
    // reference dispatch server translates the provider's host errno before
    // putting it on the wire.
    assert_eq!(
        fs.getxattr(ctx(), entry.inode, &cstr("user.tag"), 64)
            .err()
            .unwrap()
            .raw_os_error(),
        Some(61)
    );
}

#[test]
fn getattr_many_over_rpc() {
    use std::path::Path;

    let provider = Arc::new(InMemoryFs::new());
    let fs = RpcPathFs::new(InMemoryTransport {
        provider: Arc::clone(&provider),
        state: Mutex::new(DispatchState::default()),
    });
    fs.create(Path::new("/a"), &VAttr::file(0o644, 0)).unwrap();
    fs.create(Path::new("/b"), &VAttr::file(0o644, 0)).unwrap();

    let paths = [Path::new("/a"), Path::new("/missing"), Path::new("/b")];
    let results = fs.getattr_many(&paths).unwrap();
    assert_eq!(results.len(), 3);
    assert!(results[0].is_ok());
    // Per-path failures are reported in-band as a Linux errno (ENOENT = 2),
    // not as a whole-batch error.
    assert_eq!(results[1].as_ref().err().unwrap().raw_os_error(), Some(2));
    assert!(results[2].is_ok());

    // The batched result matches per-path getattr for the existing entries.
    assert_eq!(
        results[0].as_ref().unwrap().kind,
        fs.getattr(Path::new("/a")).unwrap().kind
    );
}

#[test]
fn statfs_over_rpc() {
    let fs = mem_fs();
    let st = fs.statfs(ctx(), 1).unwrap();
    // The provider default: 4096 block size, 255 name max.
    assert_eq!(st.f_bsize, 4096);
    assert_eq!(st.f_namemax, 255);
}

//--------------------------------------------------------------------------------------------------
// Loopback socket transport: real framing + CBOR over a UnixStream
//--------------------------------------------------------------------------------------------------

#[test]
fn socket_transport_roundtrip() {
    let (client, mut server) = UnixStream::pair().unwrap();

    // Server thread: decode requests, dispatch against a real backend, reply.
    let server_thread = thread::spawn(move || {
        let provider = InMemoryFs::new();
        let state = DispatchState::default();
        // Responder half of the handshake: read the peer hello, then send ours.
        if read_hello(&mut server).is_err() || write_hello(&mut server).is_err() {
            return;
        }
        // Loop until the client hangs up (read_frame errors with EOF).
        while let Ok((id, req_bytes)) = read_frame(&mut server) {
            let resp = match decode_request(&req_bytes) {
                Ok(req) => dispatch_with_state(&provider, req, &state),
                Err(err) => VfsResponse::Err(decode_error_errno(&err)),
            };
            if write_frame(&mut server, id, &to_cbor(&resp)).is_err() {
                break;
            }
        }
    });

    let transport = SocketTransport::connect(client).unwrap();
    let fs = VirtualFs::new(RpcPathFs::new(transport)).unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let (entry, handle) = create(&fs, 1, "f.txt");
    assert_eq!(
        write(&fs, entry.inode, handle, b"over the wire", 0).unwrap(),
        13
    );
    assert_eq!(
        &read(&fs, entry.inode, handle, 1024, 0).unwrap()[..],
        b"over the wire"
    );
    assert_eq!(
        fs.lookup(ctx(), 1, &cstr("missing"))
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENOENT)
    );

    // Dropping the fs drops the client socket, ending the server loop.
    drop(fs);
    server_thread.join().unwrap();
}

#[test]
fn unix_socket_backend_serves() {
    // The runtime-side constructor: an inherited socket -> a mountable backend.
    let (client, server) = UnixStream::pair().unwrap();
    let provider = Arc::new(InMemoryFs::new());
    let server_thread = thread::spawn(move || {
        let _ = super::serve::serve_unix(server, provider);
    });

    let fs = unix_socket_backend(client).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let (entry, handle) = create(&fs, 1, "f.txt");
    write(&fs, entry.inode, handle, b"via backend", 0).unwrap();
    assert_eq!(
        &read(&fs, entry.inode, handle, 64, 0).unwrap()[..],
        b"via backend"
    );

    drop(fs);
    server_thread.join().unwrap();
}

struct FlushFsyncSpy {
    inner: InMemoryFs,
    flushes: Arc<std::sync::atomic::AtomicUsize>,
    fsyncs: Arc<std::sync::atomic::AtomicUsize>,
}

impl FlushFsyncSpy {
    fn new() -> (
        Self,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let flushes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fsyncs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            FlushFsyncSpy {
                inner: InMemoryFs::new(),
                flushes: Arc::clone(&flushes),
                fsyncs: Arc::clone(&fsyncs),
            },
            flushes,
            fsyncs,
        )
    }
}

impl PathFs for FlushFsyncSpy {
    fn getattr(&self, path: &Path) -> io::Result<super::super::VAttr> {
        self.inner.getattr(path)
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        self.inner.readdir(path)
    }

    fn read(&self, path: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
        self.inner.read(path, offset, size)
    }

    fn write(&self, path: &Path, offset: u64, data: &[u8]) -> io::Result<usize> {
        self.inner.write(path, offset, data)
    }

    fn create(&self, path: &Path, attr: &super::super::VAttr) -> io::Result<super::super::VAttr> {
        self.inner.create(path, attr)
    }

    fn flush(&self, path: &Path) -> io::Result<()> {
        self.flushes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _ = path;
        Ok(())
    }

    fn fsync(&self, path: &Path, datasync: bool) -> io::Result<()> {
        self.fsyncs
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _ = (path, datasync);
        Ok(())
    }
}

#[test]
fn unix_socket_flush_and_fsync_reach_provider() {
    let (client, server) = UnixStream::pair().unwrap();
    let (spy, flushes, fsyncs) = FlushFsyncSpy::new();
    let provider = Arc::new(spy);
    let server_thread = thread::spawn(move || {
        let _ = super::serve::serve_unix(server, provider);
    });

    let fs = unix_socket_backend(client).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let (entry, handle) = create(&fs, 1, "f.txt");
    fs.flush(ctx(), entry.inode, handle, 0).unwrap();
    fs.fsync(ctx(), entry.inode, false, handle).unwrap();
    fs.fsync(ctx(), entry.inode, true, handle).unwrap();
    assert_eq!(flushes.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(fsyncs.load(std::sync::atomic::Ordering::SeqCst), 2);

    drop(fs);
    server_thread.join().unwrap();
}

struct PanicOnGetAttr;

impl PathFs for PanicOnGetAttr {
    fn getattr(&self, _path: &Path) -> io::Result<VAttr> {
        panic!("provider panic");
    }

    fn readdir(&self, _path: &Path) -> io::Result<Vec<VDirEntry>> {
        Ok(Vec::new())
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

#[test]
fn serve_recovers_from_provider_panic() {
    let (client, server) = UnixStream::pair().unwrap();
    let provider = Arc::new(PanicOnGetAttr);
    let server_thread = thread::spawn(move || {
        let _ = super::serve::serve_unix(server, provider);
    });

    let transport = SocketTransport::connect(client).unwrap();
    let rpc = RpcPathFs::new(transport);
    match rpc.getattr(Path::new("/")) {
        Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO)),
        Ok(_) => panic!("expected EIO after provider panic"),
    }

    drop(rpc);
    server_thread.join().unwrap();
}

/// Like [`unix_socket_backend_serves`], but adopts the runtime-side socket from
/// a dup'd fd — the same shape `msb sandbox` uses after inherited-fd placement.
#[test]
fn unix_socket_backend_adopts_duped_fd() {
    use std::mem::forget;
    use std::os::fd::{AsRawFd, FromRawFd};

    fn unused_fd(min: i32) -> i32 {
        let fd = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_DUPFD, min) };
        assert!(fd >= min, "fcntl(F_DUPFD) failed: {fd}");
        fd
    }

    let (parent, child) = UnixStream::pair().unwrap();
    let child_fd = child.as_raw_fd();
    forget(child);

    let provider = Arc::new(InMemoryFs::new());
    let server_thread = thread::spawn(move || {
        let _ = super::serve::serve_unix(parent, provider);
    });

    let target = unused_fd(200);
    assert_eq!(unsafe { libc::dup2(child_fd, target) }, target);
    if child_fd != target {
        let _ = unsafe { libc::close(child_fd) };
    }

    let runtime = unsafe { UnixStream::from_raw_fd(target) };
    let fs = unix_socket_backend(runtime).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let (entry, handle) = create(&fs, 1, "f.txt");
    write(&fs, entry.inode, handle, b"via duped fd", 0).unwrap();
    assert_eq!(
        &read(&fs, entry.inode, handle, 64, 0).unwrap()[..],
        b"via duped fd"
    );

    drop(fs);
    server_thread.join().unwrap();
}

#[test]
fn socket_transport_multiplexes_concurrent_calls() {
    use std::sync::Barrier;

    let (client, mut server) = UnixStream::pair().unwrap();
    let barrier = Arc::new(Barrier::new(2));

    let server_thread = thread::spawn({
        let barrier = Arc::clone(&barrier);
        move || {
            let provider = InMemoryFs::new();
            let state = DispatchState::default();
            if read_hello(&mut server).is_err() || write_hello(&mut server).is_err() {
                return;
            }
            barrier.wait();
            while let Ok((id, req_bytes)) = read_frame(&mut server) {
                let resp = match decode_request(&req_bytes) {
                    Ok(req) => dispatch_with_state(&provider, req, &state),
                    Err(err) => VfsResponse::Err(decode_error_errno(&err)),
                };
                if write_frame(&mut server, id, &to_cbor(&resp)).is_err() {
                    break;
                }
            }
        }
    });

    let transport = SocketTransport::connect(client).unwrap();
    let fs = VirtualFs::new(RpcPathFs::new(transport)).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    barrier.wait();

    let fs = Arc::new(fs);
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let fs = Arc::clone(&fs);
            thread::spawn(move || {
                let name = format!("f{i}.txt");
                let (entry, handle) = create(&fs, 1, &name);
                assert_eq!(write(&fs, entry.inode, handle, b"x", 0).unwrap(), 1);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    drop(fs);
    server_thread.join().unwrap();
}

#[test]
fn orphan_response_is_dropped_without_tearing_down_transport() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let provider = Arc::new(InMemoryFs::new());
    let server_thread = thread::spawn(move || {
        read_hello(&mut server).unwrap();
        write_hello(&mut server).unwrap();
        let (id, req_bytes) = read_frame(&mut server).unwrap();
        let req = decode_request(&req_bytes).unwrap();
        let resp = dispatch(provider.as_ref(), req);
        // A stray response for an unknown request id must be dropped, not treated
        // as a fatal protocol error — the real reply that follows still lands.
        write_frame(&mut server, 9999, &to_cbor(&VfsResponse::Ok)).unwrap();
        write_frame(&mut server, id, &to_cbor(&resp)).unwrap();
    });

    let transport = SocketTransport::connect(client).unwrap();
    let fs = RpcPathFs::new(transport);
    fs.getattr(std::path::Path::new("/"))
        .expect("real reply lands despite the preceding orphan frame");

    server_thread.join().unwrap();
}

#[test]
fn read_frame_rejects_oversized_length() {
    // A 4-byte 0xffffffff length prefix must be rejected, not allocated.
    let mut cursor = io::Cursor::new(vec![0xffu8, 0xff, 0xff, 0xff]);
    let err = read_frame(&mut cursor).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn dispatch_rejects_oversized_read_and_write() {
    use serde_bytes::ByteBuf;

    let provider = InMemoryFs::new();
    let oversize = super::protocol::MAX_IO_SIZE as u64 + 1;
    let read = dispatch(
        &provider,
        VfsRequest::Read {
            path: ByteBuf::from(b"/".to_vec()),
            offset: 0,
            size: oversize as u32,
        },
    );
    match read {
        VfsResponse::Err(errno) => assert_eq!(errno, libc::EINVAL),
        other => panic!("expected Err(EINVAL), got {other:?}"),
    }

    let write = dispatch(
        &provider,
        VfsRequest::Write {
            path: ByteBuf::from(b"/".to_vec()),
            offset: 0,
            data: ByteBuf::from(vec![0u8; super::protocol::MAX_IO_SIZE as usize + 1]),
        },
    );
    match write {
        VfsResponse::Err(errno) => assert_eq!(errno, libc::EINVAL),
        other => panic!("expected Err(EINVAL), got {other:?}"),
    }
}

struct LieOnWriteFs;

impl PathFs for LieOnWriteFs {
    fn getattr(&self, _path: &Path) -> io::Result<VAttr> {
        Ok(VAttr::file(0o644, 0))
    }

    fn readdir(&self, _path: &Path) -> io::Result<Vec<super::super::VDirEntry>> {
        Ok(Vec::new())
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn write(&self, _path: &Path, _offset: u64, data: &[u8]) -> io::Result<usize> {
        Ok(data.len() + 1)
    }
}

#[test]
fn dispatch_rejects_write_count_larger_than_payload() {
    let provider = LieOnWriteFs;
    let resp = dispatch(
        &provider,
        VfsRequest::Write {
            path: serde_bytes::ByteBuf::from(b"/f".to_vec()),
            offset: 0,
            data: serde_bytes::ByteBuf::from(vec![1u8, 2, 3]),
        },
    );
    match resp {
        VfsResponse::Err(_) => {}
        other => panic!("expected Err response, got {other:?}"),
    }
}

struct OversizedCountTransport;

impl VfsTransport for OversizedCountTransport {
    fn call(&self, req: VfsRequest) -> io::Result<VfsResponse> {
        match req {
            VfsRequest::Write { data, .. } => Ok(VfsResponse::Count(data.len() as u64 + 1)),
            other => Ok(dispatch(&InMemoryFs::new(), other)),
        }
    }
}

#[test]
fn rpc_path_fs_rejects_oversized_write_count() {
    let fs = RpcPathFs::new(OversizedCountTransport);
    let err = fs
        .write(std::path::Path::new("/f"), 0, &[1, 2, 3])
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn in_flight_call_fails_promptly_when_peer_closes() {
    use std::time::{Duration, Instant};

    let (client, mut server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        if read_hello(&mut server).is_err() || write_hello(&mut server).is_err() {
            return;
        }
        // Receive one request, then hang up without ever replying — as if the
        // controlling process closed the sandbox while an op was in flight.
        let _ = read_frame(&mut server);
        drop(server);
    });

    let transport = SocketTransport::connect(client).unwrap();
    let fs = RpcPathFs::new(transport);

    let start = Instant::now();
    let result = fs.getattr(std::path::Path::new("/"));
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "call must fail when the peer closes mid-op"
    );
    // The broken connection must surface via EOF detection, not by waiting out
    // the (30s default) call timeout.
    assert!(
        elapsed < Duration::from_secs(5),
        "close should surface promptly, not after the call timeout; took {elapsed:?}"
    );

    server_thread.join().unwrap();
}

#[test]
fn in_flight_call_times_out_without_panicking() {
    use std::io::Read as _;
    use std::time::{Duration, Instant};

    let (client, mut server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        if read_hello(&mut server).is_err() || write_hello(&mut server).is_err() {
            return;
        }
        // Never reply: drain and discard whatever the client sends (so its
        // writer never blocks) while holding the connection open, forcing each
        // call to hit its timeout rather than EOF. Exit only on client close.
        let mut buf = [0u8; 256];
        while let Ok(n) = server.read(&mut buf) {
            if n == 0 {
                break;
            }
        }
    });

    // Manual handshake + a short call timeout so the test runs quickly.
    let mut client = client;
    write_hello(&mut client).unwrap();
    read_hello(&mut client).unwrap();
    let transport = SocketTransport::with_call_timeout(client, Duration::from_millis(200)).unwrap();
    let fs = RpcPathFs::new(transport);

    let start = Instant::now();
    let result = fs.getattr(std::path::Path::new("/"));
    let elapsed = start.elapsed();

    // The timeout arm must surface EIO to the guest, not panic with a
    // RefCell BorrowMutError while swapping the thread-local channel.
    let err = result.expect_err("call must fail when the peer never replies");
    assert_eq!(
        err.raw_os_error(),
        crate::backends::shared::platform::eio().raw_os_error(),
        "got: {err:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(150),
        "should wait out the call timeout, took {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(5), "should not hang");

    // A second call on the same thread must still work after the channel swap:
    // it times out again (no reply) instead of picking up a stale response.
    assert_eq!(
        fs.getattr(std::path::Path::new("/"))
            .expect_err("second call also times out")
            .raw_os_error(),
        crate::backends::shared::platform::eio().raw_os_error()
    );

    drop(fs); // dropping the transport closes the client end and wakes the server
    server_thread.join().unwrap();
}

#[test]
fn io_thread_exits_after_transport_drop() {
    use std::io::Read as _;
    use std::time::Duration;

    let (client, mut server) = UnixStream::pair().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    // No handshake and no calls: we only prove that dropping the transport reaps
    // its I/O thread, which owns the client socket and closes it on exit.
    let transport = SocketTransport::with_call_timeout(client, Duration::from_secs(30)).unwrap();
    drop(transport);

    // When the I/O thread exits it drops the client end, so the server observes
    // EOF. A leaked thread would hold the socket open and this read would block
    // until the 2s timeout instead.
    let mut buf = [0u8; 1];
    let n = server
        .read(&mut buf)
        .expect("server read should observe client EOF, not time out");
    assert_eq!(
        n, 0,
        "expected EOF after the I/O thread closed the client socket"
    );
}

#[test]
fn dispatch_rejects_dotdot_path() {
    let provider = InMemoryFs::new();
    let resp = dispatch(
        &provider,
        VfsRequest::GetAttr {
            path: ByteBuf::from(b"/inbox/../etc/passwd".to_vec()),
        },
    );
    assert!(matches!(resp, VfsResponse::Err(_)));
}

#[test]
fn dispatch_rejects_dot_path_component() {
    let provider = InMemoryFs::new();
    let resp = dispatch(
        &provider,
        VfsRequest::GetAttr {
            path: ByteBuf::from(b"/inbox/./msg".to_vec()),
        },
    );
    assert!(matches!(resp, VfsResponse::Err(_)));
}

#[test]
fn dispatch_rejects_invalid_xattr_name() {
    let provider = InMemoryFs::new();
    let resp = dispatch(
        &provider,
        VfsRequest::SetXattr {
            path: ByteBuf::from(b"/a".to_vec()),
            name: ByteBuf::from(b"user/bad".to_vec()),
            value: ByteBuf::from(b"v".to_vec()),
            flags: 0,
        },
    );
    assert!(matches!(resp, VfsResponse::Err(errno) if errno == libc::EINVAL));
}

struct LargeDirFs;

impl PathFs for LargeDirFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        if path == Path::new("/big") {
            return Ok(VAttr::new(NodeKind::Dir, 0o755, 0));
        }
        Err(io::Error::from_raw_os_error(libc::ENOENT))
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        if path != Path::new("/big") {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        Ok((0..5000)
            .map(|i| VDirEntry::new(format!("f{i:04}").into_bytes(), NodeKind::File))
            .collect())
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Err(io::Error::from_raw_os_error(libc::EISDIR))
    }
}

#[test]
fn readdir_dispatch_paginates_large_directory() {
    let provider = LargeDirFs;
    let state = super::DispatchState::default();
    let page = super::protocol::MAX_READDIR_ENTRIES as u32;
    let resp = super::dispatch_with_state(
        &provider,
        VfsRequest::ReadDir {
            path: ByteBuf::from(b"/big".to_vec()),
            offset: 0,
            limit: page,
        },
        &state,
    );
    let VfsResponse::Dir(first) = resp else {
        panic!("expected Dir, got {resp:?}");
    };
    assert_eq!(first.len(), page as usize);

    let resp = super::dispatch_with_state(
        &provider,
        VfsRequest::ReadDir {
            path: ByteBuf::from(b"/big".to_vec()),
            offset: page as u64,
            limit: page,
        },
        &state,
    );
    let VfsResponse::Dir(second) = resp else {
        panic!("expected Dir, got {resp:?}");
    };
    assert_eq!(second.len(), 5000 - page as usize);
}

struct BadNameDirFs;

impl PathFs for BadNameDirFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        if path == Path::new("/mix") {
            return Ok(VAttr::new(NodeKind::Dir, 0o755, 0));
        }
        Err(io::Error::from_raw_os_error(libc::ENOENT))
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        if path != Path::new("/mix") {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        Ok(vec![
            VDirEntry::new(b"ok.txt".to_vec(), NodeKind::File),
            VDirEntry::new(b".".to_vec(), NodeKind::File),
            VDirEntry::new(b"..".to_vec(), NodeKind::Dir),
        ])
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Err(io::Error::from_raw_os_error(libc::EISDIR))
    }
}

#[test]
fn dispatch_skips_unrepresentable_readdir_names() {
    let resp = dispatch(
        &BadNameDirFs,
        VfsRequest::ReadDir {
            path: ByteBuf::from(b"/mix".to_vec()),
            offset: 0,
            limit: super::protocol::MAX_READDIR_ENTRIES as u32,
        },
    );
    let VfsResponse::Dir(entries) = resp else {
        panic!("expected Dir, got {resp:?}");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(&entries[0].name[..], b"ok.txt");
}

struct MixedLargeDirFs;

impl PathFs for MixedLargeDirFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        if path == Path::new("/big") {
            return Ok(VAttr::new(NodeKind::Dir, 0o755, 0));
        }
        Err(io::Error::from_raw_os_error(libc::ENOENT))
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        if path != Path::new("/big") {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        Ok((0..5000)
            .map(|i| {
                if i % 100 == 0 {
                    VDirEntry::new(b".".to_vec(), NodeKind::File)
                } else {
                    VDirEntry::new(format!("f{i:04}").into_bytes(), NodeKind::File)
                }
            })
            .collect())
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Err(io::Error::from_raw_os_error(libc::EISDIR))
    }
}

#[test]
fn readdir_dispatch_paginates_large_directory_with_filtered_names() {
    let provider = MixedLargeDirFs;
    let state = super::DispatchState::default();
    let page = super::protocol::MAX_READDIR_ENTRIES as u32;
    let mut total = 0usize;
    let mut offset = 0u64;
    loop {
        let resp = super::dispatch_with_state(
            &provider,
            VfsRequest::ReadDir {
                path: ByteBuf::from(b"/big".to_vec()),
                offset,
                limit: page,
            },
            &state,
        );
        let VfsResponse::Dir(batch) = resp else {
            panic!("expected Dir, got {resp:?}");
        };
        let n = batch.len();
        if n == 0 {
            break;
        }
        total += n;
        if n < page as usize {
            break;
        }
        offset = offset.saturating_add(n as u64);
    }
    // 5000 entries minus 50 filtered "." names (every 100th index).
    assert_eq!(total, 4950);
}

struct MutableDirFs {
    entries: std::sync::Mutex<Vec<VDirEntry>>,
}

impl PathFs for MutableDirFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        if path == Path::new("/") {
            Ok(VAttr::new(NodeKind::Dir, 0o755, 0))
        } else {
            Err(io::Error::from_raw_os_error(libc::ENOENT))
        }
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        if path != Path::new("/") {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        Ok(self.entries.lock().unwrap().clone())
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn write(&self, _path: &Path, _offset: u64, _data: &[u8]) -> io::Result<usize> {
        Ok(1)
    }
}

#[test]
fn readdir_dispatch_returns_eagain_when_cache_invalidated_mid_pagination() {
    let provider = MutableDirFs {
        entries: std::sync::Mutex::new(vec![
            VDirEntry::new(b"a".to_vec(), NodeKind::File),
            VDirEntry::new(b"b".to_vec(), NodeKind::File),
        ]),
    };
    let state = super::DispatchState::default();
    let resp = super::dispatch_with_state(
        &provider,
        VfsRequest::ReadDir {
            path: ByteBuf::from(b"/".to_vec()),
            offset: 0,
            limit: 1,
        },
        &state,
    );
    let VfsResponse::Dir(first) = resp else {
        panic!("expected Dir, got {resp:?}");
    };
    assert_eq!(first.len(), 1);

    *provider.entries.lock().unwrap() = vec![
        VDirEntry::new(b"c".to_vec(), NodeKind::File),
        VDirEntry::new(b"d".to_vec(), NodeKind::File),
    ];
    super::dispatch_with_state(
        &provider,
        VfsRequest::Write {
            path: ByteBuf::from(b"/a".to_vec()),
            offset: 0,
            data: ByteBuf::from(b"x".to_vec()),
        },
        &state,
    );

    let resp = super::dispatch_with_state(
        &provider,
        VfsRequest::ReadDir {
            path: ByteBuf::from(b"/".to_vec()),
            offset: 1,
            limit: 64,
        },
        &state,
    );
    assert!(matches!(
        resp,
        VfsResponse::Err(e) if e == crate::backends::shared::platform::LINUX_EAGAIN
    ));
}

#[test]
fn dispatch_rejects_symlink_target_with_dotdot_component() {
    let provider = InMemoryFs::new();
    let resp = dispatch(
        &provider,
        VfsRequest::Symlink {
            path: ByteBuf::from(b"/link".to_vec()),
            target: ByteBuf::from(b"foo/..".to_vec()),
        },
    );
    assert!(matches!(resp, VfsResponse::Err(_)));
}

#[test]
fn dispatch_rejects_rename_exchange() {
    let provider = InMemoryFs::new();
    let resp = dispatch(
        &provider,
        VfsRequest::Rename {
            from: ByteBuf::from(b"/a".to_vec()),
            to: ByteBuf::from(b"/b".to_vec()),
            flags: 2,
        },
    );
    assert!(matches!(
        resp,
        VfsResponse::Err(errno) if errno == crate::backends::shared::platform::LINUX_ENOSYS
    ));
}

struct BadReadLinkFs;

impl PathFs for BadReadLinkFs {
    fn getattr(&self, _path: &Path) -> io::Result<VAttr> {
        Ok(VAttr::file(0o644, 0))
    }

    fn readdir(&self, _path: &Path) -> io::Result<Vec<VDirEntry>> {
        Ok(Vec::new())
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn readlink(&self, _path: &Path) -> io::Result<Vec<u8>> {
        Ok(b"/etc/passwd".to_vec())
    }
}

#[test]
fn dispatch_rejects_absolute_readlink_target_from_provider() {
    let resp = dispatch(
        &BadReadLinkFs,
        VfsRequest::ReadLink {
            path: ByteBuf::from(b"/link".to_vec()),
        },
    );
    assert!(matches!(resp, VfsResponse::Err(_)));
}

struct EnosysWriteFs(InMemoryFs);

impl PathFs for EnosysWriteFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        self.0.getattr(path)
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        self.0.readdir(path)
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        self.0.read(_path, _offset, _size)
    }

    fn write(&self, _path: &Path, _offset: u64, _data: &[u8]) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(
            crate::backends::shared::platform::LINUX_ENOSYS,
        ))
    }
}

#[test]
fn dispatch_preserves_platform_linux_wire_enosys() {
    let provider = EnosysWriteFs(InMemoryFs::new());
    let resp = dispatch(
        &provider,
        VfsRequest::Write {
            path: ByteBuf::from(b"/a".to_vec()),
            offset: 0,
            data: ByteBuf::from(b"x".to_vec()),
        },
    );
    assert!(matches!(
        resp,
        VfsResponse::Err(errno) if errno == crate::backends::shared::platform::LINUX_ENOSYS
    ));
}

struct BadListXattrFs;

impl PathFs for BadListXattrFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        if path == Path::new("/a") {
            Ok(VAttr::new(NodeKind::File, 0o644, 0))
        } else {
            Err(io::Error::from_raw_os_error(libc::ENOENT))
        }
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        if path == Path::new("/") {
            Ok(vec![VDirEntry::new(b"a".to_vec(), NodeKind::File)])
        } else {
            Err(io::Error::from_raw_os_error(libc::ENOENT))
        }
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn listxattr(&self, path: &Path) -> io::Result<Vec<Vec<u8>>> {
        if path == Path::new("/a") {
            Ok(vec![b"user/bad".to_vec()])
        } else {
            Err(io::Error::from_raw_os_error(libc::ENOENT))
        }
    }
}

#[test]
fn dispatch_rejects_invalid_listxattr_names_from_provider() {
    let provider = BadListXattrFs;
    let resp = dispatch(
        &provider,
        VfsRequest::ListXattr {
            path: ByteBuf::from(b"/a".to_vec()),
        },
    );
    assert!(matches!(resp, VfsResponse::Err(errno) if errno == libc::EINVAL));
}

struct MutableListingRpcFs {
    dir_children: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PathFs for MutableListingRpcFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        match path.to_str() {
            Some("/") | Some("/d") => Ok(VAttr::dir(0o755)),
            Some(p) if p.starts_with("/d/") => Ok(VAttr::file(0o644, 0)),
            _ => Err(io::Error::from_raw_os_error(libc::ENOENT)),
        }
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        if path == Path::new("/") {
            return Ok(vec![VDirEntry::new(b"d".to_vec(), NodeKind::Dir)]);
        }
        if path == Path::new("/d") {
            return Ok(self
                .dir_children
                .lock()
                .unwrap()
                .iter()
                .map(|name| VDirEntry::new(name.clone(), NodeKind::File))
                .collect());
        }
        Err(io::Error::from_raw_os_error(libc::ENOENT))
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

#[test]
fn fsyncdir_dispatch_invalidates_read_dir_cache() {
    let provider = MutableListingRpcFs {
        dir_children: Arc::new(Mutex::new(vec![b"a".to_vec()])),
    };
    let state = DispatchState::default();
    let resp = dispatch_with_state(
        &provider,
        VfsRequest::ReadDir {
            path: ByteBuf::from(b"/d".to_vec()),
            offset: 0,
            limit: 4096,
        },
        &state,
    );
    let VfsResponse::Dir(first) = resp else {
        panic!("expected Dir, got {resp:?}");
    };
    assert_eq!(first.len(), 1);

    provider.dir_children.lock().unwrap().push(b"c".to_vec());
    let resp = dispatch_with_state(
        &provider,
        VfsRequest::ReadDir {
            path: ByteBuf::from(b"/d".to_vec()),
            offset: 0,
            limit: 4096,
        },
        &state,
    );
    let VfsResponse::Dir(stale) = resp else {
        panic!("expected Dir, got {resp:?}");
    };
    assert_eq!(
        stale.len(),
        1,
        "cached listing should stay stale until FsyncDir"
    );

    let resp = dispatch_with_state(
        &provider,
        VfsRequest::FsyncDir {
            path: ByteBuf::from(b"/d".to_vec()),
        },
        &state,
    );
    assert!(matches!(resp, VfsResponse::Ok));

    let resp = dispatch_with_state(
        &provider,
        VfsRequest::ReadDir {
            path: ByteBuf::from(b"/d".to_vec()),
            offset: 0,
            limit: 4096,
        },
        &state,
    );
    let VfsResponse::Dir(fresh) = resp else {
        panic!("expected Dir, got {resp:?}");
    };
    assert_eq!(fresh.len(), 2);
}

#[test]
fn fsyncdir_refreshes_stale_directory_listing_over_rpc() {
    let children = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let provider = Arc::new(MutableListingRpcFs {
        dir_children: Arc::clone(&children),
    });
    let (client, mut server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        let state = DispatchState::default();
        if read_hello(&mut server).is_err() || write_hello(&mut server).is_err() {
            return;
        }
        while let Ok((id, req_bytes)) = read_frame(&mut server) {
            let resp = match decode_request(&req_bytes) {
                Ok(req) => dispatch_with_state(provider.as_ref(), req, &state),
                Err(err) => VfsResponse::Err(decode_error_errno(&err)),
            };
            if write_frame(&mut server, id, &to_cbor(&resp)).is_err() {
                break;
            }
        }
    });

    let transport = SocketTransport::connect(client).unwrap();
    let fs = VirtualFs::new(RpcPathFs::new(transport)).unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let root = fs.lookup(ctx(), 1, &cstr(".")).unwrap();
    let dir = fs.lookup(ctx(), root.inode, &cstr("d")).unwrap();
    let (dh, _) = fs.opendir(ctx(), dir.inode, 0).unwrap();
    let dh = dh.unwrap();
    let before = fs.readdir(ctx(), dir.inode, dh, 65536, 0).unwrap();
    assert!(
        before.iter().all(|e| e.name == b"." || e.name == b".."),
        "directory should only contain dot entries initially"
    );
    children.lock().unwrap().push(b"newfile".to_vec());
    let stale = fs.readdir(ctx(), dir.inode, dh, 65536, 0).unwrap();
    assert!(
        stale.iter().all(|e| e.name == b"." || e.name == b".."),
        "open handle keeps point-in-time snapshot"
    );
    fs.fsyncdir(ctx(), dir.inode, false, dh).unwrap();
    let after = fs.readdir(ctx(), dir.inode, dh, 65536, 0).unwrap();
    let names: Vec<_> = after
        .iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .map(|e| e.name.as_ref())
        .collect();
    assert_eq!(names, vec![b"newfile".as_ref()]);

    drop(fs);
    server_thread.join().unwrap();
}
