//! Tests for the Windows passthrough backend.

use super::*;
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::fs::FileExt;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir {
    path: PathBuf,
}

struct CaptureWriter {
    bytes: Vec<u8>,
}

struct SourceReader {
    bytes: Vec<u8>,
    pos: usize,
}

impl TempDir {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "msb-windows-fs-test-{}-{unique}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ZeroCopyWriter for CaptureWriter {
    fn write_from(&mut self, file: &File, count: usize, offset: u64) -> io::Result<usize> {
        let mut file = file.try_clone()?;
        file.seek(SeekFrom::Start(offset))?;
        let mut take = file.take(count as u64);
        take.read_to_end(&mut self.bytes)
    }
}

impl Read for SourceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len().min(self.bytes.len().saturating_sub(self.pos));
        buf[..len].copy_from_slice(&self.bytes[self.pos..self.pos + len]);
        self.pos += len;
        Ok(len)
    }
}

impl ZeroCopyReader for SourceReader {
    fn read_to(&mut self, file: &File, count: usize, offset: u64) -> io::Result<usize> {
        let len = count.min(self.bytes.len().saturating_sub(self.pos));
        if len == 0 {
            return Ok(0);
        }

        let written = file.seek_write(&self.bytes[self.pos..self.pos + len], offset)?;
        self.pos += written;
        Ok(written)
    }
}

fn context() -> Context {
    Context {
        uid: 0,
        gid: 0,
        pid: 0,
    }
}

fn fs_for(path: &Path) -> PassthroughFs {
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: path.to_path_buf(),
        inject_init: false,
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs
}

fn external_fs_for(path: &Path, relaxed: bool, remapped: bool) -> PassthroughFs {
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: path.to_path_buf(),
        inject_init: false,
        stat_virtualization: StatVirtualization::Off,
        external_checkpoint: Some(super::super::ExternalCheckpointOptions {
            relaxed,
            remapped,
            ..Default::default()
        }),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs
}

fn assert_ads_store(fs: &PassthroughFs) {
    let store = fs.stat_store.as_ref().expect("stat store enabled");
    assert!(matches!(
        store.backend,
        StatStoreBackend::AlternateDataStream
    ));
}

fn assert_override(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected_rdev: u32,
) {
    let override_stat = read_override_stream(&ads_override_path(path)).unwrap();
    let uid = override_stat.uid;
    let gid = override_stat.gid;
    let mode = override_stat.mode;
    let rdev = override_stat.rdev;
    assert_eq!(uid, expected_uid);
    assert_eq!(gid, expected_gid);
    assert_eq!(mode, expected_mode);
    assert_eq!(rdev, expected_rdev);
}

fn expect_errno<T>(result: io::Result<T>, errno: i32) {
    match result {
        Ok(_) => panic!("expected errno {errno}"),
        Err(error) => assert_eq!(error.raw_os_error(), Some(errno)),
    }
}

#[test]
fn external_checkpoint_changed_file_requires_relaxed_and_retains_stale_ids() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), b"before").unwrap();
    let source = external_fs_for(&temp.path, false, false);
    let entry = source.lookup(context(), ROOT_INODE, c"data").unwrap();
    source.open(context(), entry.inode, false, 0).unwrap();
    let bytes = source.capture_state().unwrap();
    std::fs::write(temp.path.join("data"), b"after!").unwrap();

    let strict = external_fs_for(&temp.path, false, false);
    let untouched = strict.capture_state().unwrap();
    assert!(strict.restore_state(&bytes).is_err());
    assert_eq!(strict.capture_state().unwrap(), untouched);

    let relaxed = external_fs_for(&temp.path, true, false);
    relaxed.restore_state(&bytes).unwrap();
    assert_eq!(relaxed.request_error(entry.inode), Some(116));
    assert_eq!(relaxed.request_error(ROOT_INODE), None);
    assert!(relaxed.handles.read().unwrap().is_empty());
    let current = relaxed.lookup(context(), ROOT_INODE, c"data").unwrap();
    assert_ne!(current.inode, entry.inode);
    assert_eq!(relaxed.request_error(current.inode), None);
    assert_eq!(
        *relaxed
            .cfg
            .external_checkpoint
            .as_ref()
            .unwrap()
            .invalid_inodes
            .lock()
            .unwrap(),
        vec![entry.inode]
    );

    // A later checkpoint must not recycle an inode previously reported as stale.
    let second = relaxed.capture_state().unwrap();
    let next = external_fs_for(&temp.path, true, false);
    next.restore_state(&second).unwrap();
    assert_eq!(next.request_error(entry.inode), Some(116));
    assert_eq!(
        next.lookup(context(), ROOT_INODE, c"data").unwrap().inode,
        current.inode
    );
}

#[test]
fn external_checkpoint_remap_validates_content_and_requires_explicit_policy() {
    let source_dir = TempDir::new();
    let destination_dir = TempDir::new();
    std::fs::write(source_dir.path.join("data"), b"identical").unwrap();
    std::fs::write(destination_dir.path.join("data"), b"identical").unwrap();
    let source = external_fs_for(&source_dir.path, false, false);
    let entry = source.lookup(context(), ROOT_INODE, c"data").unwrap();
    let bytes = source.capture_state().unwrap();
    assert!(
        external_fs_for(&destination_dir.path, false, false)
            .restore_state(&bytes)
            .is_err()
    );
    let remapped = external_fs_for(&destination_dir.path, false, true);
    remapped.restore_state(&bytes).unwrap();
    assert_eq!(
        remapped
            .lookup(context(), ROOT_INODE, c"data")
            .unwrap()
            .inode,
        entry.inode
    );
    std::fs::write(destination_dir.path.join("data"), b"different").unwrap();
    assert!(remapped.restore_state(&bytes).is_err());
}

#[test]
fn external_checkpoint_refuses_replaced_live_file_handle() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), b"same").unwrap();
    let source = external_fs_for(&temp.path, false, false);
    let entry = source.lookup(context(), ROOT_INODE, c"data").unwrap();
    source.open(context(), entry.inode, false, 0).unwrap();
    std::fs::rename(temp.path.join("data"), temp.path.join("old-data")).unwrap();
    std::fs::write(temp.path.join("data"), b"same").unwrap();
    assert!(source.capture_state().is_err());
}

#[test]
fn unavailable_external_checkpoint_validates_bytes_and_always_returns_eio() {
    let temp = TempDir::new();
    let source = external_fs_for(&temp.path, false, false);
    let bytes = source.capture_state().unwrap();
    let unavailable = crate::UnavailableFs::default();
    unavailable.restore_state(&bytes).unwrap();
    assert_eq!(unavailable.request_error(ROOT_INODE), Some(5));
    assert_eq!(unavailable.request_error(123), Some(5));
    let relaxed = external_fs_for(&temp.path, true, false);
    assert!(relaxed.restore_state(&bytes[..bytes.len() - 1]).is_err());
    assert!(unavailable.restore_state(b"invalid").is_err());
    assert!(unavailable.capture_state().is_err());
}

#[test]
fn lists_and_reads_host_file() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("hello.txt"), b"hello from windows").unwrap();
    let fs = fs_for(&temp.path);

    let (handle, _) = fs
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let entries = fs
        .readdirplus(context(), ROOT_INODE, handle.unwrap(), 4096, 0)
        .unwrap();
    assert!(entries.iter().any(|(entry, _)| entry.name == b"hello.txt"));

    let name = c"hello.txt";
    let entry = fs.lookup(context(), ROOT_INODE, name).unwrap();
    let (handle, _) = fs.open(context(), entry.inode, false, 0).unwrap();
    let mut writer = CaptureWriter { bytes: Vec::new() };
    fs.read(
        context(),
        entry.inode,
        handle.unwrap(),
        &mut writer,
        5,
        6,
        None,
        0,
    )
    .unwrap();
    assert_eq!(writer.bytes, b"from ");
}

#[test]
fn creates_writes_and_reads_file() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let flags = (LINUX_O_CREAT | LINUX_O_RDWR) as u32;
    let (entry, handle, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"created.txt",
            S_IFREG | 0o644,
            false,
            flags,
            0,
            Extensions::default(),
        )
        .unwrap();
    let handle = handle.unwrap();
    let mut reader = SourceReader {
        bytes: b"payload".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        handle,
        &mut reader,
        7,
        0,
        None,
        false,
        false,
        0,
    )
    .unwrap();

    let mut writer = CaptureWriter { bytes: Vec::new() };
    fs.read(context(), entry.inode, handle, &mut writer, 7, 0, None, 0)
        .unwrap();
    assert_eq!(writer.bytes, b"payload");
}

#[test]
fn quota_rejects_growth_past_limit() {
    let temp = TempDir::new();
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        quota_bytes: Some(4),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let flags = (LINUX_O_CREAT | LINUX_O_RDWR) as u32;
    let (entry, handle, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"quota.txt",
            S_IFREG | 0o644,
            false,
            flags,
            0,
            Extensions::default(),
        )
        .unwrap();
    let handle = handle.unwrap();

    let mut first = SourceReader {
        bytes: b"abcd".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        handle,
        &mut first,
        4,
        0,
        None,
        false,
        false,
        0,
    )
    .unwrap();
    assert_eq!(fs.quota.as_ref().unwrap().used(), 4);

    let mut second = SourceReader {
        bytes: b"e".to_vec(),
        pos: 0,
    };
    expect_errno(
        fs.write(
            context(),
            entry.inode,
            handle,
            &mut second,
            1,
            4,
            None,
            false,
            false,
            0,
        ),
        LINUX_ENOSPC,
    );
}

#[test]
fn mobility_preserves_inode_file_handle_and_directory_cookie_state() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("alpha.txt"), b"alpha").unwrap();
    std::fs::write(temp.path.join("beta.txt"), b"beta").unwrap();
    let source = fs_for(&temp.path);

    let alpha = source.lookup(context(), ROOT_INODE, c"alpha.txt").unwrap();
    let beta = source.lookup(context(), ROOT_INODE, c"beta.txt").unwrap();
    let (file_handle, _) = source.open(context(), alpha.inode, false, 0).unwrap();
    let file_handle = file_handle.unwrap();
    let (dir_handle, _) = source
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let dir_handle = dir_handle.unwrap();
    let entries = source
        .readdir(context(), ROOT_INODE, dir_handle, 4096, 0)
        .unwrap();
    let cookie = entries
        .iter()
        .find(|entry| entry.name == b"alpha.txt")
        .unwrap()
        .offset;
    let expected_tail = source
        .readdir(context(), ROOT_INODE, dir_handle, 4096, cookie)
        .unwrap()
        .into_iter()
        .map(|entry| (entry.ino, entry.offset, entry.name.to_vec()))
        .collect::<Vec<_>>();
    let next_inode = source.next_inode.load(Ordering::Acquire);
    let next_handle = source.next_handle.load(Ordering::Acquire);
    let state = source.capture_state().unwrap();

    let destination = fs_for(&temp.path);
    destination.restore_state(&state).unwrap();

    assert_eq!(
        destination
            .lookup(context(), ROOT_INODE, c"alpha.txt")
            .unwrap()
            .inode,
        alpha.inode
    );
    assert_eq!(
        destination
            .lookup(context(), ROOT_INODE, c"beta.txt")
            .unwrap()
            .inode,
        beta.inode
    );
    let mut writer = CaptureWriter { bytes: Vec::new() };
    destination
        .read(
            context(),
            alpha.inode,
            file_handle,
            &mut writer,
            5,
            0,
            None,
            0,
        )
        .unwrap();
    assert_eq!(writer.bytes, b"alpha");
    let restored_tail = destination
        .readdir(context(), ROOT_INODE, dir_handle, 4096, cookie)
        .unwrap()
        .into_iter()
        .map(|entry| (entry.ino, entry.offset, entry.name.to_vec()))
        .collect::<Vec<_>>();
    assert_eq!(restored_tail, expected_tail);
    assert_eq!(destination.next_inode.load(Ordering::Acquire), next_inode);
    assert_eq!(destination.next_handle.load(Ordering::Acquire), next_handle);
}

#[test]
fn mobility_missing_object_rejection_does_not_mutate_destination() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("source.txt"), b"source").unwrap();
    std::fs::write(temp.path.join("destination.txt"), b"destination").unwrap();
    let source = fs_for(&temp.path);
    let source_entry = source.lookup(context(), ROOT_INODE, c"source.txt").unwrap();
    let (source_handle, _) = source
        .open(context(), source_entry.inode, false, 0)
        .unwrap();
    assert!(source_handle.is_some());
    let state = source.capture_state().unwrap();

    let destination = fs_for(&temp.path);
    let destination_entry = destination
        .lookup(context(), ROOT_INODE, c"destination.txt")
        .unwrap();
    let (destination_handle, _) = destination
        .open(context(), destination_entry.inode, false, 0)
        .unwrap();
    assert!(destination_handle.is_some());
    let before = destination.capture_state().unwrap();
    drop(source);
    std::fs::remove_file(temp.path.join("source.txt")).unwrap();

    assert!(destination.restore_state(&state).is_err());

    assert_eq!(destination.capture_state().unwrap(), before);
    let mut writer = CaptureWriter { bytes: Vec::new() };
    destination
        .read(
            context(),
            destination_entry.inode,
            destination_handle.unwrap(),
            &mut writer,
            11,
            0,
            None,
            0,
        )
        .unwrap();
    assert_eq!(writer.bytes, b"destination");
}

#[test]
fn mobility_preserves_quota_accounting_and_open_handle() {
    let temp = TempDir::new();
    let config = PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        quota_bytes: Some(8),
        ..Default::default()
    };
    let source = PassthroughFs::new(config.clone()).unwrap();
    source.init(FsOptions::empty()).unwrap();
    let (entry, handle, _) = source
        .create(
            context(),
            ROOT_INODE,
            c"quota.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let handle = handle.unwrap();
    let mut initial = SourceReader {
        bytes: b"abcd".to_vec(),
        pos: 0,
    };
    source
        .write(
            context(),
            entry.inode,
            handle,
            &mut initial,
            4,
            0,
            None,
            false,
            false,
            0,
        )
        .unwrap();
    let quota_state = source.quota.as_ref().unwrap().capture_state();
    let state = source.capture_state().unwrap();

    let destination = PassthroughFs::new(config).unwrap();
    destination.init(FsOptions::empty()).unwrap();
    destination.restore_state(&state).unwrap();

    assert_eq!(
        destination.quota.as_ref().unwrap().capture_state(),
        quota_state
    );
    let mut remaining = SourceReader {
        bytes: b"efgh".to_vec(),
        pos: 0,
    };
    destination
        .write(
            context(),
            entry.inode,
            handle,
            &mut remaining,
            4,
            4,
            None,
            false,
            false,
            0,
        )
        .unwrap();
    let mut over = SourceReader {
        bytes: b"i".to_vec(),
        pos: 0,
    };
    expect_errno(
        destination.write(
            context(),
            entry.inode,
            handle,
            &mut over,
            1,
            8,
            None,
            false,
            false,
            0,
        ),
        LINUX_ENOSPC,
    );
}

#[test]
fn rejects_malicious_components() {
    for name in [c"..", c".", c"a/b", c"a\\b", c"a:b", c".msb_override_stat"] {
        expect_errno(validate_component(name), LINUX_EPERM);
    }
}

#[test]
fn readonly_rejects_mutation() {
    let temp = TempDir::new();
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        readonly: true,
        inject_init: false,
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    expect_errno(
        fs.create(
            context(),
            ROOT_INODE,
            c"created.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        ),
        LINUX_EROFS,
    );
}

#[test]
fn directory_rename_preserves_cached_descendants() {
    for external in [true, false] {
        let temp = TempDir::new();
        std::fs::create_dir_all(temp.path.join("directory/nested")).unwrap();
        std::fs::write(temp.path.join("directory/nested/file"), b"child").unwrap();
        let fs = if external {
            external_fs_for(&temp.path, false, false)
        } else {
            fs_for(&temp.path)
        };
        let directory = fs.lookup(context(), ROOT_INODE, c"directory").unwrap();
        let nested = fs.lookup(context(), directory.inode, c"nested").unwrap();
        let file = fs.lookup(context(), nested.inode, c"file").unwrap();

        fs.rename(context(), ROOT_INODE, c"directory", ROOT_INODE, c"moved", 0)
            .unwrap();

        let (stat, _) = fs.getattr(context(), file.inode, None).unwrap();
        assert_eq!(stat.st_size, 5);
        let (handle, _) = fs.open(context(), file.inode, false, 0).unwrap();
        let handle = handle.unwrap();
        assert_eq!(owned_read(&fs, file.inode, handle), b"child");
        fs.release(context(), file.inode, 0, handle, false, false, None)
            .unwrap();
        let entries = fs.dir_entries(nested.inode).unwrap();
        assert!(entries.iter().any(|(entry, _)| entry.name == b"file"));
        assert_eq!(
            fs.lookup(context(), ROOT_INODE, c"moved").unwrap().inode,
            directory.inode
        );
        assert_eq!(
            fs.lookup(context(), directory.inode, c"nested")
                .unwrap()
                .inode,
            nested.inode
        );
        assert_eq!(
            fs.lookup(context(), nested.inode, c"file").unwrap().inode,
            file.inode
        );
        expect_errno(fs.lookup(context(), ROOT_INODE, c"directory"), LINUX_ENOENT);
    }
}

#[test]
fn heartbeat_style_rename_keeps_source_inode_usable() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("heartbeat.json"), b"old").unwrap();
    std::fs::write(temp.path.join("heartbeat.tmp"), b"new").unwrap();
    let fs = fs_for(&temp.path);

    let source = fs.lookup(context(), ROOT_INODE, c"heartbeat.tmp").unwrap();
    fs.rename(
        context(),
        ROOT_INODE,
        c"heartbeat.tmp",
        ROOT_INODE,
        c"heartbeat.json",
        0,
    )
    .unwrap();

    let (handle, _) = fs.open(context(), source.inode, false, 0).unwrap();
    let mut writer = CaptureWriter { bytes: Vec::new() };
    fs.read(
        context(),
        source.inode,
        handle.unwrap(),
        &mut writer,
        3,
        0,
        None,
        0,
    )
    .unwrap();
    assert_eq!(writer.bytes, b"new");
}

#[test]
fn stat_virtualization_persists_across_backend_restart() {
    let temp = TempDir::new();
    {
        let fs = fs_for(&temp.path);
        assert_ads_store(&fs);
        let ctx = Context {
            uid: 1000,
            gid: 1001,
            pid: 0,
        };
        let (entry, _, _) = fs
            .create(
                ctx,
                ROOT_INODE,
                c"owned.txt",
                S_IFREG | 0o644,
                false,
                (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        let attr = stat64 {
            st_uid: 1234,
            st_gid: 5678,
            st_mode: S_IFREG | 0o640,
            ..Default::default()
        };
        fs.setattr(
            ctx,
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
        )
        .unwrap();
    }

    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"owned.txt").unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 1234);
    assert_eq!(st.st_gid, 5678);
    assert_eq!(st.st_mode & 0o7777, 0o640);
    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
}

#[test]
fn seeded_virtual_permissions_are_visible_after_backend_start() {
    let temp = TempDir::new();
    let script = temp.path.join("scripts").join("hello");
    std::fs::create_dir_all(script.parent().unwrap()).unwrap();
    std::fs::write(&script, b"#!/bin/sh\necho hello\n").unwrap();

    PassthroughFs::set_path_virtual_permissions(&temp.path, &script, 0, 0, 0o755).unwrap();

    let fs = fs_for(&temp.path);
    let dir = fs.lookup(context(), ROOT_INODE, c"scripts").unwrap();
    let entry = fs.lookup(context(), dir.inode, c"hello").unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();

    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
    assert_eq!(st.st_mode & 0o7777, 0o755);
}

#[test]
fn host_files_without_override_are_executable() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("program"), b"\x7fELFbinary").unwrap();

    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"program").unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();

    // NTFS has no Unix exec bit, but a freshly bound host file must still be
    // runnable (e.g. binaries in a bind rootfs) before the guest chmods it.
    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
    assert_eq!(st.st_mode & 0o7777, 0o777);
    assert_ne!(
        st.st_mode & 0o111,
        0,
        "host file should be executable by default"
    );

    // Root must pass an X_OK access check against the synthesized mode.
    check_access(context(), &st, LINUX_ACCESS_X_OK).unwrap();
}

#[test]
fn readonly_host_files_without_override_are_read_execute_only() {
    let temp = TempDir::new();
    let file = temp.path.join("locked");
    std::fs::write(&file, b"data").unwrap();
    let mut perms = std::fs::metadata(&file).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&file, perms).unwrap();

    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"locked").unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();

    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
    assert_eq!(st.st_mode & 0o7777, 0o555);
}

#[test]
fn strict_uses_ads_and_does_not_create_sidecar() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    assert_ads_store(&fs);

    let ctx = Context {
        uid: 111,
        gid: 222,
        pid: 0,
    };
    let (entry, _, _) = fs
        .create(
            ctx,
            ROOT_INODE,
            c"ads.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let data = fs.inode(entry.inode).unwrap();

    assert!(!temp.path.join(FALLBACK_METADATA_DIR_NAME).exists());
    assert_override(&data.path(), 111, 222, S_IFREG | 0o644, 0);
}

#[test]
fn readonly_probes_do_not_create_metadata() {
    let temp = TempDir::new();
    let override_path = ads_override_path(&temp.path);
    let probe_path = ads_probe_path(&temp.path);

    for policy in [StatVirtualization::Strict, StatVirtualization::Relaxed] {
        let fs = PassthroughFs::new(PassthroughConfig {
            root_dir: temp.path.clone(),
            inject_init: false,
            readonly: true,
            stat_virtualization: policy,
            ..Default::default()
        })
        .unwrap();

        assert_ads_store(&fs);
    }

    for path in [override_path, probe_path] {
        assert_eq!(
            std::fs::metadata(path).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
    assert!(!temp.path.join(FALLBACK_METADATA_DIR_NAME).exists());
}

#[test]
fn readonly_relaxed_probe_preserves_mount_root_override() {
    let temp = TempDir::new();
    write_override_stream(
        &ads_override_path(&temp.path),
        OverrideStat::new(1234, 2345, S_IFDIR | 0o1755, 0),
    )
    .unwrap();

    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        readonly: true,
        stat_virtualization: StatVirtualization::Relaxed,
        ..Default::default()
    })
    .unwrap();

    assert_ads_store(&fs);
    assert_override(&temp.path, 1234, 2345, S_IFDIR | 0o1755, 0);
    assert_eq!(
        std::fs::metadata(ads_probe_path(&temp.path))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert!(!temp.path.join(FALLBACK_METADATA_DIR_NAME).exists());
}

#[test]
fn writable_probe_preserves_mount_root_override() {
    let temp = TempDir::new();
    write_override_stream(
        &ads_override_path(&temp.path),
        OverrideStat::new(1234, 2345, S_IFDIR | 0o1755, 0),
    )
    .unwrap();

    let fs = fs_for(&temp.path);
    assert_ads_store(&fs);

    assert_override(&temp.path, 1234, 2345, S_IFDIR | 0o1755, 0);
    assert_eq!(
        std::fs::metadata(ads_probe_path(&temp.path))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn ads_stat_virtualization_persists_for_directories() {
    let temp = TempDir::new();
    {
        let fs = fs_for(&temp.path);
        assert_ads_store(&fs);
        let ctx = Context {
            uid: 321,
            gid: 654,
            pid: 0,
        };
        let entry = fs
            .mkdir(
                ctx,
                ROOT_INODE,
                c"dir",
                S_IFDIR | 0o750,
                0,
                Extensions::default(),
            )
            .unwrap();
        let attr = stat64 {
            st_uid: 333,
            st_gid: 444,
            st_mode: S_IFDIR | 0o710,
            ..Default::default()
        };
        fs.setattr(
            ctx,
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
        )
        .unwrap();
    }

    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"dir").unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 333);
    assert_eq!(st.st_gid, 444);
    assert_eq!(st.st_mode & S_IFMT, S_IFDIR);
    assert_eq!(st.st_mode & 0o7777, 0o710);
}

#[test]
fn ads_metadata_follows_rename_without_sidecar_move() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    assert_ads_store(&fs);

    let (entry, _, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"old.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let old_data = fs.inode(entry.inode).unwrap();
    let old_path = old_data.path();
    let attr = stat64 {
        st_uid: 700,
        st_gid: 701,
        st_mode: S_IFREG | 0o600,
        ..Default::default()
    };
    fs.setattr(
        context(),
        entry.inode,
        attr,
        None,
        SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
    )
    .unwrap();

    fs.rename(context(), ROOT_INODE, c"old.txt", ROOT_INODE, c"new.txt", 0)
        .unwrap();

    expect_errno(
        read_override_stream(&ads_override_path(&old_path)),
        LINUX_ENOENT,
    );
    let renamed = fs.lookup(context(), ROOT_INODE, c"new.txt").unwrap();
    let data = fs.inode(renamed.inode).unwrap();
    assert_override(&data.path(), 700, 701, S_IFREG | 0o600, 0);
    let (st, _) = fs.getattr(context(), renamed.inode, None).unwrap();
    assert_eq!(st.st_uid, 700);
    assert_eq!(st.st_gid, 701);
    assert_eq!(st.st_mode & 0o7777, 0o600);
}

#[test]
fn metadata_store_is_hidden_from_guest_namespace() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    assert!(!temp.path.join(FALLBACK_METADATA_DIR_NAME).exists());
    std::fs::create_dir(temp.path.join(FALLBACK_METADATA_DIR_NAME)).unwrap();

    let (handle, _) = fs
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let entries = fs
        .readdirplus(context(), ROOT_INODE, handle.unwrap(), 4096, 0)
        .unwrap();
    assert!(
        !entries
            .iter()
            .any(|(entry, _)| entry.name == FALLBACK_METADATA_DIR_NAME.as_bytes())
    );
    expect_errno(
        fs.lookup(context(), ROOT_INODE, c".msb_override_stat"),
        LINUX_EPERM,
    );
}

#[test]
fn corrupt_stat_metadata_fails_closed() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let (entry, _, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"corrupt.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let data = fs.inode(entry.inode).unwrap();
    let override_path = fs
        .stat_store
        .as_ref()
        .unwrap()
        .override_file_path(&data.path())
        .unwrap();
    std::fs::write(override_path, b"bad").unwrap();

    expect_errno(fs.lookup(context(), ROOT_INODE, c"corrupt.txt"), LINUX_EIO);
}

#[test]
fn ads_metadata_does_not_survive_host_delete_and_recreate() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let entry = fs
        .symlink(
            context(),
            c"target.txt",
            ROOT_INODE,
            c"reused",
            Extensions::default(),
        )
        .unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_mode & S_IFMT, S_IFLNK);

    std::fs::remove_file(temp.path.join("reused")).unwrap();
    std::fs::write(temp.path.join("reused"), b"plain").unwrap();

    let replacement = fs.lookup(context(), ROOT_INODE, c"reused").unwrap();
    let (st, _) = fs.getattr(context(), replacement.inode, None).unwrap();
    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
    expect_errno(fs.readlink(context(), replacement.inode), LINUX_EINVAL);
}

#[test]
fn ads_regular_metadata_does_not_survive_host_delete_and_recreate() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let (entry, _, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"reused.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let attr = stat64 {
        st_uid: 4321,
        st_gid: 8765,
        st_mode: S_IFREG | 0o600,
        ..Default::default()
    };
    fs.setattr(
        context(),
        entry.inode,
        attr,
        None,
        SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
    )
    .unwrap();

    std::fs::remove_file(temp.path.join("reused.txt")).unwrap();
    std::fs::write(temp.path.join("reused.txt"), b"replacement").unwrap();

    let replacement = fs.lookup(context(), ROOT_INODE, c"reused.txt").unwrap();
    let (st, _) = fs.getattr(context(), replacement.inode, None).unwrap();
    assert_ne!(st.st_uid, 4321);
    assert_ne!(st.st_gid, 8765);
    assert_ne!(st.st_mode & 0o7777, 0o600);
    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
}

#[test]
fn unlink_removes_ads_metadata_with_file() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let (entry, _, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"gone.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let data = fs.inode(entry.inode).unwrap();
    assert_override(&data.path(), 0, 0, S_IFREG | 0o644, 0);
    let ads_path = ads_override_path(&data.path());

    fs.unlink(context(), ROOT_INODE, c"gone.txt").unwrap();

    expect_errno(read_override_stream(&ads_path), LINUX_ENOENT);
    std::fs::write(temp.path.join("gone.txt"), b"new").unwrap();
    let replacement = fs.lookup(context(), ROOT_INODE, c"gone.txt").unwrap();
    let (st, _) = fs.getattr(context(), replacement.inode, None).unwrap();
    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
    assert_eq!(st.st_uid, 0);
    assert_eq!(st.st_gid, 0);
}

#[test]
fn sidecar_fallback_renames_and_removes_metadata() {
    let temp = TempDir::new();
    let root = std::fs::canonicalize(&temp.path).unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    let store = StatStore::sidecar(&root);
    store.probe().unwrap();

    let old_path = root.join("old.txt");
    let new_path = root.join("sub").join("new.txt");
    store.write(&old_path, 12, 34, S_IFREG | 0o640, 0).unwrap();
    store.rename(&old_path, &new_path).unwrap();

    assert!(store.read(&old_path).unwrap().is_none());
    let override_stat = store.read(&new_path).unwrap().unwrap();
    let uid = override_stat.uid;
    let gid = override_stat.gid;
    let mode = override_stat.mode;
    assert_eq!(uid, 12);
    assert_eq!(gid, 34);
    assert_eq!(mode, S_IFREG | 0o640);

    store.remove(&new_path).unwrap();
    assert!(store.read(&new_path).unwrap().is_none());
}

#[test]
fn symlink_is_file_backed_and_readlink_checks_virtual_type() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let ctx = Context {
        uid: 42,
        gid: 43,
        pid: 0,
    };
    let entry = fs
        .symlink(
            ctx,
            c"target.txt",
            ROOT_INODE,
            c"link",
            Extensions::default(),
        )
        .unwrap();
    let target = fs.readlink(context(), entry.inode).unwrap();
    assert_eq!(target, b"target.txt");

    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 42);
    assert_eq!(st.st_gid, 43);
    assert_eq!(st.st_mode & S_IFMT, S_IFLNK);
    assert!(std::fs::metadata(temp.path.join("link")).unwrap().is_file());

    let (file_entry, _, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"regular.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    expect_errno(fs.readlink(context(), file_entry.inode), LINUX_EINVAL);
}

#[test]
fn mknod_virtualizes_special_type() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let entry = fs
        .mknod(
            context(),
            ROOT_INODE,
            c"pipe",
            S_IFIFO | 0o600,
            0,
            0,
            Extensions::default(),
        )
        .unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_mode & S_IFMT, S_IFIFO);
    assert!(std::fs::metadata(temp.path.join("pipe")).unwrap().is_file());

    let (handle, _) = fs
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let entries = fs
        .readdirplus(context(), ROOT_INODE, handle.unwrap(), 4096, 0)
        .unwrap();
    let (dir_entry, _) = entries
        .iter()
        .find(|(dir_entry, _)| dir_entry.name == b"pipe")
        .unwrap();
    assert_eq!(dir_entry.type_, DT_FIFO);
}

#[test]
fn access_uses_virtualized_owner_and_mode() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let owner = Context {
        uid: 1000,
        gid: 1000,
        pid: 0,
    };
    let other = Context {
        uid: 2000,
        gid: 2000,
        pid: 0,
    };
    let (entry, _, _) = fs
        .create(
            owner,
            ROOT_INODE,
            c"private.txt",
            S_IFREG | 0o600,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();

    fs.access(owner, entry.inode, LINUX_ACCESS_R_OK).unwrap();
    expect_errno(
        fs.access(other, entry.inode, LINUX_ACCESS_R_OK),
        LINUX_EACCES,
    );
}

#[test]
fn setattr_updates_mtime() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let (entry, _, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"times.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let attr = stat64 {
        st_atime: 1_700_000_000,
        st_atime_nsec: 123_000_000,
        st_mtime: 1_700_000_123,
        st_mtime_nsec: 456_000_000,
        ..Default::default()
    };
    fs.setattr(
        context(),
        entry.inode,
        attr,
        None,
        SetattrValid::ATIME | SetattrValid::MTIME,
    )
    .unwrap();

    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_mtime, attr.st_mtime);
}

#[test]
fn write_killpriv_clears_virtual_suid_sgid() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let flags = (LINUX_O_CREAT | LINUX_O_RDWR) as u32;
    let (entry, handle, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"suid.txt",
            S_IFREG | S_ISUID | S_ISGID | 0o755,
            false,
            flags,
            0,
            Extensions::default(),
        )
        .unwrap();

    let mut reader = SourceReader {
        bytes: b"x".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        handle.unwrap(),
        &mut reader,
        1,
        0,
        None,
        false,
        true,
        0,
    )
    .unwrap();

    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_mode & (S_ISUID | S_ISGID), 0);
}

//--------------------------------------------------------------------------------------------------
// Tests: mount-root containment (no_symlink_root)
//--------------------------------------------------------------------------------------------------

/// Build a two-tenant layout under a canonical (reparse-free) base:
/// `<base>/vol/tenant-a` and `<base>/vol/tenant-b`, with a secret in tenant-b.
fn two_tenant_layout(temp: &TempDir) -> (PathBuf, PathBuf, PathBuf) {
    // Canonicalize so no redirected system folder trips the no-reparse walk;
    // the control plane owns this step.
    let base = std::fs::canonicalize(&temp.path).unwrap();
    let tenant_a = base.join("vol").join("tenant-a");
    let tenant_b = base.join("vol").join("tenant-b");
    std::fs::create_dir_all(&tenant_a).unwrap();
    std::fs::create_dir_all(&tenant_b).unwrap();
    std::fs::write(tenant_b.join("secret.txt"), b"tenant-b private data").unwrap();
    (base, tenant_a, tenant_b)
}

fn build_no_symlink(root_dir: PathBuf) -> io::Result<PassthroughFs> {
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir,
        no_symlink_root: true,
        stat_virtualization: StatVirtualization::Off,
        inject_init: false,
        ..Default::default()
    })?;
    fs.init(FsOptions::empty())?;
    Ok(fs)
}

/// Legacy behavior: `canonicalize` follows a junction/symlink root out to the
/// sibling tenant, exposing its files. Documents the escape the flag closes.
#[test]
fn legacy_symlink_root_is_followed() {
    let temp = TempDir::new();
    let (_base, tenant_a, tenant_b) = two_tenant_layout(&temp);

    let evil = tenant_a.join("evil");
    if std::os::windows::fs::symlink_dir(&tenant_b, &evil).is_err() {
        eprintln!("skip: cannot create directory symlink (privilege/Developer Mode)");
        return;
    }

    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: evil,
        no_symlink_root: false,
        stat_virtualization: StatVirtualization::Off,
        inject_init: false,
        ..Default::default()
    })
    .expect("legacy path follows the symlink silently");
    fs.init(FsOptions::empty()).unwrap();

    assert!(
        fs.lookup(context(), ROOT_INODE, c"secret.txt").is_ok(),
        "guest reached tenant-b's secret.txt through the mount (escape)"
    );
}

/// A junction/symlink as the mount root is refused — never followed.
#[test]
fn no_symlink_root_rejects_symlink_root() {
    let temp = TempDir::new();
    let (_base, tenant_a, tenant_b) = two_tenant_layout(&temp);

    let evil = tenant_a.join("evil");
    if std::os::windows::fs::symlink_dir(&tenant_b, &evil).is_err() {
        eprintln!("skip: cannot create directory symlink (privilege/Developer Mode)");
        return;
    }

    let result = build_no_symlink(evil);
    assert!(result.is_err(), "symlink root must be refused");
    assert_eq!(
        result.err().and_then(|e| e.raw_os_error()),
        Some(LINUX_ELOOP)
    );
}

/// A reparse point in a NON-tenant prefix is refused too — nothing is trusted.
#[test]
fn no_symlink_root_rejects_symlinked_prefix() {
    let temp = TempDir::new();
    let (base, _tenant_a, _tenant_b) = two_tenant_layout(&temp);

    let real = base.join("real-mnt");
    std::fs::create_dir_all(real.join("work")).unwrap();
    let linked_prefix = base.join("linked-mnt");
    if std::os::windows::fs::symlink_dir(&real, &linked_prefix).is_err() {
        eprintln!("skip: cannot create directory symlink (privilege/Developer Mode)");
        return;
    }

    let result = build_no_symlink(linked_prefix.join("work"));
    assert!(
        result.is_err(),
        "a symlinked prefix component must be refused"
    );
    assert_eq!(
        result.err().and_then(|e| e.raw_os_error()),
        Some(LINUX_ELOOP)
    );

    // The same real path with no reparse component mounts fine.
    build_no_symlink(real.join("work")).expect("real path should mount");
}

/// A `..` segment is refused even though it crosses no reparse point.
#[test]
fn no_symlink_root_rejects_dotdot() {
    let temp = TempDir::new();
    let (_base, tenant_a, _tenant_b) = two_tenant_layout(&temp);

    // Build the `..` path from a RAW STRING. `PathBuf::join("..")` collapses the
    // `..` at construction on Windows (especially verbatim `\\?\` paths), so it
    // would never reach the resolver; a string preserves the literal segment,
    // which is exactly what a caller that concatenates an untrusted subpath
    // would produce.
    let escaping = PathBuf::from(format!("{}\\..\\tenant-b", tenant_a.display()));
    let result = build_no_symlink(escaping);
    assert_eq!(
        result.err().and_then(|e| e.raw_os_error()),
        Some(LINUX_EINVAL)
    );
}

// Relative paths resolve from the working directory (still no reparse point
// followed), so relative bind mounts keep working under the protective default.
// Covered end-to-end at the app level rather than here to avoid a unit test
// mutating the shared process working directory.

/// A legitimate real subdirectory mounts and the guest sees its own files.
#[test]
fn no_symlink_root_allows_real_subdir() {
    let temp = TempDir::new();
    let (_base, tenant_a, _tenant_b) = two_tenant_layout(&temp);
    let work = tenant_a.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("hello.txt"), b"tenant-a data").unwrap();

    let fs = build_no_symlink(work).expect("real subdir should mount");
    fs.lookup(context(), ROOT_INODE, c"hello.txt")
        .expect("guest should see its own file");
}

/// A deep chain of real directories is allowed — the resolver rejects reparse
/// points, not depth.
#[test]
fn no_symlink_root_allows_deep_real_path() {
    let temp = TempDir::new();
    let (_base, tenant_a, _tenant_b) = two_tenant_layout(&temp);
    let deep = tenant_a.join("a").join("b").join("c");
    std::fs::create_dir_all(&deep).unwrap();

    build_no_symlink(deep).expect("deep real path should mount");
}

#[test]
fn no_override_falls_back_to_configured_default_owner() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("hostfile.txt"), b"host-created").unwrap();

    // A host-created file has no override stored; with default_owner set it is
    // presented as that owner instead of the raw 0:0.
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        default_owner: Some((1000, 1000)),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let entry = fs.lookup(context(), ROOT_INODE, c"hostfile.txt").unwrap();
    assert_eq!(entry.attr.st_uid, 1000);
    assert_eq!(entry.attr.st_gid, 1000);

    // Without default_owner the same host file falls back to 0:0.
    let plain = fs_for(&temp.path);
    let entry = plain
        .lookup(context(), ROOT_INODE, c"hostfile.txt")
        .unwrap();
    assert_eq!(entry.attr.st_uid, 0);
    assert_eq!(entry.attr.st_gid, 0);
}

#[test]
fn default_owner_rejected_when_stat_virtualization_is_off() {
    let cfg = PassthroughConfig {
        root_dir: PathBuf::from(r"Z:\this-path-must-not-be-resolved"),
        stat_virtualization: StatVirtualization::Off,
        default_owner: Some((1000, 1000)),
        ..Default::default()
    };

    // EINVAL proves validation happens before root resolution, which would
    // otherwise return a host path-not-found error for this sentinel path.
    let err = match PassthroughFs::new(cfg) {
        Ok(_) => panic!("default owner with stat virtualization off must fail"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(LINUX_EINVAL));
}

#[test]
fn setattr_preserves_default_owner_for_host_created_file() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("hostfile.txt"), b"host-created").unwrap();

    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        default_owner: Some((1000, 1000)),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let entry = fs.lookup(context(), ROOT_INODE, c"hostfile.txt").unwrap();

    // The guest changes only the mode (chmod, no chown). The mutation baseline
    // must seed the configured default owner rather than 0:0, so the file does
    // not silently become root-owned after the metadata write.
    let attr = stat64 {
        st_mode: S_IFREG | 0o640,
        ..Default::default()
    };
    fs.setattr(context(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();

    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 1000);
    assert_eq!(st.st_gid, 1000);
    assert_eq!(st.st_mode & 0o7777, 0o640);
}

fn owned_fs_for(path: &Path, checkpoint: crate::OwnedDirectoryCheckpoint) -> PassthroughFs {
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: path.into(),
        inject_init: false,
        owned_checkpoint: Some(checkpoint),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs
}

fn owned_read(fs: &PassthroughFs, inode: u64, handle: u64) -> Vec<u8> {
    let mut output = CaptureWriter { bytes: Vec::new() };
    fs.read(context(), inode, handle, &mut output, 4096, 0, None, 0)
        .unwrap();
    output.bytes
}

fn owned_write(fs: &PassthroughFs, inode: u64, handle: u64, bytes: &[u8]) {
    let mut input = SourceReader {
        bytes: bytes.to_vec(),
        pos: 0,
    };
    assert_eq!(
        fs.write(
            context(),
            inode,
            handle,
            &mut input,
            bytes.len() as u32,
            0,
            None,
            false,
            false,
            0
        )
        .unwrap(),
        bytes.len()
    );
}

#[test]
fn owned_detached_roundtrip_keeps_handle_metadata_and_private_generations() {
    let temp = TempDir::new();
    let root = temp.path.join("source");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("file"), b"before").unwrap();
    std::fs::write(root.join("never-looked-up"), b"whole namespace").unwrap();
    let checkpoint = crate::OwnedDirectoryCheckpoint::default();
    let source = owned_fs_for(&root, checkpoint.clone());
    let inode = source.lookup(context(), ROOT_INODE, c"file").unwrap().inode;
    let handle = source
        .open(context(), inode, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    source
        .setattr(
            context(),
            inode,
            stat64 {
                st_uid: 1234,
                st_gid: 2345,
                st_mode: 0o640,
                ..Default::default()
            },
            None,
            SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
        )
        .unwrap();
    source.unlink(context(), ROOT_INODE, c"file").unwrap();
    owned_write(&source, inode, handle, b"after!");
    std::fs::write(root.join("file"), b"replacement").unwrap();
    assert_eq!(
        source.getattr(context(), inode, None).unwrap().0.st_uid,
        1234
    );
    let reopened = source.open(context(), inode, false, 0).unwrap().0.unwrap();
    assert_eq!(owned_read(&source, inode, reopened), b"after!");
    let generation = temp.path.join("generation");
    checkpoint.prepare_capture(&generation).unwrap();
    let state = source.capture_state().unwrap();
    let snapshot = checkpoint.finish_capture().unwrap();
    drop(source);
    std::fs::remove_dir_all(&root).unwrap();

    let child = temp.path.join("child");
    snapshot.materialize(&generation, &child).unwrap();
    let restored_checkpoint = crate::OwnedDirectoryCheckpoint::default();
    restored_checkpoint.set_restore(&generation).unwrap();
    let destination = owned_fs_for(&child, restored_checkpoint.clone());
    destination.restore_state(&state).unwrap();
    assert_eq!(owned_read(&destination, inode, handle), b"after!");
    assert_eq!(std::fs::read(child.join("file")).unwrap(), b"replacement");
    assert_eq!(
        std::fs::read(child.join("never-looked-up")).unwrap(),
        b"whole namespace"
    );
    owned_write(&destination, inode, handle, b"child!");
    destination
        .setattr(
            context(),
            inode,
            stat64 {
                st_size: 4,
                st_uid: 3456,
                ..Default::default()
            },
            None,
            SetattrValid::SIZE | SetattrValid::UID,
        )
        .unwrap();
    assert_eq!(owned_read(&destination, inode, handle), b"chil");
    assert_eq!(
        destination
            .getattr(context(), inode, None)
            .unwrap()
            .0
            .st_uid,
        3456
    );

    let sibling = temp.path.join("sibling");
    snapshot.materialize(&generation, &sibling).unwrap();
    let sibling_checkpoint = crate::OwnedDirectoryCheckpoint::default();
    sibling_checkpoint.set_restore(&generation).unwrap();
    let other = owned_fs_for(&sibling, sibling_checkpoint);
    other.restore_state(&state).unwrap();
    assert_eq!(owned_read(&other, inode, handle), b"after!");
    restored_checkpoint
        .prepare_capture(&temp.path.join("second"))
        .unwrap();
    destination.capture_state().unwrap();
    assert!(
        !restored_checkpoint
            .finish_capture()
            .unwrap()
            .payloads()
            .is_empty()
    );
}

#[test]
fn owned_detached_reclaims_only_after_last_lookup_and_open_handle() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("file"), b"data").unwrap();
    let source = owned_fs_for(&temp.path, crate::OwnedDirectoryCheckpoint::default());
    let inode = source.lookup(context(), ROOT_INODE, c"file").unwrap().inode;
    source.lookup(context(), ROOT_INODE, c"file").unwrap();
    let handle = source
        .open(context(), inode, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    source.unlink(context(), ROOT_INODE, c"file").unwrap();
    source.forget(context(), inode, 1);
    source
        .release(context(), inode, 0, handle, false, false, None)
        .unwrap();
    assert!(source.inode(inode).is_ok());
    source.forget(context(), inode, 1);
    assert!(source.inode(inode).is_err());
}

#[test]
fn owned_retained_hardlink_aliases_share_one_restored_object() {
    for remove_alias in [false, true] {
        let temp = TempDir::new();
        let root = temp.path.join("source");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("file"), b"before").unwrap();
        std::fs::hard_link(root.join("file"), root.join("alias")).unwrap();
        let checkpoint = crate::OwnedDirectoryCheckpoint::default();
        let source = owned_fs_for(&root, checkpoint.clone());
        let inode = source.lookup(context(), ROOT_INODE, c"file").unwrap().inode;
        let handle = source
            .open(context(), inode, false, LINUX_O_RDWR as u32)
            .unwrap()
            .0
            .unwrap();
        let alias = remove_alias.then(|| {
            let inode = source
                .lookup(context(), ROOT_INODE, c"alias")
                .unwrap()
                .inode;
            let handle = source
                .open(context(), inode, false, LINUX_O_RDWR as u32)
                .unwrap()
                .0
                .unwrap();
            (inode, handle)
        });
        source.unlink(context(), ROOT_INODE, c"file").unwrap();
        if remove_alias {
            source.unlink(context(), ROOT_INODE, c"alias").unwrap();
        }
        let generation = temp.path.join("generation");
        checkpoint.prepare_capture(&generation).unwrap();
        let state = source.capture_state().unwrap();
        let snapshot = checkpoint.finish_capture().unwrap();
        drop(source);
        std::fs::remove_dir_all(&root).unwrap();
        let child = temp.path.join("child");
        snapshot.materialize(&generation, &child).unwrap();
        let restored_checkpoint = crate::OwnedDirectoryCheckpoint::default();
        restored_checkpoint.set_restore(&generation).unwrap();
        let restored = owned_fs_for(&child, restored_checkpoint);
        restored.restore_state(&state).unwrap();
        owned_write(&restored, inode, handle, b"shared");
        if let Some((inode, handle)) = alias {
            assert_eq!(owned_read(&restored, inode, handle), b"shared");
        } else {
            assert_eq!(std::fs::read(child.join("alias")).unwrap(), b"shared");
        }
    }
}

#[test]
fn owned_rename_replacement_and_cached_descendants_survive_capture() {
    let temp = TempDir::new();
    let root = temp.path.join("source");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("directory")).unwrap();
    std::fs::write(root.join("directory/file"), b"child").unwrap();
    std::fs::write(root.join("target"), b"old").unwrap();
    std::fs::write(root.join("new"), b"new").unwrap();
    let checkpoint = crate::OwnedDirectoryCheckpoint::default();
    let source = owned_fs_for(&root, checkpoint.clone());
    let directory = source
        .lookup(context(), ROOT_INODE, c"directory")
        .unwrap()
        .inode;
    let child_inode = source.lookup(context(), directory, c"file").unwrap().inode;
    let old_inode = source
        .lookup(context(), ROOT_INODE, c"target")
        .unwrap()
        .inode;
    let old_handle = source
        .open(context(), old_inode, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    source
        .rename(context(), ROOT_INODE, c"new", ROOT_INODE, c"target", 0)
        .unwrap();
    source
        .rename(context(), ROOT_INODE, c"directory", ROOT_INODE, c"moved", 0)
        .unwrap();
    assert_eq!(
        source
            .getattr(context(), child_inode, None)
            .unwrap()
            .0
            .st_size,
        5
    );
    assert_eq!(owned_read(&source, old_inode, old_handle), b"old");
    let generation = temp.path.join("generation");
    checkpoint.prepare_capture(&generation).unwrap();
    let state = source.capture_state().unwrap();
    let snapshot = checkpoint.finish_capture().unwrap();
    let child = temp.path.join("child");
    snapshot.materialize(&generation, &child).unwrap();
    let restore = crate::OwnedDirectoryCheckpoint::default();
    restore.set_restore(&generation).unwrap();
    let destination = owned_fs_for(&child, restore);
    destination.restore_state(&state).unwrap();
    assert_eq!(owned_read(&destination, old_inode, old_handle), b"old");
    assert_eq!(std::fs::read(child.join("target")).unwrap(), b"new");
    assert_eq!(
        destination
            .getattr(context(), child_inode, None)
            .unwrap()
            .0
            .st_size,
        5
    );
}

//--------------------------------------------------------------------------------------------------
// DAX
//--------------------------------------------------------------------------------------------------

const DAX_GUEST_BASE: u64 = 0x1000_0000;
const DAX_WINDOW: u64 = 0x2000;
const DAX_FLAG_WRITE: u64 = 0x1;

type DaxSender = crossbeam_channel::Sender<msb_krun_utils::worker_message::WorkerMessage>;
type DaxRecorded = std::sync::Arc<std::sync::Mutex<Vec<(u64, u64, u64, bool)>>>;

/// Spawn a stub VMM worker and return its sender and the mappings it received.
fn dax_worker_stub(accept: impl FnMut() -> bool + Send + 'static) -> (DaxSender, DaxRecorded) {
    dax_worker_stub_with_removals(accept, |_, _| true)
}

fn dax_worker_stub_with_removals(
    mut accept: impl FnMut() -> bool + Send + 'static,
    mut remove: impl FnMut(u64, u64) -> bool + Send + 'static,
) -> (DaxSender, DaxRecorded) {
    use msb_krun_utils::worker_message::WorkerMessage;
    let (sender, receiver) = crossbeam_channel::unbounded();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = seen.clone();
    std::thread::spawn(move || {
        while let Ok(message) = receiver.recv() {
            match message {
                WorkerMessage::DaxAddMapping(reply, host, guest, len, writable) => {
                    let accept = accept();
                    if accept {
                        recorded.lock().unwrap().push((host, guest, len, writable));
                    }
                    let _ = reply.send(accept);
                }
                WorkerMessage::GpuRemoveMapping(reply, guest, len) => {
                    if !remove(guest, len) {
                        let _ = reply.send(false);
                        continue;
                    }
                    let mut mappings = recorded.lock().unwrap();
                    let mut retained = Vec::new();
                    for (host, start, size, writable) in mappings.drain(..) {
                        let end = start + size;
                        if end <= guest || start >= guest + len {
                            retained.push((host, start, size, writable));
                        } else {
                            if start < guest {
                                retained.push((host, start, guest - start, writable));
                            }
                            if guest + len < end {
                                let tail = guest + len;
                                retained.push((host + tail - start, tail, end - tail, writable));
                            }
                        }
                    }
                    *mappings = retained;
                    let _ = reply.send(true);
                }
                _ => {}
            }
        }
    });
    (sender, seen)
}

#[test]
fn dax_setupmapping_readonly_round_trip() {
    let temp = TempDir::new();
    let content: Vec<u8> = (0..0x1000u32).map(|i| i as u8).collect();
    std::fs::write(temp.path.join("data"), &content).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();

    let (sender, seen) = dax_worker_stub(|| true);
    fs.setupmapping(
        context(),
        entry.inode,
        0,
        0,
        0x1000,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender.clone()),
    )
    .unwrap();

    let recorded = seen.lock().unwrap().clone();
    let &(host, guest, len, writable) = recorded.last().expect("mapping sent");
    assert_eq!(guest, DAX_GUEST_BASE);
    assert_eq!(len, 0x1000);
    assert!(!writable);
    // The host view backs the guest window, so reading it exposes the file.
    let mapped = unsafe { std::slice::from_raw_parts(host as *const u8, 0x1000) };
    assert_eq!(mapped, &content[..]);
    drop(recorded);
    assert_eq!(seen.lock().unwrap().len(), 1);

    fs.removemapping(
        context(),
        vec![crate::RemovemappingOne {
            moffset: 0,
            len: 0x1000,
        }],
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender),
    )
    .unwrap();
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn dax_setupmapping_writable_round_trip() {
    // Linux requests 2 MiB slots even when the file is smaller than the slot.
    for (file_len, mapping_len) in [
        (1, 0x20_0000),
        (0x1000, 0x1000),
        (0x1000, 0x20_0000),
        (0x10001, 0x20_0000),
    ] {
        let temp = TempDir::new();
        let path = temp.path.join("data");
        std::fs::write(&path, vec![0u8; file_len]).unwrap();
        let fs = fs_for(&temp.path);
        let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();

        let (sender, seen) = dax_worker_stub(|| true);
        fs.setupmapping(
            context(),
            entry.inode,
            u64::MAX,
            0,
            mapping_len,
            DAX_FLAG_WRITE,
            0,
            DAX_GUEST_BASE,
            mapping_len,
            &Some(sender),
        )
        .unwrap();

        let recorded = seen.lock().unwrap();
        let &(host, guest, _, writable) = recorded
            .iter()
            .rev()
            .find(|(_, guest, _, _)| *guest == DAX_GUEST_BASE)
            .expect("file mapping sent");
        assert_eq!(guest, DAX_GUEST_BASE);
        assert!(writable);
        // SAFETY: the acknowledged writable view remains owned by `fs`.
        unsafe { (host as *mut u8).write_volatile(b'x') };
        drop(recorded);

        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), file_len, "mapping must not extend the file");
        assert_eq!(bytes[0], b'x', "DAX writes must reach the backing file");
    }
}

#[test]
fn dax_readonly_mapping_observes_fuse_append() {
    for initial_len in [1, 0x1000, 0x10001] {
        let temp = TempDir::new();
        let path = temp.path.join("data");
        std::fs::write(&path, vec![b'a'; initial_len]).unwrap();
        let fs = fs_for(&temp.path);
        let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
        let (handle, _) = fs
            .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
            .unwrap();
        let (sender, seen) = dax_worker_stub(|| true);
        fs.setupmapping(
            context(),
            entry.inode,
            u64::MAX,
            0,
            0x20_0000,
            0,
            0,
            DAX_GUEST_BASE,
            0x20_0000,
            &Some(sender),
        )
        .unwrap();

        // Extending writes use FUSE_WRITE even when the guest uses DAX for reads.
        let mut reader = SourceReader {
            bytes: b"appended".to_vec(),
            pos: 0,
        };
        assert_eq!(
            fs.write(
                context(),
                entry.inode,
                handle.unwrap(),
                &mut reader,
                8,
                initial_len as u64,
                None,
                false,
                false,
                0,
            )
            .unwrap(),
            8,
        );
        assert_eq!(&std::fs::read(&path).unwrap()[initial_len..], b"appended");

        let recorded = seen.lock().unwrap();
        let address = DAX_GUEST_BASE + initial_len as u64;
        let &(host, guest, _, _) = recorded
            .iter()
            .rev()
            .find(|(_, guest, len, _)| *guest <= address && address + 8 <= *guest + *len)
            .expect("appended range remains mapped");
        // SAFETY: the current acknowledged mapping covers these eight bytes and
        // remains owned by `fs`; all filesystem operations above have completed.
        let bytes = unsafe { std::slice::from_raw_parts((host + address - guest) as *const u8, 8) };
        assert_eq!(
            bytes, b"appended",
            "guest reads must see the completed write"
        );
    }
}

#[test]
fn dax_mapping_survives_truncate_and_regrowth() {
    let temp = TempDir::new();
    let path = temp.path.join("data");
    std::fs::write(&path, vec![b'a'; 4096]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
    let (handle, _) = fs
        .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
        .unwrap();
    let (sender, seen) = dax_worker_stub(|| true);
    fs.setupmapping(
        context(),
        entry.inode,
        u64::MAX,
        0,
        0x20_0000,
        0,
        0,
        DAX_GUEST_BASE,
        0x20_0000,
        &Some(sender),
    )
    .unwrap();

    for size in [0, 4104] {
        fs.setattr(
            context(),
            entry.inode,
            stat64 {
                st_size: size,
                ..Default::default()
            },
            handle,
            SetattrValid::SIZE,
        )
        .unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size as u64);
        if size == 0 {
            assert!(
                seen.lock().unwrap().is_empty(),
                "empty file has no mapped pages"
            );
        }
    }
    let mut reader = SourceReader {
        bytes: b"regrown!".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        handle.unwrap(),
        &mut reader,
        8,
        4096,
        None,
        false,
        false,
        0,
    )
    .unwrap();
    let recorded = seen.lock().unwrap();
    let &(host, _, len, _) = recorded.last().unwrap();
    assert!(len >= 4104);
    // SAFETY: the stub worker's live mapping is retained by the filesystem.
    assert_eq!(
        unsafe { std::slice::from_raw_parts((host + 4096) as *const u8, 8) },
        b"regrown!"
    );
    drop(recorded);

    fs.open(
        context(),
        entry.inode,
        false,
        (LINUX_O_RDWR | LINUX_O_TRUNC) as u32,
    )
    .unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn dax_write_to_another_inode_completes_while_a_write_is_paused() {
    struct PausedReader {
        source: SourceReader,
        entered: crossbeam_channel::Sender<()>,
        resume: crossbeam_channel::Receiver<()>,
    }

    impl Read for PausedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.source.read(buf)
        }
    }

    impl ZeroCopyReader for PausedReader {
        fn read_to(&mut self, file: &File, count: usize, offset: u64) -> io::Result<usize> {
            self.entered.send(()).unwrap();
            self.resume.recv().unwrap();
            self.source.read_to(file, count, offset)
        }
    }

    let temp = TempDir::new();
    std::fs::write(temp.path.join("first"), b"a").unwrap();
    std::fs::write(temp.path.join("second"), b"b").unwrap();
    let fs = fs_for(&temp.path);
    let first = fs.lookup(context(), ROOT_INODE, c"first").unwrap().inode;
    let second = fs.lookup(context(), ROOT_INODE, c"second").unwrap().inode;
    let open = |inode| {
        fs.open(context(), inode, false, LINUX_O_RDWR as u32)
            .unwrap()
            .0
            .unwrap()
    };
    let first_handle = open(first);
    let second_handle = open(second);
    let (sender, seen) = dax_worker_stub(|| true);
    for (inode, moffset) in [(first, 0), (second, 0x1000)] {
        fs.setupmapping(
            context(),
            inode,
            0,
            0,
            0x1000,
            0,
            moffset,
            DAX_GUEST_BASE,
            DAX_WINDOW,
            &Some(sender.clone()),
        )
        .unwrap();
    }

    let (entered_tx, entered_rx) = crossbeam_channel::bounded(1);
    let (resume_tx, resume_rx) = crossbeam_channel::bounded(1);
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let write = |inode, handle, reader: &mut dyn ZeroCopyReader| {
        fs.write(
            context(),
            inode,
            handle,
            reader,
            1,
            1,
            None,
            false,
            false,
            0,
        )
    };
    let completed = std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut reader = PausedReader {
                source: SourceReader {
                    bytes: b"x".to_vec(),
                    pos: 0,
                },
                entered: entered_tx,
                resume: resume_rx,
            };
            write(first, first_handle, &mut reader).unwrap();
        });
        entered_rx.recv().unwrap();
        scope.spawn(|| {
            let mut reader = SourceReader {
                bytes: b"y".to_vec(),
                pos: 0,
            };
            done_tx
                .send(write(second, second_handle, &mut reader))
                .unwrap();
        });
        // The timeout is a hang watchdog. The second write must finish before
        // the first is released; always release it so a regression can exit.
        let completed = done_rx.recv_timeout(std::time::Duration::from_secs(5));
        resume_tx.send(()).unwrap();
        completed
    });
    assert_eq!(
        completed
            .expect("unrelated write blocked behind paused file I/O")
            .unwrap(),
        1
    );
    assert_eq!(std::fs::read(temp.path.join("first")).unwrap(), b"ax");
    assert_eq!(std::fs::read(temp.path.join("second")).unwrap(), b"by");
    let recorded = seen.lock().unwrap();
    for (guest, expected) in [(DAX_GUEST_BASE, b"ax"), (DAX_GUEST_BASE + 0x1000, b"by")] {
        let &(host, _, _, _) = recorded
            .iter()
            .find(|(_, addr, _, _)| *addr == guest)
            .unwrap();
        // SAFETY: the filesystem retains both live views and writes have joined.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(host as *const u8, 2) },
            expected
        );
    }
}

#[test]
fn dax_resize_preserves_concurrent_slot_removal_and_replacement() {
    let temp = TempDir::new();
    let first_path = temp.path.join("first");
    std::fs::write(&first_path, vec![b'a'; 8192]).unwrap();
    std::fs::write(temp.path.join("second"), b"replacement").unwrap();
    let fs = fs_for(&temp.path);
    let first = fs.lookup(context(), ROOT_INODE, c"first").unwrap().inode;
    let second = fs.lookup(context(), ROOT_INODE, c"second").unwrap().inode;
    let (sender, seen) = dax_worker_stub(|| true);
    let sender = Some(sender);
    fs.setupmapping(
        context(),
        first,
        0,
        0,
        8192,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &sender,
    )
    .unwrap();
    let (entered_tx, entered_rx) = crossbeam_channel::bounded(1);
    let (resume_tx, resume_rx) = crossbeam_channel::bounded(1);
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);

    let completed = std::thread::scope(|scope| {
        scope.spawn(|| {
            fs.resize_inode(first, || {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                StdOpenOptions::new()
                    .write(true)
                    .open(&first_path)?
                    .set_len(16384)
            })
            .unwrap();
        });
        entered_rx.recv().unwrap();
        scope.spawn(|| {
            let result = fs
                .removemapping(
                    context(),
                    vec![crate::RemovemappingOne {
                        moffset: 0,
                        len: 4096,
                    }],
                    DAX_GUEST_BASE,
                    DAX_WINDOW,
                    &sender,
                )
                .and_then(|()| {
                    fs.setupmapping(
                        context(),
                        second,
                        0,
                        0,
                        4096,
                        0,
                        4096,
                        DAX_GUEST_BASE,
                        DAX_WINDOW,
                        &sender,
                    )
                });
            done_tx.send(result).unwrap();
        });
        // Always release the resize before asserting so a lock regression exits.
        let completed = done_rx.recv_timeout(std::time::Duration::from_secs(5));
        resume_tx.send(()).unwrap();
        completed
    });
    completed
        .expect("unrelated mapping changes blocked during file resize")
        .unwrap();
    assert_eq!(std::fs::metadata(first_path).unwrap().len(), 16384);
    let recorded = seen.lock().unwrap();
    assert_eq!(recorded.len(), 1, "resize must not resurrect removed slots");
    let (host, guest, len, _) = recorded[0];
    assert_eq!((guest, len), (DAX_GUEST_BASE + 4096, 4096));
    // SAFETY: the surviving replacement is retained by the filesystem.
    assert_eq!(
        unsafe { std::slice::from_raw_parts(host as *const u8, 11) },
        b"replacement"
    );
}

#[test]
fn dax_setupmapping_honors_readonly() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), b"x").unwrap();
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        readonly: true,
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();

    let (sender, _) = dax_worker_stub(|| true);
    expect_errno(
        fs.setupmapping(
            context(),
            entry.inode,
            0,
            0,
            0x1000,
            DAX_FLAG_WRITE,
            0,
            DAX_GUEST_BASE,
            DAX_WINDOW,
            &Some(sender),
        ),
        LINUX_EROFS,
    );
}

#[test]
fn dax_setupmapping_propagates_worker_rejection() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![0u8; 0x1000]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();

    let (sender, _) = dax_worker_stub(|| false);
    expect_errno(
        fs.setupmapping(
            context(),
            entry.inode,
            0,
            0,
            0x1000,
            0,
            0,
            DAX_GUEST_BASE,
            DAX_WINDOW,
            &Some(sender),
        ),
        LINUX_EINVAL,
    );
}

#[test]
fn dax_removemapping_keeps_the_unremoved_tail() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![0u8; 0x2000]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();

    let (sender, seen) = dax_worker_stub(|| true);
    fs.setupmapping(
        context(),
        entry.inode,
        0,
        0,
        0x20_0000,
        0,
        0,
        DAX_GUEST_BASE,
        0x20_0000,
        &Some(sender.clone()),
    )
    .unwrap();
    let host = seen.lock().unwrap().last().unwrap().0;

    fs.removemapping(
        context(),
        vec![crate::RemovemappingOne {
            moffset: 0,
            len: 0x1000,
        }],
        DAX_GUEST_BASE,
        0x20_0000,
        &Some(sender.clone()),
    )
    .unwrap();

    let recorded = seen.lock().unwrap();
    assert_eq!(
        recorded.as_slice(),
        &[(host + 0x1000, DAX_GUEST_BASE + 0x1000, 0x1000, false)]
    );
    // SAFETY: the worker's remaining mapping must retain its backing.
    assert_eq!(unsafe { ((host + 0x1000) as *const u8).read_volatile() }, 0);
    drop(recorded);

    let (handle, _) = fs
        .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
        .unwrap();
    let mut reader = SourceReader {
        bytes: b"appended".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        handle.unwrap(),
        &mut reader,
        8,
        0x2000,
        None,
        false,
        false,
        0,
    )
    .unwrap();
    let recorded = seen.lock().unwrap();
    assert!(
        recorded
            .iter()
            .all(|(_, guest, _, _)| *guest >= DAX_GUEST_BASE + 0x1000),
        "growth must not reinstall the removed prefix"
    );
    let &(host, guest, len, _) = recorded.last().unwrap();
    let address = DAX_GUEST_BASE + 0x2000;
    assert!(guest <= address && address + 8 <= guest + len);
    // SAFETY: the live worker mapping covers the appended bytes.
    assert_eq!(
        unsafe { std::slice::from_raw_parts((host + address - guest) as *const u8, 8) },
        b"appended"
    );
}

#[test]
fn dax_setupmapping_upgrades_existing_window() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![0u8; 0x1000]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();

    // Read-only mapping first.
    let (sender, _) = dax_worker_stub(|| true);
    fs.setupmapping(
        context(),
        entry.inode,
        0,
        0,
        0x1000,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender),
    )
    .unwrap();

    // The guest re-sends `FUSE_SETUPMAPPING` for the same range with WRITE to
    // upgrade the mapping; it must replace the window, not fail.
    let (sender, seen) = dax_worker_stub(|| true);
    fs.setupmapping(
        context(),
        entry.inode,
        0,
        0,
        0x1000,
        DAX_FLAG_WRITE,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender),
    )
    .unwrap();

    let &(_, guest, _, writable) = seen.lock().unwrap().last().unwrap();
    assert_eq!(guest, DAX_GUEST_BASE);
    assert!(writable);
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn dax_failed_upgrade_restores_previous_mapping() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![b'a'; 4096]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
    let mut requests = 0;
    let (sender, seen) = dax_worker_stub(move || {
        requests += 1;
        requests != 2
    });
    fs.setupmapping(
        context(),
        entry.inode,
        u64::MAX,
        0,
        0x20_0000,
        0,
        0,
        DAX_GUEST_BASE,
        0x20_0000,
        &Some(sender.clone()),
    )
    .unwrap();
    let original_host = seen.lock().unwrap()[0].0;
    expect_errno(
        fs.setupmapping(
            context(),
            entry.inode,
            u64::MAX,
            0,
            0x20_0000,
            DAX_FLAG_WRITE,
            0,
            DAX_GUEST_BASE,
            0x20_0000,
            &Some(sender),
        ),
        LINUX_EINVAL,
    );
    let recorded = seen.lock().unwrap();
    assert_eq!(
        recorded.as_slice(),
        &[(original_host, DAX_GUEST_BASE, 4096, false)]
    );
    // SAFETY: the restored view remains owned by the filesystem.
    assert_eq!(
        unsafe { (original_host as *const u8).read_volatile() },
        b'a'
    );
}

#[test]
fn setattr_size_uses_existing_handle_after_file_becomes_readonly() {
    for mapped in [false, true] {
        let temp = TempDir::new();
        let path = temp.path.join("data");
        std::fs::write(&path, vec![b'a'; 4096]).unwrap();
        let fs = fs_for(&temp.path);
        let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
        let handle = fs
            .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
            .unwrap()
            .0;
        let (sender, seen) = dax_worker_stub(|| true);
        if mapped {
            fs.setupmapping(
                context(),
                entry.inode,
                0,
                0,
                DAX_WINDOW,
                0,
                0,
                DAX_GUEST_BASE,
                DAX_WINDOW,
                &Some(sender),
            )
            .unwrap();
        }
        let permissions = std::fs::metadata(&path).unwrap().permissions();
        let mut readonly = permissions.clone();
        readonly.set_readonly(true);
        std::fs::set_permissions(&path, readonly).unwrap();
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());

        let result = fs.setattr(
            context(),
            entry.inode,
            stat64 {
                st_size: 0,
                ..Default::default()
            },
            handle,
            SetattrValid::SIZE,
        );
        std::fs::set_permissions(&path, permissions).unwrap();
        result.expect("an existing writable handle retains permission to truncate");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        assert!(seen.lock().unwrap().is_empty());
    }
}

#[test]
fn dax_hardlink_write_and_truncate_update_existing_mapping() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![b'a'; 4096]).unwrap();
    std::fs::hard_link(temp.path.join("data"), temp.path.join("alias")).unwrap();
    let fs = fs_for(&temp.path);
    let data = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
    let alias = fs.lookup(context(), ROOT_INODE, c"alias").unwrap();
    assert_eq!(
        data.inode, alias.inode,
        "the guest must share one size and page cache across hardlinks"
    );
    let handle = fs
        .open(context(), alias.inode, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    let (sender, seen) = dax_worker_stub(|| true);
    fs.setupmapping(
        context(),
        data.inode,
        0,
        0,
        8192,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender),
    )
    .unwrap();
    let mut reader = SourceReader {
        bytes: b"x".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        alias.inode,
        handle,
        &mut reader,
        1,
        4096,
        None,
        false,
        false,
        0,
    )
    .unwrap();
    {
        let recorded = seen.lock().unwrap();
        let &(host, _, len, _) = recorded.last().unwrap();
        assert_eq!(
            len, 8192,
            "growth through an alias must refresh the mapped file"
        );
        // SAFETY: this acknowledged mapping is retained by the filesystem.
        assert_eq!(
            unsafe { ((host + 4096) as *const u8).read_volatile() },
            b'x'
        );
    }
    fs.setattr(
        context(),
        alias.inode,
        stat64 {
            st_size: 0,
            ..Default::default()
        },
        Some(handle),
        SetattrValid::SIZE,
    )
    .unwrap();
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(std::fs::metadata(temp.path.join("data")).unwrap().len(), 0);

    // Renaming one hardlink over another must leave both names intact.
    fs.rename(context(), ROOT_INODE, c"data", ROOT_INODE, c"alias", 0)
        .unwrap();
    assert!(temp.path.join("data").exists());
    assert!(temp.path.join("alias").exists());
    assert_eq!(
        fs.getattr(context(), data.inode, None).unwrap().0.st_nlink,
        2
    );

    // Removing the canonical name must keep the surviving alias usable through
    // the inode the guest already cached, without requiring another lookup.
    fs.unlink(context(), ROOT_INODE, c"data").unwrap();
    let stat = fs.getattr(context(), alias.inode, None).unwrap().0;
    assert_eq!(stat.st_nlink, 1);
    assert_eq!(stat.st_size, 0);
}

#[test]
fn dax_failed_refresh_still_clears_privilege_bits() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![b'a'; 4096]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
    let handle = fs
        .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    fs.setattr(
        context(),
        entry.inode,
        stat64 {
            st_mode: S_IFREG | 0o6755,
            ..Default::default()
        },
        Some(handle),
        SetattrValid::MODE,
    )
    .unwrap();
    assert_eq!(
        fs.getattr(context(), entry.inode, Some(handle))
            .unwrap()
            .0
            .st_mode
            & 0o6000,
        0o6000
    );
    let mut calls = 0;
    let (sender, _) = dax_worker_stub(move || {
        calls += 1;
        calls == 1
    });
    fs.setupmapping(
        context(),
        entry.inode,
        0,
        0,
        8192,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender),
    )
    .unwrap();
    let mut reader = SourceReader {
        bytes: b"x".to_vec(),
        pos: 0,
    };
    assert!(
        fs.write(
            context(),
            entry.inode,
            handle,
            &mut reader,
            1,
            4096,
            None,
            false,
            true,
            0
        )
        .is_err()
    );
    assert_eq!(
        std::fs::metadata(temp.path.join("data")).unwrap().len(),
        4097
    );
    assert_eq!(
        fs.getattr(context(), entry.inode, Some(handle))
            .unwrap()
            .0
            .st_mode
            & 0o6000,
        0,
        "modified file must lose privilege bits even if refresh fails"
    );
}

#[test]
fn dax_failed_rollback_is_repaired_by_a_later_write() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![b'a'; 4096]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
    let handle = fs
        .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    let mut calls = 0;
    let (sender, seen) = dax_worker_stub(move || {
        calls += 1;
        calls != 2 && calls != 3
    });
    fs.setupmapping(
        context(),
        entry.inode,
        0,
        0,
        4096,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender.clone()),
    )
    .unwrap();
    assert!(
        fs.setupmapping(
            context(),
            entry.inode,
            0,
            0,
            4096,
            DAX_FLAG_WRITE,
            0,
            DAX_GUEST_BASE,
            DAX_WINDOW,
            &Some(sender)
        )
        .is_err()
    );
    assert!(seen.lock().unwrap().is_empty());
    let mut reader = SourceReader {
        bytes: b"x".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        handle,
        &mut reader,
        1,
        0,
        None,
        false,
        false,
        0,
    )
    .unwrap();
    let recorded = seen.lock().unwrap();
    assert_eq!(
        recorded.len(),
        1,
        "a failed rollback must not be treated as installed"
    );
    let (host, guest, len, writable) = recorded[0];
    assert_eq!((guest, len, writable), (DAX_GUEST_BASE, 4096, false));
    // SAFETY: the recovered live mapping is retained by the filesystem.
    assert_eq!(unsafe { (host as *const u8).read_volatile() }, b'x');
}

#[test]
fn dax_unmapped_file_write_does_not_wait_for_worker() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("mapped"), b"a").unwrap();
    std::fs::write(temp.path.join("plain"), b"b").unwrap();
    let fs = fs_for(&temp.path);
    let mapped = fs.lookup(context(), ROOT_INODE, c"mapped").unwrap().inode;
    let plain = fs.lookup(context(), ROOT_INODE, c"plain").unwrap().inode;
    let handle = fs
        .open(context(), plain, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    let (entered_tx, entered_rx) = crossbeam_channel::bounded(1);
    let (resume_tx, resume_rx) = crossbeam_channel::bounded(1);
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let (sender, _) = dax_worker_stub(move || {
        entered_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
        true
    });
    let completed = std::thread::scope(|scope| {
        scope.spawn(|| {
            fs.setupmapping(
                context(),
                mapped,
                0,
                0,
                4096,
                0,
                0,
                DAX_GUEST_BASE,
                DAX_WINDOW,
                &Some(sender),
            )
            .unwrap()
        });
        entered_rx.recv().unwrap();
        scope.spawn(|| {
            let mut reader = SourceReader {
                bytes: b"x".to_vec(),
                pos: 0,
            };
            done_tx
                .send(fs.write(
                    context(),
                    plain,
                    handle,
                    &mut reader,
                    1,
                    0,
                    None,
                    false,
                    false,
                    0,
                ))
                .unwrap();
        });
        let completed = done_rx.recv_timeout(std::time::Duration::from_secs(5));
        resume_tx.send(()).unwrap();
        completed
    });
    assert_eq!(
        completed
            .expect("unmapped file waited for the VMM worker")
            .unwrap(),
        1
    );
    assert_eq!(std::fs::read(temp.path.join("plain")).unwrap(), b"x");
}

#[test]
fn dax_unmapping_skips_holes_and_retries_only_unacknowledged_ranges() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![b'a'; 8192]).unwrap();
    let fs = fs_for(&temp.path);
    let inode = fs.lookup(context(), ROOT_INODE, c"data").unwrap().inode;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let (sender, seen) = dax_worker_stub_with_removals(
        || true,
        move |guest, len| {
            let mut requests = recorded.lock().unwrap();
            requests.push((guest, len));
            requests.len() != 2
        },
    );
    let sender = Some(sender);
    for offset in [0, 4096] {
        fs.setupmapping(
            context(),
            inode,
            0,
            offset,
            4096,
            0,
            offset,
            DAX_GUEST_BASE,
            DAX_WINDOW,
            &sender,
        )
        .unwrap();
    }
    assert!(
        requests.lock().unwrap().is_empty(),
        "setup must not remove unmapped pages"
    );
    let remove = || {
        fs.removemapping(
            context(),
            vec![crate::RemovemappingOne {
                moffset: 0,
                len: 8192,
            }],
            DAX_GUEST_BASE,
            DAX_WINDOW,
            &sender,
        )
    };
    assert!(remove().is_err());
    {
        let live = seen.lock().unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!((live[0].1, live[0].2), (DAX_GUEST_BASE + 4096, 4096));
        // SAFETY: a rejected removal must retain this live host backing.
        assert_eq!(unsafe { (live[0].0 as *const u8).read_volatile() }, b'a');
    }
    remove().unwrap();
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(
        *requests.lock().unwrap(),
        vec![
            (DAX_GUEST_BASE, 4096),
            (DAX_GUEST_BASE + 4096, 4096),
            (DAX_GUEST_BASE + 4096, 4096),
        ]
    );
    remove().unwrap();
    assert_eq!(
        requests.lock().unwrap().len(),
        3,
        "empty ranges need no worker request"
    );
}

#[test]
fn dax_mapping_survives_unlink() {
    for fail_refresh in [false, true] {
        dax_namespace_change_keeps_mapping(false, fail_refresh);
    }
}

#[test]
fn dax_mapping_survives_rename_over() {
    for fail_refresh in [false, true] {
        dax_namespace_change_keeps_mapping(true, fail_refresh);
    }
}

fn dax_namespace_change_keeps_mapping(replace: bool, fail_refresh: bool) {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), b"old contents").unwrap();
    std::fs::write(temp.path.join("replacement"), b"new contents").unwrap();
    let fs = fs_for(&temp.path);
    let inode = fs.lookup(context(), ROOT_INODE, c"data").unwrap().inode;
    let replacement = fs.lookup(context(), ROOT_INODE, c"replacement").unwrap();
    let mut calls = 0;
    let (sender, seen) = dax_worker_stub(move || {
        calls += 1;
        !fail_refresh || calls == 1
    });
    fs.setupmapping(
        context(),
        inode,
        0,
        0,
        8192,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender.clone()),
    )
    .unwrap();
    if replace {
        let result = fs.rename(
            context(),
            ROOT_INODE,
            c"replacement",
            ROOT_INODE,
            c"data",
            0,
        );
        assert_eq!(result.is_err(), fail_refresh);
        assert_eq!(
            fs.getattr(context(), replacement.inode, None)
                .unwrap()
                .0
                .st_size,
            12
        );
        assert_eq!(
            fs.lookup(context(), ROOT_INODE, c"data").unwrap().inode,
            replacement.inode
        );
        assert_eq!(
            std::fs::read(temp.path.join("data")).unwrap(),
            b"new contents"
        );
    } else {
        let result = fs.unlink(context(), ROOT_INODE, c"data");
        assert_eq!(result.is_err(), fail_refresh);
        assert!(!temp.path.join("data").exists());
        std::fs::write(temp.path.join("data"), b"fresh").unwrap();
        assert_ne!(
            fs.lookup(context(), ROOT_INODE, c"data").unwrap().inode,
            inode
        );
    }
    if fail_refresh {
        assert!(seen.lock().unwrap().is_empty());
    } else {
        let live = seen.lock().unwrap();
        let host = live[0].0;
        // SAFETY: removing a name must retain the acknowledged mapped object.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(host as *const u8, 12) },
            b"old contents"
        );
    }
    fs.removemapping(
        context(),
        vec![crate::RemovemappingOne {
            moffset: 0,
            len: 8192,
        }],
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender),
    )
    .unwrap();
    assert!(seen.lock().unwrap().is_empty());
}
