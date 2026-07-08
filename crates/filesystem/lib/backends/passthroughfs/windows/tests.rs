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
        let mut path = std::env::temp_dir();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "msb-windows-fs-test-{}-{unique}",
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
    assert_override(&data.path, 111, 222, S_IFREG | 0o644, 0);
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
    let old_path = old_data.path.clone();
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
    assert_override(&data.path, 700, 701, S_IFREG | 0o600, 0);
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
        .override_file_path(&data.path)
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
    assert_override(&data.path, 0, 0, S_IFREG | 0o644, 0);
    let ads_path = ads_override_path(&data.path);

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
