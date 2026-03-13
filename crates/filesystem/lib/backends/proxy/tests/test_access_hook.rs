use super::*;

#[test]
fn test_access_allow_all() {
    let sb = ProxyFsTestSandbox::with_access_log();
    // Create a file — create calls the access hook.
    let (entry, handle) = sb.fuse_create_root("allowed.txt").unwrap();
    let handle = handle.unwrap();
    // Open the file.
    let (open_handle, _opts) = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    assert!(open_handle.is_some());
    // Release handles.
    sb.fs
        .release(
            ProxyFsTestSandbox::ctx(),
            entry.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
    sb.fs
        .release(
            ProxyFsTestSandbox::ctx(),
            entry.inode,
            0,
            open_handle.unwrap(),
            false,
            false,
            None,
        )
        .unwrap();
    // Open a directory.
    let (dir_handle, _opts) = sb.fuse_opendir(ROOT_INODE).unwrap();
    assert!(dir_handle.is_some());
    sb.fs
        .releasedir(
            ProxyFsTestSandbox::ctx(),
            ROOT_INODE,
            0,
            dir_handle.unwrap(),
        )
        .unwrap();
}

#[test]
fn test_access_deny_all_open() {
    let sb = ProxyFsTestSandbox::with_deny_all();
    // Create a file without hooks first (need a separate sandbox for setup).
    let setup = ProxyFsTestSandbox::new();
    let (entry, handle) = setup.fuse_create_root("file.txt").unwrap();
    let _ = (entry, handle);

    // With deny-all, we cannot create files either, so we test open on a
    // file that would exist. But since create also goes through the hook,
    // the file won't exist. Instead, test that open on ROOT_INODE fails.
    // Actually, we need to create first without hook, then test open with hook.
    // Since ProxyFs wraps its own MemFs, we can't share state.
    // Instead, use with_access_deny to deny only opens but allow creates.
    // Let's just test that open on root (which has a known inode) fails.
    let result = sb.fuse_open(ROOT_INODE, libc::O_RDONLY as u32);
    ProxyFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_access_deny_all_create() {
    let sb = ProxyFsTestSandbox::with_deny_all();
    let result = sb.fuse_create_root("denied.txt");
    ProxyFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_access_deny_all_opendir() {
    let sb = ProxyFsTestSandbox::with_deny_all();
    let result = sb.fuse_opendir(ROOT_INODE);
    ProxyFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_access_deny_write_allow_read() {
    // Custom hook: deny Write, allow Read.
    let memfs = MemFs::builder().build().unwrap();
    let fs = ProxyFs::builder(Box::new(memfs))
        .on_access(|_path, mode| {
            if mode == AccessMode::Write {
                Err(io::Error::from_raw_os_error(LINUX_EACCES))
            } else {
                Ok(())
            }
        })
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let sb = ProxyFsTestSandbox {
        fs,
        access_log: Arc::new(Mutex::new(Vec::new())),
        read_log: Arc::new(Mutex::new(Vec::new())),
        write_log: Arc::new(Mutex::new(Vec::new())),
    };

    // Create fails (requires Write).
    let result = sb.fuse_create_root("test.txt");
    ProxyFsTestSandbox::assert_errno(result, LINUX_EACCES);

    // Opendir succeeds (requires Read).
    let (dir_handle, _opts) = sb.fuse_opendir(ROOT_INODE).unwrap();
    assert!(dir_handle.is_some());
    sb.fs
        .releasedir(
            ProxyFsTestSandbox::ctx(),
            ROOT_INODE,
            0,
            dir_handle.unwrap(),
        )
        .unwrap();
}

#[test]
fn test_access_deny_rdwr() {
    // Custom hook: deny Write, allow Read.
    let memfs = MemFs::builder().build().unwrap();
    let fs = ProxyFs::builder(Box::new(memfs))
        .on_access(|_path, mode| {
            if mode == AccessMode::Write {
                Err(io::Error::from_raw_os_error(LINUX_EACCES))
            } else {
                Ok(())
            }
        })
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let sb = ProxyFsTestSandbox {
        fs,
        access_log: Arc::new(Mutex::new(Vec::new())),
        read_log: Arc::new(Mutex::new(Vec::new())),
        write_log: Arc::new(Mutex::new(Vec::new())),
    };

    // Use mknod to create a file without going through ProxyFs::create.
    let mode = libc::S_IFREG as u32 | 0o644;
    let entry = sb
        .fs
        .mknod(
            ProxyFsTestSandbox::ctx(),
            ROOT_INODE,
            &ProxyFsTestSandbox::cstr("rdwr_test.txt"),
            mode,
            0,
            0,
            Extensions::default(),
        )
        .unwrap();

    // O_RDWR requires both Read and Write — Write denied → EACCES.
    let result = sb.fuse_open(entry.inode, libc::O_RDWR as u32);
    ProxyFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_access_selective_by_path() {
    let sb = ProxyFsTestSandbox::with_access_deny("secret");
    // Create dirs without access hook (mkdir doesn't go through access hook).
    let secret_dir = sb.fuse_mkdir_root("secret").unwrap();
    let public_dir = sb.fuse_mkdir_root("public").unwrap();

    // Create files in each dir via mknod (bypasses access hook).
    let mode = libc::S_IFREG as u32 | 0o644;
    let secret_file = sb
        .fs
        .mknod(
            ProxyFsTestSandbox::ctx(),
            secret_dir.inode,
            &ProxyFsTestSandbox::cstr("file.txt"),
            mode,
            0,
            0,
            Extensions::default(),
        )
        .unwrap();
    // Lookup to register path.
    let _ = sb.lookup(secret_dir.inode, "file.txt").unwrap();

    let public_file = sb
        .fs
        .mknod(
            ProxyFsTestSandbox::ctx(),
            public_dir.inode,
            &ProxyFsTestSandbox::cstr("file.txt"),
            mode,
            0,
            0,
            Extensions::default(),
        )
        .unwrap();
    // Lookup to register path.
    let _ = sb.lookup(public_dir.inode, "file.txt").unwrap();

    // Open secret file → denied.
    let result = sb.fuse_open(secret_file.inode, libc::O_RDONLY as u32);
    ProxyFsTestSandbox::assert_errno(result, LINUX_EACCES);

    // Open public file → allowed.
    let (handle, _opts) = sb
        .fuse_open(public_file.inode, libc::O_RDONLY as u32)
        .unwrap();
    assert!(handle.is_some());
}

#[test]
fn test_access_inner_not_called_on_deny() {
    let sb = ProxyFsTestSandbox::with_deny_all();
    // Attempt to create a file — should fail at the hook level.
    let result = sb.fuse_create_root("should_not_exist.txt");
    assert!(result.is_err());
    // Verify the file was never created in the inner MemFs (lookup should fail).
    // Since the create was denied, the inner never saw it. We can't directly
    // access inner, but lookup through ProxyFs (which delegates) should fail.
    let result = sb.lookup_root("should_not_exist.txt");
    ProxyFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_access_open_flags_mapping() {
    let sb = ProxyFsTestSandbox::with_access_log();
    // Create a file (this logs Write).
    let mode = libc::S_IFREG as u32 | 0o644;
    let entry = sb
        .fs
        .mknod(
            ProxyFsTestSandbox::ctx(),
            ROOT_INODE,
            &ProxyFsTestSandbox::cstr("flags_test.txt"),
            mode,
            0,
            0,
            Extensions::default(),
        )
        .unwrap();
    // Lookup to register path.
    let _ = sb.lookup_root("flags_test.txt").unwrap();

    // Clear access log.
    sb.access_log.lock().unwrap().clear();

    // O_RDONLY → Read
    let (h1, _) = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    sb.fs
        .release(
            ProxyFsTestSandbox::ctx(),
            entry.inode,
            0,
            h1.unwrap(),
            false,
            false,
            None,
        )
        .unwrap();

    // O_WRONLY → Write
    let (h2, _) = sb.fuse_open(entry.inode, libc::O_WRONLY as u32).unwrap();
    sb.fs
        .release(
            ProxyFsTestSandbox::ctx(),
            entry.inode,
            0,
            h2.unwrap(),
            false,
            false,
            None,
        )
        .unwrap();

    // O_RDWR → Read + Write
    let (h3, _) = sb.fuse_open(entry.inode, libc::O_RDWR as u32).unwrap();
    sb.fs
        .release(
            ProxyFsTestSandbox::ctx(),
            entry.inode,
            0,
            h3.unwrap(),
            false,
            false,
            None,
        )
        .unwrap();

    let log = sb.access_log.lock().unwrap();
    // O_RDONLY logs one Read.
    assert_eq!(log[0].1, AccessMode::Read, "O_RDONLY should map to Read");
    // O_WRONLY logs one Write.
    assert_eq!(log[1].1, AccessMode::Write, "O_WRONLY should map to Write");
    // O_RDWR logs Read then Write.
    assert_eq!(log[2].1, AccessMode::Read, "O_RDWR should first check Read");
    assert_eq!(
        log[3].1,
        AccessMode::Write,
        "O_RDWR should then check Write"
    );
}

#[test]
fn test_access_create_always_write() {
    let sb = ProxyFsTestSandbox::with_access_log();
    sb.fuse_create_root("created.txt").unwrap();
    let log = sb.access_log.lock().unwrap();
    // Create calls check_access_by_path with Write.
    assert!(
        log.iter().any(|(_, mode)| *mode == AccessMode::Write),
        "create should call hook with Write mode"
    );
}

#[test]
fn test_access_opendir_always_read() {
    let sb = ProxyFsTestSandbox::with_access_log();
    sb.access_log.lock().unwrap().clear();
    let (handle, _opts) = sb.fuse_opendir(ROOT_INODE).unwrap();
    sb.fs
        .releasedir(ProxyFsTestSandbox::ctx(), ROOT_INODE, 0, handle.unwrap())
        .unwrap();
    let log = sb.access_log.lock().unwrap();
    assert_eq!(log.len(), 1, "opendir should call hook exactly once");
    assert_eq!(
        log[0].1,
        AccessMode::Read,
        "opendir should call hook with Read mode"
    );
}

#[test]
fn test_access_hook_receives_correct_path() {
    let sb = ProxyFsTestSandbox::with_access_log();
    // Create nested dirs a/b.
    let dir_a = sb.fuse_mkdir_root("a").unwrap();
    let dir_b = sb.fuse_mkdir(dir_a.inode, "b", 0o755).unwrap();
    // Create file a/b/c via mknod (bypass access hook for create).
    let mode = libc::S_IFREG as u32 | 0o644;
    let entry = sb
        .fs
        .mknod(
            ProxyFsTestSandbox::ctx(),
            dir_b.inode,
            &ProxyFsTestSandbox::cstr("c"),
            mode,
            0,
            0,
            Extensions::default(),
        )
        .unwrap();
    // Lookup to register path.
    let _ = sb.lookup(dir_b.inode, "c").unwrap();

    sb.access_log.lock().unwrap().clear();

    // Open the file.
    let (handle, _opts) = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    sb.fs
        .release(
            ProxyFsTestSandbox::ctx(),
            entry.inode,
            0,
            handle.unwrap(),
            false,
            false,
            None,
        )
        .unwrap();

    let log = sb.access_log.lock().unwrap();
    assert!(
        log.iter().any(|(path, _)| path == "a/b/c"),
        "access hook should receive path 'a/b/c', got: {:?}",
        log.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn test_access_fuse_access_not_hooked() {
    let sb = ProxyFsTestSandbox::with_access_log();
    sb.access_log.lock().unwrap().clear();
    // FUSE access() should delegate directly without calling on_access.
    let result = sb
        .fs
        .access(ProxyFsTestSandbox::ctx(), ROOT_INODE, libc::F_OK as u32);
    assert!(result.is_ok());
    let log = sb.access_log.lock().unwrap();
    assert!(
        log.is_empty(),
        "FUSE access() should not call on_access hook, got: {:?}",
        *log
    );
}
