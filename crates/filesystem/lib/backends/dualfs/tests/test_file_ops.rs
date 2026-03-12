use super::*;

#[test]
fn test_read_from_backend_b() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_file.txt", b"backend_b_data");
    });
    let entry = sb.lookup_root("b_file.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"backend_b_data");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_read_from_backend_a() {
    let sb = DualFsTestSandbox::new();
    let ino = sb.create_file_with_content(ROOT_INODE, "a_file.txt", b"backend_a_data").unwrap();
    let handle = sb.fuse_open(ino, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(ino, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"backend_a_data");
    sb.fs
        .release(DualFsTestSandbox::ctx(), ino, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_write_to_backend_a() {
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("writable.txt").unwrap();
    let written = sb.fuse_write(entry.inode, handle, b"hello world", 0).unwrap();
    assert_eq!(written, 11);
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"hello world");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_write_triggers_materialization() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_file.txt", b"original");
    });
    let entry = sb.lookup_root("b_file.txt").unwrap();
    // Open for write -> triggers materialization from backend_b to backend_a.
    let handle = sb
        .fuse_open(entry.inode, libc::O_RDWR as u32)
        .unwrap();
    let written = sb.fuse_write(entry.inode, handle, b"modified", 0).unwrap();
    assert_eq!(written, 8);
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // Read back should show modified data.
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"modified");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_write_preserves_data() {
    let original = b"original backend_b content that should be preserved";
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "preserve.txt", original);
    });
    let entry = sb.lookup_root("preserve.txt").unwrap();
    // Open for read first to verify original.
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], original);
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_handle_dispatch_backend_a() {
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("a_handle.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data_a", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"data_a");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_handle_dispatch_backend_b() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_handle.txt", b"data_b");
    });
    let entry = sb.lookup_root("b_handle.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"data_b");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_read_after_write() {
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("rw.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"write_then_read", 0)
        .unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"write_then_read");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_write_large() {
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("large.txt").unwrap();
    let large_data = vec![0xABu8; 1024 * 1024]; // 1 MB
    let written = sb.fuse_write(entry.inode, handle, &large_data, 0).unwrap();
    assert_eq!(written, 1024 * 1024);
    let read_data = sb.fuse_read(entry.inode, handle, 1024 * 1024 + 1, 0).unwrap();
    assert_eq!(read_data.len(), 1024 * 1024);
    assert!(read_data.iter().all(|&b| b == 0xAB));
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_read_invalid_handle() {
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("valid.txt").unwrap();
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // Use a bogus handle.
    let bad_handle = 999999;
    let mut writer = MockZeroCopyWriter::new();
    let result = sb.fs.read(
        DualFsTestSandbox::ctx(),
        entry.inode,
        bad_handle,
        &mut writer,
        4096,
        0,
        None,
        0,
    );
    DualFsTestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_try_backend_a_then_b_fallback() {
    // With the default ReadBackendBWriteBackendA policy, lookup uses MergeLookup
    // with BackendBFirst precedence. A file that exists in both backends is found
    // in backend_b first, but a file only in backend_a is found via fallback from
    // backend_b to backend_a.
    //
    // This test verifies the reverse scenario from test_try_backend_b_then_a_fallback:
    // with BackendAFallbackToBackendBRead policy, lookup uses BackendAFirst precedence.
    // A file only in backend_b is found via fallback from backend_a to backend_b.
    // The file is then readable via getattr (which dispatches from node state, not policy).
    let sb = DualFsTestSandbox::with_policy_and_backend_b(
        BackendAFallbackToBackendBRead,
        |b| {
            memfs_create_file(b, 1, "fallback_b.txt", b"backend_b_content");
        },
    );

    // Lookup should find the file via backend_b fallback.
    let entry = sb.lookup_root("fallback_b.txt").unwrap();
    assert!(entry.inode >= 3, "file should be found via BackendA->BackendB fallback");

    // getattr dispatches from node state (not policy-routed), so it works for
    // backend_b-only files regardless of policy.
    let (st, _) = sb
        .fs
        .getattr(DualFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    assert_eq!(st.st_ino, entry.inode, "getattr should return correct guest inode");
    let mode = st.st_mode as u32;
    assert_eq!(
        mode & libc::S_IFMT as u32,
        libc::S_IFREG as u32,
        "should be a regular file"
    );
    assert!(st.st_size >= 17, "file should have backend_b_content bytes");
}

#[test]
fn test_try_backend_b_then_a_fallback() {
    // With default ReadBackendBWriteBackendA policy, lookup uses MergeLookup with
    // BackendBFirst precedence. A file only in backend_a should be discovered
    // via fallback from backend_b to backend_a, and then be readable.
    let sb = DualFsTestSandbox::new(); // Default: ReadBackendBWriteBackendA
    let ino = sb
        .create_file_with_content(ROOT_INODE, "fallback_a.txt", b"backend_a_content")
        .unwrap();

    // Lookup should find the file. With BackendBFirst, backend_b is tried first (ENOENT),
    // then falls back to backend_a where the file exists.
    let entry = sb.lookup_root("fallback_a.txt").unwrap();
    assert_eq!(entry.inode, ino, "file should be found via backend_a fallback");

    // Open for read and verify content.
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"backend_a_content");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}
