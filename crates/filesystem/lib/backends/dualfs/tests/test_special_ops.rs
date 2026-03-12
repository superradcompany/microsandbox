use super::*;

#[test]
fn test_fsync() {
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("sync.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    let result = sb.fs.fsync(DualFsTestSandbox::ctx(), entry.inode, false, handle);
    assert!(result.is_ok(), "fsync should succeed");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_fsync_handle_bound_dispatch() {
    // Create file on backend_b, open read-only -> handle bound to backend_b.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_sync.txt", b"data");
    });
    let entry = sb.lookup_root("b_sync.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    // fsync should dispatch to backend_b (handle-bound).
    let result = sb.fs.fsync(DualFsTestSandbox::ctx(), entry.inode, false, handle);
    assert!(result.is_ok(), "fsync on backend_b handle should succeed");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_fallocate() {
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("alloc.txt").unwrap();
    sb.fs
        .fallocate(DualFsTestSandbox::ctx(), entry.inode, handle, 0, 0, 1024)
        .unwrap();
    let (st, _) = sb
        .fs
        .getattr(DualFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    assert!(st.st_size >= 1024, "file size should be at least 1024 after fallocate");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_lseek() {
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("seek.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"hello", 0).unwrap();
    // SEEK_SET = 0
    let offset = sb
        .fs
        .lseek(DualFsTestSandbox::ctx(), entry.inode, handle, 0, 0)
        .unwrap();
    assert_eq!(offset, 0);
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_statfs_merges() {
    let sb = DualFsTestSandbox::new();
    let st = sb.fs.statfs(DualFsTestSandbox::ctx(), ROOT_INODE).unwrap();
    // Both backends are MemFs, so merged statfs should have positive values.
    assert!(st.f_bsize > 0, "block size should be positive");
    assert!(st.f_frsize > 0, "fragment size should be positive");
    assert!(st.f_namemax > 0, "namemax should be positive");
    // On Linux, blocks/files are u64 and large enough.
    // On macOS, MemFs uses `as u32` which overflows for large capacities.
    #[cfg(target_os = "linux")]
    {
        assert!(st.f_blocks > 0, "total blocks should be positive");
        assert!(st.f_files > 0, "total files should be positive");
    }
}

#[test]
fn test_statfs_saturating() {
    // Both MemFs backends return their statfs. Merging should not overflow.
    // Since both are default MemFs, they have normal values. Just verify no panic.
    let sb = DualFsTestSandbox::new();
    let st = sb.fs.statfs(DualFsTestSandbox::ctx(), ROOT_INODE).unwrap();
    // Verify the fields are reasonable (no overflow to very small or negative).
    assert!(st.f_bsize > 0, "bsize should be positive");
    assert!(st.f_frsize > 0, "frsize should be positive");
}

#[test]
fn test_statfs_policy_independent() {
    // statfs always merges both backends regardless of policy.
    let sb = DualFsTestSandbox::with_policy(BackendAOnly);
    let st = sb.fs.statfs(DualFsTestSandbox::ctx(), ROOT_INODE).unwrap();
    assert!(st.f_bsize > 0, "statfs should work even with BackendAOnly policy");
    assert!(st.f_frsize > 0, "fragment size should be positive");
    #[cfg(target_os = "linux")]
    assert!(st.f_blocks > 0, "merged blocks should be positive");
}
