use super::*;

#[test]
fn test_fsync() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("sync.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    let result = sb.fs.fsync(sb.ctx(), entry.inode, false, handle);
    assert!(result.is_ok());
}

#[test]
fn test_fsync_datasync() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("dsync.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    let result = sb.fs.fsync(sb.ctx(), entry.inode, true, handle);
    assert!(result.is_ok());
}

#[test]
fn test_fsync_invalid_handle() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let result = sb.fs.fsync(sb.ctx(), entry.inode, false, 99999);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_fsync_init_noop() {
    let sb = TestSandbox::new();
    let result = sb.fs.fsync(sb.ctx(), INIT_INODE, false, INIT_HANDLE);
    assert!(result.is_ok());
}

#[test]
fn test_fsyncdir() {
    let sb = TestSandbox::new();
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let result = sb.fs.fsyncdir(sb.ctx(), ROOT_INODE, false, handle);
    assert!(result.is_ok());
}

#[test]
fn test_fallocate() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("alloc.txt").unwrap();
    sb.fs
        .fallocate(sb.ctx(), entry.inode, handle, 0, 0, 4096)
        .unwrap();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert!(
        st.st_size >= 4096,
        "file should be at least 4096 bytes after fallocate"
    );
}

#[test]
fn test_fallocate_init_rejected() {
    let sb = TestSandbox::new();
    let result = sb
        .fs
        .fallocate(sb.ctx(), INIT_INODE, INIT_HANDLE, 0, 0, 4096);
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_fallocate_invalid_handle() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let result = sb.fs.fallocate(sb.ctx(), entry.inode, 99999, 0, 0, 4096);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[cfg(target_os = "macos")]
#[test]
fn test_fallocate_nonzero_mode_unsupported() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("alloc_mode.txt").unwrap();
    let result = sb.fs.fallocate(sb.ctx(), entry.inode, handle, 1, 0, 4096);
    TestSandbox::assert_errno(result, LINUX_EOPNOTSUPP);
}

#[cfg(target_os = "macos")]
#[test]
fn test_fallocate_overflow_rejected() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("alloc_overflow.txt").unwrap();
    let result = sb
        .fs
        .fallocate(sb.ctx(), entry.inode, handle, 0, u64::MAX, 1);
    TestSandbox::assert_errno(result, LINUX_EOVERFLOW);
}

#[test]
fn test_lseek_set() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("seek.txt").unwrap();
    sb.fuse_write(entry.inode, handle, &[0u8; 100], 0).unwrap();
    let offset = sb
        .fs
        .lseek(sb.ctx(), entry.inode, handle, 5, libc::SEEK_SET as u32)
        .unwrap();
    assert_eq!(offset, 5);
}

#[test]
fn test_lseek_end() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("seek.txt").unwrap();
    let data = [0u8; 50];
    sb.fuse_write(entry.inode, handle, &data, 0).unwrap();
    let offset = sb
        .fs
        .lseek(sb.ctx(), entry.inode, handle, 0, libc::SEEK_END as u32)
        .unwrap();
    assert_eq!(offset, 50);
}

#[test]
fn test_lseek_init_rejected() {
    let sb = TestSandbox::new();
    let result = sb
        .fs
        .lseek(sb.ctx(), INIT_INODE, INIT_HANDLE, 0, libc::SEEK_SET as u32);
    TestSandbox::assert_errno(result, LINUX_ENOSYS);
}

#[test]
fn test_lseek_invalid_handle() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let result = sb
        .fs
        .lseek(sb.ctx(), entry.inode, 99999, 0, libc::SEEK_SET as u32);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_statfs_root() {
    let sb = TestSandbox::new();
    let st = sb.fs.statfs(sb.ctx(), ROOT_INODE).unwrap();
    assert!(st.f_bsize > 0, "block size should be positive");
}

#[test]
fn test_statfs_init() {
    let sb = TestSandbox::new();
    let st = sb.fs.statfs(sb.ctx(), INIT_INODE).unwrap();
    assert!(st.f_bsize > 0);
}

#[test]
fn test_statfs_file() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("statfs.txt").unwrap();
    let st = sb.fs.statfs(sb.ctx(), entry.inode).unwrap();
    assert!(st.f_bsize > 0);
}

#[test]
fn test_copyfilerange_init_in_rejected() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("dst.txt").unwrap();
    let result = sb.fs.copyfilerange(
        sb.ctx(),
        INIT_INODE,
        INIT_HANDLE,
        0,
        entry.inode,
        handle,
        0,
        100,
        0,
    );
    TestSandbox::assert_errno(result, LINUX_ENOSYS);
}

#[test]
fn test_copyfilerange_init_out_rejected() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("src.txt").unwrap();
    let result = sb.fs.copyfilerange(
        sb.ctx(),
        entry.inode,
        handle,
        0,
        INIT_INODE,
        INIT_HANDLE,
        0,
        100,
        0,
    );
    TestSandbox::assert_errno(result, LINUX_ENOSYS);
}

/// On Linux: copies data via copy_file_range(2) and verifies contents.
/// On macOS: returns ENOSYS (guest kernel falls back to read+write).
#[test]
fn test_copyfilerange_basic() {
    let sb = TestSandbox::new();
    let (src_entry, src_handle) = sb.fuse_create_root("copy_src.txt").unwrap();
    let (dst_entry, dst_handle) = sb.fuse_create_root("copy_dst.txt").unwrap();
    sb.fuse_write(src_entry.inode, src_handle, b"copy this data", 0)
        .unwrap();

    let result = sb.fs.copyfilerange(
        sb.ctx(),
        src_entry.inode,
        src_handle,
        0,
        dst_entry.inode,
        dst_handle,
        0,
        14,
        0,
    );

    #[cfg(target_os = "linux")]
    {
        let copied = result.unwrap();
        assert_eq!(copied, 14);
        let data = sb.fuse_read(dst_entry.inode, dst_handle, 1024, 0).unwrap();
        assert_eq!(&data[..], b"copy this data");
    }

    #[cfg(target_os = "macos")]
    TestSandbox::assert_errno(result, LINUX_ENOSYS);
}

/// On Linux: invalid out-handle returns EBADF.
/// On macOS: returns ENOSYS before handle lookup.
#[test]
fn test_copyfilerange_invalid_handle() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("src.txt").unwrap();
    let result = sb.fs.copyfilerange(
        sb.ctx(),
        entry.inode,
        handle,
        0,
        entry.inode,
        99999,
        0,
        100,
        0,
    );

    #[cfg(target_os = "linux")]
    TestSandbox::assert_errno(result, LINUX_EBADF);

    #[cfg(target_os = "macos")]
    TestSandbox::assert_errno(result, LINUX_ENOSYS);
}

/// On Linux: copies from a source offset.
/// On macOS: returns ENOSYS.
#[test]
fn test_copyfilerange_with_offset() {
    let sb = TestSandbox::new();
    let (src_entry, src_handle) = sb.fuse_create_root("off_src.txt").unwrap();
    let (dst_entry, dst_handle) = sb.fuse_create_root("off_dst.txt").unwrap();
    sb.fuse_write(src_entry.inode, src_handle, b"hello world", 0)
        .unwrap();

    let result = sb.fs.copyfilerange(
        sb.ctx(),
        src_entry.inode,
        src_handle,
        6,
        dst_entry.inode,
        dst_handle,
        0,
        5,
        0,
    );

    #[cfg(target_os = "linux")]
    {
        let copied = result.unwrap();
        assert_eq!(copied, 5);
        let data = sb.fuse_read(dst_entry.inode, dst_handle, 1024, 0).unwrap();
        assert_eq!(&data[..], b"world");
    }

    #[cfg(target_os = "macos")]
    TestSandbox::assert_errno(result, LINUX_ENOSYS);
}
