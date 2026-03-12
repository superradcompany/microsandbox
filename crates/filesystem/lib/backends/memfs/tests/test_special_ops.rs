use super::*;

#[test]
fn test_fsync() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("fsync.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    let result = sb
        .fs
        .fsync(MemFsTestSandbox::ctx(), entry.inode, false, handle);
    assert!(result.is_ok());
}

#[test]
fn test_fsyncdir() {
    let sb = MemFsTestSandbox::new();
    let (handle, _) = sb.fuse_opendir(ROOT_INODE).unwrap();
    let handle = handle.unwrap();
    let result = sb
        .fs
        .fsyncdir(MemFsTestSandbox::ctx(), ROOT_INODE, false, handle);
    assert!(result.is_ok());
    sb.fs
        .releasedir(MemFsTestSandbox::ctx(), ROOT_INODE, 0, handle)
        .unwrap();
}

#[test]
fn test_fallocate_extend() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("falloc.txt").unwrap();
    let handle = handle.unwrap();
    // Extend file to 1000 bytes via fallocate.
    sb.fs
        .fallocate(MemFsTestSandbox::ctx(), entry.inode, handle, 0, 0, 1000)
        .unwrap();
    let (st, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    assert_eq!(st.st_size, 1000);
}

#[test]
fn test_fallocate_within_size() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("falloc_noop.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"hello world", 0).unwrap();
    // fallocate within existing size should be a no-op.
    sb.fs
        .fallocate(MemFsTestSandbox::ctx(), entry.inode, handle, 0, 0, 5)
        .unwrap();
    let (st, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    assert_eq!(st.st_size, 11); // Size unchanged.
}

#[test]
fn test_lseek_data() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("lseek_data.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"some data here", 0).unwrap();
    // SEEK_DATA from offset 0 should return 0 (data starts at beginning).
    let pos = sb
        .fs
        .lseek(MemFsTestSandbox::ctx(), entry.inode, handle, 0, 3) // SEEK_DATA = 3
        .unwrap();
    assert_eq!(pos, 0);
}

#[test]
fn test_lseek_hole() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("lseek_hole.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"file content", 0).unwrap();
    // SEEK_HOLE from offset 0 should return file size.
    let pos = sb
        .fs
        .lseek(MemFsTestSandbox::ctx(), entry.inode, handle, 0, 4) // SEEK_HOLE = 4
        .unwrap();
    assert_eq!(pos, 12); // "file content" is 12 bytes.
}

#[test]
fn test_statfs() {
    let sb = MemFsTestSandbox::new();
    let st = sb
        .fs
        .statfs(MemFsTestSandbox::ctx(), ROOT_INODE)
        .unwrap();
    assert!(st.f_bsize > 0);
    assert!(st.f_namemax > 0);
}

#[test]
fn test_statfs_capacity() {
    let sb = MemFsTestSandbox::with_capacity(1024 * 1024); // 1MB
    sb.create_file_with_content(ROOT_INODE, "some.txt", &[0u8; 4096]).unwrap();
    let st = sb
        .fs
        .statfs(MemFsTestSandbox::ctx(), ROOT_INODE)
        .unwrap();
    // Free blocks should be less than total blocks.
    assert!(st.f_bfree < st.f_blocks);
}
