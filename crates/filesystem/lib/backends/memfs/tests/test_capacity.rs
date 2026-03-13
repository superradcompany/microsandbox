use std::sync::atomic::Ordering;

use super::*;

#[test]
fn test_capacity_write_within_limit() {
    let sb = MemFsTestSandbox::with_capacity(1024);
    let (entry, handle) = sb.fuse_create_root("within.txt").unwrap();
    let handle = handle.unwrap();
    let result = sb.fuse_write(entry.inode, handle, &[0u8; 512], 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 512);
}

#[test]
fn test_capacity_write_exceeds_limit() {
    let sb = MemFsTestSandbox::with_capacity(100);
    let (entry, handle) = sb.fuse_create_root("overflow.txt").unwrap();
    let handle = handle.unwrap();
    let result = sb.fuse_write(entry.inode, handle, &[0u8; 200], 0);
    MemFsTestSandbox::assert_errno(result, LINUX_ENOSPC);
}

#[test]
fn test_capacity_truncate_reclaims() {
    let sb = MemFsTestSandbox::with_capacity(1024);
    let ino = sb
        .create_file_with_content(ROOT_INODE, "trunc_cap.txt", &[0u8; 512])
        .unwrap();

    let used_before = sb.fs.used_bytes.load(Ordering::Relaxed);
    assert_eq!(used_before, 512);

    // Truncate to 0.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 0;
    sb.fs
        .setattr(MemFsTestSandbox::ctx(), ino, attr, None, SetattrValid::SIZE)
        .unwrap();

    let used_after = sb.fs.used_bytes.load(Ordering::Relaxed);
    assert_eq!(used_after, 0);
}

#[test]
fn test_capacity_unlink_reclaims() {
    let sb = MemFsTestSandbox::with_capacity(1024);
    let ino = sb
        .create_file_with_content(ROOT_INODE, "unlink_cap.txt", &[0u8; 512])
        .unwrap();

    // Unlink the file.
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("unlink_cap.txt"),
        )
        .unwrap();
    // Forget lookup ref from create.
    sb.fs.forget(MemFsTestSandbox::ctx(), ino, 1);

    let used_after = sb.fs.used_bytes.load(Ordering::Relaxed);
    assert_eq!(used_after, 0);
}

#[test]
fn test_capacity_unlink_open_file() {
    let sb = MemFsTestSandbox::with_capacity(1024);
    let (entry, handle) = sb.fuse_create_root("open_cap.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, &[0u8; 512], 0).unwrap();

    // Unlink while handle is open.
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("open_cap.txt"),
        )
        .unwrap();
    // Forget lookup ref.
    sb.fs.forget(MemFsTestSandbox::ctx(), entry.inode, 1);

    // Bytes should still be charged (handle keeps node alive).
    let used_mid = sb.fs.used_bytes.load(Ordering::Relaxed);
    assert_eq!(used_mid, 512);

    // Release handle.
    sb.fs
        .release(
            MemFsTestSandbox::ctx(),
            entry.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();

    // Now bytes should be freed.
    let used_after = sb.fs.used_bytes.load(Ordering::Relaxed);
    assert_eq!(used_after, 0);
}

#[test]
fn test_capacity_multiple_files() {
    let sb = MemFsTestSandbox::with_capacity(1024);
    sb.create_file_with_content(ROOT_INODE, "a.txt", &[0u8; 256])
        .unwrap();
    sb.create_file_with_content(ROOT_INODE, "b.txt", &[0u8; 256])
        .unwrap();
    sb.create_file_with_content(ROOT_INODE, "c.txt", &[0u8; 256])
        .unwrap();

    let used = sb.fs.used_bytes.load(Ordering::Relaxed);
    assert_eq!(used, 768);

    // Fourth file that would exceed capacity.
    let (entry, handle) = sb.fuse_create_root("d.txt").unwrap();
    let handle = handle.unwrap();
    let result = sb.fuse_write(entry.inode, handle, &[0u8; 300], 0);
    MemFsTestSandbox::assert_errno(result, LINUX_ENOSPC);
}

#[test]
fn test_inode_limit_create() {
    // max_inodes=3 means root(1) + 2 more inodes allowed.
    let sb = MemFsTestSandbox::with_max_inodes(3);
    // Root already uses 1 inode.
    sb.fuse_create_root("first.txt").unwrap();
    sb.fuse_create_root("second.txt").unwrap();
    // Third create should fail (1 root + 2 files = 3, at limit).
    let result = sb.fuse_create_root("third.txt");
    MemFsTestSandbox::assert_errno(result, LINUX_ENOSPC);
}

#[test]
fn test_inode_limit_unlink_reclaims() {
    let sb = MemFsTestSandbox::with_max_inodes(3);
    let (entry, handle) = sb.fuse_create_root("temp.txt").unwrap();
    let handle = handle.unwrap();
    sb.fs
        .release(
            MemFsTestSandbox::ctx(),
            entry.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
    sb.fuse_create_root("temp2.txt").unwrap();

    // At limit now. Unlink one to free a slot.
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("temp.txt"),
        )
        .unwrap();
    // Forget lookup ref.
    sb.fs.forget(MemFsTestSandbox::ctx(), entry.inode, 1);

    // Should be able to create one more.
    let result = sb.fuse_create_root("reused.txt");
    assert!(result.is_ok());
}

#[test]
fn test_capacity_sparse_write() {
    let sb = MemFsTestSandbox::with_capacity(2048);
    let (entry, handle) = sb.fuse_create_root("sparse_cap.txt").unwrap();
    let handle = handle.unwrap();
    // Write at offset 1000 with 4 bytes. This creates 1004 bytes total (zero-filled gap).
    sb.fuse_write(entry.inode, handle, b"data", 1000).unwrap();
    let used = sb.fs.used_bytes.load(Ordering::Relaxed);
    assert_eq!(used, 1004);
}
