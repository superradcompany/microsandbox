use super::*;

#[test]
fn test_read_via_handle_after_unlink() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("doomed.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"still here", 0)
        .unwrap();

    // Unlink the file — name is gone but handle keeps data alive.
    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("doomed.txt"))
        .unwrap();

    // Lookup should fail — name is removed.
    let result = sb.lookup_root("doomed.txt");
    TestSandbox::assert_errno(result, LINUX_ENOENT);

    // Read via existing handle should still work.
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(
        &data[..],
        b"still here",
        "data should be readable after unlink via open handle"
    );
}

#[test]
fn test_write_via_handle_after_unlink() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("doomed_write.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"before", 0).unwrap();

    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("doomed_write.txt"))
        .unwrap();

    // Write via existing handle should still work.
    sb.fuse_write(entry.inode, handle, b"after!", 0).unwrap();

    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(
        &data[..],
        b"after!",
        "data should be writable after unlink via open handle"
    );
}

#[test]
fn test_open_inode_after_unlink() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("reopen.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"reopen data", 0)
        .unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    // Bump refcount so inode stays in the table after unlink.
    // (The create gave refcount=1; we need the inode alive after unlink.)
    let _ = sb.lookup_root("reopen.txt").unwrap(); // refcount=2

    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("reopen.txt"))
        .unwrap();

    // Open the inode by number (macOS uses unlinked_fd, Linux uses /proc/self/fd).
    let handle2 = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle2, 1024, 0).unwrap();
    assert_eq!(
        &data[..],
        b"reopen data",
        "should be able to open inode after unlink"
    );
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle2, false, false, None)
        .unwrap();
}

#[test]
fn test_release_after_unlink() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("release_unlink.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();

    sb.fs
        .unlink(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("release_unlink.txt"),
        )
        .unwrap();

    // Release should succeed even after unlink.
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    // Handle is now gone — reading should fail.
    let result = sb.fuse_read(entry.inode, handle, 1024, 0);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_flush_after_unlink() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("flush_unlink.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();

    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("flush_unlink.txt"))
        .unwrap();

    // Flush should succeed — it dup+closes the fd.
    let result = sb.fs.flush(sb.ctx(), entry.inode, handle, 0);
    assert!(result.is_ok(), "flush should succeed after unlink");
}
