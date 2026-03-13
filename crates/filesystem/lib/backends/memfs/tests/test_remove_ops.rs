use super::*;

#[test]
fn test_unlink_file() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("doomed.txt").unwrap();
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
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("doomed.txt"),
        )
        .unwrap();
    let result = sb.lookup_root("doomed.txt");
    MemFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_unlink_nonexistent() {
    let sb = MemFsTestSandbox::new();
    let result = sb.fs.unlink(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("ghost.txt"),
    );
    MemFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_unlink_decrements_nlink() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("linked.txt").unwrap();
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

    // Create a hard link.
    sb.fs
        .link(
            MemFsTestSandbox::ctx(),
            entry.inode,
            ROOT_INODE,
            &MemFsTestSandbox::cstr("linked2.txt"),
        )
        .unwrap();

    // nlink should be 2.
    let (st, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(st.st_nlink, 2);
    #[cfg(target_os = "macos")]
    assert_eq!(st.st_nlink, 2);

    // Unlink one.
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("linked.txt"),
        )
        .unwrap();

    // nlink should be 1.
    let (st, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(st.st_nlink, 1);
    #[cfg(target_os = "macos")]
    assert_eq!(st.st_nlink, 1);
}

#[test]
fn test_unlink_last_link() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("last.txt").unwrap();
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
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("last.txt"),
        )
        .unwrap();
    // Forget the lookup ref from create.
    sb.fs.forget(MemFsTestSandbox::ctx(), entry.inode, 1);
    // Node should be evicted: getattr should fail.
    let result = sb.fs.getattr(MemFsTestSandbox::ctx(), entry.inode, None);
    assert!(result.is_err());
}

#[test]
fn test_unlink_open_file() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("open_unlink.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"still here", 0)
        .unwrap();

    // Unlink while handle is still open.
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("open_unlink.txt"),
        )
        .unwrap();

    // Handle should still work.
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"still here");

    // Clean up.
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
}

#[test]
fn test_rmdir_empty() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_mkdir_root("empty_dir").unwrap();
    sb.fs
        .rmdir(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("empty_dir"),
        )
        .unwrap();
    let result = sb.lookup_root("empty_dir");
    MemFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_rmdir_nonempty() {
    let sb = MemFsTestSandbox::new();
    let dir = sb.fuse_mkdir_root("full_dir").unwrap();
    sb.fuse_create(dir.inode, "child.txt", 0o644).unwrap();
    let result = sb.fs.rmdir(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("full_dir"),
    );
    MemFsTestSandbox::assert_errno(result, LINUX_ENOTEMPTY);
}

#[test]
fn test_rmdir_file() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_create_root("not_a_dir.txt").unwrap();
    let result = sb.fs.rmdir(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("not_a_dir.txt"),
    );
    // rmdir on a non-directory returns ENOTDIR (Linux errno 20).
    assert!(result.is_err());
}

#[test]
fn test_rmdir_decrements_parent_nlink() {
    let sb = MemFsTestSandbox::new();
    let (st_before, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), ROOT_INODE, None)
        .unwrap();
    let nlink_before = st_before.st_nlink;

    sb.fuse_mkdir_root("child_dir").unwrap();
    let (st_mid, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), ROOT_INODE, None)
        .unwrap();
    assert_eq!(st_mid.st_nlink, nlink_before + 1);

    sb.fs
        .rmdir(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("child_dir"),
        )
        .unwrap();
    let (st_after, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), ROOT_INODE, None)
        .unwrap();
    assert_eq!(st_after.st_nlink, nlink_before);
}

#[test]
fn test_unlink_traversal() {
    let sb = MemFsTestSandbox::new();
    let result = sb.fs.unlink(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr(".."),
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EPERM);
}
