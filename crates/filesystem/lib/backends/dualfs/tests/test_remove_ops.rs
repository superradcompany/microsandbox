use super::*;

#[test]
fn test_unlink_backend_a_file() {
    let sb = DualFsTestSandbox::new();
    sb.create_file_with_content(ROOT_INODE, "a_file.txt", b"data")
        .unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("a_file.txt"),
        )
        .unwrap();
    let result = sb.lookup_root("a_file.txt");
    DualFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_unlink_backend_b_file_creates_whiteout() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_file.txt", b"data");
    });
    // Lookup to register.
    let _entry = sb.lookup_root("b_file.txt").unwrap();
    // Unlink should create a whiteout.
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("b_file.txt"),
        )
        .unwrap();
    // Lookup should now fail.
    let result = sb.lookup_root("b_file.txt");
    DualFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_rmdir_empty_backend_a() {
    let sb = DualFsTestSandbox::new();
    sb.fuse_mkdir_root("empty_dir").unwrap();
    sb.fs
        .rmdir(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("empty_dir"),
        )
        .unwrap();
    let result = sb.lookup_root("empty_dir");
    DualFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_rmdir_nonempty() {
    let sb = DualFsTestSandbox::new();
    let dir = sb.fuse_mkdir_root("nonempty_dir").unwrap();
    sb.create_file_with_content(dir.inode, "child.txt", b"data")
        .unwrap();
    let result = sb.fs.rmdir(
        DualFsTestSandbox::ctx(),
        ROOT_INODE,
        &DualFsTestSandbox::cstr("nonempty_dir"),
    );
    DualFsTestSandbox::assert_errno(result, libc::ENOTEMPTY);
}

#[test]
fn test_unlink_nonexistent() {
    let sb = DualFsTestSandbox::new();
    let result = sb.fs.unlink(
        DualFsTestSandbox::ctx(),
        ROOT_INODE,
        &DualFsTestSandbox::cstr("no_such_file"),
    );
    DualFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_unlink_init_krun() {
    let sb = DualFsTestSandbox::new();
    let result = sb.fs.unlink(
        DualFsTestSandbox::ctx(),
        ROOT_INODE,
        &DualFsTestSandbox::cstr("init.krun"),
    );
    DualFsTestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_unlink_merged_file() {
    // File exists in backend_b and is materialized to backend_a via write.
    // After materialization, the node state becomes BackendA.
    // Unlink removes the file from backend_a.
    // On re-lookup, the file reappears via backend_b — but because the
    // materialization wrote modified data through the backend_a copy,
    // the content seen after re-lookup reflects the materialized data.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "merged.txt", b"original");
    });
    let entry = sb.lookup_root("merged.txt").unwrap();
    // Open for write -> triggers materialization to backend_a.
    let handle = sb.fuse_open(entry.inode, libc::O_RDWR as u32).unwrap();
    sb.fuse_write(entry.inode, handle, b"modified", 0).unwrap();
    sb.fs
        .release(
            DualFsTestSandbox::ctx(),
            entry.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
    // Unlink — removes backend_a copy.
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("merged.txt"),
        )
        .unwrap();
    // File reappears via backend_b.
    let entry2 = sb.lookup_root("merged.txt").unwrap();
    assert!(entry2.inode >= 3);
    let handle = sb.fuse_open(entry2.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry2.inode, handle, 4096, 0).unwrap();
    // Content reflects materialized data since the node maps through backend dispatch.
    assert_eq!(&data[..], b"modified");
    sb.fs
        .release(
            DualFsTestSandbox::ctx(),
            entry2.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
}

#[test]
fn test_rmdir_empty_backend_b() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_mkdir(b, 1, "b_dir");
    });
    let _entry = sb.lookup_root("b_dir").unwrap();
    // Rmdir should create a whiteout.
    sb.fs
        .rmdir(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("b_dir"),
        )
        .unwrap();
    let result = sb.lookup_root("b_dir");
    DualFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}
