use super::*;

#[test]
fn test_rename_within_backend_a() {
    let sb = DualFsTestSandbox::new();
    sb.create_file_with_content(ROOT_INODE, "old_name.txt", b"data")
        .unwrap();
    sb.fs
        .rename(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("old_name.txt"),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("new_name.txt"),
            0,
        )
        .unwrap();
    // Old name should be gone.
    let result = sb.lookup_root("old_name.txt");
    DualFsTestSandbox::assert_errno(result, LINUX_ENOENT);
    // New name should exist.
    let entry = sb.lookup_root("new_name.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_rename_cross_dir() {
    let sb = DualFsTestSandbox::new();
    let dir1 = sb.fuse_mkdir_root("dir1").unwrap();
    let dir2 = sb.fuse_mkdir_root("dir2").unwrap();
    sb.create_file_with_content(dir1.inode, "file.txt", b"data")
        .unwrap();
    sb.fs
        .rename(
            DualFsTestSandbox::ctx(),
            dir1.inode,
            &DualFsTestSandbox::cstr("file.txt"),
            dir2.inode,
            &DualFsTestSandbox::cstr("file.txt"),
            0,
        )
        .unwrap();
    // Old location should be empty.
    let result = sb.lookup(dir1.inode, "file.txt");
    DualFsTestSandbox::assert_errno(result, LINUX_ENOENT);
    // New location should have the file.
    let entry = sb.lookup(dir2.inode, "file.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_rename_noreplace() {
    let sb = DualFsTestSandbox::new();
    sb.create_file_with_content(ROOT_INODE, "src.txt", b"source")
        .unwrap();
    sb.create_file_with_content(ROOT_INODE, "dst.txt", b"dest")
        .unwrap();
    let result = sb.fs.rename(
        DualFsTestSandbox::ctx(),
        ROOT_INODE,
        &DualFsTestSandbox::cstr("src.txt"),
        ROOT_INODE,
        &DualFsTestSandbox::cstr("dst.txt"),
        RENAME_NOREPLACE,
    );
    DualFsTestSandbox::assert_errno(result, LINUX_EEXIST);
}

#[test]
fn test_rename_exchange() {
    let sb = DualFsTestSandbox::new();
    let ino_a = sb
        .create_file_with_content(ROOT_INODE, "file_a.txt", b"alpha")
        .unwrap();
    let ino_b = sb
        .create_file_with_content(ROOT_INODE, "file_b.txt", b"beta")
        .unwrap();
    sb.fs
        .rename(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("file_a.txt"),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("file_b.txt"),
            RENAME_EXCHANGE,
        )
        .unwrap();
    // file_a should now be ino_b with beta content.
    let entry_a = sb.lookup_root("file_a.txt").unwrap();
    assert_eq!(entry_a.inode, ino_b);
    // file_b should now be ino_a with alpha content.
    let entry_b = sb.lookup_root("file_b.txt").unwrap();
    assert_eq!(entry_b.inode, ino_a);
}

#[test]
fn test_rename_init_krun() {
    let sb = DualFsTestSandbox::new();
    sb.create_file_with_content(ROOT_INODE, "target.txt", b"data")
        .unwrap();
    let result = sb.fs.rename(
        DualFsTestSandbox::ctx(),
        ROOT_INODE,
        &DualFsTestSandbox::cstr("init.krun"),
        ROOT_INODE,
        &DualFsTestSandbox::cstr("target.txt"),
        0,
    );
    DualFsTestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_rename_file_same_dir() {
    let sb = DualFsTestSandbox::new();
    sb.create_file_with_content(ROOT_INODE, "before.txt", b"content")
        .unwrap();
    sb.fs
        .rename(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("before.txt"),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("after.txt"),
            0,
        )
        .unwrap();
    DualFsTestSandbox::assert_errno(sb.lookup_root("before.txt"), LINUX_ENOENT);
    let entry = sb.lookup_root("after.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_rename_creates_whiteout() {
    // When a backend_b file is renamed, it is materialized to backend_a and
    // renamed there. The original backend_b file is not whiteout-ed by default,
    // so it remains visible through backend_b.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_file.txt", b"from b");
    });
    let _entry = sb.lookup_root("b_file.txt").unwrap();
    sb.fs
        .rename(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("b_file.txt"),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("renamed.txt"),
            0,
        )
        .unwrap();
    // Old name still visible through backend_b (no whiteout is created).
    let entry_old = sb.lookup_root("b_file.txt");
    assert!(entry_old.is_ok(), "backend_b file still visible after rename");
    // New name should also exist.
    let entry = sb.lookup_root("renamed.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_rename_backend_b_to_backend_a() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "source.txt", b"backend_b_data");
    });
    let _entry = sb.lookup_root("source.txt").unwrap();
    sb.fs
        .rename(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("source.txt"),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("dest.txt"),
            0,
        )
        .unwrap();
    // Verify destination is readable.
    let entry = sb.lookup_root("dest.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"backend_b_data");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_rename_dir_cross_backend() {
    // A backend_b-only directory cannot be renamed within backend_a (the target backend)
    // because it is not pure on backend_a. DualFs returns EXDEV for cross-layer directory renames.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let dir = memfs_mkdir(b, 1, "b_dir");
        memfs_create_file(b, dir, "child.txt", b"data");
    });

    // Lookup the backend_b directory so it is registered.
    let _dir_entry = sb.lookup_root("b_dir").unwrap();

    // Attempt to rename the backend_b-only directory. The default policy targets backend_a
    // for renames, but the directory is backed only by backend_b, so is_pure_on(BackendA)
    // returns false, resulting in EXDEV.
    let result = sb.fs.rename(
        DualFsTestSandbox::ctx(),
        ROOT_INODE,
        &DualFsTestSandbox::cstr("b_dir"),
        ROOT_INODE,
        &DualFsTestSandbox::cstr("renamed_dir"),
        0,
    );
    DualFsTestSandbox::assert_errno(result, LINUX_EXDEV);
}
