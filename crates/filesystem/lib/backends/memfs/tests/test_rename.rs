use super::*;

#[test]
fn test_rename_file_same_dir() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_create_root("old_name.txt").unwrap();
    sb.fs
        .rename(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("old_name.txt"),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("new_name.txt"),
            0,
        )
        .unwrap();
    let result = sb.lookup_root("old_name.txt");
    MemFsTestSandbox::assert_errno(result, LINUX_ENOENT);
    let entry = sb.lookup_root("new_name.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_rename_file_cross_dir() {
    let sb = MemFsTestSandbox::new();
    let dir_a = sb.fuse_mkdir_root("dir_a").unwrap();
    let dir_b = sb.fuse_mkdir_root("dir_b").unwrap();
    sb.fuse_create(dir_a.inode, "moveme.txt", 0o644).unwrap();
    sb.fs
        .rename(
            MemFsTestSandbox::ctx(),
            dir_a.inode,
            &MemFsTestSandbox::cstr("moveme.txt"),
            dir_b.inode,
            &MemFsTestSandbox::cstr("moveme.txt"),
            0,
        )
        .unwrap();
    let result = sb.lookup(dir_a.inode, "moveme.txt");
    MemFsTestSandbox::assert_errno(result, LINUX_ENOENT);
    let entry = sb.lookup(dir_b.inode, "moveme.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_rename_directory() {
    let sb = MemFsTestSandbox::new();
    let (st_before, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), ROOT_INODE, None)
        .unwrap();
    let nlink_before = st_before.st_nlink;

    sb.fuse_mkdir_root("old_dir").unwrap();
    sb.fs
        .rename(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("old_dir"),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("new_dir"),
            0,
        )
        .unwrap();
    let result = sb.lookup_root("old_dir");
    MemFsTestSandbox::assert_errno(result, LINUX_ENOENT);
    let entry = sb.lookup_root("new_dir").unwrap();
    assert!(entry.inode >= 3);

    // Same-dir rename of a dir doesn't change parent nlink.
    let (st_after, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), ROOT_INODE, None)
        .unwrap();
    assert_eq!(st_after.st_nlink, nlink_before + 1); // +1 from the mkdir
}

#[test]
fn test_rename_nonempty_dir() {
    let sb = MemFsTestSandbox::new();
    let dir = sb.fuse_mkdir_root("parent_dir").unwrap();
    sb.fuse_create(dir.inode, "child.txt", 0o644).unwrap();
    sb.fs
        .rename(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("parent_dir"),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("moved_dir"),
            0,
        )
        .unwrap();
    let moved = sb.lookup_root("moved_dir").unwrap();
    let child = sb.lookup(moved.inode, "child.txt").unwrap();
    assert!(child.inode >= 3);
}

#[test]
fn test_rename_replace_file() {
    let sb = MemFsTestSandbox::new();
    let ino_a = sb
        .create_file_with_content(ROOT_INODE, "a.txt", b"data_a")
        .unwrap();
    sb.create_file_with_content(ROOT_INODE, "b.txt", b"data_b")
        .unwrap();
    sb.fs
        .rename(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("a.txt"),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("b.txt"),
            0,
        )
        .unwrap();
    let result = sb.lookup_root("a.txt");
    MemFsTestSandbox::assert_errno(result, LINUX_ENOENT);
    let entry = sb.lookup_root("b.txt").unwrap();
    assert_eq!(entry.inode, ino_a);
    // Read data through a new handle to confirm it's a.txt's data.
    let (handle, _) = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"data_a");
}

#[test]
fn test_rename_replace_type_mismatch() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_create_root("file.txt").unwrap();
    sb.fuse_mkdir_root("dir").unwrap();
    let result = sb.fs.rename(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("file.txt"),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("dir"),
        0,
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EISDIR);
}

#[test]
fn test_rename_replace_nonempty_dir() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_mkdir_root("src_dir").unwrap();
    let dst_dir = sb.fuse_mkdir_root("dst_dir").unwrap();
    sb.fuse_create(dst_dir.inode, "occupant.txt", 0o644)
        .unwrap();
    let result = sb.fs.rename(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("src_dir"),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("dst_dir"),
        0,
    );
    MemFsTestSandbox::assert_errno(result, LINUX_ENOTEMPTY);
}

#[test]
fn test_rename_noreplace() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_create_root("exist.txt").unwrap();
    sb.fuse_create_root("also.txt").unwrap();
    let result = sb.fs.rename(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("exist.txt"),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("also.txt"),
        1, // RENAME_NOREPLACE
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EEXIST);
}

#[test]
fn test_rename_exchange() {
    let sb = MemFsTestSandbox::new();
    let ino_a = sb
        .create_file_with_content(ROOT_INODE, "swap_a.txt", b"data_a")
        .unwrap();
    let ino_b = sb
        .create_file_with_content(ROOT_INODE, "swap_b.txt", b"data_b")
        .unwrap();
    sb.fs
        .rename(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("swap_a.txt"),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("swap_b.txt"),
            2, // RENAME_EXCHANGE
        )
        .unwrap();

    // "swap_a.txt" should now be ino_b with data_b.
    let e_a = sb.lookup_root("swap_a.txt").unwrap();
    assert_eq!(e_a.inode, ino_b);
    let (h, _) = sb.fuse_open(e_a.inode, libc::O_RDONLY as u32).unwrap();
    let h = h.unwrap();
    let d = sb.fuse_read(e_a.inode, h, 1024, 0).unwrap();
    assert_eq!(&d[..], b"data_b");

    // "swap_b.txt" should now be ino_a with data_a.
    let e_b = sb.lookup_root("swap_b.txt").unwrap();
    assert_eq!(e_b.inode, ino_a);
    let (h, _) = sb.fuse_open(e_b.inode, libc::O_RDONLY as u32).unwrap();
    let h = h.unwrap();
    let d = sb.fuse_read(e_b.inode, h, 1024, 0).unwrap();
    assert_eq!(&d[..], b"data_a");
}

#[test]
fn test_rename_parent_update() {
    let sb = MemFsTestSandbox::new();
    let dir_a = sb.fuse_mkdir_root("from").unwrap();
    let dir_b = sb.fuse_mkdir_root("to").unwrap();
    let child_dir = sb.fuse_mkdir(dir_a.inode, "child_dir", 0o755).unwrap();

    sb.fs
        .rename(
            MemFsTestSandbox::ctx(),
            dir_a.inode,
            &MemFsTestSandbox::cstr("child_dir"),
            dir_b.inode,
            &MemFsTestSandbox::cstr("child_dir"),
            0,
        )
        .unwrap();

    // Verify child_dir is now under dir_b.
    let looked = sb.lookup(dir_b.inode, "child_dir").unwrap();
    assert_eq!(looked.inode, child_dir.inode);

    // Verify ".." in child_dir points to dir_b by checking readdir.
    let (handle, _) = sb.fuse_opendir(child_dir.inode).unwrap();
    let handle = handle.unwrap();
    let entries = sb
        .fs
        .readdir(MemFsTestSandbox::ctx(), child_dir.inode, handle, 65536, 0)
        .unwrap();
    let dotdot = entries.iter().find(|e| e.name == b"..");
    assert!(dotdot.is_some());
    assert_eq!(dotdot.unwrap().ino, dir_b.inode);
    sb.fs
        .releasedir(MemFsTestSandbox::ctx(), child_dir.inode, 0, handle)
        .unwrap();
}

#[test]
fn test_rename_init_krun_rejected() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_create_root("target.txt").unwrap();
    let result = sb.fs.rename(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("init.krun"),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("target.txt"),
        0,
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_rename_onto_init_krun_rejected() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_create_root("source.txt").unwrap();
    let result = sb.fs.rename(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("source.txt"),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("init.krun"),
        0,
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EACCES);
}
