use super::*;

#[test]
fn test_rename_upper_file() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("old.txt").unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("old.txt"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("new.txt"),
            0,
        )
        .unwrap();
    let result = sb.lookup_root("old.txt");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
    let entry = sb.lookup_root("new.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_rename_lower_file() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("lower.txt"), b"lower data").unwrap();
    });
    let entry = sb.lookup_root("lower.txt").unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("lower.txt"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("renamed.txt"),
            0,
        )
        .unwrap();
    // Old name should be gone (whiteout created).
    let result = sb.lookup_root("lower.txt");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
    // New name should exist.
    let new_entry = sb.lookup_root("renamed.txt").unwrap();
    assert!(new_entry.inode >= 3);
}

#[test]
fn test_rename_across_dirs() {
    let sb = OverlayTestSandbox::new();
    let dir_a = sb.fuse_mkdir_root("dir_a").unwrap();
    let dir_b = sb.fuse_mkdir_root("dir_b").unwrap();
    sb.fuse_create(dir_a.inode, "moveme.txt", 0o644).unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            dir_a.inode,
            &OverlayTestSandbox::cstr("moveme.txt"),
            dir_b.inode,
            &OverlayTestSandbox::cstr("moveme.txt"),
            0,
        )
        .unwrap();
    let result = sb.lookup(dir_a.inode, "moveme.txt");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
    let entry = sb.lookup(dir_b.inode, "moveme.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_rename_overwrite() {
    let sb = OverlayTestSandbox::new();
    let (entry_a, handle_a) = sb.fuse_create_root("a.txt").unwrap();
    sb.fuse_write(entry_a.inode, handle_a, b"data_a", 0)
        .unwrap();
    let (_entry_b, handle_b) = sb.fuse_create_root("b.txt").unwrap();
    sb.fuse_write(_entry_b.inode, handle_b, b"data_b", 0)
        .unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("a.txt"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("b.txt"),
            0,
        )
        .unwrap();
    let result = sb.lookup_root("a.txt");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
    let entry = sb.lookup_root("b.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"data_a");
}

#[test]
fn test_rename_noreplace_eexist() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("exist.txt").unwrap();
    sb.fuse_create_root("also_exist.txt").unwrap();
    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("exist.txt"),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("also_exist.txt"),
        1, // RENAME_NOREPLACE
    );
    OverlayTestSandbox::assert_errno(result, LINUX_EEXIST);
}

#[test]
fn test_rename_init_source_rejected() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("target").unwrap();
    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("init.krun"),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("target"),
        0,
    );
    OverlayTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_rename_init_target_rejected() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("source").unwrap();
    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("source"),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("init.krun"),
        0,
    );
    OverlayTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_rename_upper_dir() {
    let sb = OverlayTestSandbox::new();
    let dir = sb.fuse_mkdir_root("old_dir").unwrap();
    sb.fuse_create(dir.inode, "child.txt", 0o644).unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("old_dir"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("new_dir"),
            0,
        )
        .unwrap();
    let result = sb.lookup_root("old_dir");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
    let new_dir = sb.lookup_root("new_dir").unwrap();
    // Child should be accessible under new name.
    let child = sb.lookup(new_dir.inode, "child.txt").unwrap();
    assert!(child.inode >= 3);
}

#[test]
fn test_rename_lower_dir() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::create_dir(lower.join("lower_dir")).unwrap();
        std::fs::write(lower.join("lower_dir/child.txt"), b"child data").unwrap();
    });
    let dir_entry = sb.lookup_root("lower_dir").unwrap();
    // Lookup child to ensure it's discovered.
    let _ = sb.lookup(dir_entry.inode, "child.txt").unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("lower_dir"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("moved_dir"),
            0,
        )
        .unwrap();
    // Old name should be gone.
    let result = sb.lookup_root("lower_dir");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
    // New name should exist.
    let new_dir = sb.lookup_root("moved_dir").unwrap();
    assert!(new_dir.inode >= 3);
}

#[test]
fn test_rename_lower_dir_children_accessible() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::create_dir(lower.join("src_dir")).unwrap();
        std::fs::write(lower.join("src_dir/file.txt"), b"child content").unwrap();
    });
    let dir_entry = sb.lookup_root("src_dir").unwrap();
    let _ = sb.lookup(dir_entry.inode, "file.txt").unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("src_dir"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("dst_dir"),
            0,
        )
        .unwrap();
    let new_dir = sb.lookup_root("dst_dir").unwrap();
    // Children should be accessible at the new path via redirect.
    let child = sb.lookup(new_dir.inode, "file.txt").unwrap();
    assert!(child.inode >= 3);
    // Read the child's data to verify it's intact.
    let handle = sb
        .fuse_open(child.inode, libc::O_RDONLY as u32)
        .unwrap();
    let data = sb.fuse_read(child.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"child content");
}

#[test]
fn test_rename_data_preserved() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("original.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"important data", 0)
        .unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("original.txt"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("renamed.txt"),
            0,
        )
        .unwrap();
    let entry = sb.lookup_root("renamed.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"important data");
}
