use super::*;

#[test]
fn test_unlink_upper_file() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("to_delete.txt").unwrap();
    sb.fs
        .unlink(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("to_delete.txt"),
        )
        .unwrap();
    let result = sb.lookup_root("to_delete.txt");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_unlink_lower_file() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("lower_file.txt"), b"data").unwrap();
    });
    sb.lookup_root("lower_file.txt").unwrap();
    sb.fs
        .unlink(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("lower_file.txt"),
        )
        .unwrap();
    // Should create a whiteout on upper.
    assert!(
        sb.upper_has_whiteout("lower_file.txt"),
        "unlink of lower file should create whiteout on upper"
    );
}

#[test]
fn test_unlink_lower_lookup_enoent() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("gone.txt"), b"data").unwrap();
    });
    sb.lookup_root("gone.txt").unwrap();
    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &OverlayTestSandbox::cstr("gone.txt"))
        .unwrap();
    let result = sb.lookup_root("gone.txt");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_unlink_nonexistent() {
    let sb = OverlayTestSandbox::new();
    let result = sb.fs.unlink(
        sb.ctx(),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("does_not_exist"),
    );
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_unlink_init_rejected() {
    let sb = OverlayTestSandbox::new();
    let result = sb
        .fs
        .unlink(sb.ctx(), ROOT_INODE, &OverlayTestSandbox::cstr("init.krun"));
    OverlayTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_rmdir_upper_empty() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_mkdir_root("empty_dir").unwrap();
    sb.fs
        .rmdir(sb.ctx(), ROOT_INODE, &OverlayTestSandbox::cstr("empty_dir"))
        .unwrap();
    let result = sb.lookup_root("empty_dir");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_rmdir_lower_empty() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::create_dir(lower.join("lower_dir")).unwrap();
    });
    sb.lookup_root("lower_dir").unwrap();
    sb.fs
        .rmdir(sb.ctx(), ROOT_INODE, &OverlayTestSandbox::cstr("lower_dir"))
        .unwrap();
    let result = sb.lookup_root("lower_dir");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_rmdir_nonempty() {
    let sb = OverlayTestSandbox::new();
    let dir = sb.fuse_mkdir_root("nonempty").unwrap();
    sb.fuse_create(dir.inode, "child.txt", 0o644).unwrap();
    let result = sb
        .fs
        .rmdir(sb.ctx(), ROOT_INODE, &OverlayTestSandbox::cstr("nonempty"));
    OverlayTestSandbox::assert_errno(result, LINUX_ENOTEMPTY);
}

#[test]
fn test_rmdir_init_rejected() {
    let sb = OverlayTestSandbox::new();
    let result = sb
        .fs
        .rmdir(sb.ctx(), ROOT_INODE, &OverlayTestSandbox::cstr("init.krun"));
    OverlayTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_unlink_readdir_hides() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("visible.txt"), b"data").unwrap();
    });
    // Verify it appears in readdir before unlink.
    let names_before = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(names_before.iter().any(|n| n == b"visible.txt"));

    sb.lookup_root("visible.txt").unwrap();
    sb.fs
        .unlink(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("visible.txt"),
        )
        .unwrap();

    // After unlink, readdir should not show it.
    let names_after = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(
        !names_after.iter().any(|n| n == b"visible.txt"),
        "unlinked file should not appear in readdir"
    );
}
