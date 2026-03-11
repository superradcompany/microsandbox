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
    sb.lookup_root("lower.txt").unwrap();
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
    // New name should exist with data preserved through copy-up + rename.
    let new_entry = sb.lookup_root("renamed.txt").unwrap();
    assert!(new_entry.inode >= 3);
    let handle = sb.fuse_open(new_entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(new_entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data, b"lower data");
    sb.fs.release(sb.ctx(), new_entry.inode, 0, handle, false, false, Some(0)).unwrap();
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

//--------------------------------------------------------------------------------------------------
// Tests: RENAME_EXCHANGE
//--------------------------------------------------------------------------------------------------

#[test]
fn test_rename_exchange_upper_files() {
    let sb = OverlayTestSandbox::new();
    let (ea, ha) = sb.fuse_create_root("a.txt").unwrap();
    sb.fuse_write(ea.inode, ha, b"data_a", 0).unwrap();
    let (eb, hb) = sb.fuse_create_root("b.txt").unwrap();
    sb.fuse_write(eb.inode, hb, b"data_b", 0).unwrap();

    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("a.txt"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("b.txt"),
            2, // RENAME_EXCHANGE
        )
        .unwrap();

    // "a.txt" should now hold data_b, "b.txt" should hold data_a.
    let e = sb.lookup_root("a.txt").unwrap();
    let h = sb.fuse_open(e.inode, libc::O_RDONLY as u32).unwrap();
    let d = sb.fuse_read(e.inode, h, 4096, 0).unwrap();
    assert_eq!(&d[..], b"data_b");

    let e = sb.lookup_root("b.txt").unwrap();
    let h = sb.fuse_open(e.inode, libc::O_RDONLY as u32).unwrap();
    let d = sb.fuse_read(e.inode, h, 4096, 0).unwrap();
    assert_eq!(&d[..], b"data_a");
}

#[test]
fn test_rename_exchange_upper_file_with_lower_file() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("lower.txt"), b"lower_data").unwrap();
    });
    // Force lookup so the overlay discovers the lower entry.
    let _ = sb.lookup_root("lower.txt").unwrap();

    let (eu, hu) = sb.fuse_create_root("upper.txt").unwrap();
    sb.fuse_write(eu.inode, hu, b"upper_data", 0).unwrap();

    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("lower.txt"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("upper.txt"),
            2,
        )
        .unwrap();

    // "lower.txt" should now hold upper_data.
    let e = sb.lookup_root("lower.txt").unwrap();
    let h = sb.fuse_open(e.inode, libc::O_RDONLY as u32).unwrap();
    let d = sb.fuse_read(e.inode, h, 4096, 0).unwrap();
    assert_eq!(&d[..], b"upper_data");

    // "upper.txt" should now hold lower_data.
    let e = sb.lookup_root("upper.txt").unwrap();
    let h = sb.fuse_open(e.inode, libc::O_RDONLY as u32).unwrap();
    let d = sb.fuse_read(e.inode, h, 4096, 0).unwrap();
    assert_eq!(&d[..], b"lower_data");
}

#[test]
fn test_rename_exchange_upper_dirs() {
    let sb = OverlayTestSandbox::new();
    let da = sb.fuse_mkdir_root("dir_a").unwrap();
    sb.fuse_create(da.inode, "child_a.txt", 0o644).unwrap();
    let db = sb.fuse_mkdir_root("dir_b").unwrap();
    sb.fuse_create(db.inode, "child_b.txt", 0o644).unwrap();

    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("dir_a"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("dir_b"),
            2,
        )
        .unwrap();

    // "dir_a" should now contain child_b, "dir_b" should contain child_a.
    let da = sb.lookup_root("dir_a").unwrap();
    sb.lookup(da.inode, "child_b.txt").unwrap();
    let result = sb.lookup(da.inode, "child_a.txt");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);

    let db = sb.lookup_root("dir_b").unwrap();
    sb.lookup(db.inode, "child_a.txt").unwrap();
    let result = sb.lookup(db.inode, "child_b.txt");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_rename_exchange_lower_dir_with_upper_file() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::create_dir(lower.join("ldir")).unwrap();
        std::fs::write(lower.join("ldir/child.txt"), b"child_data").unwrap();
    });
    let ldir = sb.lookup_root("ldir").unwrap();
    let _ = sb.lookup(ldir.inode, "child.txt").unwrap();

    let (ef, hf) = sb.fuse_create_root("ufile.txt").unwrap();
    sb.fuse_write(ef.inode, hf, b"file_data", 0).unwrap();

    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("ldir"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("ufile.txt"),
            2,
        )
        .unwrap();

    // "ldir" should now be the file with file_data.
    let e = sb.lookup_root("ldir").unwrap();
    let h = sb.fuse_open(e.inode, libc::O_RDONLY as u32).unwrap();
    let d = sb.fuse_read(e.inode, h, 4096, 0).unwrap();
    assert_eq!(&d[..], b"file_data");

    // "ufile.txt" should now be the directory with child.txt accessible via redirect.
    let dir = sb.lookup_root("ufile.txt").unwrap();
    let child = sb.lookup(dir.inode, "child.txt").unwrap();
    let ch = sb.fuse_open(child.inode, libc::O_RDONLY as u32).unwrap();
    let cd = sb.fuse_read(child.inode, ch, 4096, 0).unwrap();
    assert_eq!(&cd[..], b"child_data");
}

#[test]
fn test_rename_exchange_lower_dirs() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::create_dir(lower.join("dir_x")).unwrap();
        std::fs::write(lower.join("dir_x/x_child.txt"), b"x_data").unwrap();
        std::fs::create_dir(lower.join("dir_y")).unwrap();
        std::fs::write(lower.join("dir_y/y_child.txt"), b"y_data").unwrap();
    });
    let dx = sb.lookup_root("dir_x").unwrap();
    let _ = sb.lookup(dx.inode, "x_child.txt").unwrap();
    let dy = sb.lookup_root("dir_y").unwrap();
    let _ = sb.lookup(dy.inode, "y_child.txt").unwrap();

    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("dir_x"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("dir_y"),
            2,
        )
        .unwrap();

    // "dir_x" should now have y_child.txt via redirect.
    let dx = sb.lookup_root("dir_x").unwrap();
    let child = sb.lookup(dx.inode, "y_child.txt").unwrap();
    let h = sb.fuse_open(child.inode, libc::O_RDONLY as u32).unwrap();
    let d = sb.fuse_read(child.inode, h, 4096, 0).unwrap();
    assert_eq!(&d[..], b"y_data");

    // "dir_y" should now have x_child.txt via redirect.
    let dy = sb.lookup_root("dir_y").unwrap();
    let child = sb.lookup(dy.inode, "x_child.txt").unwrap();
    let h = sb.fuse_open(child.inode, libc::O_RDONLY as u32).unwrap();
    let d = sb.fuse_read(child.inode, h, 4096, 0).unwrap();
    assert_eq!(&d[..], b"x_data");
}

#[test]
fn test_rename_exchange_init_rejected() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("other.txt").unwrap();
    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("init.krun"),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("other.txt"),
        2,
    );
    OverlayTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_rename_exchange_nonexistent() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("exists.txt").unwrap();
    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("exists.txt"),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("missing.txt"),
        2,
    );
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_rename_exchange_opaque_dir_no_redirect() {
    // A pure-upper opaque dir exchanged with a lower file should NOT
    // get a redirect to the lower subtree it was masking.
    let sb = OverlayTestSandbox::with_lower(|lower| {
        // Create an empty lower dir that the upper dir can replace.
        std::fs::create_dir(lower.join("slot")).unwrap();
        std::fs::write(lower.join("file.txt"), b"file_data").unwrap();
    });

    // Lookup the lower entries to discover them.
    let _ = sb.lookup_root("file.txt").unwrap();
    let _ = sb.lookup_root("slot").unwrap();

    // Create a pure-upper dir and rename it onto the empty lower dir.
    // This marks it opaque (suppressing the lower "slot" dir).
    let new_dir = sb.fuse_mkdir_root("temp_dir").unwrap();
    sb.fuse_create(new_dir.inode, "upper_child.txt", 0o644).unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("temp_dir"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("slot"),
            0,
        )
        .unwrap();

    // Now "slot" is pure-upper + opaque (sits on lower "slot").
    // Exchange it with the lower file.
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("slot"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("file.txt"),
            2,
        )
        .unwrap();

    // "file.txt" should now be the upper dir with upper_child only.
    let dir = sb.lookup_root("file.txt").unwrap();
    sb.lookup(dir.inode, "upper_child.txt").unwrap();

    // "slot" should now be the file.
    let e = sb.lookup_root("slot").unwrap();
    let h = sb.fuse_open(e.inode, libc::O_RDONLY as u32).unwrap();
    let d = sb.fuse_read(e.inode, h, 4096, 0).unwrap();
    assert_eq!(&d[..], b"file_data");
}

/// Renaming a directory into its own subtree must fail with EINVAL.
#[test]
fn test_rename_into_own_subtree_rejected() {
    let sb = OverlayTestSandbox::new();
    let parent = sb.fuse_mkdir_root("parent").unwrap();
    let child = sb.fuse_mkdir(parent.inode, "child", 0o755).unwrap();

    // Try to move "parent" into "parent/child/" — should be rejected.
    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("parent"),
        child.inode,
        &OverlayTestSandbox::cstr("moved"),
        0,
    );
    OverlayTestSandbox::assert_errno(result, LINUX_EINVAL);
}

/// RENAME_EXCHANGE with init.krun as target must fail with EACCES.
#[test]
fn test_rename_exchange_init_as_target_rejected() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("other.txt").unwrap();

    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("other.txt"),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("init.krun"),
        2, // RENAME_EXCHANGE
    );
    OverlayTestSandbox::assert_errno(result, LINUX_EACCES);
}

/// Unknown rename flags must fail with EINVAL.
#[test]
fn test_rename_unknown_flags_rejected() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("a.txt").unwrap();
    sb.fuse_create_root("b.txt").unwrap();

    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("a.txt"),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("b.txt"),
        0xFF,
    );
    OverlayTestSandbox::assert_errno(result, LINUX_EINVAL);
}

/// RENAME_NOREPLACE | RENAME_EXCHANGE (flags=3) must fail with EINVAL.
#[test]
fn test_rename_noreplace_exchange_rejected() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("a.txt").unwrap();
    sb.fuse_create_root("b.txt").unwrap();

    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("a.txt"),
        ROOT_INODE,
        &OverlayTestSandbox::cstr("b.txt"),
        3, // NOREPLACE | EXCHANGE
    );
    OverlayTestSandbox::assert_errno(result, LINUX_EINVAL);
}
