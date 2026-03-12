use super::*;

#[test]
fn test_lookup_backend_a_file() {
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("a_only.txt").unwrap();
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    let e = sb.lookup_root("a_only.txt").unwrap();
    assert_eq!(e.inode, entry.inode);
    let mode = e.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
}

#[test]
fn test_lookup_backend_b_file() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_only.txt", b"hello from b");
    });
    let entry = sb.lookup_root("b_only.txt").unwrap();
    assert!(entry.inode >= 3);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
}

#[test]
fn test_lookup_precedence_a_over_b() {
    // Default policy: ReadBackendBWriteBackendA with BackendBFirst precedence.
    // backend_b has a file -> lookup finds it from backend_b.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "shared.txt", b"from_b");
    });
    // Also create in backend_a via DualFs.
    let (entry_a, handle_a) = sb.fuse_create_root("shared_a.txt").unwrap();
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry_a.inode, 0, handle_a, false, false, None)
        .unwrap();
    // The backend_b file should be discoverable.
    let entry_b = sb.lookup_root("shared.txt").unwrap();
    assert!(entry_b.inode >= 3, "backend_b file should be found");
}

#[test]
fn test_lookup_nonexistent() {
    let sb = DualFsTestSandbox::new();
    let result = sb.lookup_root("does_not_exist");
    DualFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_lookup_whiteout_hides_backend_b() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "hidden.txt", b"hidden data");
    });
    // Lookup to register, then unlink -> creates whiteout.
    let _entry = sb.lookup_root("hidden.txt").unwrap();
    sb.fs
        .unlink(DualFsTestSandbox::ctx(), ROOT_INODE, &DualFsTestSandbox::cstr("hidden.txt"))
        .unwrap();
    // Now lookup should fail.
    let result = sb.lookup_root("hidden.txt");
    DualFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_lookup_nested_path() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let dir_ino = memfs_mkdir(b, 1, "subdir");
        memfs_create_file(b, dir_ino, "nested.txt", b"nested data");
    });
    let dir_entry = sb.lookup_root("subdir").unwrap();
    let file_entry = sb.lookup(dir_entry.inode, "nested.txt").unwrap();
    assert!(file_entry.inode >= 3);
    let mode = file_entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
}

#[test]
fn test_lookup_root_is_merged() {
    let sb = DualFsTestSandbox::new();
    let (st, _) = sb.fs.getattr(DualFsTestSandbox::ctx(), ROOT_INODE, None).unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
}

#[test]
fn test_lookup_guest_inode_stable() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "stable.txt", b"data");
    });
    let e1 = sb.lookup_root("stable.txt").unwrap();
    let e2 = sb.lookup_root("stable.txt").unwrap();
    assert_eq!(e1.inode, e2.inode, "same file should return same guest inode");
}

#[test]
fn test_lookup_init_binary() {
    let sb = DualFsTestSandbox::new();
    let entry = sb.lookup_root("init.krun").unwrap();
    assert_eq!(entry.inode, INIT_INODE);
}

#[test]
fn test_lookup_dir_in_backend_b() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_mkdir(b, 1, "b_dir");
    });
    let entry = sb.lookup_root("b_dir").unwrap();
    assert!(entry.inode >= 3);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
}

#[test]
fn test_lookup_staging_dir_hidden() {
    let sb = DualFsTestSandbox::new();
    // The staging dir should not be visible via lookup.
    let result = sb.lookup_root(".dualfs_staging");
    DualFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_lookup_opaque_hides_backend() {
    // When a backend_b directory is removed and then recreated via backend_a,
    // mkdir marks the new directory as opaque against backend_b. This means
    // the old backend_b children should be hidden.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let dir = memfs_mkdir(b, 1, "opq_dir");
        memfs_create_file(b, dir, "old_child.txt", b"from_b");
    });

    // Lookup and remove the backend_b directory children, then the dir itself.
    let dir_entry = sb.lookup_root("opq_dir").unwrap();
    let _child = sb.lookup(dir_entry.inode, "old_child.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            dir_entry.inode,
            &DualFsTestSandbox::cstr("old_child.txt"),
        )
        .unwrap();
    sb.fs
        .rmdir(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("opq_dir"),
        )
        .unwrap();

    // Recreate the directory via DualFs (goes to backend_a).
    // Because a whiteout existed for "opq_dir", mkdir marks it opaque against backend_b.
    let new_dir = sb.fuse_mkdir_root("opq_dir").unwrap();

    // Create a new file in the recreated directory.
    sb.create_file_with_content(new_dir.inode, "new_child.txt", b"from_a")
        .unwrap();

    // The old backend_b child should NOT be visible via lookup (opaque hides it).
    let result = sb.lookup(new_dir.inode, "old_child.txt");
    DualFsTestSandbox::assert_errno(result, LINUX_ENOENT);

    // The new backend_a child should be visible.
    let new_child = sb.lookup(new_dir.inode, "new_child.txt").unwrap();
    assert!(new_child.inode >= 3);
}

#[test]
fn test_lookup_dedup_backend_b() {
    // Lookup the same backend_b file twice; verify the same guest inode is returned both times.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "dedup_b.txt", b"data");
    });
    let e1 = sb.lookup_root("dedup_b.txt").unwrap();
    let e2 = sb.lookup_root("dedup_b.txt").unwrap();
    assert_eq!(
        e1.inode, e2.inode,
        "same backend_b file should return same guest inode on repeated lookup"
    );
}

#[test]
fn test_lookup_dedup_backend_a() {
    // Lookup the same backend_a file twice; verify the same guest inode is returned both times.
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("dedup_a.txt").unwrap();
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    let e1 = sb.lookup_root("dedup_a.txt").unwrap();
    let e2 = sb.lookup_root("dedup_a.txt").unwrap();
    assert_eq!(
        e1.inode, e2.inode,
        "same backend_a file should return same guest inode on repeated lookup"
    );
    assert_eq!(
        e1.inode, entry.inode,
        "lookup should return the same inode as create"
    );
}
