use super::*;

#[test]
fn test_whiteout_hides_backend_b_file() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "hidden.txt", b"data");
    });
    // Lookup to register, then unlink to create whiteout.
    let _entry = sb.lookup_root("hidden.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("hidden.txt"),
        )
        .unwrap();
    // Lookup should fail — whiteout hides the file.
    DualFsTestSandbox::assert_errno(sb.lookup_root("hidden.txt"), LINUX_ENOENT);
}

#[test]
fn test_whiteout_hides_backend_b_dir() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_mkdir(b, 1, "hidden_dir");
    });
    let _entry = sb.lookup_root("hidden_dir").unwrap();
    sb.fs
        .rmdir(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("hidden_dir"),
        )
        .unwrap();
    DualFsTestSandbox::assert_errno(sb.lookup_root("hidden_dir"), LINUX_ENOENT);
}

#[test]
fn test_whiteout_does_not_affect_backend_a() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_only.txt", b"from b");
    });
    // Create a file with a different name in backend_a.
    sb.create_file_with_content(ROOT_INODE, "a_only.txt", b"from a")
        .unwrap();
    // Whiteout the backend_b file.
    let _entry = sb.lookup_root("b_only.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("b_only.txt"),
        )
        .unwrap();
    // Backend_a file should still be visible.
    let entry = sb.lookup_root("a_only.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_opaque_hides_all_backend_children() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let dir = memfs_mkdir(b, 1, "opaque_dir");
        memfs_create_file(b, dir, "child1.txt", b"c1");
        memfs_create_file(b, dir, "child2.txt", b"c2");
    });
    let dir_entry = sb.lookup_root("opaque_dir").unwrap();
    // Create a file in the directory via backend_a (through DualFs).
    sb.create_file_with_content(dir_entry.inode, "a_child.txt", b"from_a")
        .unwrap();
    // Mark directory as opaque against backend_b by removing backend_b children.
    // In DualFs, we cannot directly set opaque. Instead, remove backend_b children:
    // lookup them and unlink to create whiteouts.
    let _c1 = sb.lookup(dir_entry.inode, "child1.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            dir_entry.inode,
            &DualFsTestSandbox::cstr("child1.txt"),
        )
        .unwrap();
    let _c2 = sb.lookup(dir_entry.inode, "child2.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            dir_entry.inode,
            &DualFsTestSandbox::cstr("child2.txt"),
        )
        .unwrap();
    // Now only a_child.txt should be visible.
    let names = sb.readdir_names(dir_entry.inode).unwrap();
    assert!(names.contains(&"a_child.txt".to_string()));
    assert!(!names.contains(&"child1.txt".to_string()));
    assert!(!names.contains(&"child2.txt".to_string()));
}

#[test]
fn test_opaque_does_not_hide_backend_a() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let dir = memfs_mkdir(b, 1, "mixed_dir");
        memfs_create_file(b, dir, "b_child.txt", b"from b");
    });
    let dir_entry = sb.lookup_root("mixed_dir").unwrap();
    // Create a backend_a file in the directory.
    sb.create_file_with_content(dir_entry.inode, "a_child.txt", b"from a")
        .unwrap();
    // Whiteout backend_b child.
    let _c = sb.lookup(dir_entry.inode, "b_child.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            dir_entry.inode,
            &DualFsTestSandbox::cstr("b_child.txt"),
        )
        .unwrap();
    // Backend_a child should still be visible.
    let entry = sb.lookup(dir_entry.inode, "a_child.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_whiteout_created_on_unlink() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "to_unlink.txt", b"data");
    });
    let _entry = sb.lookup_root("to_unlink.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("to_unlink.txt"),
        )
        .unwrap();
    // Verify whiteout by attempting lookup.
    DualFsTestSandbox::assert_errno(sb.lookup_root("to_unlink.txt"), LINUX_ENOENT);
}

#[test]
fn test_whiteout_created_on_rmdir() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_mkdir(b, 1, "to_rmdir");
    });
    let _entry = sb.lookup_root("to_rmdir").unwrap();
    sb.fs
        .rmdir(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("to_rmdir"),
        )
        .unwrap();
    DualFsTestSandbox::assert_errno(sb.lookup_root("to_rmdir"), LINUX_ENOENT);
}

#[test]
fn test_readdir_filters_whiteouts() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "visible.txt", b"see me");
        memfs_create_file(b, 1, "invisible.txt", b"hide me");
    });
    // Lookup and whiteout one file.
    let _entry = sb.lookup_root("invisible.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("invisible.txt"),
        )
        .unwrap();

    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(
        names.contains(&"visible.txt".to_string()),
        "non-whited-out file should appear"
    );
    assert!(
        !names.contains(&"invisible.txt".to_string()),
        "whited-out file should NOT appear"
    );
}

#[test]
fn test_whiteout_in_memory_only() {
    // Whiteouts are in-memory, not on-disk (.wh. files).
    // After adding a whiteout, no .wh. file should appear in readdir.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "mem_wh.txt", b"data");
    });
    let _entry = sb.lookup_root("mem_wh.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("mem_wh.txt"),
        )
        .unwrap();

    let names = sb.readdir_names(ROOT_INODE).unwrap();
    let has_wh_file = names.iter().any(|n| n.starts_with(".wh."));
    assert!(
        !has_wh_file,
        "no .wh. files should appear — whiteouts are in-memory"
    );
}

#[test]
fn test_readdir_filters_opaque() {
    // When backend_b entries are individually whited out, they should not appear.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let dir = memfs_mkdir(b, 1, "opq_dir");
        memfs_create_file(b, dir, "b1.txt", b"1");
        memfs_create_file(b, dir, "b2.txt", b"2");
    });
    let dir_entry = sb.lookup_root("opq_dir").unwrap();
    // Whiteout both backend_b children.
    let _c1 = sb.lookup(dir_entry.inode, "b1.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            dir_entry.inode,
            &DualFsTestSandbox::cstr("b1.txt"),
        )
        .unwrap();
    let _c2 = sb.lookup(dir_entry.inode, "b2.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            dir_entry.inode,
            &DualFsTestSandbox::cstr("b2.txt"),
        )
        .unwrap();

    let names = sb.readdir_names(dir_entry.inode).unwrap();
    assert!(!names.contains(&"b1.txt".to_string()));
    assert!(!names.contains(&"b2.txt".to_string()));
}
