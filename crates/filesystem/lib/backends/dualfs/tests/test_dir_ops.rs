use super::*;

#[test]
fn test_readdir_merged() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_file.txt", b"from b");
    });
    // Create a file in backend_a via DualFs.
    sb.create_file_with_content(ROOT_INODE, "a_file.txt", b"from a")
        .unwrap();

    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(
        names.contains(&"a_file.txt".to_string()),
        "backend_a file should appear"
    );
    assert!(
        names.contains(&"b_file.txt".to_string()),
        "backend_b file should appear"
    );
    // No duplicates.
    let unique_count = {
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        sorted.len()
    };
    assert_eq!(unique_count, names.len(), "no duplicates in readdir");
}

#[test]
fn test_readdir_whiteout_filtered() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "hidden.txt", b"should be hidden");
    });
    // Lookup then unlink to create a whiteout.
    let _entry = sb.lookup_root("hidden.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("hidden.txt"),
        )
        .unwrap();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(
        !names.contains(&"hidden.txt".to_string()),
        "whited-out file should not appear in readdir"
    );
}

#[test]
fn test_readdir_excludes_staging() {
    let sb = DualFsTestSandbox::new();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(
        !names.contains(&".dualfs_staging".to_string()),
        "staging dir should be excluded from readdir"
    );
}

#[test]
fn test_readdir_snapshot_stable() {
    let sb = DualFsTestSandbox::new();
    sb.create_file_with_content(ROOT_INODE, "before.txt", b"data")
        .unwrap();

    // Open dir handle.
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries_before = sb
        .fs
        .readdir(DualFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();

    // Create another file after opendir.
    sb.create_file_with_content(ROOT_INODE, "after.txt", b"data")
        .unwrap();

    // Re-read with same handle — snapshot should be unchanged.
    let entries_after = sb
        .fs
        .readdir(DualFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();

    assert_eq!(
        entries_before.len(),
        entries_after.len(),
        "readdir snapshot should be stable across calls with same handle"
    );
    sb.fs
        .releasedir(DualFsTestSandbox::ctx(), ROOT_INODE, 0, handle)
        .unwrap();
}

#[test]
fn test_readdir_root_has_init() {
    let sb = DualFsTestSandbox::new();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(
        names.contains(&"init.krun".to_string()),
        "root readdir should include init.krun"
    );
}

#[test]
fn test_readdir_dot_dotdot() {
    let sb = DualFsTestSandbox::new();
    let dir_entry = sb.fuse_mkdir_root("subdir").unwrap();
    let names = sb.readdir_names(dir_entry.inode).unwrap();
    assert!(names.contains(&".".to_string()), ". should be present");
    assert!(names.contains(&"..".to_string()), ".. should be present");
}

#[test]
fn test_readdirplus_merged() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_plus.txt", b"data");
    });
    sb.create_file_with_content(ROOT_INODE, "a_plus.txt", b"data")
        .unwrap();

    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdirplus(DualFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    let names: Vec<String> = entries
        .iter()
        .map(|(de, _)| String::from_utf8_lossy(de.name).to_string())
        .collect();
    assert!(names.contains(&"a_plus.txt".to_string()));
    assert!(names.contains(&"b_plus.txt".to_string()));
    // Each entry should have valid attrs.
    for (_, entry) in &entries {
        assert!(
            entry.inode > 0,
            "readdirplus entries should have valid inodes"
        );
    }
    sb.fs
        .releasedir(DualFsTestSandbox::ctx(), ROOT_INODE, 0, handle)
        .unwrap();
}

#[test]
fn test_readdir_backend_a_only() {
    let sb = DualFsTestSandbox::with_policy_and_backend_b(BackendAOnly, |b| {
        memfs_create_file(b, 1, "b_only.txt", b"should not appear");
    });
    // Create file in backend_a via DualFs.
    sb.create_file_with_content(ROOT_INODE, "a_only.txt", b"visible")
        .unwrap();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(
        names.contains(&"a_only.txt".to_string()),
        "backend_a file should appear"
    );
    assert!(
        !names.contains(&"b_only.txt".to_string()),
        "backend_b file should NOT appear with BackendAOnly policy"
    );
}

#[test]
fn test_readdir_empty_dir() {
    let sb = DualFsTestSandbox::new();
    let dir_entry = sb.fuse_mkdir_root("emptydir").unwrap();
    let names = sb.readdir_names(dir_entry.inode).unwrap();
    // Should only have . and ..
    assert!(names.contains(&".".to_string()));
    assert!(names.contains(&"..".to_string()));
    assert_eq!(names.len(), 2, "empty dir should only have . and ..");
}

#[test]
fn test_readdir_backend_a_precedence() {
    // With MergeReadsBackendAPrecedence policy, readdir uses MergeReaddir with
    // BackendAFirst precedence. When the same file name exists in both backends,
    // readdir should show it only once (deduplicated).
    let sb = DualFsTestSandbox::with_policy_and_backend_b(MergeReadsBackendAPrecedence, |b| {
        memfs_create_file(b, 1, "shared.txt", b"from_b");
    });
    // Create a file with the same name in backend_a via DualFs.
    sb.create_file_with_content(ROOT_INODE, "shared.txt", b"from_a")
        .unwrap();

    let names = sb.readdir_names(ROOT_INODE).unwrap();

    // "shared.txt" should appear exactly once (deduplicated).
    let shared_count = names.iter().filter(|n| *n == "shared.txt").count();
    assert_eq!(
        shared_count, 1,
        "same-named file should appear exactly once with backend_a precedence"
    );
    assert!(
        names.contains(&"shared.txt".to_string()),
        "shared.txt should be present in readdir"
    );
}

#[test]
fn test_readdir_opaque_stops() {
    // When a directory is marked opaque against backend_b, its backend_b children
    // should not appear in readdir. Opaque is set when a directory is recreated
    // after being deleted (rmdir + mkdir).
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let dir = memfs_mkdir(b, 1, "opq_readdir");
        memfs_create_file(b, dir, "b_child1.txt", b"data1");
        memfs_create_file(b, dir, "b_child2.txt", b"data2");
    });

    // Lookup the dir, remove its children, then remove the dir.
    let dir_entry = sb.lookup_root("opq_readdir").unwrap();
    let _c1 = sb.lookup(dir_entry.inode, "b_child1.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            dir_entry.inode,
            &DualFsTestSandbox::cstr("b_child1.txt"),
        )
        .unwrap();
    let _c2 = sb.lookup(dir_entry.inode, "b_child2.txt").unwrap();
    sb.fs
        .unlink(
            DualFsTestSandbox::ctx(),
            dir_entry.inode,
            &DualFsTestSandbox::cstr("b_child2.txt"),
        )
        .unwrap();
    sb.fs
        .rmdir(
            DualFsTestSandbox::ctx(),
            ROOT_INODE,
            &DualFsTestSandbox::cstr("opq_readdir"),
        )
        .unwrap();

    // Recreate the directory (goes to backend_a). This marks it opaque against backend_b
    // because a whiteout existed for this name.
    let new_dir = sb.fuse_mkdir_root("opq_readdir").unwrap();

    // Create a new file in the recreated directory.
    sb.create_file_with_content(new_dir.inode, "a_child.txt", b"from_a")
        .unwrap();

    // Readdir should NOT show the old backend_b children.
    let names = sb.readdir_names(new_dir.inode).unwrap();
    assert!(
        names.contains(&"a_child.txt".to_string()),
        "new backend_a child should appear"
    );
    assert!(
        !names.contains(&"b_child1.txt".to_string()),
        "opaque should hide old backend_b child1"
    );
    assert!(
        !names.contains(&"b_child2.txt".to_string()),
        "opaque should hide old backend_b child2"
    );
}
