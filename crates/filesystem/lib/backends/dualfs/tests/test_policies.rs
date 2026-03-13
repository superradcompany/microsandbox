use super::*;

// --- BackendAOnly ---

#[test]
fn test_backend_a_only_create() {
    let sb = DualFsTestSandbox::with_policy(BackendAOnly);
    let (entry, handle) = sb.fuse_create_root("a_file.txt").unwrap();
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
    let e = sb.lookup_root("a_file.txt").unwrap();
    assert_eq!(e.inode, entry.inode);
}

#[test]
fn test_backend_a_only_lookup() {
    let sb = DualFsTestSandbox::with_policy(BackendAOnly);
    sb.create_file_with_content(ROOT_INODE, "findme.txt", b"data")
        .unwrap();
    let e = sb.lookup_root("findme.txt").unwrap();
    assert!(e.inode >= 3, "should find file in backend_a");
}

#[test]
fn test_backend_a_only_write() {
    let sb = DualFsTestSandbox::with_policy(BackendAOnly);
    let (entry, handle) = sb.fuse_create_root("write_a.txt").unwrap();
    let written = sb
        .fuse_write(entry.inode, handle, b"backend_a_data", 0)
        .unwrap();
    assert_eq!(written, 14);
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"backend_a_data");
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
}

// --- BackendAFallbackToBackendBRead ---

#[test]
fn test_backend_a_fallback_lookup() {
    // Should try backend_a first (BackendAFirst precedence).
    let sb = DualFsTestSandbox::with_policy_and_backend_b(BackendAFallbackToBackendBRead, |b| {
        memfs_create_file(b, 1, "b_only.txt", b"from b");
    });
    // File only in backend_b -> fallback should find it.
    let entry = sb.lookup_root("b_only.txt").unwrap();
    assert!(entry.inode >= 3, "fallback should find backend_b file");
}

#[test]
fn test_backend_a_fallback_create() {
    let sb = DualFsTestSandbox::with_policy(BackendAFallbackToBackendBRead);
    let (entry, handle) = sb.fuse_create_root("new.txt").unwrap();
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
    let e = sb.lookup_root("new.txt").unwrap();
    assert_eq!(e.inode, entry.inode, "create should go to backend_a");
}

// --- ReadBackendBWriteBackendA (default) ---

#[test]
fn test_read_b_write_a_create() {
    // Default policy. Creates go to backend_a.
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("created.txt").unwrap();
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
    let e = sb.lookup_root("created.txt").unwrap();
    assert_eq!(e.inode, entry.inode);
}

#[test]
fn test_read_b_write_a_lookup() {
    // Lookup finds files in backend_b.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_lookup.txt", b"data");
    });
    let entry = sb.lookup_root("b_lookup.txt").unwrap();
    assert!(entry.inode >= 3, "should find backend_b file");
}

#[test]
fn test_read_b_write_a_open_write() {
    // Write on backend_b file -> triggers materialization.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_write.txt", b"original");
    });
    let entry = sb.lookup_root("b_write.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDWR as u32).unwrap();
    sb.fuse_write(entry.inode, handle, b"modified", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"modified");
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
}

#[test]
fn test_read_b_write_a_open_read() {
    // Read on backend_b file -> no materialization.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_read.txt", b"backend_b_content");
    });
    let entry = sb.lookup_root("b_read.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"backend_b_content");
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
}

// --- MergeReadsBackendAPrecedence ---

#[test]
fn test_merge_reads_readdir() {
    let sb = DualFsTestSandbox::with_policy_and_backend_b(MergeReadsBackendAPrecedence, |b| {
        memfs_create_file(b, 1, "b_merge.txt", b"from b");
    });
    sb.create_file_with_content(ROOT_INODE, "a_merge.txt", b"from a")
        .unwrap();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(
        names.contains(&"a_merge.txt".to_string()),
        "backend_a file should appear in merged readdir"
    );
    assert!(
        names.contains(&"b_merge.txt".to_string()),
        "backend_b file should appear in merged readdir"
    );
}

// --- Init node ---

#[test]
fn test_policy_init_node() {
    // Init node should be accessible regardless of policy.
    let sb = DualFsTestSandbox::with_policy(BackendAOnly);
    let entry = sb.lookup_root("init.krun").unwrap();
    assert_eq!(entry.inode, INIT_INODE, "init.krun should be found");
}

#[test]
fn test_policy_determinism() {
    // Same inputs -> same behavior.
    let sb = DualFsTestSandbox::new();
    let (entry1, h1) = sb.fuse_create_root("det1.txt").unwrap();
    sb.fs
        .release(
            DualFsTestSandbox::ctx(),
            entry1.inode,
            0,
            h1,
            false,
            false,
            None,
        )
        .unwrap();
    let (entry2, h2) = sb.fuse_create_root("det2.txt").unwrap();
    sb.fs
        .release(
            DualFsTestSandbox::ctx(),
            entry2.inode,
            0,
            h2,
            false,
            false,
            None,
        )
        .unwrap();
    // Both should be in backend_a (default policy).
    let e1 = sb.lookup_root("det1.txt").unwrap();
    let e2 = sb.lookup_root("det2.txt").unwrap();
    assert!(e1.inode >= 3);
    assert!(e2.inode >= 3);
    // Both lookups should yield same inode as creation.
    assert_eq!(e1.inode, entry1.inode);
    assert_eq!(e2.inode, entry2.inode);
}
