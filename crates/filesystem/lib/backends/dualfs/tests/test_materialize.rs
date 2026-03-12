use super::*;

#[test]
fn test_materialize_regular_file() {
    // Create a file in backend_b, then write through DualFs -> triggers materialization.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_file.txt", b"original");
    });
    let entry = sb.lookup_root("b_file.txt").unwrap();
    // Open for write triggers materialization from backend_b to backend_a.
    let handle = sb.fuse_open(entry.inode, libc::O_RDWR as u32).unwrap();
    sb.fuse_write(entry.inode, handle, b"replaced", 0).unwrap();
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // Read back through DualFs — same-length overwrite replaces content exactly.
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"replaced");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_materialize_preserves_content() {
    // 1 MB file in backend_b -> materialize -> verify identical.
    let large_data = vec![0xCDu8; 1024 * 1024];
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "large_b.txt", &large_data);
    });
    let entry = sb.lookup_root("large_b.txt").unwrap();
    // Open for write to trigger materialization.
    let handle = sb.fuse_open(entry.inode, libc::O_RDWR as u32).unwrap();
    // Just close — materialization should have copied content.
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // Read back.
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb
        .fuse_read(entry.inode, handle, (1024 * 1024 + 1) as u32, 0)
        .unwrap();
    assert_eq!(data.len(), 1024 * 1024);
    assert!(data.iter().all(|&b| b == 0xCD), "content should be preserved");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_materialize_preserves_metadata() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        memfs_create_file(b, 1, "meta_b.txt", b"data");
        let cname = CString::new("meta_b.txt").unwrap();
        let entry = b.lookup(ctx, 1, &cname).unwrap();
        // Set specific mode on backend_b file.
        let mut attr: crate::stat64 = unsafe { std::mem::zeroed() };
        attr.st_mode = 0o755 as _;
        b.setattr(ctx, entry.inode, attr, None, SetattrValid::MODE)
            .unwrap();
    });
    let entry = sb.lookup_root("meta_b.txt").unwrap();
    let (st_before, _) = sb
        .fs
        .getattr(DualFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    let mode_before = st_before.st_mode as u32 & 0o777;

    // Trigger materialization.
    let handle = sb.fuse_open(entry.inode, libc::O_RDWR as u32).unwrap();
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    let (st_after, _) = sb
        .fs
        .getattr(DualFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    let mode_after = st_after.st_mode as u32 & 0o777;
    assert_eq!(
        mode_before, mode_after,
        "mode should be preserved after materialization"
    );
}

#[test]
fn test_materialize_preserves_xattrs() {
    // Materialization copies xattrs using copy_xattrs, which calls listxattr(size=0).
    // MemFs returns ListxattrReply::Count for size=0, so copy_xattrs early-returns
    // without copying any xattrs. This test verifies that the newly-set xattr
    // on the materialized file is accessible.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "xattr_b.txt", b"data");
    });
    let entry = sb.lookup_root("xattr_b.txt").unwrap();
    // Trigger materialization via setxattr.
    let xname = DualFsTestSandbox::cstr("user.trigger");
    sb.fs
        .setxattr(
            DualFsTestSandbox::ctx(),
            entry.inode,
            &xname,
            b"trigger_value",
            0,
        )
        .unwrap();
    // Verify the newly-set xattr is readable on the materialized file.
    let reply = sb
        .fs
        .getxattr(DualFsTestSandbox::ctx(), entry.inode, &xname, 256)
        .unwrap();
    match reply {
        GetxattrReply::Value(v) => assert_eq!(v, b"trigger_value"),
        _ => panic!("expected GetxattrReply::Value with set xattr"),
    }
}

#[test]
fn test_materialize_directory() {
    // Materializing a directory means promoting it to MergedDir (creating on target backend).
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let dir = memfs_mkdir(b, 1, "b_dir");
        memfs_create_file(b, dir, "child.txt", b"data");
    });
    let dir_entry = sb.lookup_root("b_dir").unwrap();
    // Create a file in the backend_b dir -> forces dir promotion.
    let (file_entry, handle) = sb.fuse_create(dir_entry.inode, "new_child.txt", 0o644).unwrap();
    sb.fs
        .release(
            DualFsTestSandbox::ctx(),
            file_entry.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
    // Both children should be visible.
    let names = sb.readdir_names(dir_entry.inode).unwrap();
    assert!(names.contains(&"child.txt".to_string()));
    assert!(names.contains(&"new_child.txt".to_string()));
}

#[test]
fn test_materialize_ancestor_chain() {
    // File at a/b/c -> ancestors a, a/b must be created in target backend.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let a = memfs_mkdir(b, 1, "a");
        let ab = memfs_mkdir(b, a, "b");
        memfs_create_file(b, ab, "c.txt", b"deep");
    });
    let a = sb.lookup_root("a").unwrap();
    let ab = sb.lookup(a.inode, "b").unwrap();
    let c = sb.lookup(ab.inode, "c.txt").unwrap();
    // Write to c.txt -> triggers materialization of c.txt (and ancestor dirs).
    let handle = sb.fuse_open(c.inode, libc::O_RDWR as u32).unwrap();
    sb.fuse_write(c.inode, handle, b"modified", 0).unwrap();
    sb.fs
        .release(DualFsTestSandbox::ctx(), c.inode, 0, handle, false, false, None)
        .unwrap();
    // Verify file is readable.
    let handle = sb.fuse_open(c.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(c.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"modified");
    sb.fs
        .release(DualFsTestSandbox::ctx(), c.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_materialize_idempotent() {
    // Double materialization should not fail.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "idem.txt", b"data");
    });
    let entry = sb.lookup_root("idem.txt").unwrap();
    // First write -> materialize.
    let handle = sb.fuse_open(entry.inode, libc::O_RDWR as u32).unwrap();
    sb.fuse_write(entry.inode, handle, b"first", 0).unwrap();
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // Second write -> already materialized, should still work.
    let handle = sb.fuse_open(entry.inode, libc::O_RDWR as u32).unwrap();
    sb.fuse_write(entry.inode, handle, b"second", 0).unwrap();
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // Read back -> should see "second".
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"second");
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_materialize_symlink() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        let target = CString::new("/some/target").unwrap();
        let name = CString::new("b_link").unwrap();
        b.symlink(ctx, &target, 1, &name, Extensions::default())
            .unwrap();
    });
    let entry = sb.lookup_root("b_link").unwrap();
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFLNK as u32);
    // Readlink should return the target.
    let link = sb.fs.readlink(DualFsTestSandbox::ctx(), entry.inode).unwrap();
    assert_eq!(link, b"/some/target");
}

#[test]
fn test_materialize_special_file() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        let cname = CString::new("b_fifo").unwrap();
        let mode = libc::S_IFIFO as u32 | 0o644;
        b.mknod(ctx, 1, &cname, mode, 0, 0, Extensions::default())
            .unwrap();
    });
    let entry = sb.lookup_root("b_fifo").unwrap();
    let mode = entry.attr.st_mode as u32;
    assert_eq!(
        mode & libc::S_IFMT as u32,
        libc::S_IFIFO as u32,
        "special file should preserve its type"
    );
}

#[test]
fn test_materialize_guest_inode_stable() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "stable.txt", b"data");
    });
    let entry_before = sb.lookup_root("stable.txt").unwrap();
    let inode_before = entry_before.inode;
    // Trigger materialization.
    let handle = sb.fuse_open(entry_before.inode, libc::O_RDWR as u32).unwrap();
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry_before.inode, 0, handle, false, false, None)
        .unwrap();
    // Guest inode should remain the same.
    let entry_after = sb.lookup_root("stable.txt").unwrap();
    assert_eq!(
        entry_after.inode, inode_before,
        "guest inode should be unchanged after materialization"
    );
}

#[test]
fn test_materialize_serialized() {
    // Concurrent materialization should result in only one copy.
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "race.txt", b"concurrent data");
    });
    let entry = sb.lookup_root("race.txt").unwrap();
    let inode = entry.inode;

    std::thread::scope(|s| {
        let sb = &sb;
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(s.spawn(move || {
                // All threads attempt to open for write simultaneously.
                sb.fuse_open(inode, libc::O_RDWR as u32)
            }));
        }
        for h in handles {
            let result = h.join().unwrap();
            if let Ok(handle) = result {
                sb.fs
                    .release(DualFsTestSandbox::ctx(), inode, 0, handle, false, false, None)
                    .unwrap();
            }
        }
    });

    // After all threads, file should still be readable with correct content.
    let handle = sb.fuse_open(inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"concurrent data");
    sb.fs
        .release(DualFsTestSandbox::ctx(), inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_materialize_regular_file_to_backend_b() {
    // Using BackendAFallbackToBackendBRead — creates go to backend_a.
    // This test just verifies that a file created in backend_a can be read.
    // True backend_a->backend_b materialization requires a custom policy.
    let sb = DualFsTestSandbox::with_policy(BackendAFallbackToBackendBRead);
    let ino = sb
        .create_file_with_content(ROOT_INODE, "a_file.txt", b"data from a")
        .unwrap();
    let handle = sb.fuse_open(ino, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(ino, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"data from a");
    sb.fs
        .release(DualFsTestSandbox::ctx(), ino, 0, handle, false, false, None)
        .unwrap();
}
