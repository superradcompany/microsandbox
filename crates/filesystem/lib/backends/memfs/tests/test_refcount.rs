use super::*;

#[test]
fn test_forget_removes_path() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("forget_me.txt").unwrap();
    let handle = handle.unwrap();
    sb.fs
        .release(
            MemFsTestSandbox::ctx(),
            entry.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();

    // Unlink sets nlink=0.
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("forget_me.txt"),
        )
        .unwrap();

    // Forget the lookup ref from create (lookup_refs goes to 0).
    sb.fs.forget(MemFsTestSandbox::ctx(), entry.inode, 1);

    // Node should be evicted.
    let result = sb.fs.getattr(MemFsTestSandbox::ctx(), entry.inode, None);
    assert!(result.is_err());
}

#[test]
fn test_forget_partial() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("partial.txt").unwrap();
    let handle = handle.unwrap();
    sb.fs
        .release(
            MemFsTestSandbox::ctx(),
            entry.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();

    // Three more lookups (create gives 1, so total refs = 4).
    sb.lookup_root("partial.txt").unwrap();
    sb.lookup_root("partial.txt").unwrap();
    sb.lookup_root("partial.txt").unwrap();

    // Forget only 1 ref.
    sb.fs.forget(MemFsTestSandbox::ctx(), entry.inode, 1);

    // Node should still be accessible (3 refs remain, and nlink=1).
    let result = sb.fs.getattr(MemFsTestSandbox::ctx(), entry.inode, None);
    assert!(result.is_ok());
}

#[test]
fn test_nlink_zero_lookup_refs_positive() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("nlink_test.txt").unwrap();
    let handle = handle.unwrap();
    sb.fs
        .release(
            MemFsTestSandbox::ctx(),
            entry.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();

    // Do an extra lookup to increase refs (create=1, lookup=1 => refs=2).
    sb.lookup_root("nlink_test.txt").unwrap();

    // Unlink sets nlink=0 but lookup_refs=2, so node stays.
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("nlink_test.txt"),
        )
        .unwrap();

    // Node should still be accessible via getattr.
    let result = sb.fs.getattr(MemFsTestSandbox::ctx(), entry.inode, None);
    assert!(result.is_ok());

    // Forget all refs to evict.
    sb.fs.forget(MemFsTestSandbox::ctx(), entry.inode, 2);

    // Now it should be gone.
    let result = sb.fs.getattr(MemFsTestSandbox::ctx(), entry.inode, None);
    assert!(result.is_err());
}

#[test]
fn test_handle_pins_node() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("pinned.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"pinned data", 0)
        .unwrap();

    // Unlink and forget.
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("pinned.txt"),
        )
        .unwrap();
    sb.fs.forget(MemFsTestSandbox::ctx(), entry.inode, 1);

    // Handle should still work (handle's Arc keeps node alive).
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"pinned data");
}

#[test]
fn test_handle_release_frees() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("release_free.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();

    // Unlink and forget (node evicted from table but handle's Arc alive).
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("release_free.txt"),
        )
        .unwrap();
    sb.fs.forget(MemFsTestSandbox::ctx(), entry.inode, 1);

    // Release handle — should drop the last Arc.
    sb.fs
        .release(
            MemFsTestSandbox::ctx(),
            entry.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();

    // Handle no longer works.
    let result = sb.fuse_read(entry.inode, handle, 1024, 0);
    MemFsTestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_batch_forget() {
    let sb = MemFsTestSandbox::new();
    let (e1, h1) = sb.fuse_create_root("batch1.txt").unwrap();
    let h1 = h1.unwrap();
    let (e2, h2) = sb.fuse_create_root("batch2.txt").unwrap();
    let h2 = h2.unwrap();
    let (e3, h3) = sb.fuse_create_root("batch3.txt").unwrap();
    let h3 = h3.unwrap();

    // Release handles.
    sb.fs
        .release(MemFsTestSandbox::ctx(), e1.inode, 0, h1, false, false, None)
        .unwrap();
    sb.fs
        .release(MemFsTestSandbox::ctx(), e2.inode, 0, h2, false, false, None)
        .unwrap();
    sb.fs
        .release(MemFsTestSandbox::ctx(), e3.inode, 0, h3, false, false, None)
        .unwrap();

    // Unlink all.
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("batch1.txt"),
        )
        .unwrap();
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("batch2.txt"),
        )
        .unwrap();
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("batch3.txt"),
        )
        .unwrap();

    // Batch forget all three.
    sb.fs.batch_forget(
        MemFsTestSandbox::ctx(),
        vec![(e1.inode, 1), (e2.inode, 1), (e3.inode, 1)],
    );

    // All should be evicted.
    assert!(
        sb.fs
            .getattr(MemFsTestSandbox::ctx(), e1.inode, None)
            .is_err()
    );
    assert!(
        sb.fs
            .getattr(MemFsTestSandbox::ctx(), e2.inode, None)
            .is_err()
    );
    assert!(
        sb.fs
            .getattr(MemFsTestSandbox::ctx(), e3.inode, None)
            .is_err()
    );
}
