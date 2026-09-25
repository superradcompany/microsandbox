#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;

use super::*;

#[test]
fn test_remaining_hard_link_can_reopen_for_write_and_truncate() {
    for (removed, remaining) in [("original", "alias"), ("alias", "original")] {
        let sb = TestSandbox::new();
        let (entry, handle) = sb.fuse_create_root("original").unwrap();
        sb.fuse_write(entry.inode, handle, b"before", 0).unwrap();
        sb.fs
            .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
            .unwrap();
        let alias = sb
            .fs
            .link(sb.ctx(), entry.inode, ROOT_INODE, c"alias")
            .unwrap();
        assert_eq!(alias.attr.st_nlink, 2);

        sb.fs
            .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr(removed))
            .unwrap();
        let remaining = sb.lookup_root(remaining).unwrap();
        assert_eq!(remaining.inode, entry.inode);
        assert_eq!(remaining.attr.st_nlink, 1);

        // Reopen after unlink: an existing writable handle would hide the bug.
        let handle = sb.fuse_open(remaining.inode, LINUX_O_RDWR).unwrap();
        sb.fuse_write(remaining.inode, handle, b"!", 6).unwrap();
        assert_eq!(
            sb.fuse_read(remaining.inode, handle, 32, 0).unwrap(),
            b"before!"
        );
        let mut attr: stat64 = unsafe { std::mem::zeroed() };
        attr.st_size = 3;
        let (st, _) = sb
            .fs
            .setattr(
                sb.ctx(),
                remaining.inode,
                attr,
                Some(handle),
                SetattrValid::SIZE,
            )
            .unwrap();
        assert_eq!(st.st_size, 3);
        assert_eq!(
            sb.fuse_read(remaining.inode, handle, 32, 0).unwrap(),
            b"bef"
        );
        sb.fs
            .release(sb.ctx(), remaining.inode, 0, handle, false, false, None)
            .unwrap();

        let handle = sb
            .fuse_open(remaining.inode, LINUX_O_RDWR | LINUX_O_TRUNC)
            .unwrap();
        assert!(
            sb.fuse_read(remaining.inode, handle, 32, 0)
                .unwrap()
                .is_empty()
        );
        sb.fs
            .release(sb.ctx(), remaining.inode, 0, handle, false, false, None)
            .unwrap();
    }
}

#[test]
fn test_read_via_handle_after_unlink() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("doomed.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"still here", 0)
        .unwrap();

    // Unlink the file — name is gone but handle keeps data alive.
    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("doomed.txt"))
        .unwrap();

    // Lookup should fail — name is removed.
    let result = sb.lookup_root("doomed.txt");
    TestSandbox::assert_errno(result, LINUX_ENOENT);

    // Read via existing handle should still work.
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(
        &data[..],
        b"still here",
        "data should be readable after unlink via open handle"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn test_reopen_after_host_removes_remaining_hard_link() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("original").unwrap();
    sb.fuse_write(entry.inode, handle, b"still here", 0)
        .unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    sb.fs
        .link(sb.ctx(), entry.inode, ROOT_INODE, c"alias")
        .unwrap();
    sb.fs.unlink(sb.ctx(), ROOT_INODE, c"original").unwrap();

    // The host bypasses FUSE, so the backend gets no final-unlink notification.
    std::fs::remove_file(sb.root.join("alias")).unwrap();
    let handle = sb.fuse_open(entry.inode, LINUX_O_RDWR).unwrap();
    assert_eq!(
        sb.fuse_read(entry.inode, handle, 32, 0).unwrap(),
        b"still here"
    );
    sb.fuse_write(entry.inode, handle, b"!", 10).unwrap();
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 5;
    sb.fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            Some(handle),
            SetattrValid::SIZE,
        )
        .unwrap();
    assert_eq!(sb.fuse_read(entry.inode, handle, 32, 0).unwrap(), b"still");
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // A writable retained descriptor must not widen a read-only guest handle.
    let readonly = sb.fuse_open(entry.inode, 0).unwrap();
    TestSandbox::assert_errno(sb.fuse_write(entry.inode, readonly, b"bad", 0), LINUX_EBADF);
    TestSandbox::assert_errno(
        sb.fs.setattr(
            sb.ctx(),
            entry.inode,
            attr,
            Some(readonly),
            SetattrValid::SIZE,
        ),
        LINUX_EINVAL,
    );
    TestSandbox::assert_errno(
        sb.fs.fallocate(sb.ctx(), entry.inode, readonly, 0, 0, 32),
        LINUX_EBADF,
    );
    assert_eq!(
        sb.fuse_read(entry.inode, readonly, 32, 0).unwrap(),
        b"still"
    );
    sb.fs
        .release(sb.ctx(), entry.inode, 0, readonly, false, false, None)
        .unwrap();

    // Linux O_WRONLY | O_APPEND; writes use the offset supplied by FUSE.
    let append = sb.fuse_open(entry.inode, 1 | 0x400).unwrap();
    sb.fuse_write(entry.inode, append, b"!", 5).unwrap();
    TestSandbox::assert_errno(sb.fuse_read(entry.inode, append, 32, 0), LINUX_EBADF);
    sb.fs
        .release(sb.ctx(), entry.inode, 0, append, false, false, None)
        .unwrap();
    let handle = sb
        .fuse_open(entry.inode, LINUX_O_RDWR | LINUX_O_TRUNC)
        .unwrap();
    assert!(sb.fuse_read(entry.inode, handle, 32, 0).unwrap().is_empty());
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn test_detached_readonly_host_file_rejects_writable_reopen() {
    // Root can open host files for writing regardless of their mode bits.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for revoke_after_pin in [false, true] {
        let sb = TestSandbox::new();
        let (entry, existing_handle) = sb.fuse_create_root("readonly").unwrap();
        sb.fuse_write(entry.inode, existing_handle, b"keep", 0)
            .unwrap();
        sb.fs
            .link(sb.ctx(), entry.inode, ROOT_INODE, c"alias")
            .unwrap();
        if !revoke_after_pin {
            std::fs::set_permissions(
                sb.root.join("alias"),
                std::fs::Permissions::from_mode(0o400),
            )
            .unwrap();
        }
        sb.fs.unlink(sb.ctx(), ROOT_INODE, c"readonly").unwrap();
        if revoke_after_pin {
            std::fs::set_permissions(
                sb.root.join("alias"),
                std::fs::Permissions::from_mode(0o400),
            )
            .unwrap();
        }
        std::fs::remove_file(sb.root.join("alias")).unwrap();

        for flags in [1, LINUX_O_RDWR, LINUX_O_RDWR | LINUX_O_TRUNC, LINUX_O_TRUNC] {
            TestSandbox::assert_errno(sb.fuse_open(entry.inode, flags), LINUX_EACCES);
        }
        // Permission changes gate new opens, not already-open writable handles.
        sb.fuse_write(entry.inode, existing_handle, b"okay", 0)
            .unwrap();
        let handle = sb.fuse_open(entry.inode, 0).unwrap();
        assert_eq!(sb.fuse_read(entry.inode, handle, 32, 0).unwrap(), b"okay");
        sb.fs
            .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
            .unwrap();
        sb.fs
            .release(
                sb.ctx(),
                entry.inode,
                0,
                existing_handle,
                false,
                false,
                None,
            )
            .unwrap();
    }
}

#[test]
fn test_write_via_handle_after_unlink() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("doomed_write.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"before", 0).unwrap();

    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("doomed_write.txt"))
        .unwrap();

    // Write via existing handle should still work.
    sb.fuse_write(entry.inode, handle, b"after!", 0).unwrap();

    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(
        &data[..],
        b"after!",
        "data should be writable after unlink via open handle"
    );
}

#[test]
fn test_open_inode_after_unlink() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("reopen.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"reopen data", 0)
        .unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    // Bump refcount so inode stays in the table after unlink.
    // (The create gave refcount=1; we need the inode alive after unlink.)
    let _ = sb.lookup_root("reopen.txt").unwrap(); // refcount=2

    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("reopen.txt"))
        .unwrap();

    // Open the inode by number (macOS uses unlinked_fd, Linux uses /proc/self/fd).
    let handle2 = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle2, 1024, 0).unwrap();
    assert_eq!(
        &data[..],
        b"reopen data",
        "should be able to open inode after unlink"
    );
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle2, false, false, None)
        .unwrap();
}

#[test]
fn test_release_after_unlink() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("release_unlink.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();

    sb.fs
        .unlink(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("release_unlink.txt"),
        )
        .unwrap();

    // Release should succeed even after unlink.
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    // Handle is now gone — reading should fail.
    let result = sb.fuse_read(entry.inode, handle, 1024, 0);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_flush_after_unlink() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("flush_unlink.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();

    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("flush_unlink.txt"))
        .unwrap();

    // Flush should succeed — it dup+closes the fd.
    let result = sb.fs.flush(sb.ctx(), entry.inode, handle, 0);
    assert!(result.is_ok(), "flush should succeed after unlink");
}
