use super::*;

//--------------------------------------------------------------------------------------------------
// Tests: Nested /.vol lookup (subdirectory inode resolution)
//--------------------------------------------------------------------------------------------------

/// Lookup a file inside a nested subdirectory — exercises /.vol lookup for
/// the subdirectory inode used as the parent fd in the child lookup.
#[test]
fn test_vol_lookup_nested_subdir() {
    let sb = TestSandbox::new();
    sb.host_create_dir("a");
    sb.host_create_dir("a/b");
    sb.host_create_file("a/b/deep.txt", b"deep");

    let dir_a = sb.lookup_root("a").unwrap();
    let dir_b = sb.lookup(dir_a.inode, "b").unwrap();
    let file = sb.lookup(dir_b.inode, "deep.txt").unwrap();
    assert!(file.inode >= 3);

    // Verify we can actually read the file via its inode.
    let handle = sb.fuse_open(file.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(file.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"deep");
}

/// Lookup a deeply nested path (3 levels) — each intermediate lookup goes
/// through get_inode_fd which opens via /.vol on macOS.
#[test]
fn test_vol_lookup_three_levels() {
    let sb = TestSandbox::new();
    sb.host_create_dir("x");
    sb.host_create_dir("x/y");
    sb.host_create_dir("x/y/z");
    sb.host_create_file("x/y/z/leaf.txt", b"leaf");

    let x = sb.lookup_root("x").unwrap();
    let y = sb.lookup(x.inode, "y").unwrap();
    let z = sb.lookup(y.inode, "z").unwrap();
    let leaf = sb.lookup(z.inode, "leaf.txt").unwrap();

    let handle = sb.fuse_open(leaf.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(leaf.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"leaf");
}

//--------------------------------------------------------------------------------------------------
// Tests: /.vol after rename (inode identity stability)
//--------------------------------------------------------------------------------------------------

/// After renaming a file, the existing inode should still be accessible
/// via getattr — /.vol references by dev+ino, not by name.
#[test]
fn test_vol_lookup_stable_after_rename() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("before.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"renamed", 0).unwrap();

    // Rename via FUSE.
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("before.txt"),
            ROOT_INODE,
            &TestSandbox::cstr("after.txt"),
            0,
        )
        .unwrap();

    // Old name gone.
    TestSandbox::assert_errno(sb.lookup_root("before.txt"), LINUX_ENOENT);

    // Inode should still be valid (/.vol path uses dev+ino, not name).
    let (st, _) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_eq!(
        st.st_mode as u32 & libc::S_IFMT as u32,
        libc::S_IFREG as u32
    );

    // Data should still be readable.
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"renamed");
}

/// Rename a directory and verify nested lookups still work through the
/// renamed parent's inode.
#[test]
fn test_vol_lookup_dir_after_rename() {
    let sb = TestSandbox::new();
    sb.host_create_dir("olddir");
    sb.host_create_file("olddir/child.txt", b"child");
    let dir_entry = sb.lookup_root("olddir").unwrap();

    // Rename the directory.
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("olddir"),
            ROOT_INODE,
            &TestSandbox::cstr("newdir"),
            0,
        )
        .unwrap();

    // Child lookup via old inode should still work (inode identity stable).
    let child = sb.lookup(dir_entry.inode, "child.txt").unwrap();
    let handle = sb.fuse_open(child.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(child.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"child");
}

//--------------------------------------------------------------------------------------------------
// Tests: /.vol after unlink (stale path behavior)
//--------------------------------------------------------------------------------------------------

/// After unlink, open_inode_fd should use the unlinked_fd (macOS) or
/// /proc/self/fd (Linux) to still reach the file data.
#[test]
fn test_vol_open_inode_after_unlink() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("vol_unlink.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"alive", 0).unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    // Extra lookup to keep inode alive after unlink.
    let _ = sb.lookup_root("vol_unlink.txt").unwrap();

    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("vol_unlink.txt"))
        .unwrap();

    // open_inode_fd should succeed (using unlinked_fd on macOS).
    let handle2 = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle2, 1024, 0).unwrap();
    assert_eq!(&data[..], b"alive");
}

/// getattr after unlink via stat_inode.
///
/// Both Linux (/proc/self/fd) and macOS (unlinked_fd) should return valid
/// attributes for an inode that was unlinked but still has references.
#[test]
fn test_vol_getattr_after_unlink() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("stat_unlink.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"12345", 0).unwrap();

    // Extra lookup to keep inode alive.
    let _ = sb.lookup_root("stat_unlink.txt").unwrap();

    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("stat_unlink.txt"))
        .unwrap();

    let (st, _) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_eq!(st.st_size, 5, "file size should be 5 after writing 5 bytes");
}

//--------------------------------------------------------------------------------------------------
// Tests: /.vol fallback logic
//--------------------------------------------------------------------------------------------------

/// open_vol_fd tries O_DIRECTORY first, then falls back to O_RDONLY.
/// Verify that files (non-directories) are accessible via get_inode_fd.
#[test]
fn test_vol_file_inode_fd_works() {
    let sb = TestSandbox::new();
    sb.host_create_file("plain.txt", b"data");
    let entry = sb.lookup_root("plain.txt").unwrap();

    // getattr exercises get_inode_fd → open_vol_fd on macOS.
    let (st, _) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_eq!(
        st.st_mode as u32 & libc::S_IFMT as u32,
        libc::S_IFREG as u32
    );
}

/// Verify that directories are accessible via get_inode_fd (the O_DIRECTORY
/// first-try path in open_vol_fd).
#[test]
fn test_vol_dir_inode_fd_works() {
    let sb = TestSandbox::new();
    sb.host_create_dir("somedir");
    let entry = sb.lookup_root("somedir").unwrap();

    let (st, _) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_eq!(
        st.st_mode as u32 & libc::S_IFMT as u32,
        libc::S_IFDIR as u32
    );
}

/// After forgetting an inode, operations on it should fail (/.vol fd can't
/// be opened because the inode is no longer tracked).
#[test]
fn test_vol_forgotten_inode_ebadf() {
    let sb = TestSandbox::new();
    sb.host_create_file("forgotten.txt", b"data");
    let entry = sb.lookup_root("forgotten.txt").unwrap();
    sb.fs.forget(sb.ctx(), entry.inode, 1);

    let result = sb.fs.getattr(sb.ctx(), entry.inode, None);
    assert!(result.is_err(), "getattr on forgotten inode should fail");
}

//--------------------------------------------------------------------------------------------------
// Tests: Cross-directory rename with /.vol inode identity
//--------------------------------------------------------------------------------------------------

/// Move a file between directories — the inode should keep working because
/// /.vol references dev+ino, not the directory entry.
#[test]
fn test_vol_cross_dir_rename() {
    let sb = TestSandbox::new();
    let src_dir = sb.fuse_mkdir_root("src").unwrap();
    let dst_dir = sb.fuse_mkdir_root("dst").unwrap();
    let (entry, handle) = sb.fuse_create(src_dir.inode, "moving.txt", 0o644).unwrap();
    sb.fuse_write(entry.inode, handle, b"moved", 0).unwrap();

    sb.fs
        .rename(
            sb.ctx(),
            src_dir.inode,
            &TestSandbox::cstr("moving.txt"),
            dst_dir.inode,
            &TestSandbox::cstr("moved.txt"),
            0,
        )
        .unwrap();

    // Inode should still be valid after cross-directory move.
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"moved");

    // New name should be resolvable.
    let new_entry = sb.lookup(dst_dir.inode, "moved.txt").unwrap();
    assert_eq!(
        new_entry.inode, entry.inode,
        "renamed file should keep same inode"
    );
}
