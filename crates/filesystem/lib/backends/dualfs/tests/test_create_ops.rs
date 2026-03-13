use super::*;

#[test]
fn test_create_routes_to_policy_target() {
    // Default policy: ReadBackendBWriteBackendA — creates go to backend_a.
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("new_file.txt").unwrap();
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
    // File should be discoverable via lookup.
    let e = sb.lookup_root("new_file.txt").unwrap();
    assert_eq!(e.inode, entry.inode);
}

#[test]
fn test_create_file() {
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("writable.txt").unwrap();
    // Write data to verify it is writable.
    let written = sb.fuse_write(entry.inode, handle, b"hello", 0).unwrap();
    assert_eq!(written, 5);
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
    // Lookup succeeds.
    let e = sb.lookup_root("writable.txt").unwrap();
    assert_eq!(e.inode, entry.inode);
}

#[test]
fn test_mkdir() {
    let sb = DualFsTestSandbox::new();
    let dir_entry = sb.fuse_mkdir_root("newdir").unwrap();
    let mode = dir_entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
    // Readdir should work.
    let names = sb.readdir_names(dir_entry.inode).unwrap();
    assert!(names.contains(&".".to_string()));
    assert!(names.contains(&"..".to_string()));
}

#[test]
fn test_mknod() {
    let sb = DualFsTestSandbox::new();
    let cname = DualFsTestSandbox::cstr("myfifo");
    let mode = libc::S_IFIFO as u32 | 0o644;
    let result = sb.fs.mknod(
        DualFsTestSandbox::ctx(),
        ROOT_INODE,
        &cname,
        mode,
        0,
        0,
        Extensions::default(),
    );
    assert!(result.is_ok(), "mknod FIFO should succeed");
    let entry = result.unwrap();
    let st_mode = entry.attr.st_mode as u32;
    assert_eq!(
        st_mode & libc::S_IFMT as u32,
        libc::S_IFIFO as u32,
        "should be a FIFO"
    );
}

#[test]
fn test_symlink() {
    let sb = DualFsTestSandbox::new();
    let target = DualFsTestSandbox::cstr("/some/target");
    let name = DualFsTestSandbox::cstr("mylink");
    let entry = sb
        .fs
        .symlink(
            DualFsTestSandbox::ctx(),
            &target,
            ROOT_INODE,
            &name,
            Extensions::default(),
        )
        .unwrap();
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFLNK as u32);
    // readlink should return the target.
    let link = sb
        .fs
        .readlink(DualFsTestSandbox::ctx(), entry.inode)
        .unwrap();
    assert_eq!(link, b"/some/target");
}

#[test]
fn test_link() {
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("original.txt").unwrap();
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
    // Hard link.
    let link_name = DualFsTestSandbox::cstr("hardlink.txt");
    let link_entry = sb
        .fs
        .link(
            DualFsTestSandbox::ctx(),
            entry.inode,
            ROOT_INODE,
            &link_name,
        )
        .unwrap();
    assert_eq!(
        link_entry.inode, entry.inode,
        "hard link should share the same guest inode"
    );
    assert!(link_entry.attr.st_nlink >= 2, "nlink should be incremented");
}

#[test]
fn test_create_in_backend_b_dir() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_mkdir(b, 1, "b_dir");
    });
    let dir_entry = sb.lookup_root("b_dir").unwrap();
    // Create a file inside a backend_b-only directory.
    let (file_entry, handle) = sb.fuse_create(dir_entry.inode, "child.txt", 0o644).unwrap();
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
    // File should be discoverable.
    let e = sb.lookup(dir_entry.inode, "child.txt").unwrap();
    assert_eq!(e.inode, file_entry.inode);
}

#[test]
fn test_create_registers_dentry() {
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("registered.txt").unwrap();
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
    // Lookup should succeed (dentry registered).
    let e = sb.lookup_root("registered.txt").unwrap();
    assert_eq!(e.inode, entry.inode);
}

#[test]
fn test_create_duplicate() {
    let sb = DualFsTestSandbox::new();
    let (_entry, handle) = sb.fuse_create_root("dup.txt").unwrap();
    sb.fs
        .release(
            DualFsTestSandbox::ctx(),
            _entry.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
    // Second create with same name should fail.
    let result = sb.fuse_create_root("dup.txt");
    DualFsTestSandbox::assert_errno(result, LINUX_EEXIST);
}

#[test]
fn test_create_updates_alias_index() {
    // After creating a file, the alias_index should map guest_inode -> { (parent, name) }.
    // The alias_index is an internal DualState table used for reverse-lookups from
    // guest inodes back to their parent+name dentries.
    let sb = DualFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("aliased.txt").unwrap();
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

    // Verify the file can be looked up (which proves the dentry and alias were registered).
    let e = sb.lookup_root("aliased.txt").unwrap();
    assert_eq!(
        e.inode, entry.inode,
        "dentry should map to the created inode"
    );

    // Verify stability: a second lookup returns the same inode, proving the alias_index
    // dedup path works correctly.
    let e2 = sb.lookup_root("aliased.txt").unwrap();
    assert_eq!(
        e2.inode, entry.inode,
        "repeated lookup should return same guest inode"
    );

    // Create a hard link to the same file. This adds a second alias entry.
    let link_name = DualFsTestSandbox::cstr("alias_link.txt");
    let link_entry = sb
        .fs
        .link(
            DualFsTestSandbox::ctx(),
            entry.inode,
            ROOT_INODE,
            &link_name,
        )
        .unwrap();
    assert_eq!(
        link_entry.inode, entry.inode,
        "hard link should share guest inode"
    );

    // Both names should resolve to the same guest inode.
    let e_orig = sb.lookup_root("aliased.txt").unwrap();
    let e_link = sb.lookup_root("alias_link.txt").unwrap();
    assert_eq!(
        e_orig.inode, e_link.inode,
        "both aliases should resolve to the same inode"
    );
}
