use super::*;

#[test]
fn test_lookup_file() {
    let sb = MemFsTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("hello.txt").unwrap();
    let looked = sb.lookup_root("hello.txt").unwrap();
    assert_eq!(looked.inode, entry.inode);
    let mode = looked.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert_eq!(mode & 0o777, 0o644);
}

#[test]
fn test_lookup_directory() {
    let sb = MemFsTestSandbox::new();
    let entry = sb.fuse_mkdir_root("subdir").unwrap();
    let looked = sb.lookup_root("subdir").unwrap();
    assert_eq!(looked.inode, entry.inode);
    let mode = looked.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
    #[cfg(target_os = "linux")]
    assert_eq!(looked.attr.st_nlink, 2);
    #[cfg(target_os = "macos")]
    assert_eq!(looked.attr.st_nlink, 2);
}

#[test]
fn test_lookup_nested() {
    let sb = MemFsTestSandbox::new();
    let dir_a = sb.fuse_mkdir_root("a").unwrap();
    let dir_b = sb.fuse_mkdir(dir_a.inode, "b", 0o755).unwrap();
    let dir_c = sb.fuse_mkdir(dir_b.inode, "c", 0o755).unwrap();
    let (file_entry, _) = sb.fuse_create(dir_c.inode, "file.txt", 0o644).unwrap();

    let a = sb.lookup_root("a").unwrap();
    assert_eq!(a.inode, dir_a.inode);
    let b = sb.lookup(a.inode, "b").unwrap();
    assert_eq!(b.inode, dir_b.inode);
    let c = sb.lookup(b.inode, "c").unwrap();
    assert_eq!(c.inode, dir_c.inode);
    let f = sb.lookup(c.inode, "file.txt").unwrap();
    assert_eq!(f.inode, file_entry.inode);
}

#[test]
fn test_lookup_nonexistent() {
    let sb = MemFsTestSandbox::new();
    let result = sb.lookup_root("missing.txt");
    MemFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_lookup_refcount() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("ref_test.txt").unwrap();
    // Create starts with lookup_refs=1. Three more lookups.
    sb.lookup_root("ref_test.txt").unwrap();
    sb.lookup_root("ref_test.txt").unwrap();
    sb.lookup_root("ref_test.txt").unwrap();
    // Inode should still be accessible.
    let looked = sb.lookup_root("ref_test.txt").unwrap();
    assert_eq!(looked.inode, entry.inode);
    // Forget all refs (create gives 1, 3 lookups give 3, last lookup gives 1 = 5 total).
    sb.fs.forget(MemFsTestSandbox::ctx(), entry.inode, 5);
    // File is still linked in parent, so lookup should still work.
    let looked = sb.lookup_root("ref_test.txt").unwrap();
    assert_eq!(looked.inode, entry.inode);
}

#[test]
fn test_lookup_after_forget() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("ephemeral.txt").unwrap();
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
    // Unlink file.
    sb.fs
        .unlink(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("ephemeral.txt"),
        )
        .unwrap();
    // Forget the lookup ref from create.
    sb.fs.forget(MemFsTestSandbox::ctx(), entry.inode, 1);
    // Lookup should fail now.
    let result = sb.lookup_root("ephemeral.txt");
    MemFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_lookup_dot_dot() {
    let sb = MemFsTestSandbox::new();
    let result = sb.fs.lookup(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr(".."),
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_lookup_slash_in_name() {
    let sb = MemFsTestSandbox::new();
    let result = sb.fs.lookup(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("a/b"),
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_lookup_empty_name() {
    let sb = MemFsTestSandbox::new();
    let name = c"";
    let result = sb.fs.lookup(MemFsTestSandbox::ctx(), ROOT_INODE, name);
    MemFsTestSandbox::assert_errno(result, LINUX_EINVAL);
}
