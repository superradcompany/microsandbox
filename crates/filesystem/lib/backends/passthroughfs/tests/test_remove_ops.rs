use super::*;

#[test]
fn test_unlink_file() {
    let sb = TestSandbox::new();
    sb.fuse_create_root("to_delete.txt").unwrap();
    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("to_delete.txt"))
        .unwrap();
    let result = sb.lookup_root("to_delete.txt");
    TestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_unlink_nonexistent() {
    let sb = TestSandbox::new();
    let result = sb
        .fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("does_not_exist"));
    TestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_unlink_init_rejected() {
    let sb = TestSandbox::new();
    let result = sb
        .fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("init.krun"));
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_rmdir_empty() {
    let sb = TestSandbox::new();
    sb.fuse_mkdir_root("empty_dir").unwrap();
    sb.fs
        .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("empty_dir"))
        .unwrap();
    let result = sb.lookup_root("empty_dir");
    TestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_rmdir_nonempty() {
    let sb = TestSandbox::new();
    let dir = sb.fuse_mkdir_root("nonempty").unwrap();
    sb.fuse_create(dir.inode, "child.txt", 0o644).unwrap();
    let result = sb
        .fs
        .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("nonempty"));
    TestSandbox::assert_errno(result, LINUX_ENOTEMPTY);
}

#[test]
fn test_rmdir_init_rejected() {
    let sb = TestSandbox::new();
    let result = sb
        .fs
        .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("init.krun"));
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_rename_basic() {
    let sb = TestSandbox::new();
    sb.fuse_create_root("old_name.txt").unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("old_name.txt"),
            ROOT_INODE,
            &TestSandbox::cstr("new_name.txt"),
            0,
        )
        .unwrap();
    let result = sb.lookup_root("old_name.txt");
    TestSandbox::assert_errno(result, LINUX_ENOENT);
    let entry = sb.lookup_root("new_name.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_rename_across_dirs() {
    let sb = TestSandbox::new();
    let dir_a = sb.fuse_mkdir_root("dir_a").unwrap();
    let dir_b = sb.fuse_mkdir_root("dir_b").unwrap();
    sb.fuse_create(dir_a.inode, "moveme.txt", 0o644).unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            dir_a.inode,
            &TestSandbox::cstr("moveme.txt"),
            dir_b.inode,
            &TestSandbox::cstr("moveme.txt"),
            0,
        )
        .unwrap();
    let result = sb.lookup(dir_a.inode, "moveme.txt");
    TestSandbox::assert_errno(result, LINUX_ENOENT);
    let entry = sb.lookup(dir_b.inode, "moveme.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_rename_init_source() {
    let sb = TestSandbox::new();
    sb.fuse_create_root("target").unwrap();
    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr("init.krun"),
        ROOT_INODE,
        &TestSandbox::cstr("target"),
        0,
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_rename_init_target() {
    let sb = TestSandbox::new();
    sb.fuse_create_root("source").unwrap();
    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr("source"),
        ROOT_INODE,
        &TestSandbox::cstr("init.krun"),
        0,
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_rename_overwrite() {
    let sb = TestSandbox::new();
    let (entry_a, handle_a) = sb.fuse_create_root("a.txt").unwrap();
    sb.fuse_write(entry_a.inode, handle_a, b"data_a", 0)
        .unwrap();
    let (_entry_b, handle_b) = sb.fuse_create_root("b.txt").unwrap();
    sb.fuse_write(_entry_b.inode, handle_b, b"data_b", 0)
        .unwrap();
    // Rename a.txt -> b.txt with flags=0 (overwrite allowed).
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("a.txt"),
            ROOT_INODE,
            &TestSandbox::cstr("b.txt"),
            0,
        )
        .unwrap();
    // a.txt should be gone.
    let result = sb.lookup_root("a.txt");
    TestSandbox::assert_errno(result, LINUX_ENOENT);
    // b.txt should have a.txt's data.
    let entry = sb.lookup_root("b.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"data_a");
}

#[test]
fn test_rename_noreplace() {
    let sb = TestSandbox::new();
    sb.fuse_create_root("exist.txt").unwrap();
    sb.fuse_create_root("also_exist.txt").unwrap();
    // RENAME_NOREPLACE = 1 on Linux. Should fail when target exists.
    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr("exist.txt"),
        ROOT_INODE,
        &TestSandbox::cstr("also_exist.txt"),
        1, // RENAME_NOREPLACE
    );
    TestSandbox::assert_errno(result, LINUX_EEXIST);
}

#[cfg(target_os = "linux")]
#[test]
fn test_rename_exchange_same_inode_keeps_aliases() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("a.txt").unwrap();
    sb.fs
        .link(
            sb.ctx(),
            entry.inode,
            ROOT_INODE,
            &TestSandbox::cstr("b.txt"),
        )
        .unwrap();

    let alias = sb.lookup_root("b.txt").unwrap();
    assert_eq!(alias.inode, entry.inode);

    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("a.txt"),
            ROOT_INODE,
            &TestSandbox::cstr("b.txt"),
            2,
        )
        .unwrap();

    let data = {
        let inodes = sb.fs.inodes.read().unwrap();
        inodes.get(&entry.inode).cloned().unwrap()
    };
    let aliases = data.aliases.read().unwrap();
    assert_eq!(aliases.len(), 2);
    assert!(
        aliases.contains(&crate::backends::shared::inode_table::NamespaceAlias::new(
            ROOT_INODE, b"a.txt",
        ))
    );
    assert!(
        aliases.contains(&crate::backends::shared::inode_table::NamespaceAlias::new(
            ROOT_INODE, b"b.txt",
        ))
    );
}
