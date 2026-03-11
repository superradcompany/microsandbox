use super::*;

#[test]
fn test_lookup_empty() {
    let sb = TestSandbox::new();
    let result = sb.fs.lookup(sb.ctx(), ROOT_INODE, &TestSandbox::cstr(""));
    TestSandbox::assert_errno(result, LINUX_EINVAL);
}

#[test]
fn test_lookup_dotdot() {
    let sb = TestSandbox::new();
    let result = sb.lookup_root("..");
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_lookup_slash() {
    let sb = TestSandbox::new();
    let result = sb.lookup_root("a/b");
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_lookup_backslash_allowed() {
    // Backslash is a valid filename character on Linux — not rejected.
    let sb = TestSandbox::new();
    sb.fuse_create_root("a\\b").unwrap();
    let result = sb.lookup_root("a\\b");
    assert!(result.is_ok());
}

#[test]
fn test_create_empty() {
    let sb = TestSandbox::new();
    let result = sb.fs.create(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr(""),
        0o644,
        false,
        libc::O_RDWR as u32,
        0,
        Extensions::default(),
    );
    TestSandbox::assert_errno(result, LINUX_EINVAL);
}

#[test]
fn test_create_dotdot() {
    let sb = TestSandbox::new();
    let result = sb.fs.create(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr(".."),
        0o644,
        false,
        libc::O_RDWR as u32,
        0,
        Extensions::default(),
    );
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_create_slash() {
    let sb = TestSandbox::new();
    let result = sb.fs.create(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr("a/b"),
        0o644,
        false,
        libc::O_RDWR as u32,
        0,
        Extensions::default(),
    );
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_mkdir_dotdot() {
    let sb = TestSandbox::new();
    let result = sb.fs.mkdir(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr(".."),
        0o755,
        0,
        Extensions::default(),
    );
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_unlink_dotdot() {
    let sb = TestSandbox::new();
    let result = sb.fs.unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr(".."));
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_rmdir_slash() {
    let sb = TestSandbox::new();
    let result = sb.fs.rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("a/b"));
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_rename_old_dotdot() {
    let sb = TestSandbox::new();
    sb.fuse_create_root("target").unwrap();
    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr(".."),
        ROOT_INODE,
        &TestSandbox::cstr("target"),
        0,
    );
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_rename_new_backslash_allowed() {
    // Backslash is a valid filename character on Linux — not rejected.
    let sb = TestSandbox::new();
    sb.fuse_create_root("source").unwrap();
    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr("source"),
        ROOT_INODE,
        &TestSandbox::cstr("a\\b"),
        0,
    );
    assert!(result.is_ok());
}

#[test]
fn test_symlink_name_dotdot() {
    let sb = TestSandbox::new();
    let result = sb.fs.symlink(
        sb.ctx(),
        &TestSandbox::cstr("/target"),
        ROOT_INODE,
        &TestSandbox::cstr(".."),
        Extensions::default(),
    );
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_link_name_slash() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("source").unwrap();
    let result = sb
        .fs
        .link(sb.ctx(), entry.inode, ROOT_INODE, &TestSandbox::cstr("a/b"));
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_mknod_backslash_allowed() {
    // Backslash is a valid filename character on Linux — not rejected.
    let sb = TestSandbox::new();
    let result = sb.fs.mknod(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr("a\\b"),
        libc::S_IFREG as u32 | 0o644,
        0,
        0,
        Extensions::default(),
    );
    assert!(result.is_ok());
}
