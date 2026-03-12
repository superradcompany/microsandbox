use super::*;

#[test]
fn test_init_krun_lookup() {
    let sb = DualFsTestSandbox::new();
    let entry = sb.lookup_root("init.krun").unwrap();
    assert_eq!(entry.inode, INIT_INODE);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert_eq!(mode & 0o777, 0o755, "init.krun should be executable");
}

#[test]
fn test_init_krun_not_from_children() {
    // Each child MemFs has its own init.krun at inode 2.
    // DualFs should present only ONE init.krun — its own.
    let sb = DualFsTestSandbox::new();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    let init_count = names.iter().filter(|n| n.as_str() == "init.krun").count();
    assert_eq!(
        init_count, 1,
        "only one init.krun should be visible in root readdir"
    );
}

#[test]
fn test_init_krun_read() {
    let sb = DualFsTestSandbox::new();
    let (handle, _opts) = sb
        .fs
        .open(DualFsTestSandbox::ctx(), INIT_INODE, false, libc::O_RDONLY as u32)
        .unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(INIT_INODE, handle, 4096, 0).unwrap();
    assert!(!data.is_empty(), "init.krun should return data on read");
    sb.fs
        .release(DualFsTestSandbox::ctx(), INIT_INODE, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_init_krun_write_fails() {
    let sb = DualFsTestSandbox::new();
    let (handle, _opts) = sb
        .fs
        .open(DualFsTestSandbox::ctx(), INIT_INODE, false, libc::O_RDONLY as u32)
        .unwrap();
    let handle = handle.unwrap();
    let mut reader = MockZeroCopyReader::new(vec![0u8; 10]);
    let result = sb.fs.write(
        DualFsTestSandbox::ctx(),
        INIT_INODE,
        handle,
        &mut reader,
        10,
        0,
        None,
        false,
        false,
        0,
    );
    DualFsTestSandbox::assert_errno(result, LINUX_EACCES);
    sb.fs
        .release(DualFsTestSandbox::ctx(), INIT_INODE, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_init_krun_unlink_fails() {
    let sb = DualFsTestSandbox::new();
    let result = sb.fs.unlink(
        DualFsTestSandbox::ctx(),
        ROOT_INODE,
        &DualFsTestSandbox::cstr("init.krun"),
    );
    // DualFs uses libc::EPERM (not EACCES) to protect init.krun from unlink/rmdir/rename.
    DualFsTestSandbox::assert_errno(result, LINUX_EPERM);
}
