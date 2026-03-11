use super::*;
use crate::agentd::AGENTD_BYTES;

#[test]
fn test_init_lookup_inode_2() {
    let sb = TestSandbox::new();
    let entry = sb.lookup_root("init.krun").unwrap();
    assert_eq!(entry.inode, INIT_INODE);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert_eq!(mode & 0o777, 0o755);
}

#[test]
fn test_init_getattr() {
    let sb = TestSandbox::new();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), INIT_INODE, None).unwrap();
    assert_eq!(st.st_uid, 0);
    assert_eq!(st.st_gid, 0);
    assert_eq!(st.st_size, AGENTD_BYTES.len() as i64);
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert_eq!(mode & 0o777, 0o755);
}

#[test]
fn test_init_open_handle_0() {
    let sb = TestSandbox::new();
    let (handle, opts) = sb
        .fs
        .open(sb.ctx(), INIT_INODE, false, libc::O_RDONLY as u32)
        .unwrap();
    assert_eq!(handle, Some(INIT_HANDLE));
    assert_eq!(opts, OpenOptions::KEEP_CACHE);
}

#[test]
fn test_init_read_full() {
    let sb = TestSandbox::new();
    let data = sb
        .fuse_read(INIT_INODE, INIT_HANDLE, AGENTD_BYTES.len() as u32, 0)
        .unwrap();
    assert_eq!(data.len(), AGENTD_BYTES.len());
    assert_eq!(&data[..], AGENTD_BYTES);
}

#[test]
fn test_init_read_partial_from_start() {
    let sb = TestSandbox::new();
    let size = 64u32;
    let data = sb.fuse_read(INIT_INODE, INIT_HANDLE, size, 0).unwrap();
    assert_eq!(data.len(), size as usize);
    assert_eq!(&data[..], &AGENTD_BYTES[..size as usize]);
}

#[test]
fn test_init_read_at_offset() {
    let sb = TestSandbox::new();
    let offset = 100u64;
    let size = 64u32;
    let data = sb.fuse_read(INIT_INODE, INIT_HANDLE, size, offset).unwrap();
    assert_eq!(data.len(), size as usize);
    assert_eq!(
        &data[..],
        &AGENTD_BYTES[offset as usize..offset as usize + size as usize]
    );
}

#[test]
fn test_init_read_past_eof() {
    let sb = TestSandbox::new();
    let data = sb
        .fuse_read(INIT_INODE, INIT_HANDLE, 1024, AGENTD_BYTES.len() as u64)
        .unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn test_init_read_spanning_eof() {
    let sb = TestSandbox::new();
    let offset = AGENTD_BYTES.len() as u64 - 10;
    let data = sb.fuse_read(INIT_INODE, INIT_HANDLE, 1024, offset).unwrap();
    assert_eq!(data.len(), 10);
    assert_eq!(&data[..], &AGENTD_BYTES[offset as usize..]);
}

#[test]
fn test_init_write_rejected() {
    let sb = TestSandbox::new();
    let mut reader = MockZeroCopyReader::new(vec![0u8; 10]);
    let result = sb.fs.write(
        sb.ctx(),
        INIT_INODE,
        INIT_HANDLE,
        &mut reader,
        10,
        0,
        None,
        false,
        false,
        0,
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_setattr_rejected() {
    let sb = TestSandbox::new();
    let attr = unsafe { std::mem::zeroed() };
    let result = sb
        .fs
        .setattr(sb.ctx(), INIT_INODE, attr, None, SetattrValid::MODE);
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_unlink_rejected() {
    let sb = TestSandbox::new();
    let result = sb
        .fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("init.krun"));
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_rmdir_rejected() {
    let sb = TestSandbox::new();
    let result = sb
        .fs
        .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("init.krun"));
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_rename_source_rejected() {
    let sb = TestSandbox::new();
    // Create a target file so the rename has a valid destination.
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
fn test_init_rename_target_rejected() {
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
fn test_init_create_rejected() {
    let sb = TestSandbox::new();
    let result = sb.fs.create(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr("init.krun"),
        0o644,
        false,
        libc::O_RDWR as u32,
        0,
        Extensions::default(),
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_mkdir_rejected() {
    let sb = TestSandbox::new();
    let result = sb.fs.mkdir(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr("init.krun"),
        0o755,
        0,
        Extensions::default(),
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_symlink_rejected() {
    let sb = TestSandbox::new();
    let result = sb.fs.symlink(
        sb.ctx(),
        &TestSandbox::cstr("/target"),
        ROOT_INODE,
        &TestSandbox::cstr("init.krun"),
        Extensions::default(),
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_link_name_rejected() {
    let sb = TestSandbox::new();
    // Create a file to use as link source.
    let (entry, _handle) = sb.fuse_create_root("source").unwrap();
    let result = sb.fs.link(
        sb.ctx(),
        entry.inode,
        ROOT_INODE,
        &TestSandbox::cstr("init.krun"),
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_link_inode_rejected() {
    let sb = TestSandbox::new();
    let result = sb.fs.link(
        sb.ctx(),
        INIT_INODE,
        ROOT_INODE,
        &TestSandbox::cstr("link_to_init"),
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_mknod_rejected() {
    let sb = TestSandbox::new();
    let result = sb.fs.mknod(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr("init.krun"),
        libc::S_IFREG as u32 | 0o644,
        0,
        0,
        Extensions::default(),
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_getxattr_enodata() {
    let sb = TestSandbox::new();
    let result = sb
        .fs
        .getxattr(sb.ctx(), INIT_INODE, &TestSandbox::cstr("user.test"), 256);
    TestSandbox::assert_errno(result, LINUX_ENODATA);
}

#[test]
fn test_init_setxattr_rejected() {
    let sb = TestSandbox::new();
    let result = sb.fs.setxattr(
        sb.ctx(),
        INIT_INODE,
        &TestSandbox::cstr("user.test"),
        b"value",
        0,
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_listxattr_enodata() {
    let sb = TestSandbox::new();
    let result = sb.fs.listxattr(sb.ctx(), INIT_INODE, 0);
    TestSandbox::assert_errno(result, LINUX_ENODATA);
}

#[test]
fn test_init_removexattr_rejected() {
    let sb = TestSandbox::new();
    let result = sb
        .fs
        .removexattr(sb.ctx(), INIT_INODE, &TestSandbox::cstr("user.test"));
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_forget_noop() {
    let sb = TestSandbox::new();
    // Forget with a large count — must not panic or remove init.
    sb.fs.forget(sb.ctx(), INIT_INODE, 100);
    // Init should still be accessible.
    let result = sb.fs.getattr(sb.ctx(), INIT_INODE, None);
    assert!(result.is_ok());
}

#[test]
fn test_init_readlink_rejected() {
    let sb = TestSandbox::new();
    let result = sb.fs.readlink(sb.ctx(), INIT_INODE);
    TestSandbox::assert_errno(result, LINUX_EINVAL);
}

#[test]
fn test_init_flush_noop() {
    let sb = TestSandbox::new();
    let result = sb.fs.flush(sb.ctx(), INIT_INODE, INIT_HANDLE, 0);
    assert!(result.is_ok());
}

#[test]
fn test_init_release_noop() {
    let sb = TestSandbox::new();
    let result = sb
        .fs
        .release(sb.ctx(), INIT_INODE, 0, INIT_HANDLE, false, false, None);
    assert!(result.is_ok());
}

#[test]
fn test_init_access_ok() {
    let sb = TestSandbox::new();
    let result = sb.fs.access(sb.ctx(), INIT_INODE, libc::R_OK as u32);
    assert!(result.is_ok());
}
