use super::*;
use crate::agentd::AGENTD_BYTES;

#[test]
fn test_init_krun_lookup() {
    let sb = MemFsTestSandbox::new();
    let entry = sb.lookup_root("init.krun").unwrap();
    assert_eq!(entry.inode, INIT_INODE);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert_eq!(mode & 0o777, 0o755);
    assert_eq!(entry.attr.st_size, AGENTD_BYTES.len() as i64);
}

#[test]
fn test_init_krun_open_and_read() {
    let sb = MemFsTestSandbox::new();
    let (handle, opts) = sb
        .fs
        .open(
            MemFsTestSandbox::ctx(),
            INIT_INODE,
            false,
            libc::O_RDONLY as u32,
        )
        .unwrap();
    assert_eq!(handle, Some(0)); // INIT_HANDLE = 0
    assert_eq!(opts, OpenOptions::KEEP_CACHE);

    let data = sb
        .fuse_read(INIT_INODE, 0, AGENTD_BYTES.len() as u32, 0)
        .unwrap();
    assert_eq!(data.len(), AGENTD_BYTES.len());
    assert_eq!(&data[..], AGENTD_BYTES);
}

#[test]
fn test_init_krun_partial_read() {
    let sb = MemFsTestSandbox::new();
    let offset = 100u64;
    let size = 64u32;
    let data = sb.fuse_read(INIT_INODE, 0, size, offset).unwrap();
    assert_eq!(data.len(), size as usize);
    assert_eq!(
        &data[..],
        &AGENTD_BYTES[offset as usize..offset as usize + size as usize]
    );
}

#[test]
fn test_init_krun_write_fails() {
    let sb = MemFsTestSandbox::new();
    let mut reader = MockZeroCopyReader::new(vec![0u8; 10]);
    let result = sb.fs.write(
        MemFsTestSandbox::ctx(),
        INIT_INODE,
        0, // INIT_HANDLE
        &mut reader,
        10,
        0,
        None,
        false,
        false,
        0,
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_krun_unlink_fails() {
    let sb = MemFsTestSandbox::new();
    let result = sb.fs.unlink(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("init.krun"),
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_krun_setattr_fails() {
    let sb = MemFsTestSandbox::new();
    let attr: stat64 = unsafe { std::mem::zeroed() };
    let result = sb.fs.setattr(
        MemFsTestSandbox::ctx(),
        INIT_INODE,
        attr,
        None,
        SetattrValid::MODE,
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_init_krun_getattr() {
    let sb = MemFsTestSandbox::new();
    let (st, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), INIT_INODE, None)
        .unwrap();
    assert_eq!(st.st_ino, INIT_INODE);
    assert_eq!(st.st_uid, 0);
    assert_eq!(st.st_gid, 0);
    assert_eq!(st.st_size, AGENTD_BYTES.len() as i64);
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert_eq!(mode & 0o777, 0o755);
    #[cfg(target_os = "linux")]
    assert_eq!(st.st_nlink, 1);
    #[cfg(target_os = "macos")]
    assert_eq!(st.st_nlink, 1);
}
