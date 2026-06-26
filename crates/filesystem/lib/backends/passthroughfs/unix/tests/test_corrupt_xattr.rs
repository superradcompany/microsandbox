use std::{ffi::CString, os::fd::AsRawFd};

use super::*;
use crate::backends::shared::stat_override::OVERRIDE_XATTR_KEY;

/// Write raw bytes to the override xattr on a host file, bypassing the filesystem.
fn host_set_raw_xattr(path: &std::path::Path, data: &[u8]) {
    let path_cstr = CString::new(path.to_str().unwrap()).unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let fd = file.as_raw_fd();

    #[cfg(target_os = "linux")]
    let ret = unsafe {
        libc::fsetxattr(
            fd,
            OVERRIDE_XATTR_KEY.as_ptr(),
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
        )
    };

    #[cfg(target_os = "macos")]
    let ret = unsafe {
        libc::fsetxattr(
            fd,
            OVERRIDE_XATTR_KEY.as_ptr(),
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            0,
        )
    };

    let _ = path_cstr;
    assert!(ret == 0, "fsetxattr failed: {}", io::Error::last_os_error());
}

#[test]
fn test_corrupt_xattr_wrong_size_returns_eio() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("corrupt_size.txt").unwrap();

    // Verify getattr works before corruption.
    assert!(sb.fs.getattr(sb.ctx(), entry.inode, None).is_ok());

    // Overwrite the override xattr with too-short data (expect 20 bytes, write 5).
    let host_path = sb.root.join("corrupt_size.txt");
    host_set_raw_xattr(&host_path, &[0u8; 5]);

    // getattr should fail with EIO because the xattr is too short.
    let result = sb.fs.getattr(sb.ctx(), entry.inode, None);
    TestSandbox::assert_errno(result, LINUX_EIO);
}

#[test]
fn test_corrupt_xattr_wrong_version_returns_eio() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("corrupt_ver.txt").unwrap();

    // Verify getattr works before corruption.
    assert!(sb.fs.getattr(sb.ctx(), entry.inode, None).is_ok());

    // Write a 20-byte xattr with version=0xFF (expected version is 1).
    let mut data = [0u8; 20];
    data[0] = 0xFF; // corrupt version byte
    let host_path = sb.root.join("corrupt_ver.txt");
    host_set_raw_xattr(&host_path, &data);

    // getattr should fail with EIO because the version is wrong.
    let result = sb.fs.getattr(sb.ctx(), entry.inode, None);
    TestSandbox::assert_errno(result, LINUX_EIO);
}

#[test]
fn test_corrupt_xattr_zero_length_returns_eio() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("corrupt_empty.txt").unwrap();

    assert!(sb.fs.getattr(sb.ctx(), entry.inode, None).is_ok());

    // Overwrite with a 1-byte xattr (way too short).
    let host_path = sb.root.join("corrupt_empty.txt");
    host_set_raw_xattr(&host_path, &[1]); // version=1 but only 1 byte

    let result = sb.fs.getattr(sb.ctx(), entry.inode, None);
    TestSandbox::assert_errno(result, LINUX_EIO);
}

#[test]
fn test_corrupt_xattr_lookup_returns_eio() {
    let sb = TestSandbox::new();

    // Create a file on the host, then set a corrupt xattr on it.
    let host_path = sb.host_create_file("corrupt_lookup.txt", b"data");
    host_set_raw_xattr(&host_path, &[0xFF; 20]); // wrong version

    // Lookup should fail with EIO because patched_stat propagates the error.
    let result = sb.lookup_root("corrupt_lookup.txt");
    TestSandbox::assert_errno(result, LINUX_EIO);
}

#[test]
fn test_no_xattr_returns_unpatched_stat() {
    let sb = TestSandbox::new();

    // Create a file directly on the host (no override xattr set).
    sb.host_create_file("no_xattr.txt", b"data");

    // Lookup should succeed — read_override returns Ok(None), patched_stat
    // returns the unmodified stat.
    let entry = sb.lookup_root("no_xattr.txt").unwrap();
    assert!(entry.inode >= 3);
    let (st, _) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_eq!(st.st_size, 4);
}
