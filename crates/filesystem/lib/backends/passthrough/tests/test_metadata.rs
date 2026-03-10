use super::*;

#[test]
fn test_getattr_root() {
    let sb = TestSandbox::new();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), ROOT_INODE, None).unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
}

#[test]
fn test_getattr_with_override() {
    let sb = TestSandbox::new();
    // Create via FUSE — this sets override xattr with ctx uid/gid.
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    // Should reflect the guest context (uid=0, gid=0 from ctx()).
    assert_eq!(st.st_uid, 0);
    assert_eq!(st.st_gid, 0);
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert_eq!(mode & 0o777, 0o644);
}

#[test]
fn test_getattr_invalid_inode() {
    let sb = TestSandbox::new();
    let result = sb.fs.getattr(sb.ctx(), 9999, None);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_setattr_mode() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    // Change mode to 0o755.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "linux")]
    {
        attr.st_mode = 0o755;
    }
    #[cfg(target_os = "macos")]
    {
        attr.st_mode = 0o755;
    }
    let (st, _timeout) = sb
        .fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();
    let mode = st.st_mode as u32;
    // File type should be preserved; perm bits should be 0o755.
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert_eq!(mode & 0o777, 0o755);
}

#[test]
fn test_setattr_uid_gid() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_uid = 1000;
    attr.st_gid = 1000;
    let (st, _timeout) = sb
        .fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::GID,
        )
        .unwrap();
    assert_eq!(st.st_uid, 1000);
    assert_eq!(st.st_gid, 1000);
}

#[test]
fn test_setattr_size_truncate() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("file.txt").unwrap();
    // Write 100 bytes.
    sb.fuse_write(entry.inode, handle, &[0xAA; 100], 0).unwrap();
    // Truncate to 50.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 50;
    let (st, _timeout) = sb
        .fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::SIZE)
        .unwrap();
    assert_eq!(st.st_size, 50);
}

#[test]
fn test_setattr_size_expand() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("file.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"hello", 0).unwrap();
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 1000;
    let (st, _timeout) = sb
        .fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::SIZE)
        .unwrap();
    assert_eq!(st.st_size, 1000);
}

#[test]
fn test_setattr_timestamps() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_atime = 1000;
    attr.st_atime_nsec = 0;
    attr.st_mtime = 2000;
    attr.st_mtime_nsec = 0;
    let (st, _timeout) = sb
        .fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::ATIME | SetattrValid::MTIME,
        )
        .unwrap();
    assert_eq!(st.st_atime, 1000);
    assert_eq!(st.st_mtime, 2000);
}

#[test]
fn test_setattr_atime_now() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let attr: stat64 = unsafe { std::mem::zeroed() };
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (st, _timeout) = sb
        .fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::ATIME | SetattrValid::ATIME_NOW,
        )
        .unwrap();
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(st.st_atime >= before && st.st_atime <= after + 1);
}

#[test]
fn test_setattr_mode_preserves_type() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    // Set mode bits only — file type S_IFREG should be preserved.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "linux")]
    {
        attr.st_mode = 0o777;
    }
    #[cfg(target_os = "macos")]
    {
        attr.st_mode = 0o777;
    }
    let (st, _timeout) = sb
        .fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert_eq!(mode & 0o777, 0o777);
}

#[test]
fn test_setattr_init_rejected() {
    let sb = TestSandbox::new();
    let attr = unsafe { std::mem::zeroed() };
    let result = sb
        .fs
        .setattr(sb.ctx(), INIT_INODE, attr, None, SetattrValid::MODE);
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_access_f_ok() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let result = sb.fs.access(sb.ctx(), entry.inode, libc::F_OK as u32);
    assert!(result.is_ok());
}

#[test]
fn test_access_root_bypasses_rw() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    // Root (uid=0) should bypass R_OK|W_OK even on 0o000 mode.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "linux")]
    {
        attr.st_mode = 0o000;
    }
    #[cfg(target_os = "macos")]
    {
        attr.st_mode = 0o000;
    }
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();
    let result = sb
        .fs
        .access(sb.ctx(), entry.inode, (libc::R_OK | libc::W_OK) as u32);
    assert!(result.is_ok());
}

#[test]
fn test_access_root_needs_exec_bit() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    // Mode 0o600 — no execute bits anywhere.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "linux")]
    {
        attr.st_mode = 0o600;
    }
    #[cfg(target_os = "macos")]
    {
        attr.st_mode = 0o600;
    }
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();
    let result = sb.fs.access(sb.ctx(), entry.inode, libc::X_OK as u32);
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_access_owner_read() {
    let sb = TestSandbox::new();
    // Create file with uid=1000 and mode 0o400 (owner read only).
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_uid = 1000;
    #[cfg(target_os = "linux")]
    {
        attr.st_mode = 0o400;
    }
    #[cfg(target_os = "macos")]
    {
        attr.st_mode = 0o400;
    }
    sb.fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::MODE,
        )
        .unwrap();
    let result = sb
        .fs
        .access(sb.ctx_as(1000, 1000), entry.inode, libc::R_OK as u32);
    assert!(result.is_ok());
}

#[test]
fn test_access_owner_write_denied() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_uid = 1000;
    #[cfg(target_os = "linux")]
    {
        attr.st_mode = 0o444;
    }
    #[cfg(target_os = "macos")]
    {
        attr.st_mode = 0o444;
    }
    sb.fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::MODE,
        )
        .unwrap();
    let result = sb
        .fs
        .access(sb.ctx_as(1000, 1000), entry.inode, libc::W_OK as u32);
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_access_group_bits() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    // uid=1000, gid=2000, mode 0o040 (group read).
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_uid = 1000;
    attr.st_gid = 2000;
    #[cfg(target_os = "linux")]
    {
        attr.st_mode = 0o040;
    }
    #[cfg(target_os = "macos")]
    {
        attr.st_mode = 0o040;
    }
    sb.fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
        )
        .unwrap();
    // User with matching gid=2000 but different uid should be able to read.
    let result = sb
        .fs
        .access(sb.ctx_as(9999, 2000), entry.inode, libc::R_OK as u32);
    assert!(result.is_ok());
}

#[test]
fn test_access_other_bits() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    // uid=1000, gid=2000, mode 0o004 (other read).
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_uid = 1000;
    attr.st_gid = 2000;
    #[cfg(target_os = "linux")]
    {
        attr.st_mode = 0o004;
    }
    #[cfg(target_os = "macos")]
    {
        attr.st_mode = 0o004;
    }
    sb.fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
        )
        .unwrap();
    // User with neither matching uid nor gid should use other bits.
    let result = sb
        .fs
        .access(sb.ctx_as(9999, 9999), entry.inode, libc::R_OK as u32);
    assert!(result.is_ok());
    // Write should be denied (other bits = 4 = read only).
    let result = sb
        .fs
        .access(sb.ctx_as(9999, 9999), entry.inode, libc::W_OK as u32);
    TestSandbox::assert_errno(result, LINUX_EACCES);
}
