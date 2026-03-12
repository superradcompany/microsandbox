use super::*;

#[test]
fn test_getattr_file() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("attr_file.txt").unwrap();
    let (st, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    assert_eq!(st.st_uid, 1000);
    assert_eq!(st.st_gid, 1000);
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert_eq!(mode & 0o777, 0o644);
    assert_eq!(st.st_size, 0);
    #[cfg(target_os = "linux")]
    assert_eq!(st.st_nlink, 1);
    #[cfg(target_os = "macos")]
    assert_eq!(st.st_nlink, 1);
}

#[test]
fn test_getattr_directory() {
    let sb = MemFsTestSandbox::new();
    let entry = sb.fuse_mkdir_root("attr_dir").unwrap();
    let (st, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
    assert_eq!(mode & 0o777, 0o755);
    #[cfg(target_os = "linux")]
    assert_eq!(st.st_nlink, 2);
    #[cfg(target_os = "macos")]
    assert_eq!(st.st_nlink, 2);
}

#[test]
fn test_getattr_symlink() {
    let sb = MemFsTestSandbox::new();
    let target = "/some/target";
    let entry = sb
        .fs
        .symlink(
            MemFsTestSandbox::ctx(),
            &MemFsTestSandbox::cstr(target),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("mylink"),
            Extensions::default(),
        )
        .unwrap();
    let (st, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFLNK as u32);
    assert_eq!(st.st_size, target.len() as i64);
}

#[test]
fn test_getattr_special() {
    let sb = MemFsTestSandbox::new();
    let entry = sb
        .fs
        .mknod(
            MemFsTestSandbox::ctx(),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("blkdev"),
            libc::S_IFBLK as u32 | 0o660,
            42,
            0,
            Extensions::default(),
        )
        .unwrap();
    let (st, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFBLK as u32);
    #[cfg(target_os = "linux")]
    assert_eq!(st.st_rdev, 42);
    #[cfg(target_os = "macos")]
    assert_eq!(st.st_rdev, 42);
}

#[test]
fn test_getattr_invalid_inode() {
    let sb = MemFsTestSandbox::new();
    let result = sb.fs.getattr(MemFsTestSandbox::ctx(), 999999, None);
    MemFsTestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_setattr_mode() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("chmod_test.txt").unwrap();

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
        .setattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::MODE,
        )
        .unwrap();

    let (st, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    assert_eq!(st.st_mode as u32 & 0o777, 0o600);
}

#[test]
fn test_setattr_uid_gid() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("chown_test.txt").unwrap();

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_uid = 0;
    attr.st_gid = 0;
    sb.fs
        .setattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::GID,
        )
        .unwrap();

    let (st, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    assert_eq!(st.st_uid, 0);
    assert_eq!(st.st_gid, 0);
}

#[test]
fn test_setattr_size_truncate() {
    let sb = MemFsTestSandbox::new();
    let ino = sb
        .create_file_with_content(ROOT_INODE, "trunc.txt", b"hello world")
        .unwrap();

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 5;
    sb.fs
        .setattr(
            MemFsTestSandbox::ctx(),
            ino,
            attr,
            None,
            SetattrValid::SIZE,
        )
        .unwrap();

    let (st, _) = sb.fs.getattr(MemFsTestSandbox::ctx(), ino, None).unwrap();
    assert_eq!(st.st_size, 5);

    // Read back to verify content.
    let (handle, _) = sb.fuse_open(ino, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(ino, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"hello");
}

#[test]
fn test_setattr_size_extend() {
    let sb = MemFsTestSandbox::new();
    let ino = sb
        .create_file_with_content(ROOT_INODE, "extend.txt", b"hi")
        .unwrap();

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 10;
    sb.fs
        .setattr(
            MemFsTestSandbox::ctx(),
            ino,
            attr,
            None,
            SetattrValid::SIZE,
        )
        .unwrap();

    let (st, _) = sb.fs.getattr(MemFsTestSandbox::ctx(), ino, None).unwrap();
    assert_eq!(st.st_size, 10);

    // Read back to verify zero-fill.
    let (handle, _) = sb.fuse_open(ino, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(ino, handle, 1024, 0).unwrap();
    assert_eq!(data.len(), 10);
    assert_eq!(&data[..2], b"hi");
    assert!(data[2..].iter().all(|&b| b == 0));
}

#[test]
fn test_setattr_timestamps() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("time_test.txt").unwrap();

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_atime = 1000;
    attr.st_atime_nsec = 42;
    attr.st_mtime = 2000;
    attr.st_mtime_nsec = 99;
    sb.fs
        .setattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::ATIME | SetattrValid::MTIME,
        )
        .unwrap();

    let (st, _) = sb
        .fs
        .getattr(MemFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    assert_eq!(st.st_atime, 1000);
    assert_eq!(st.st_atime_nsec, 42);
    assert_eq!(st.st_mtime, 2000);
    assert_eq!(st.st_mtime_nsec, 99);
}

#[test]
fn test_setattr_init_krun() {
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
fn test_access_owner_read() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("access_read.txt").unwrap();
    // File mode is 0o644, uid=1000. ctx uid=1000 should have read access.
    let result = sb
        .fs
        .access(MemFsTestSandbox::ctx(), entry.inode, libc::R_OK as u32);
    assert!(result.is_ok());
}

#[test]
fn test_access_owner_write_denied() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("access_w.txt").unwrap();

    // Change mode to 0o400 (read-only for owner).
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
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
            MemFsTestSandbox::ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::MODE,
        )
        .unwrap();

    let result = sb
        .fs
        .access(MemFsTestSandbox::ctx(), entry.inode, libc::W_OK as u32);
    MemFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_access_group() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("access_grp.txt").unwrap();

    // Change owner to someone else so group bits apply.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_uid = 9999;
    attr.st_gid = 1000;
    sb.fs
        .setattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::GID,
        )
        .unwrap();

    // Mode is 0o644: group has read (4). Set mode to 0o070 for group rwx.
    let mut attr2: stat64 = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "linux")]
    {
        attr2.st_mode = 0o070;
    }
    #[cfg(target_os = "macos")]
    {
        attr2.st_mode = 0o070;
    }
    sb.fs
        .setattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            attr2,
            None,
            SetattrValid::MODE,
        )
        .unwrap();

    // ctx gid=1000 should have rwx.
    let result = sb.fs.access(
        MemFsTestSandbox::ctx(),
        entry.inode,
        libc::R_OK as u32 | libc::W_OK as u32 | libc::X_OK as u32,
    );
    assert!(result.is_ok());
}

#[test]
fn test_access_root_bypass() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("access_root.txt").unwrap();

    // Change mode to 0o000.
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
        .setattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::MODE,
        )
        .unwrap();

    // Root ctx should bypass read/write.
    let root_ctx = MemFsTestSandbox::ctx_as(0, 0);
    let result = sb
        .fs
        .access(root_ctx, entry.inode, libc::R_OK as u32 | libc::W_OK as u32);
    assert!(result.is_ok());
}

#[test]
fn test_access_other() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("access_other.txt").unwrap();

    // Set mode to 0o007 — only "other" has rwx; owner and group have nothing.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "linux")]
    {
        attr.st_mode = 0o007;
    }
    #[cfg(target_os = "macos")]
    {
        attr.st_mode = 0o007;
    }
    sb.fs
        .setattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::MODE,
        )
        .unwrap();

    // A context where uid and gid do NOT match the file's owner/group falls into "other".
    let other_ctx = MemFsTestSandbox::ctx_as(5000, 5000);
    let result = sb.fs.access(
        other_ctx,
        entry.inode,
        libc::R_OK as u32 | libc::W_OK as u32 | libc::X_OK as u32,
    );
    assert!(result.is_ok());

    // The owner (uid=1000) should be denied — owner bits are 0.
    let result = sb.fs.access(
        MemFsTestSandbox::ctx(),
        entry.inode,
        libc::R_OK as u32,
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_access_f_ok() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("exists.txt").unwrap();

    // F_OK on an existing inode should succeed.
    let result = sb.fs.access(MemFsTestSandbox::ctx(), entry.inode, libc::F_OK as u32);
    assert!(result.is_ok());

    // F_OK on a nonexistent inode should fail with EBADF (unknown inode).
    let result = sb.fs.access(MemFsTestSandbox::ctx(), 999999, libc::F_OK as u32);
    MemFsTestSandbox::assert_errno(result, LINUX_EBADF);
}
