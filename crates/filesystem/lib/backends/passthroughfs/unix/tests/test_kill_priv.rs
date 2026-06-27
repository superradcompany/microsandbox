use super::*;

/// Helper: create a file with SUID bit set via setattr.
fn create_suid_file(sb: &TestSandbox, name: &str) -> (Entry, u64) {
    let (entry, handle) = sb.fuse_create_root(name).unwrap();
    // Set mode to 0o4755 (SUID + rwxr-xr-x).
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "linux")]
    {
        attr.st_mode = 0o4755;
    }
    #[cfg(target_os = "macos")]
    {
        attr.st_mode = 0o4755;
    }
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();
    assert_eq!(
        sb.get_mode(entry.inode) & libc::S_ISUID as u32,
        libc::S_ISUID as u32
    );
    (entry, handle)
}

/// Helper: create a file with SGID bit set via setattr.
fn create_sgid_file(sb: &TestSandbox, name: &str) -> (Entry, u64) {
    let (entry, handle) = sb.fuse_create_root(name).unwrap();
    // Set mode to 0o2755 (SGID + rwxr-xr-x).
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "linux")]
    {
        attr.st_mode = 0o2755;
    }
    #[cfg(target_os = "macos")]
    {
        attr.st_mode = 0o2755;
    }
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();
    assert_eq!(
        sb.get_mode(entry.inode) & libc::S_ISGID as u32,
        libc::S_ISGID as u32
    );
    (entry, handle)
}

#[test]
fn test_write_kill_priv_clears_suid() {
    let sb = TestSandbox::new();
    let (entry, handle) = create_suid_file(&sb, "suid_write.txt");

    // Write with kill_priv=true should clear SUID.
    sb.fuse_write_kill_priv(entry.inode, handle, b"data", 0, true)
        .unwrap();

    let mode = sb.get_mode(entry.inode);
    assert_eq!(
        mode & libc::S_ISUID as u32,
        0,
        "SUID should be cleared after write with kill_priv"
    );
    // Permission bits should be preserved.
    assert_eq!(mode & 0o777, 0o755);
}

#[test]
fn test_write_kill_priv_clears_sgid() {
    let sb = TestSandbox::new();
    let (entry, handle) = create_sgid_file(&sb, "sgid_write.txt");

    sb.fuse_write_kill_priv(entry.inode, handle, b"data", 0, true)
        .unwrap();

    let mode = sb.get_mode(entry.inode);
    assert_eq!(
        mode & libc::S_ISGID as u32,
        0,
        "SGID should be cleared after write with kill_priv"
    );
    assert_eq!(mode & 0o777, 0o755);
}

#[test]
fn test_write_no_kill_priv_preserves_suid() {
    let sb = TestSandbox::new();
    let (entry, handle) = create_suid_file(&sb, "suid_keep.txt");

    // Write with kill_priv=false should NOT clear SUID.
    sb.fuse_write_kill_priv(entry.inode, handle, b"data", 0, false)
        .unwrap();

    let mode = sb.get_mode(entry.inode);
    assert_ne!(
        mode & libc::S_ISUID as u32,
        0,
        "SUID should be preserved when kill_priv=false"
    );
}

#[test]
fn test_open_trunc_kill_priv_clears_suid() {
    let sb = TestSandbox::new();
    let (entry, handle) = create_suid_file(&sb, "suid_trunc.txt");
    sb.fuse_write(entry.inode, handle, b"initial data", 0)
        .unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    // Open with O_TRUNC + kill_priv should clear SUID.
    // Use Linux flag values (FUSE protocol always sends Linux flags).
    let _handle = sb
        .fuse_open_kill_priv(entry.inode, true, LINUX_O_RDWR | LINUX_O_TRUNC)
        .unwrap();

    let mode = sb.get_mode(entry.inode);
    assert_eq!(
        mode & libc::S_ISUID as u32,
        0,
        "SUID should be cleared on open+truncate with kill_priv"
    );
}

#[test]
fn test_open_trunc_no_kill_priv_preserves_suid() {
    let sb = TestSandbox::new();
    let (entry, handle) = create_suid_file(&sb, "suid_trunc_keep.txt");
    sb.fuse_write(entry.inode, handle, b"initial data", 0)
        .unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    // Open with O_TRUNC but kill_priv=false should preserve SUID.
    let _handle = sb
        .fuse_open_kill_priv(entry.inode, false, LINUX_O_RDWR | LINUX_O_TRUNC)
        .unwrap();

    let mode = sb.get_mode(entry.inode);
    assert_ne!(
        mode & libc::S_ISUID as u32,
        0,
        "SUID should be preserved when kill_priv=false"
    );
}

#[test]
fn test_open_no_trunc_kill_priv_preserves_suid() {
    let sb = TestSandbox::new();
    let (entry, handle) = create_suid_file(&sb, "suid_open_no_trunc.txt");
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    // Open without O_TRUNC + kill_priv should preserve SUID (only trunc triggers clearing).
    let _handle = sb
        .fuse_open_kill_priv(entry.inode, true, libc::O_RDWR as u32)
        .unwrap();

    let mode = sb.get_mode(entry.inode);
    assert_ne!(
        mode & libc::S_ISUID as u32,
        0,
        "SUID should be preserved on open without O_TRUNC"
    );
}

#[test]
fn test_setattr_size_kill_priv_clears_suid() {
    let sb = TestSandbox::new();
    let (entry, handle) = create_suid_file(&sb, "suid_setattr_trunc.txt");
    sb.fuse_write(entry.inode, handle, b"initial data", 0)
        .unwrap();

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 4;
    sb.fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::SIZE | SetattrValid::KILL_SUIDGID,
        )
        .unwrap();

    let mode = sb.get_mode(entry.inode);
    assert_eq!(
        mode & libc::S_ISUID as u32,
        0,
        "SUID should be cleared on setattr truncate with KILL_SUIDGID"
    );
    assert_eq!(mode & 0o777, 0o755);
}

#[test]
fn test_setattr_uid_change_clears_suid() {
    let sb = TestSandbox::new();
    let (entry, _handle) = create_suid_file(&sb, "suid_setattr_uid.txt");

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_uid = 1234;
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::UID)
        .unwrap();

    let mode = sb.get_mode(entry.inode);
    assert_eq!(
        mode & libc::S_ISUID as u32,
        0,
        "SUID should be cleared on setattr uid change"
    );
    let (st, _) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 1234);
}

#[test]
fn test_write_kill_priv_clears_both_suid_and_sgid() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("suid_sgid.txt").unwrap();
    // Set mode to 0o6755 (SUID + SGID).
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "linux")]
    {
        attr.st_mode = 0o6755;
    }
    #[cfg(target_os = "macos")]
    {
        attr.st_mode = 0o6755;
    }
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();
    let mode = sb.get_mode(entry.inode);
    assert_ne!(mode & libc::S_ISUID as u32, 0);
    assert_ne!(mode & libc::S_ISGID as u32, 0);

    sb.fuse_write_kill_priv(entry.inode, handle, b"data", 0, true)
        .unwrap();

    let mode = sb.get_mode(entry.inode);
    assert_eq!(mode & libc::S_ISUID as u32, 0, "SUID should be cleared");
    assert_eq!(mode & libc::S_ISGID as u32, 0, "SGID should be cleared");
    assert_eq!(mode & 0o777, 0o755, "permission bits should be preserved");
}

#[test]
fn test_write_kill_priv_noop_when_no_suid_sgid() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("normal.txt").unwrap();

    // Mode is 0o644 (no SUID/SGID) — kill_priv should be a no-op.
    let mode_before = sb.get_mode(entry.inode);
    sb.fuse_write_kill_priv(entry.inode, handle, b"data", 0, true)
        .unwrap();
    let mode_after = sb.get_mode(entry.inode);

    assert_eq!(
        mode_before, mode_after,
        "mode should be unchanged when no SUID/SGID bits are set"
    );
}
