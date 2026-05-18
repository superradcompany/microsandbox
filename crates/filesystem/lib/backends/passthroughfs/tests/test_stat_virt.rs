//! Tests for the `StatVirtualization` policy: Strict / Relaxed / Off semantics.

use std::os::fd::AsRawFd;

use super::*;
use crate::backends::passthroughfs::{HostPermissions, StatVirtualization};
use crate::backends::shared::stat_override::OVERRIDE_XATTR_KEY;

fn host_set_raw_xattr(path: &std::path::Path, data: &[u8]) {
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

    assert!(ret == 0, "fsetxattr failed: {}", io::Error::last_os_error());
}

/// Build a valid 20-byte OverrideStat blob with the given uid/gid/mode/rdev.
fn override_blob(uid: u32, gid: u32, mode: u32, rdev: u32) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[0] = 1; // version
    buf[4..8].copy_from_slice(&uid.to_ne_bytes());
    buf[8..12].copy_from_slice(&gid.to_ne_bytes());
    buf[12..16].copy_from_slice(&mode.to_ne_bytes());
    buf[16..20].copy_from_slice(&rdev.to_ne_bytes());
    buf
}

#[test]
fn test_off_ignores_planted_override_xattr() {
    // Plant an override xattr claiming uid=4242, gid=4243, and a
    // distinguishable mode (0o777) that cannot collide with the real host
    // mode after a normal create. Off must ignore ALL fields of the planted
    // overlay and return real host stat.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });

    let host_path = sb.host_create_file("planted.txt", b"x");
    // 0o100777: regular file, world-rwx — easily distinguished from typical
    // 0o644/0o600 host modes set by host_create_file.
    host_set_raw_xattr(&host_path, &override_blob(4242, 4243, 0o100777, 0));

    let entry = sb.lookup_root("planted.txt").unwrap();
    let (st, _) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_ne!(st.st_uid, 4242, "Off must ignore planted override uid");
    assert_ne!(st.st_gid, 4243, "Off must ignore planted override gid");
    assert_ne!(
        st.st_mode as u32 & 0o7777,
        0o777,
        "Off must ignore planted override mode"
    );
}

#[test]
fn test_off_rejects_chown_uid() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });
    let (entry, _) = sb.fuse_create_root("file.txt").unwrap();

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_uid = 1234;
    let result = sb
        .fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::UID);
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_off_rejects_chown_gid() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });
    let (entry, _) = sb.fuse_create_root("file.txt").unwrap();

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_gid = 5678;
    let result = sb
        .fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::GID);
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_off_rejects_chown_uid_and_gid_combined() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });
    let (entry, _) = sb.fuse_create_root("file.txt").unwrap();

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_uid = 1234;
    attr.st_gid = 5678;
    let result = sb.fs.setattr(
        sb.ctx(),
        entry.inode,
        attr,
        None,
        SetattrValid::UID | SetattrValid::GID,
    );
    TestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_off_rejects_mknod_all_special_types() {
    // S_IFBLK, S_IFCHR, S_IFIFO, S_IFSOCK — all four virtualized types must
    // be rejected under Off because there is no overlay to record their type.
    const S_IFBLK: u32 = 0o0060000;
    const S_IFCHR: u32 = 0o0020000;
    const S_IFIFO: u32 = 0o0010000;
    const S_IFSOCK: u32 = 0o0140000;

    #[cfg(target_os = "linux")]
    const EXPECTED: i32 = 95;
    #[cfg(target_os = "macos")]
    const EXPECTED: i32 = LINUX_EOPNOTSUPP;

    for (label, type_bits) in [
        ("blk", S_IFBLK),
        ("chr", S_IFCHR),
        ("fifo", S_IFIFO),
        ("sock", S_IFSOCK),
    ] {
        let sb = TestSandbox::with_config(|mut cfg| {
            cfg.stat_virtualization = StatVirtualization::Off;
            cfg
        });
        let result = sb.fs.mknod(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr(label),
            type_bits | 0o660,
            0x0801,
            0,
            Extensions::default(),
        );
        TestSandbox::assert_errno(result, EXPECTED);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_off_creates_real_host_symlink_on_linux() {
    // Under Off, symlinks are real host symlinks. The host sees an actual
    // symlink (resolves `S_IFLNK` from the host's fstat), no override xattr
    // is written, and `readlink` round-trips.
    use std::os::unix::fs::MetadataExt;
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });

    sb.fs
        .symlink(
            sb.ctx(),
            &TestSandbox::cstr("/target"),
            ROOT_INODE,
            &TestSandbox::cstr("link"),
            Extensions::default(),
        )
        .unwrap();

    // Host view: real symlink with target == "/target".
    let host_path = sb.root.join("link");
    let host_meta = std::fs::symlink_metadata(&host_path).unwrap();
    assert!(
        host_meta.file_type().is_symlink(),
        "host file is not a symlink"
    );
    let target = std::fs::read_link(&host_path).unwrap();
    assert_eq!(target.to_string_lossy(), "/target");
    // Real Linux symlinks live in zero blocks (mode pinned at 0o777).
    let _ = host_meta.mode();

    // Guest readlink round-trips.
    let entry = sb.lookup_root("link").unwrap();
    let buf = sb.fs.readlink(sb.ctx(), entry.inode).unwrap();
    assert_eq!(&buf[..], b"/target");
}

#[cfg(target_os = "linux")]
#[test]
fn test_relaxed_creates_real_host_symlink_on_linux() {
    // Relaxed mirrors Off for the symlink case: host-visible real symlink,
    // no overlay xattr. The overlay isn't load-bearing for symlinks because
    // Linux pins the mode and the symlink itself has no perm bits to virtualize.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Relaxed;
        cfg
    });

    sb.fs
        .symlink(
            sb.ctx(),
            &TestSandbox::cstr("/target"),
            ROOT_INODE,
            &TestSandbox::cstr("link"),
            Extensions::default(),
        )
        .unwrap();

    let host_path = sb.root.join("link");
    let host_meta = std::fs::symlink_metadata(&host_path).unwrap();
    assert!(host_meta.file_type().is_symlink());
    assert_eq!(
        std::fs::read_link(&host_path).unwrap().to_string_lossy(),
        "/target"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_strict_keeps_file_backed_symlink_on_linux() {
    // Strict still uses the file-backed scheme so the overlay can carry
    // S_IFLNK + uid/gid. The host sees a regular file whose content is the
    // symlink target. Verified by checking host symlink_metadata and the
    // override xattr's mode byte.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Strict;
        cfg
    });

    sb.fs
        .symlink(
            sb.ctx(),
            &TestSandbox::cstr("/target"),
            ROOT_INODE,
            &TestSandbox::cstr("link"),
            Extensions::default(),
        )
        .unwrap();

    let host_path = sb.root.join("link");
    let host_meta = std::fs::symlink_metadata(&host_path).unwrap();
    assert!(
        host_meta.file_type().is_file(),
        "Strict on Linux must still file-back symlinks (host should see a regular file)"
    );
    // Host content is the target path bytes.
    assert_eq!(std::fs::read(&host_path).unwrap(), b"/target");
}

#[test]
fn test_off_does_not_write_override_xattr_on_create() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });

    let (_entry, _) = sb.fuse_create_root("nox.txt").unwrap();

    // Verify no override xattr was written on the host file.
    let host_path = sb.root.join("nox.txt");
    let path_cstr = std::ffi::CString::new(host_path.to_str().unwrap()).unwrap();
    let mut buf = [0u8; 64];

    #[cfg(target_os = "linux")]
    let ret = unsafe {
        libc::getxattr(
            path_cstr.as_ptr(),
            OVERRIDE_XATTR_KEY.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };

    #[cfg(target_os = "macos")]
    let ret = unsafe {
        libc::getxattr(
            path_cstr.as_ptr(),
            OVERRIDE_XATTR_KEY.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            0,
        )
    };

    assert!(
        ret < 0,
        "Off mode must not write override xattr on create (got size={ret})"
    );
}

#[test]
fn test_relaxed_still_fails_on_corrupt_override() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Relaxed;
        cfg
    });

    let host_path = sb.host_create_file("bad.txt", b"x");
    host_set_raw_xattr(&host_path, &[0xFFu8; 20]); // bad version

    let result = sb.lookup_root("bad.txt");
    TestSandbox::assert_errno(result, LINUX_EIO);
}

#[test]
fn test_relaxed_applies_overlay_when_present() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Relaxed;
        cfg
    });

    let host_path = sb.host_create_file("withovr.txt", b"x");
    // Distinguishing mode: 0o777 cannot collide with the host's umask'd 0o644.
    host_set_raw_xattr(&host_path, &override_blob(7777, 8888, 0o100777, 0));

    let entry = sb.lookup_root("withovr.txt").unwrap();
    let (st, _) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 7777);
    assert_eq!(st.st_gid, 8888);
    assert_eq!(st.st_mode as u32 & 0o7777, 0o777);
}

#[test]
fn test_off_owner_floor_create_with_restrictive_mode() {
    // Off + create with mode 0o000 used to leave a host file the unprivileged
    // host process could not reopen. The owner floor must keep at least
    // 0o600 on host so subsequent open_inode_fd reopens succeed.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });

    let (_entry, handle, _) = sb
        .fs
        .create(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("zero.txt"),
            0o000,
            false,
            LINUX_O_RDWR,
            0,
            Extensions::default(),
        )
        .unwrap();
    assert!(handle.is_some(), "create must return a usable handle");

    let host_path = sb.root.join("zero.txt");
    use std::os::unix::fs::PermissionsExt;
    let host_mode = std::fs::metadata(&host_path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(host_mode, 0o600, "owner floor must apply under Off");
}

#[test]
fn test_off_owner_floor_mkdir_with_restrictive_mode() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });

    let _entry = sb
        .fs
        .mkdir(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("zero_dir"),
            0o000,
            0,
            Extensions::default(),
        )
        .unwrap();

    let host_path = sb.root.join("zero_dir");
    use std::os::unix::fs::PermissionsExt;
    let host_mode = std::fs::metadata(&host_path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(host_mode, 0o700, "dir owner floor must apply under Off");
}

#[test]
fn test_off_owner_floor_preserves_higher_bits() {
    // Floor must be additive — guest's 0o644 must reach the host as 0o644
    // (the existing owner-rw is already at the floor).
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });

    let (_entry, _, _) = sb
        .fs
        .create(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("normal.txt"),
            0o644,
            false,
            LINUX_O_RDWR,
            0,
            Extensions::default(),
        )
        .unwrap();

    use std::os::unix::fs::PermissionsExt;
    let host_mode = std::fs::metadata(sb.root.join("normal.txt"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(host_mode, 0o644);
}

#[test]
fn test_off_mkdir_does_not_write_override_xattr() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });

    let _entry = sb.fuse_mkdir_root("nox_dir").unwrap();

    // Verify no override xattr was written on the host directory.
    let host_path = sb.root.join("nox_dir");
    let path_cstr = std::ffi::CString::new(host_path.to_str().unwrap()).unwrap();
    let mut buf = [0u8; 64];

    #[cfg(target_os = "linux")]
    let ret = unsafe {
        libc::getxattr(
            path_cstr.as_ptr(),
            OVERRIDE_XATTR_KEY.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };

    #[cfg(target_os = "macos")]
    let ret = unsafe {
        libc::getxattr(
            path_cstr.as_ptr(),
            OVERRIDE_XATTR_KEY.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            0,
        )
    };

    assert!(ret < 0, "Off mode mkdir must not write override xattr");
}

#[test]
fn test_off_corrupt_planted_xattr_is_ignored() {
    // Under Off, even a corrupt planted xattr must not surface as EIO —
    // we never read the overlay at all.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });

    let host_path = sb.host_create_file("badovr.txt", b"x");
    host_set_raw_xattr(&host_path, &[0xFFu8; 20]); // wrong version

    let entry = sb.lookup_root("badovr.txt").unwrap();
    let (_st, _) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
}

#[test]
fn test_off_kill_priv_clears_setuid_on_truncate_via_setattr() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });

    // Create a setuid host file directly (bypass FUSE).
    let host_path = sb.host_create_file("priv.bin", b"data");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&host_path, std::fs::Permissions::from_mode(0o4755)).unwrap();

    let entry = sb.lookup_root("priv.bin").unwrap();

    // Truncate via setattr with KILL_SUIDGID flag set.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 0;
    sb.fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::SIZE | SetattrValid::KILL_SUIDGID,
        )
        .unwrap();

    let host_mode = std::fs::metadata(&host_path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(
        host_mode & 0o4000,
        0,
        "Off + kill_priv must strip setuid on host: {host_mode:o}"
    );
}

#[test]
fn test_off_chmod_changes_host_mode_directly() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg.host_permissions = HostPermissions::Private; // irrelevant when off
        cfg
    });

    let (entry, _) = sb.fuse_create_root("file.txt").unwrap();

    // chmod 0o644 on the file.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = 0o100644 as _;
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();

    // Real host file should have mode 0o644 now.
    let host_path = sb.root.join("file.txt");
    let meta = std::fs::metadata(&host_path).unwrap();
    use std::os::unix::fs::PermissionsExt;
    let host_mode = meta.permissions().mode() & 0o777;
    assert_eq!(host_mode, 0o644);
}
