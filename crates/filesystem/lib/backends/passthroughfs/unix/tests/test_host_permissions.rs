//! Tests for the `HostPermissions` policy: Private vs Mirror semantics.

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::backends::passthroughfs::{HostPermissions, StatVirtualization};

fn host_mode(sb: &TestSandbox, name: &str) -> u32 {
    let path = sb.root.join(name);
    let meta = std::fs::metadata(&path).unwrap();
    meta.permissions().mode() & 0o7777
}

#[test]
fn test_private_keeps_host_mode_conservative_for_files() {
    // Private: guest chmod doesn't touch host. Host file stays at 0o600.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.host_permissions = HostPermissions::Private;
        cfg
    });

    let (entry, _) = sb.fuse_create_root("file.txt").unwrap();

    // Guest chmod 0o755.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = 0o100755 as _;
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();

    // Guest-visible mode is updated.
    assert_eq!(sb.get_mode(entry.inode), 0o755);
    // But host mode stays at the conservative initial value.
    assert_eq!(host_mode(&sb, "file.txt"), 0o600);
}

#[test]
fn test_private_keeps_host_mode_conservative_for_dirs() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.host_permissions = HostPermissions::Private;
        cfg
    });

    let entry = sb.fuse_mkdir_root("d").unwrap();
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = 0o040755 as _;
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();

    assert_eq!(sb.get_mode(entry.inode), 0o755);
    assert_eq!(host_mode(&sb, "d"), 0o700);
}

#[test]
fn test_mirror_propagates_chmod_to_host_files() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.host_permissions = HostPermissions::Mirror;
        cfg
    });

    let (entry, _) = sb.fuse_create_root("script.sh").unwrap();

    // chmod +x equivalent: 0o755.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = 0o100755 as _;
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();

    // Guest and host both reflect the chmod.
    assert_eq!(sb.get_mode(entry.inode), 0o755);
    assert_eq!(host_mode(&sb, "script.sh"), 0o755);
}

#[test]
fn test_mirror_applies_owner_floor_on_create() {
    // Even when the guest requests a restrictive mode like 0o040, the host
    // file must keep owner rw so the host process can still write to it.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.host_permissions = HostPermissions::Mirror;
        cfg
    });

    let (entry, handle, _) = sb
        .fs
        .create(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("locked"),
            0o040,
            false,
            LINUX_O_RDWR,
            0,
            Extensions::default(),
        )
        .unwrap();
    let _ = handle;

    // Guest sees 0o040 via the overlay.
    assert_eq!(sb.get_mode(entry.inode), 0o040);
    // Host has owner-rw floor merged in: 0o040 | 0o600 = 0o640.
    assert_eq!(host_mode(&sb, "locked"), 0o640);
}

#[test]
fn test_mirror_strips_setuid_from_host() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.host_permissions = HostPermissions::Mirror;
        cfg
    });

    let (entry, _) = sb.fuse_create_root("setuid.bin").unwrap();

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = (0o100755 | 0o4000) as _;
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();

    let host = host_mode(&sb, "setuid.bin");
    assert_eq!(host & 0o4000, 0, "host mode kept setuid bit: {host:o}");
}

#[test]
fn test_mirror_strips_setgid_from_host() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.host_permissions = HostPermissions::Mirror;
        cfg
    });

    let (entry, _) = sb.fuse_create_root("setgid.bin").unwrap();

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = (0o100755 | 0o2000) as _;
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();

    let host = host_mode(&sb, "setgid.bin");
    assert_eq!(host & 0o2000, 0, "host mode kept setgid bit: {host:o}");
}

#[test]
fn test_mirror_strips_setuid_setgid_combined() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.host_permissions = HostPermissions::Mirror;
        cfg
    });

    let (entry, _) = sb.fuse_create_root("both.bin").unwrap();

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = (0o100755 | 0o6000) as _;
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();

    let host = host_mode(&sb, "both.bin");
    assert_eq!(host & 0o6000, 0, "host mode kept setuid|setgid: {host:o}");
}

#[test]
fn test_mirror_propagates_on_mkdir() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.host_permissions = HostPermissions::Mirror;
        cfg
    });

    let _entry = sb.fuse_mkdir_root("readable").unwrap();
    // mkdir_root creates with 0o755.
    assert_eq!(host_mode(&sb, "readable"), 0o755);
}

#[test]
fn test_mirror_applies_dir_floor_on_restrictive_mkdir() {
    // Guest requests 0o040 on a directory — host must end up with at least
    // the dir floor (0o700) so the host process can still traverse it.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.host_permissions = HostPermissions::Mirror;
        cfg
    });

    let _entry = sb
        .fs
        .mkdir(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("locked_dir"),
            0o040,
            0,
            Extensions::default(),
        )
        .unwrap();

    // Guest mode 0o040 | dir-floor 0o700 = 0o740.
    assert_eq!(host_mode(&sb, "locked_dir"), 0o740);
}

#[test]
fn test_mirror_does_not_mirror_to_fifo() {
    // Guest mknod a FIFO, then chmod it. The Mirror gate must skip
    // fchmod for non-REG/non-DIR — the host backing file (regular
    // file representing a FIFO) should retain the conservative 0o600.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.host_permissions = HostPermissions::Mirror;
        cfg
    });

    // Create a FIFO via mknod (regular file on host, S_IFIFO in xattr).
    const S_IFIFO: u32 = 0o0010000;
    let entry = sb
        .fs
        .mknod(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("pipe"),
            S_IFIFO | 0o600,
            0,
            0,
            Extensions::default(),
        )
        .unwrap();

    // Guest chmod 0o755 — Mirror must NOT fchmod the host because the type
    // is FIFO, not REG/DIR.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = (S_IFIFO | 0o755) as _;
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();

    // Host backing file (which is a regular file representing the FIFO) keeps
    // its conservative 0o600.
    assert_eq!(host_mode(&sb, "pipe"), 0o600);
}

#[test]
fn test_mirror_does_not_fchown_host() {
    // Verify uid/gid are NEVER mirrored: after a Mirror chmod, the host
    // inode must still be owned by the real process uid (not whatever the
    // overlay records).
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.host_permissions = HostPermissions::Mirror;
        cfg
    });

    let (entry, _) = sb.fuse_create_root("uid_check.txt").unwrap();

    // Now setattr UID and MODE together — the overlay will record uid=4242,
    // but the host file must keep the real process uid.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_uid = 4242;
    attr.st_mode = 0o100755 as _;
    sb.fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::MODE,
        )
        .unwrap();

    let real_uid = unsafe { libc::getuid() };
    let host_meta = std::fs::metadata(sb.root.join("uid_check.txt")).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        host_meta.uid(),
        real_uid,
        "Mirror must not fchown the host inode"
    );
}

#[test]
fn test_off_creates_with_requested_mode_directly() {
    // With Off, there is no overlay — the host file is the guest's view.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });

    let (entry, _, _) = sb
        .fs
        .create(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("plain"),
            0o644,
            false,
            LINUX_O_RDWR,
            0,
            Extensions::default(),
        )
        .unwrap();
    let _ = entry;

    assert_eq!(host_mode(&sb, "plain"), 0o644);
}
