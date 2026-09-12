#![cfg(target_os = "macos")]

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests: volfs probe
//--------------------------------------------------------------------------------------------------

/// A temp dir on the developer's APFS volume supports volfs, so a default
/// sandbox must report volfs support and not run in anchor mode.
#[test]
fn test_probe_reports_volfs_on_apfs_tempdir() {
    let sb = TestSandbox::new();
    assert!(!sb.fs.anchor_mode());
}

/// The forced helper flips the share into anchor mode.
#[test]
fn test_with_anchor_mode_forces_anchor_mode() {
    let sb = TestSandbox::with_anchor_mode();
    assert!(sb.fs.anchor_mode());
}

/// The probe itself: a real root fd probes true; a fabricated identity that
/// cannot exist on any mounted volume probes false.
#[test]
fn test_probe_volfs_support_direct() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = std::fs::File::open(tmp.path()).unwrap();
    assert!(probe_volfs_support(dir.as_raw_fd()));
    // dev 0 is never a mounted volume: open("/.vol/0/1") must fail.
    assert!(!probe_volfs_path(0, 1));
}

//--------------------------------------------------------------------------------------------------
// Tests: alias bookkeeping
//--------------------------------------------------------------------------------------------------

/// In anchor mode a lookup records the (parent, name) alias on the inode.
#[test]
fn test_lookup_registers_alias_in_anchor_mode() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("a");
    sb.host_create_file("a/f.txt", b"x");
    let a = sb.lookup_root("a").unwrap();
    let f = sb.lookup(a.inode, "f.txt").unwrap();

    let inodes = sb.fs.inodes.read().unwrap();
    let data = inodes.get(&f.inode).unwrap();
    assert_eq!(
        data.anchor_parent
            .load(std::sync::atomic::Ordering::Acquire),
        a.inode
    );
    assert_eq!(&*data.anchor_name.read().unwrap(), b"f.txt");
    assert_eq!(data.aliases.read().unwrap().len(), 1);
}

/// In volfs mode the alias table stays empty, so APFS behaviour is unchanged.
#[test]
fn test_lookup_records_no_alias_in_volfs_mode() {
    let sb = TestSandbox::new();
    sb.host_create_file("f.txt", b"x");
    let f = sb.lookup_root("f.txt").unwrap();
    let inodes = sb.fs.inodes.read().unwrap();
    let data = inodes.get(&f.inode).unwrap();
    assert_eq!(
        data.anchor_parent
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    assert!(data.aliases.read().unwrap().is_empty());
}
