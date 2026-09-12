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

//--------------------------------------------------------------------------------------------------
// Tests: reopen by anchor
//--------------------------------------------------------------------------------------------------

/// Read a nested file entirely through anchor resolution.
#[test]
fn test_anchor_read_nested_file() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("a/b/c");
    sb.host_create_file("a/b/c/deep.txt", b"deep");
    let a = sb.lookup_root("a").unwrap();
    let b = sb.lookup(a.inode, "b").unwrap();
    let c = sb.lookup(b.inode, "c").unwrap();
    let f = sb.lookup(c.inode, "deep.txt").unwrap();
    let h = sb.fuse_open(f.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(&sb.fuse_read(f.inode, h, 64, 0).unwrap()[..], b"deep");
}

/// getattr on a tracked inode reopens through the anchor walk.
#[test]
fn test_anchor_getattr_after_lookup() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_file("g.txt", b"12345");
    let g = sb.lookup_root("g.txt").unwrap();
    let (st, _) = sb.fs.getattr(sb.ctx(), g.inode, None).unwrap();
    assert_eq!(st.st_size, 5);
}

/// opendir + readdir on a nested directory through anchor resolution.
#[test]
fn test_anchor_readdir_nested() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("d");
    sb.host_create_file("d/one", b"1");
    sb.host_create_file("d/two", b"2");
    let d = sb.lookup_root("d").unwrap();
    let h = sb.fuse_opendir(d.inode).unwrap();
    let entries = sb.fs.readdir(sb.ctx(), d.inode, h, 4096, 0).unwrap();
    let mut names: Vec<Vec<u8>> = entries.iter().map(|e| e.name.to_vec()).collect();
    names.sort();
    assert!(names.contains(&b"one".to_vec()));
    assert!(names.contains(&b"two".to_vec()));
}

/// A twelve-level path resolves; this is the deepest layout seen in a real
/// forensic case tree.
#[test]
fn test_anchor_twelve_levels() {
    let sb = TestSandbox::with_anchor_mode();
    let path = "l1/l2/l3/l4/l5/l6/l7/l8/l9/l10/l11";
    sb.host_create_dir(path);
    sb.host_create_file(&format!("{path}/leaf"), b"leaf");
    let mut parent = ROOT_INODE;
    for comp in path.split('/') {
        parent = sb.lookup(parent, comp).unwrap().inode;
    }
    let leaf = sb.lookup(parent, "leaf").unwrap();
    let h = sb.fuse_open(leaf.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(&sb.fuse_read(leaf.inode, h, 16, 0).unwrap()[..], b"leaf");
}

/// If the host swaps a different file into the anchored name after lookup, the
/// reopen must fail closed (ENOENT) rather than serve the impostor.
#[test]
fn test_anchor_identity_mismatch_fails_closed() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_file("victim.txt", b"secret");
    let v = sb.lookup_root("victim.txt").unwrap();
    // Move the original aside instead of deleting it, so its inode number
    // stays live and APFS cannot coincidentally reuse it for the
    // replacement (which would mask the identity check succeeding for the
    // wrong reason).
    std::fs::rename(sb.root.join("victim.txt"), sb.root.join("victim.orig")).unwrap();
    sb.host_create_file("victim.txt", b"impostor");

    let result = sb.fuse_open(v.inode, libc::O_RDONLY as u32);
    TestSandbox::assert_errno(result, LINUX_ENOENT);

    // Only the stale inode handle is refused; a fresh lookup of the name
    // sees the impostor normally.
    let fresh = sb.lookup_root("victim.txt").unwrap();
    let h = sb.fuse_open(fresh.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(
        &sb.fuse_read(fresh.inode, h, 64, 0).unwrap()[..],
        b"impostor"
    );
}

/// A destructive reopen (`O_TRUNC`) must not touch the impostor before the
/// identity check rejects the stale inode: truncation happens only after
/// `validate_identity_macos` passes, never as a side effect of the walk's
/// final `openat`.
#[test]
fn test_anchor_reopen_truncate_does_not_touch_impostor() {
    const LINUX_O_WRONLY: u32 = 1;

    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_file("victim.txt", b"secret");
    let v = sb.lookup_root("victim.txt").unwrap();
    std::fs::rename(sb.root.join("victim.txt"), sb.root.join("victim.moved")).unwrap();
    sb.host_create_file("victim.txt", b"impostor");

    let result = sb.fuse_open(v.inode, LINUX_O_WRONLY | LINUX_O_TRUNC);
    TestSandbox::assert_errno(result, LINUX_ENOENT);

    let contents = std::fs::read(sb.root.join("victim.txt")).unwrap();
    assert_eq!(contents, b"impostor");
}

/// A host-side symlink component in the anchor path is refused.
#[test]
fn test_anchor_refuses_symlink_component() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("real");
    sb.host_create_file("real/f", b"f");
    let real = sb.lookup_root("real").unwrap();
    let f = sb.lookup(real.inode, "f").unwrap();
    // Swap the directory for a symlink to itself-under-another-name.
    std::fs::rename(sb.root.join("real"), sb.root.join("moved")).unwrap();
    std::os::unix::fs::symlink(sb.root.join("moved"), sb.root.join("real")).unwrap();
    let result = sb.fuse_open(f.inode, libc::O_RDONLY as u32);
    TestSandbox::assert_errno(result, LINUX_ENOENT);
}

//--------------------------------------------------------------------------------------------------
// Tests: root inode
//--------------------------------------------------------------------------------------------------

/// The root inode has no anchor alias (it is inode 1 by FUSE convention, not
/// a recorded (parent, name) pair), so `getattr` on it must resolve via the
/// root-inode shortcut in `open_anchor_fd_macos` rather than the (empty)
/// alias loop.
#[test]
fn test_anchor_root_getattr() {
    let sb = TestSandbox::with_anchor_mode();
    let (st, _) = sb.fs.getattr(sb.ctx(), ROOT_INODE, None).unwrap();
    assert_eq!(
        st.st_mode as u32 & libc::S_IFMT as u32,
        libc::S_IFDIR as u32
    );
}

/// `opendir` + `readdir` on the root inode must also resolve via the
/// root-inode shortcut.
#[test]
fn test_anchor_root_readdir() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_file("marker.txt", b"x");
    let h = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb.fs.readdir(sb.ctx(), ROOT_INODE, h, 4096, 0).unwrap();
    let names: Vec<Vec<u8>> = entries.iter().map(|e| e.name.to_vec()).collect();
    assert!(names.contains(&b"marker.txt".to_vec()));
}

//--------------------------------------------------------------------------------------------------
// Tests: symlinks
//--------------------------------------------------------------------------------------------------

/// A tracked symlink inode can still be stat'ed in anchor mode: the final
/// component's `ELOOP` from `O_NOFOLLOW` triggers the `O_SYMLINK` retry
/// instead of being classified as a stale alias.
#[test]
fn test_anchor_getattr_symlink() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_file("target.txt", b"x");
    std::os::unix::fs::symlink(sb.root.join("target.txt"), sb.root.join("link")).unwrap();
    let link = sb.lookup_root("link").unwrap();
    let (st, _) = sb.fs.getattr(sb.ctx(), link.inode, None).unwrap();
    assert_eq!(
        st.st_mode as u32 & libc::S_IFMT as u32,
        libc::S_IFLNK as u32
    );
}

/// Opening a tracked symlink inode for I/O must still fail closed with
/// `ELOOP`, exactly as a real symlink would on Linux — the anchor walk must
/// not follow it just because reopening it for stat succeeds.
#[test]
fn test_anchor_open_symlink_for_io_is_eloop() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_file("target.txt", b"x");
    std::os::unix::fs::symlink(sb.root.join("target.txt"), sb.root.join("link")).unwrap();
    let link = sb.lookup_root("link").unwrap();
    let result = sb.fuse_open(link.inode, libc::O_RDONLY as u32);
    TestSandbox::assert_errno(result, LINUX_ELOOP);
}

//--------------------------------------------------------------------------------------------------
// Tests: exclusive create
//--------------------------------------------------------------------------------------------------

/// `do_create`'s reopen of a just-created file keeps `O_EXCL` set (it strips
/// only `O_CREAT`), so `open_inode_fd`'s anchor branch must let `O_EXCL`
/// through the walk rather than rejecting it: `O_CREAT|O_EXCL` creates must
/// still succeed in anchor mode, and a second exclusive create of the same
/// name must still fail `EEXIST`.
#[test]
fn test_anchor_exclusive_create() {
    const LINUX_O_WRONLY: u32 = 1;
    const LINUX_O_CREAT: u32 = 0x40;
    const LINUX_O_EXCL: u32 = 0x80;

    let sb = TestSandbox::with_anchor_mode();
    let flags = LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL;
    let (entry, handle) = sb
        .fuse_create_flags(ROOT_INODE, "excl.txt", 0o644, false, flags)
        .unwrap();
    sb.fuse_write(entry.inode, handle, b"hello", 0).unwrap();
    assert_eq!(std::fs::read(sb.root.join("excl.txt")).unwrap(), b"hello");

    let second = sb.fuse_create_flags(ROOT_INODE, "excl.txt", 0o644, false, flags);
    TestSandbox::assert_errno(second, LINUX_EEXIST);
}
