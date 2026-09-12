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

//--------------------------------------------------------------------------------------------------
// Tests: forget keeps anchors alive
//--------------------------------------------------------------------------------------------------

/// Forgetting a directory that still anchors a child must keep the directory
/// record so the child can be reopened.
#[test]
fn test_anchor_parent_survives_forget_while_child_lives() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("p");
    sb.host_create_file("p/child", b"c");
    let p = sb.lookup_root("p").unwrap();
    let child = sb.lookup(p.inode, "child").unwrap();

    sb.fs.forget(sb.ctx(), p.inode, 1);
    assert!(sb.fs.inodes.read().unwrap().get(&p.inode).is_some());

    let h = sb.fuse_open(child.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(&sb.fuse_read(child.inode, h, 8, 0).unwrap()[..], b"c");

    // Forgetting the child releases the parent too.
    sb.fs.forget(sb.ctx(), child.inode, 1);
    assert!(sb.fs.inodes.read().unwrap().get(&child.inode).is_none());
    assert!(sb.fs.inodes.read().unwrap().get(&p.inode).is_none());
}

/// In volfs mode forget removes the inode immediately, as before.
#[test]
fn test_volfs_forget_removes_immediately() {
    let sb = TestSandbox::new();
    sb.host_create_dir("q");
    sb.host_create_file("q/child", b"c");
    let q = sb.lookup_root("q").unwrap();
    let _child = sb.lookup(q.inode, "child").unwrap();
    sb.fs.forget(sb.ctx(), q.inode, 1);
    assert!(sb.fs.inodes.read().unwrap().get(&q.inode).is_none());
}

//--------------------------------------------------------------------------------------------------
// Tests: rename, unlink, rmdir keep aliases correct
//--------------------------------------------------------------------------------------------------

/// After a guest rename the inode reopens through its new name.
#[test]
fn test_anchor_rename_then_read() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_file("old.txt", b"same");
    let f = sb.lookup_root("old.txt").unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("old.txt"),
            ROOT_INODE,
            &TestSandbox::cstr("new.txt"),
            0,
        )
        .unwrap();
    let h = sb.fuse_open(f.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(&sb.fuse_read(f.inode, h, 8, 0).unwrap()[..], b"same");
    let inodes = sb.fs.inodes.read().unwrap();
    let data = inodes.get(&f.inode).unwrap();
    assert_eq!(&*data.anchor_name.read().unwrap(), b"new.txt");
}

/// Renaming a directory moves every descendant's resolution path.
#[test]
fn test_anchor_rename_directory_moves_children() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("dir1");
    sb.host_create_file("dir1/inner", b"in");
    let d = sb.lookup_root("dir1").unwrap();
    let inner = sb.lookup(d.inode, "inner").unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("dir1"),
            ROOT_INODE,
            &TestSandbox::cstr("dir2"),
            0,
        )
        .unwrap();
    let h = sb.fuse_open(inner.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(&sb.fuse_read(inner.inode, h, 8, 0).unwrap()[..], b"in");
}

/// Rename over an existing target detaches the target; an open handle on the
/// old target still reads its data.
#[test]
fn test_anchor_rename_replaces_target() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_file("src", b"source");
    sb.host_create_file("dst", b"target");
    let src = sb.lookup_root("src").unwrap();
    let dst = sb.lookup_root("dst").unwrap();
    let dst_h = sb.fuse_open(dst.inode, libc::O_RDONLY as u32).unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("src"),
            ROOT_INODE,
            &TestSandbox::cstr("dst"),
            0,
        )
        .unwrap();
    assert_eq!(
        &sb.fuse_read(dst.inode, dst_h, 8, 0).unwrap()[..],
        b"target"
    );
    let src_h = sb.fuse_open(src.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(
        &sb.fuse_read(src.inode, src_h, 8, 0).unwrap()[..],
        b"source"
    );
}

/// Unlink drops the alias; a pre-existing open handle still reads.
#[test]
fn test_anchor_unlink_keeps_open_handle() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_file("gone", b"kept");
    let g = sb.lookup_root("gone").unwrap();
    let h = sb.fuse_open(g.inode, libc::O_RDONLY as u32).unwrap();
    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("gone"))
        .unwrap();
    assert_eq!(&sb.fuse_read(g.inode, h, 8, 0).unwrap()[..], b"kept");
    let inodes = sb.fs.inodes.read().unwrap();
    let data = inodes.get(&g.inode).unwrap();
    assert!(data.aliases.read().unwrap().is_empty());
    assert!(data.unlinked_fd.load(std::sync::atomic::Ordering::Acquire) >= 0);
}

/// rmdir removes the directory's alias.
#[test]
fn test_anchor_rmdir_drops_alias() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("empty");
    let e = sb.lookup_root("empty").unwrap();
    sb.fs
        .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("empty"))
        .unwrap();
    let inodes = sb.fs.inodes.read().unwrap();
    let data = inodes.get(&e.inode).unwrap();
    assert!(data.aliases.read().unwrap().is_empty());
    assert_eq!(
        data.anchor_parent
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
}

/// Exchanging two names that are hard-linked to the same inode must leave
/// both aliases intact: nothing actually moves on disk.
#[test]
fn test_anchor_exchange_same_inode_keeps_both_aliases() {
    let sb = TestSandbox::with_anchor_mode();
    let a = sb.host_create_file("a", b"linked");
    std::fs::hard_link(&a, sb.root.join("b")).unwrap();
    let entry_a = sb.lookup_root("a").unwrap();
    let entry_b = sb.lookup_root("b").unwrap();
    assert_eq!(entry_a.inode, entry_b.inode);

    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("a"),
            ROOT_INODE,
            &TestSandbox::cstr("b"),
            2, // RENAME_EXCHANGE
        )
        .unwrap();

    let inodes = sb.fs.inodes.read().unwrap();
    let data = inodes.get(&entry_a.inode).unwrap();
    assert_eq!(data.aliases.read().unwrap().len(), 2);
    drop(inodes);

    let h_a = sb.fuse_open(entry_a.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(
        &sb.fuse_read(entry_a.inode, h_a, 8, 0).unwrap()[..],
        b"linked"
    );
    let h_b = sb.fuse_open(entry_b.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(
        &sb.fuse_read(entry_b.inode, h_b, 8, 0).unwrap()[..],
        b"linked"
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: link, readlink, symlink metadata
//--------------------------------------------------------------------------------------------------

/// Hard link creation resolves the source through its anchor.
#[test]
fn test_anchor_hard_link() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("lnk");
    sb.host_create_file("lnk/orig", b"linked");
    let d = sb.lookup_root("lnk").unwrap();
    let orig = sb.lookup(d.inode, "orig").unwrap();
    let copy = sb
        .fs
        .link(sb.ctx(), orig.inode, ROOT_INODE, &TestSandbox::cstr("copy"))
        .unwrap();
    assert_eq!(copy.inode, orig.inode);
    let h = sb.fuse_open(copy.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(&sb.fuse_read(copy.inode, h, 8, 0).unwrap()[..], b"linked");
    assert_eq!(std::fs::read(sb.root.join("copy")).unwrap(), b"linked");
}

/// readlink on a nested symlink works through the anchor parent.
#[test]
fn test_anchor_readlink_nested() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("s");
    std::os::unix::fs::symlink("target-name", sb.root.join("s/link")).unwrap();
    let s = sb.lookup_root("s").unwrap();
    let l = sb.lookup(s.inode, "link").unwrap();
    assert_eq!(sb.fs.readlink(sb.ctx(), l.inode).unwrap(), b"target-name");
}

/// setattr times on a symlink go through the anchor parent, and both atime
/// and mtime land on the verified fd via `futimens` rather than a name-based
/// `utimensat`.
#[test]
fn test_anchor_symlink_times() {
    let sb = TestSandbox::with_anchor_mode();
    std::os::unix::fs::symlink("elsewhere", sb.root.join("tl")).unwrap();
    let l = sb.lookup_root("tl").unwrap();
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mtime = 1_000_000_000;
    attr.st_atime = 2_000_000_000;
    let (st, _) = sb
        .fs
        .setattr(
            sb.ctx(),
            l.inode,
            attr,
            None,
            SetattrValid::MTIME | SetattrValid::ATIME,
        )
        .unwrap();
    assert_eq!(st.st_mtime, 1_000_000_000);
    assert_eq!(st.st_atime, 2_000_000_000);
}

/// A host-side replacement of a symlink's name with a regular file must not
/// let a stale fd operate on the replacement: the anchor-mode fd open
/// verifies (dev, ino) after opening and fails closed as `ENOENT`.
#[test]
fn test_anchor_symlink_fd_identity_mismatch() {
    let sb = TestSandbox::with_anchor_mode();
    std::os::unix::fs::symlink("elsewhere", sb.root.join("sl")).unwrap();
    let l = sb.lookup_root("sl").unwrap();

    // Simulate a host-side race: remove the symlink and put a regular file
    // under the same name, so the tracked inode's anchor now names a
    // different on-disk identity.
    std::fs::remove_file(sb.root.join("sl")).unwrap();
    std::fs::write(sb.root.join("sl"), b"not a symlink").unwrap();

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = libc::S_IFLNK | 0o777;
    let result = sb
        .fs
        .setattr(sb.ctx(), l.inode, attr, None, SetattrValid::MODE);
    TestSandbox::assert_errno(result, LINUX_ENOENT);
}
