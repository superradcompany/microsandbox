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

/// A cross-directory exchange must not collect a parent between the two
/// anchor transfers. `p` (or `q`) is forgotten and survives only through the
/// child anchored to it; moving that child away first would drop the
/// directory before the other child is re-anchored to it, and the other child
/// would then be unresolvable even though the exchange succeeded.
#[test]
fn test_anchor_exchange_cross_dir_after_parent_forgotten() {
    for forget_source_parent in [true, false] {
        let sb = TestSandbox::with_anchor_mode();
        sb.host_create_dir("p");
        sb.host_create_dir("q");
        sb.host_create_file("p/a", b"aaa");
        sb.host_create_file("q/b", b"bbb");
        let p = sb.lookup_root("p").unwrap();
        let q = sb.lookup_root("q").unwrap();
        let a = sb.lookup(p.inode, "a").unwrap();
        let b = sb.lookup(q.inode, "b").unwrap();
        assert_ne!(a.inode, b.inode);

        if forget_source_parent {
            sb.fs.forget(sb.ctx(), p.inode, 1);
        } else {
            sb.fs.forget(sb.ctx(), q.inode, 1);
        }

        sb.fs
            .rename(
                sb.ctx(),
                p.inode,
                &TestSandbox::cstr("a"),
                q.inode,
                &TestSandbox::cstr("b"),
                2, // RENAME_EXCHANGE
            )
            .unwrap();

        {
            let inodes = sb.fs.inodes.read().unwrap();
            assert!(
                inodes.get(&p.inode).is_some(),
                "p was collected during the exchange"
            );
            assert!(
                inodes.get(&q.inode).is_some(),
                "q was collected during the exchange"
            );
        }

        // `a` now lives at q/b and `b` at p/a; both must still reopen.
        let ha = sb.fuse_open(a.inode, libc::O_RDONLY as u32).unwrap();
        assert_eq!(&sb.fuse_read(a.inode, ha, 8, 0).unwrap()[..], b"aaa");
        let hb = sb.fuse_open(b.inode, libc::O_RDONLY as u32).unwrap();
        assert_eq!(&sb.fuse_read(b.inode, hb, 8, 0).unwrap()[..], b"bbb");
        assert_eq!(std::fs::read(sb.root.join("q/b")).unwrap(), b"aaa");
        assert_eq!(std::fs::read(sb.root.join("p/a")).unwrap(), b"bbb");
    }
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

//--------------------------------------------------------------------------------------------------
// Tests: root reopen is a fresh file description
//--------------------------------------------------------------------------------------------------

/// Two root directory handles must not share one file description. A dup of
/// the retained root fd would share its seek offset, so draining one listing
/// would truncate the other.
#[test]
fn test_anchor_root_opendir_twice_independent() {
    let sb = TestSandbox::with_anchor_mode();
    for i in 0..8 {
        sb.host_create_file(&format!("entry{i}"), b"x");
    }

    let first = sb.fuse_opendir(ROOT_INODE).unwrap();
    let second = sb.fuse_opendir(ROOT_INODE).unwrap();

    // Distinct file descriptions: moving one handle's offset must not move
    // the other's.
    let (fd_first, fd_second) = {
        let handles = sb.fs.dir_handles.read().unwrap();
        let a = handles
            .get(&first)
            .unwrap()
            .file
            .read()
            .unwrap()
            .as_raw_fd();
        let b = handles
            .get(&second)
            .unwrap()
            .file
            .read()
            .unwrap()
            .as_raw_fd();
        (a, b)
    };
    assert_ne!(fd_first, fd_second);
    let moved = unsafe { libc::lseek(fd_first, 0, libc::SEEK_END) };
    assert!(moved > 0);
    assert_eq!(unsafe { libc::lseek(fd_second, 0, libc::SEEK_CUR) }, 0);

    // Drain the first listing, then list the second from offset 0.
    let drained = sb.fs.readdir(sb.ctx(), ROOT_INODE, first, 4096, 0).unwrap();
    assert!(!drained.is_empty());
    assert!(
        sb.fs
            .readdir(sb.ctx(), ROOT_INODE, first, 4096, drained.len() as u64)
            .unwrap()
            .is_empty()
    );

    let names: Vec<Vec<u8>> = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, second, 4096, 0)
        .unwrap()
        .iter()
        .map(|e| e.name.to_vec())
        .collect();
    for i in 0..8 {
        assert!(names.contains(&format!("entry{i}").into_bytes()));
    }
}

//--------------------------------------------------------------------------------------------------
// Tests: entries that cannot be opened
//--------------------------------------------------------------------------------------------------

/// A Unix socket cannot be opened, but it must still look up: the anchor-mode
/// lookup falls back to `fstatat` for any open failure, not just a denied
/// permission.
#[test]
fn test_anchor_lookup_socket_entry() {
    let sb = TestSandbox::with_anchor_mode();
    let _listener = std::os::unix::net::UnixListener::bind(sb.root.join("sock")).unwrap();
    let entry = sb.lookup_root("sock").unwrap();
    assert_eq!(
        entry.attr.st_mode as u32 & libc::S_IFMT as u32,
        libc::S_IFSOCK as u32
    );
}

/// A FIFO with no writer must not park the worker: every pre-verification
/// open in anchor mode carries `O_NONBLOCK`.
#[test]
fn test_anchor_getattr_fifo_does_not_block() {
    let sb = TestSandbox::with_anchor_mode();
    let path = TestSandbox::cstr(sb.root.join("pipe").to_str().unwrap());
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0);

    let entry = sb.lookup_root("pipe").unwrap();
    assert_eq!(
        entry.attr.st_mode as u32 & libc::S_IFMT as u32,
        libc::S_IFIFO as u32
    );
    let (st, _) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_eq!(
        st.st_mode as u32 & libc::S_IFMT as u32,
        libc::S_IFIFO as u32
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: FIFO reopen helpers
//--------------------------------------------------------------------------------------------------

/// How long a FIFO test may run before the binary is considered wedged.
const FIFO_TEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a FIFO test waits for one expected step.
const FIFO_STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Aborts the test binary if a FIFO test wedges.
///
/// These tests park real threads on real FIFO opens. A regression that never
/// releases one would otherwise hang `cargo test` forever with no output, so
/// the deadline turns it into a loud, bounded failure. Cancellation travels
/// over a channel: the watchdog treats both a message and a disconnected
/// sender as "the test is done", so dropping this value — on a normal return
/// or while unwinding — disarms it, and a thread that oversleeps past the
/// deadline still sees the cancellation instead of aborting a passed test.
struct FifoWatchdog {
    _cancel: std::sync::mpsc::Sender<()>,
}

impl FifoWatchdog {
    fn new(name: &'static str) -> Self {
        let (cancel, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // A message and a disconnected sender both mean "cancelled"; only
            // the timeout is a wedged test.
            if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                rx.recv_timeout(FIFO_TEST_DEADLINE)
            {
                eprintln!("fifo watchdog: {name} did not finish within 30s; aborting");
                std::process::abort();
            }
        });
        Self { _cancel: cancel }
    }
}

/// Sets a flag when it is dropped, however the drop comes about.
struct FlagOnDrop(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for FlagOnDrop {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// One worker thread running a call that may park on a FIFO open.
///
/// The worker owns its thread. Completion is published from a guard inside the
/// worker closure, so a panic reports completion too, and `Drop` releases the
/// worker — by opening the side of the FIFO the blocked party is waiting for —
/// and then joins it, on every exit path. A worker panic is re-raised on the
/// main thread unless it is already unwinding.
struct FifoWorker<T> {
    results: std::sync::mpsc::Receiver<io::Result<T>>,
    finished: std::sync::Arc<std::sync::atomic::AtomicBool>,
    peer: CString,
    peer_flags: i32,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl<T: Send + 'static> FifoWorker<T> {
    /// Run `call` against the sandbox on its own thread.
    ///
    /// `peer_flags` is the side of `peer` that releases this worker: the
    /// opposite side of the open it may park on.
    fn spawn(
        sb: &std::sync::Arc<TestSandbox>,
        peer: CString,
        peer_flags: i32,
        call: impl FnOnce(&TestSandbox) -> io::Result<T> + Send + 'static,
    ) -> Self {
        let worker = std::sync::Arc::clone(sb);
        Self::spawn_raw(peer, peer_flags, move || call(&worker))
    }

    /// Run `call` on its own thread without a sandbox, for host-side peers.
    fn spawn_raw(
        peer: CString,
        peer_flags: i32,
        call: impl FnOnce() -> io::Result<T> + Send + 'static,
    ) -> Self {
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&finished);
        let (tx, results) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            // Declared first so it drops last: completion is published after
            // the result is sent, and also when the call panics.
            let _done = FlagOnDrop(flag);
            let _ = tx.send(call());
        });
        Self {
            results,
            finished,
            peer,
            peer_flags,
            handle: Some(handle),
        }
    }

    /// Whether the call is still running after a short observation window.
    fn is_pending(&self) -> bool {
        matches!(
            self.results
                .recv_timeout(std::time::Duration::from_millis(300)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        )
    }

    /// Wait for the call's result, or fail the test.
    fn wait(&self, what: &str) -> io::Result<T> {
        match self.results.recv_timeout(FIFO_STEP_TIMEOUT) {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("{what} ended without a result")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("{what} never completed"),
        }
    }
}

impl<T> Drop for FifoWorker<T> {
    fn drop(&mut self) {
        let deadline = std::time::Instant::now() + FIFO_STEP_TIMEOUT;
        while !self.finished.load(std::sync::atomic::Ordering::Acquire) {
            // Opening the peer side never waits: a read-open of a FIFO returns
            // at once, and a non-blocking write-open either finds the parked
            // reader or fails ENXIO. The worker may not have reached its open
            // yet, so this retries until it reports that it finished.
            let fd = unsafe { libc::open(self.peer.as_ptr(), self.peer_flags | libc::O_NONBLOCK) };
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
            if std::time::Instant::now() >= deadline {
                eprintln!("fifo worker could not be released; aborting");
                std::process::abort();
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if let Some(handle) = self.handle.take()
            && let Err(payload) = handle.join()
        {
            eprintln!("fifo worker panicked");
            if !std::thread::panicking() {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

/// Prove the inode table still takes its write lock, without hanging if it
/// does not: a lookup registers an inode, so it needs the same lock a parked
/// open must not be holding.
fn assert_inode_table_live(sb: &std::sync::Arc<TestSandbox>, name: &'static str) {
    let probe = std::sync::Arc::clone(sb);
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        probe.host_create_file(name, b"x");
        let _ = tx.send(probe.lookup_root(name).map(|_| ()));
    });
    let result = match rx.recv_timeout(FIFO_STEP_TIMEOUT) {
        Ok(result) => result,
        // The thread is left to the watchdog: it is stuck on the very lock
        // this call was meant to prove is free, so joining it here would hang
        // the test instead of failing it.
        Err(_) => panic!("the inode table was still locked while a FIFO open waited"),
    };
    result.expect("lookup failed while a FIFO open waited");
    handle.join().expect("the inode-table probe panicked");
}

/// Spin until `flag` is set, or fail with `what`.
fn await_flag(flag: &std::sync::atomic::AtomicBool, what: &str) {
    let deadline = std::time::Instant::now() + FIFO_STEP_TIMEOUT;
    while !flag.load(std::sync::atomic::Ordering::Acquire) {
        assert!(std::time::Instant::now() < deadline, "{what}");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Make the FIFO at `name` and return the C path used to reach it.
fn make_fifo(sb: &TestSandbox, name: &str) -> CString {
    let path = TestSandbox::cstr(sb.root.join(name).to_str().unwrap());
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0);
    path
}

/// Install a hook that parks the reopen at its blocking FIFO open until the
/// returned release flag is set. Returns (reached, release).
#[allow(clippy::type_complexity)]
fn park_at_blocking_fifo_open(
    sb: &TestSandbox,
) -> (
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let reached = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reached_hook = std::sync::Arc::clone(&reached);
    let release_hook = std::sync::Arc::clone(&release);
    *sb.fs.before_blocking_fifo_open.write().unwrap() = Some(std::sync::Arc::new(move || {
        reached_hook.store(true, std::sync::atomic::Ordering::Release);
        let deadline = std::time::Instant::now() + FIFO_STEP_TIMEOUT;
        while !release_hook.load(std::sync::atomic::Ordering::Acquire)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }));
    (reached, release)
}

/// Assert the anchor reopen path opened the FIFO endpoint exactly once.
///
/// Opening an endpoint is a rendezvous, so a second open — a probe that is
/// opened and discarded, wherever in the reopen path it sits — can take a
/// waiting writer's bytes away with it.
fn assert_single_endpoint_open(sb: &TestSandbox) {
    assert_eq!(
        sb.fs
            .fifo_endpoint_opens
            .load(std::sync::atomic::Ordering::Acquire),
        1,
        "the reopen path opened the FIFO endpoint more than once"
    );
}

/// A tracked regular file replaced on the host by a FIFO with no peer must not
/// park the reopen: the replacement is refused by identity before anything is
/// opened.
#[test]
fn test_anchor_reopen_replaced_by_fifo_does_not_block() {
    for flags in [libc::O_RDONLY, libc::O_WRONLY] {
        let _watchdog = FifoWatchdog::new("test_anchor_reopen_replaced_by_fifo_does_not_block");
        let sb = std::sync::Arc::new(TestSandbox::with_anchor_mode());
        sb.host_create_file("swapme", b"original");
        let file = sb.lookup_root("swapme").unwrap();

        // Keep the tracked file alive under another name so its inode number
        // cannot be reused, then put a peerless FIFO under the anchored name.
        std::fs::rename(sb.root.join("swapme"), sb.root.join("swapme.orig")).unwrap();
        let path = make_fifo(&sb, "swapme");

        let peer_flags = if flags == libc::O_RDONLY {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        };
        let worker = FifoWorker::spawn(&sb, path, peer_flags, move |sb| {
            sb.fuse_open(file.inode, flags as u32).map(|_| ())
        });
        TestSandbox::assert_errno(worker.wait("reopen of a replacement FIFO"), LINUX_ENOENT);
    }
}

/// A guest that asks for `O_NONBLOCK` itself gets the POSIX answer for a
/// write-open of a FIFO with no reader, and no retry.
#[test]
fn test_anchor_open_fifo_nonblocking_write_reports_enxio() {
    let _watchdog = FifoWatchdog::new("test_anchor_open_fifo_nonblocking_write_reports_enxio");
    let sb = TestSandbox::with_anchor_mode();
    make_fifo(&sb, "pipe");
    let entry = sb.lookup_root("pipe").unwrap();
    TestSandbox::assert_errno(
        sb.fuse_open(entry.inode, libc::O_WRONLY as u32 | LINUX_O_NONBLOCK),
        LINUX_ENXIO,
    );
}

/// A blocking read-open of a tracked FIFO must wait for a writer, as POSIX and
/// the Linux backend do — and it must wait without holding the inode table.
#[test]
fn test_anchor_open_fifo_blocking_read_waits_for_writer() {
    use std::os::fd::FromRawFd;

    let _watchdog = FifoWatchdog::new("test_anchor_open_fifo_blocking_read_waits_for_writer");
    let sb = std::sync::Arc::new(TestSandbox::with_anchor_mode());
    let path = make_fifo(&sb, "pipe");
    let entry = sb.lookup_root("pipe").unwrap();
    let (reached, release) = park_at_blocking_fifo_open(&sb);
    release.store(true, std::sync::atomic::Ordering::Release);

    let worker = FifoWorker::spawn(&sb, path.clone(), libc::O_WRONLY, move |sb| {
        sb.fuse_open(entry.inode, libc::O_RDONLY as u32).map(|_| ())
    });

    // The worker reaches the blocking open and stays there: a non-blocking fd
    // handed to the guest here would report EOF on the first read.
    await_flag(&reached, "the reopen never reached the blocking FIFO open");
    assert!(
        worker.is_pending(),
        "blocking FIFO read-open returned before any writer existed"
    );
    assert_inode_table_live(&sb, "other");

    let writer = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
    assert!(writer >= 0, "could not open the writing end of the FIFO");
    let writer = unsafe { std::fs::File::from_raw_fd(writer) };
    worker
        .wait("blocking FIFO read-open")
        .expect("blocking FIFO read-open failed");
    assert_single_endpoint_open(&sb);
    drop(writer);
}

/// The same rendezvous in the other direction: a blocking write-open waits for
/// a reader, and the wait does not freeze the inode table.
#[test]
fn test_anchor_open_fifo_blocking_write_waits_for_reader() {
    use std::os::fd::FromRawFd;

    let _watchdog = FifoWatchdog::new("test_anchor_open_fifo_blocking_write_waits_for_reader");
    let sb = std::sync::Arc::new(TestSandbox::with_anchor_mode());
    let path = make_fifo(&sb, "pipe");
    let entry = sb.lookup_root("pipe").unwrap();
    let (reached, release) = park_at_blocking_fifo_open(&sb);
    release.store(true, std::sync::atomic::Ordering::Release);

    let worker = FifoWorker::spawn(&sb, path.clone(), libc::O_RDONLY, move |sb| {
        sb.fuse_open(entry.inode, libc::O_WRONLY as u32).map(|_| ())
    });

    await_flag(&reached, "the reopen never reached the blocking FIFO open");
    assert!(
        worker.is_pending(),
        "blocking FIFO write-open returned before any reader existed"
    );
    assert_inode_table_live(&sb, "other");

    let reader = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    assert!(reader >= 0, "could not open the reading end of the FIFO");
    let reader = unsafe { std::fs::File::from_raw_fd(reader) };
    worker
        .wait("blocking FIFO write-open")
        .expect("blocking FIFO write-open failed");
    assert_single_endpoint_open(&sb);
    drop(reader);
}

/// The guest's descriptor must be the one that meets the writer, and it must
/// be the only endpoint the reopen ever opens.
///
/// While the reopen is parked at its open, a host non-blocking write-open must
/// fail `ENXIO`: that is the observable proof that no reader endpoint of this
/// FIFO is open, so the reopen has not opened one "just to look". Releasing it
/// then lets one writer deliver a payload that the guest must be able to read
/// — a probe that was opened and discarded would have taken those bytes with
/// it and left the guest waiting for a writer that had already gone.
#[test]
fn test_anchor_open_fifo_short_lived_writer_data_not_lost() {
    use std::io::{Read, Write};

    let _watchdog = FifoWatchdog::new("test_anchor_open_fifo_short_lived_writer_data_not_lost");
    let sb = std::sync::Arc::new(TestSandbox::with_anchor_mode());
    let path = make_fifo(&sb, "pipe");
    let entry = sb.lookup_root("pipe").unwrap();
    let (reached, release) = park_at_blocking_fifo_open(&sb);

    let reader = FifoWorker::spawn(&sb, path.clone(), libc::O_WRONLY, move |sb| {
        sb.fuse_open(entry.inode, libc::O_RDONLY as u32)
    });
    await_flag(&reached, "the reopen never reached the blocking FIFO open");

    // No reader endpoint may exist while the reopen waits at the boundary.
    let probe = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
    if probe >= 0 {
        unsafe { libc::close(probe) };
        panic!("the reopen had already opened a reader endpoint of the FIFO");
    }
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ENXIO),
        "unexpected error from the host write-open probe"
    );
    release.store(true, std::sync::atomic::Ordering::Release);

    // One writer, alive only long enough to deliver its payload.
    let writer_path = sb.root.join("pipe");
    let writer = FifoWorker::spawn_raw(path.clone(), libc::O_RDONLY, move || {
        let mut file = std::fs::OpenOptions::new().write(true).open(&writer_path)?;
        file.write_all(b"payload")
    });

    let handle = reader
        .wait("blocking FIFO read-open")
        .expect("blocking FIFO read-open failed");
    writer.wait("host writer").expect("host writer failed");

    // The decisive check: a probe opened and discarded anywhere in the reopen
    // path — including before the hook, where the host ENXIO check above
    // cannot see it — shows up here as a second endpoint open.
    assert_single_endpoint_open(&sb);

    // Read through the handle's own descriptor: `pread` is invalid on a FIFO,
    // so the usual FUSE read helper cannot be used here. The writer has
    // already finished, so this read cannot wait.
    let mut file = {
        let handles = sb.fs.handles.read().unwrap();
        let data = handles.get(&handle).expect("handle was not registered");
        let file = data.file.read().unwrap();
        file.try_clone().unwrap()
    };
    let mut buf = [0u8; 16];
    let n = file
        .read(&mut buf)
        .expect("read from the FIFO handle failed");
    assert_eq!(
        &buf[..n],
        b"payload",
        "the waiting writer's bytes did not reach the guest's descriptor"
    );
}

/// The pre-unlink open must not park either, and must not take a FIFO's peer:
/// an identified FIFO is never opened at all. A tracked file replaced on the
/// host by a peerless FIFO is still unlinked, and no descriptor is retained.
#[test]
fn test_anchor_unlink_of_replacement_fifo_does_not_block() {
    let _watchdog = FifoWatchdog::new("test_anchor_unlink_of_replacement_fifo_does_not_block");
    let sb = std::sync::Arc::new(TestSandbox::with_anchor_mode());
    sb.host_create_file("doomed", b"x");
    let file = sb.lookup_root("doomed").unwrap();

    std::fs::rename(sb.root.join("doomed"), sb.root.join("doomed.orig")).unwrap();
    let path = make_fifo(&sb, "doomed");

    let worker = FifoWorker::spawn(&sb, path, libc::O_WRONLY, |sb| {
        let ctx = sb.ctx();
        sb.fs.unlink(ctx, ROOT_INODE, &TestSandbox::cstr("doomed"))
    });
    worker
        .wait("unlink of a replacement FIFO")
        .expect("unlink of the replacement FIFO failed");
    assert!(!sb.root.join("doomed").exists());

    // The FIFO was never the tracked inode, so nothing was retained for it.
    let inodes = sb.fs.inodes.read().unwrap();
    let data = inodes.get(&file.inode).unwrap();
    assert_eq!(
        data.unlinked_fd.load(std::sync::atomic::Ordering::Acquire),
        -1
    );
}

/// Unlinking a FIFO keeps no descriptor for it, so once its last name is gone
/// an operation that has only the inode to work from cannot resolve it any
/// more. Operations that carry a handle keep working, because the handle owns
/// its own descriptor. Retaining a reader instead would hold the FIFO open
/// behind the guest's back and suppress its broken-pipe semantics.
#[test]
fn test_anchor_unlink_fifo_inode_only_getattr_enoent() {
    let _watchdog = FifoWatchdog::new("test_anchor_unlink_fifo_inode_only_getattr_enoent");
    let sb = TestSandbox::with_anchor_mode();
    make_fifo(&sb, "pipe");
    let entry = sb.lookup_root("pipe").unwrap();
    // A non-blocking read-open of a FIFO returns at once, with no peer needed.
    let handle = sb
        .fuse_open(entry.inode, libc::O_RDONLY as u32 | LINUX_O_NONBLOCK)
        .unwrap();

    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("pipe"))
        .unwrap();

    TestSandbox::assert_errno(sb.fs.getattr(sb.ctx(), entry.inode, None), LINUX_ENOENT);
    let (st, _) = sb
        .fs
        .getattr(sb.ctx(), entry.inode, Some(handle))
        .expect("getattr through the open handle must still work");
    assert_eq!(
        st.st_mode as u32 & libc::S_IFMT as u32,
        libc::S_IFIFO as u32
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: walk error reporting
//--------------------------------------------------------------------------------------------------

/// A host-side error on the walk is reported as itself. A denied parent
/// directory must surface as `EACCES`, never as a phantom `ENOENT`.
#[test]
fn test_anchor_reopen_preserves_host_error() {
    use std::os::unix::fs::PermissionsExt;

    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("locked");
    sb.host_create_file("locked/file", b"x");
    let dir = sb.lookup_root("locked").unwrap();
    let file = sb.lookup(dir.inode, "file").unwrap();

    let dir_path = sb.root.join("locked");
    std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let result = sb.fuse_open(file.inode, libc::O_RDONLY as u32);
    // Restore before asserting: a failed assertion must not leave a mode-000
    // directory behind for the temp-dir cleanup to trip over.
    std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

//--------------------------------------------------------------------------------------------------
// Tests: alias bookkeeping edge cases
//--------------------------------------------------------------------------------------------------

/// A plain rename of one link onto another link of the same inode changes
/// nothing on disk, so both aliases must survive.
#[test]
fn test_anchor_plain_rename_same_inode_keeps_both_aliases() {
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
            0,
        )
        .unwrap();

    {
        let inodes = sb.fs.inodes.read().unwrap();
        let data = inodes.get(&entry_a.inode).unwrap();
        assert_eq!(data.aliases.read().unwrap().len(), 2);
    }

    assert!(sb.root.join("a").exists());
    assert!(sb.root.join("b").exists());
    let handle = sb.fuse_open(entry_a.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(
        &sb.fuse_read(entry_a.inode, handle, 8, 0).unwrap()[..],
        b"linked"
    );
}

/// Renaming inside a directory the guest has already forgotten must not
/// collect that directory: the new alias is registered before the old one is
/// removed, so the parent never loses its last dependent.
#[test]
fn test_anchor_rename_after_parent_forgotten() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("p");
    sb.host_create_file("p/f", b"body");
    let parent = sb.lookup_root("p").unwrap();
    let file = sb.lookup(parent.inode, "f").unwrap();
    sb.fs.forget(sb.ctx(), parent.inode, 1);

    sb.fs
        .rename(
            sb.ctx(),
            parent.inode,
            &TestSandbox::cstr("f"),
            parent.inode,
            &TestSandbox::cstr("g"),
            0,
        )
        .unwrap();

    assert!(sb.fs.inodes.read().unwrap().get(&parent.inode).is_some());
    let handle = sb.fuse_open(file.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(
        &sb.fuse_read(file.inode, handle, 8, 0).unwrap()[..],
        b"body"
    );
}

/// Unlinking a symlink drops its alias even though the pre-unlink open fails
/// `ELOOP`: the identity comes from the directory entry, not from an fd.
#[test]
fn test_anchor_unlink_symlink_drops_alias() {
    let sb = TestSandbox::with_anchor_mode();
    std::os::unix::fs::symlink("elsewhere", sb.root.join("sl")).unwrap();
    let link = sb.lookup_root("sl").unwrap();

    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("sl"))
        .unwrap();

    let inodes = sb.fs.inodes.read().unwrap();
    let data = inodes.get(&link.inode).unwrap();
    assert!(data.aliases.read().unwrap().is_empty());
    assert_eq!(
        data.anchor_parent
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: teardown
//--------------------------------------------------------------------------------------------------

/// `destroy` must release the fds retained for unlinked inodes. They are raw
/// numbers, so only the inode's destructor closes them.
#[test]
fn test_anchor_destroy_closes_retained_fds() {
    let sb = TestSandbox::with_anchor_mode();
    let (entry, handle) = sb.fuse_create_root("doomed").unwrap();
    sb.fuse_write(entry.inode, handle, b"bye", 0).unwrap();
    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("doomed"))
        .unwrap();

    let retained = {
        let inodes = sb.fs.inodes.read().unwrap();
        inodes
            .get(&entry.inode)
            .unwrap()
            .unlinked_fd
            .load(std::sync::atomic::Ordering::Acquire)
    };
    assert!(retained >= 0);
    let before = platform::fstat(retained as i32).unwrap();

    sb.fs.destroy();

    // The number is free after the close, and the test binary runs its tests
    // in threads, so a parallel test may already have reopened it. Either the
    // number is invalid, or it now names a different file — both prove this
    // descriptor was released.
    let probe = unsafe { libc::fcntl(retained as i32, libc::F_GETFD) };
    if probe == -1 {
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    } else {
        let after = platform::fstat(retained as i32).unwrap();
        assert!(
            platform::stat_ino(&after) != platform::stat_ino(&before)
                || platform::stat_dev(&after) != platform::stat_dev(&before),
            "retained fd {retained} still names the unlinked file after destroy"
        );
    }
}

//--------------------------------------------------------------------------------------------------
// Tests: symlink fd identity
//--------------------------------------------------------------------------------------------------

/// The symlink fd open refuses a replaced name outright, whether the
/// replacement is a regular file or another symlink: the tracked identity no
/// longer lives under that name.
#[test]
fn test_open_symlink_inode_fd_rejects_replacement() {
    let sb = TestSandbox::with_anchor_mode();
    std::os::unix::fs::symlink("elsewhere", sb.root.join("sl")).unwrap();
    let link = sb.lookup_root("sl").unwrap();

    std::fs::remove_file(sb.root.join("sl")).unwrap();
    std::fs::write(sb.root.join("sl"), b"not a symlink").unwrap();
    TestSandbox::assert_errno(
        super::super::metadata::open_symlink_inode_fd_macos(&sb.fs, link.inode),
        LINUX_ENOENT,
    );

    std::fs::remove_file(sb.root.join("sl")).unwrap();
    std::os::unix::fs::symlink("somewhere-else", sb.root.join("sl")).unwrap();
    TestSandbox::assert_errno(
        super::super::metadata::open_symlink_inode_fd_macos(&sb.fs, link.inode),
        LINUX_ENOENT,
    );
}

/// The post-open identity check is what covers a replacement that lands
/// *after* the parent and name were verified. Resolving the pair first and
/// swapping the entry in between reproduces that window, which the
/// replace-before-resolve test above can never reach.
#[test]
fn test_open_verified_symlink_fd_rejects_post_open_replacement() {
    use std::os::unix::fs::MetadataExt;

    let sb = TestSandbox::with_anchor_mode();
    std::os::unix::fs::symlink("elsewhere", sb.root.join("sl")).unwrap();
    let link = sb.lookup_root("sl").unwrap();
    let expected = {
        let inodes = sb.fs.inodes.read().unwrap();
        let data = inodes.get(&link.inode).unwrap();
        crate::backends::shared::inode_table::InodeAltKey::new(data.ino, data.dev)
    };
    let (dir, name) =
        super::super::inode::anchor_parent_and_name_macos(&sb.fs, link.inode).unwrap();

    // Keep the original link alive under another name so its inode number
    // cannot be reused by the replacement.
    std::fs::rename(sb.root.join("sl"), sb.root.join("sl.orig")).unwrap();
    std::os::unix::fs::symlink("somewhere-else", sb.root.join("sl")).unwrap();
    let before = std::fs::symlink_metadata(sb.root.join("sl")).unwrap();

    TestSandbox::assert_errno(
        super::super::metadata::open_verified_symlink_fd(dir.raw(), &name, expected),
        LINUX_ENOENT,
    );

    // The refusal must leave the replacement untouched.
    let after = std::fs::symlink_metadata(sb.root.join("sl")).unwrap();
    assert_eq!(after.ino(), before.ino());
    assert_eq!(after.mtime(), before.mtime());
    assert_eq!(after.mtime_nsec(), before.mtime_nsec());
    assert_eq!(after.mode(), before.mode());
    assert_eq!(
        std::fs::read_link(sb.root.join("sl")).unwrap(),
        std::path::Path::new("somewhere-else")
    );
}

/// The fd retained across an unlink must be the file the identity key names.
///
/// The key and the fd come from two syscalls, so a host-side replacement can
/// in principle land between them. That interleaving is not reachable from a
/// single-threaded test, so this asserts the property from the outside: after
/// the name is replaced on the host, the FUSE unlink retains no descriptor for
/// the tracked inode, the tracked inode refuses to resolve through its stale
/// name, and a handle opened before the replacement still reads the original
/// bytes.
#[test]
fn test_anchor_unlink_replacement_fd_not_retained() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_file("f", b"original");
    let file = sb.lookup_root("f").unwrap();
    let handle = sb.fuse_open(file.inode, libc::O_RDONLY as u32).unwrap();

    // Move the original aside so its inode stays live, then put a different
    // file under the tracked name.
    std::fs::rename(sb.root.join("f"), sb.root.join("f.orig")).unwrap();
    sb.host_create_file("f", b"replacement");

    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("f"))
        .unwrap();
    assert!(!sb.root.join("f").exists());

    {
        let inodes = sb.fs.inodes.read().unwrap();
        let data = inodes.get(&file.inode).unwrap();
        assert_eq!(
            data.unlinked_fd.load(std::sync::atomic::Ordering::Acquire),
            -1,
            "the replacement's descriptor must not be retained"
        );
    }

    // The stale name is gone, so the tracked inode no longer resolves.
    TestSandbox::assert_errno(
        sb.fuse_open(file.inode, libc::O_RDONLY as u32),
        LINUX_ENOENT,
    );

    assert_eq!(
        &sb.fuse_read(file.inode, handle, 16, 0).unwrap()[..],
        b"original"
    );
    assert_eq!(std::fs::read(sb.root.join("f.orig")).unwrap(), b"original");
}
