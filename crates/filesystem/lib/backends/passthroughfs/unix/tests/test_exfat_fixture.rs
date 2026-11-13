#![cfg(target_os = "macos")]

//! Real FSKit exFAT fixture.
//!
//! Creates a small exFAT disk image with `hdiutil`, mounts it, and exercises
//! the passthrough backend on it. On macOS 15+ the mount is FSKit-backed and
//! has no volfs, so the share runs in anchor mode; on older hosts exFAT is a
//! kext with volfs and the share runs in volfs mode. Both must pass. The test
//! skips itself when `hdiutil` is unavailable or the mount fails (CI runners
//! without disk-image support).

use std::{
    ffi::CString,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};

use super::*;
use crate::{FsOptions, PassthroughConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct ExfatVolume {
    image: PathBuf,
    mount: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExfatVolume {
    fn create(tmp: &Path) -> Option<Self> {
        let image = tmp.join("exfat-fixture.dmg");
        let status = Command::new("hdiutil")
            .args([
                "create", "-size", "64m", "-fs", "ExFAT", "-volname", "MSBEXFAT", "-quiet",
            ])
            .arg(&image)
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
        let mount = tmp.join("mnt");
        std::fs::create_dir_all(&mount).ok()?;
        let status = Command::new("hdiutil")
            .args(["attach", "-nobrowse", "-quiet", "-mountpoint"])
            .arg(&mount)
            .arg(&image)
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
        Some(Self { image, mount })
    }
}

impl Drop for ExfatVolume {
    fn drop(&mut self) {
        let _ = Command::new("hdiutil")
            .args(["detach", "-quiet", "-force"])
            .arg(&self.mount)
            .status();
        let _ = std::fs::remove_file(&self.image);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Lookup, getattr, read, readdir, and reopen-after-forget on a real exFAT
/// volume. Inode numbers must stay stable across reopen, which anchor mode
/// relies on for its identity check.
#[test]
fn test_exfat_volume_read_path() {
    let tmp = tempfile::tempdir().unwrap();
    let Some(vol) = ExfatVolume::create(tmp.path()) else {
        eprintln!("skipping: hdiutil exFAT fixture unavailable");
        return;
    };

    let root = vol.mount.join("case");
    std::fs::create_dir_all(root.join("evidence/sub")).unwrap();
    std::fs::write(root.join("evidence/sub/file.bin"), b"exfat-bytes").unwrap();
    std::fs::write(root.join("top.txt"), b"top").unwrap();

    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: root.clone(),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let ctx = Context {
        uid: 0,
        gid: 0,
        pid: 1,
    };
    let c = |s: &str| CString::new(s).unwrap();

    let is_fskit = !probe_volfs_support(fs.root_fd.as_raw_fd());
    eprintln!(
        "exfat fixture: anchor_mode={} (fskit={is_fskit})",
        fs.anchor_mode()
    );
    assert_eq!(fs.anchor_mode(), is_fskit);

    let ev = fs.lookup(ctx, ROOT_INODE, &c("evidence")).unwrap();
    let sub = fs.lookup(ctx, ev.inode, &c("sub")).unwrap();
    let file = fs.lookup(ctx, sub.inode, &c("file.bin")).unwrap();
    let (st, _) = fs.getattr(ctx, file.inode, None).unwrap();
    assert_eq!(st.st_size, 11);

    let (handle, _) = fs.open(ctx, file.inode, false, 0).unwrap();
    let mut w = MockZeroCopyWriter::new();
    let n = fs
        .read(ctx, file.inode, handle.unwrap(), &mut w, 64, 0, None, 0)
        .unwrap();
    let mut data = w.into_data();
    data.truncate(n);
    assert_eq!(&data[..], b"exfat-bytes");

    let (dh, _) = fs.opendir(ctx, ev.inode, 0).unwrap();
    let names: Vec<Vec<u8>> = fs
        .readdir(ctx, ev.inode, dh.unwrap(), 4096, 0)
        .unwrap()
        .iter()
        .map(|e| e.name.to_vec())
        .collect();
    assert!(names.contains(&b"sub".to_vec()));

    // Reopen after the intermediate directories are forgotten by the guest.
    fs.forget(ctx, ev.inode, 1);
    fs.forget(ctx, sub.inode, 1);
    let (st2, _) = fs.getattr(ctx, file.inode, None).unwrap();
    assert_eq!(st2.st_ino, st.st_ino);
    assert_eq!(st2.st_size, 11);
}

/// Create, write, rename, unlink, rmdir, and link on a real exFAT volume, all
/// through FUSE operations. The rename assertions are the load-bearing ones:
/// anchor mode reopens an inode by name and then checks `(st_dev, st_ino)`, so
/// exFAT must keep an inode number stable while the name moves.
#[test]
fn test_exfat_volume_write_path() {
    let tmp = tempfile::tempdir().unwrap();
    let Some(vol) = ExfatVolume::create(tmp.path()) else {
        eprintln!("skipping: hdiutil exFAT fixture unavailable");
        return;
    };

    let root = vol.mount.join("case");
    std::fs::create_dir_all(root.join("movable")).unwrap();
    std::fs::write(root.join("movable/inner.txt"), b"inner").unwrap();
    std::fs::create_dir_all(root.join("emptydir")).unwrap();
    std::fs::write(root.join("doomed.txt"), b"doomed").unwrap();
    std::fs::write(root.join("linkme.txt"), b"linkme").unwrap();

    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: root.clone(),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let ctx = Context {
        uid: 0,
        gid: 0,
        pid: 1,
    };
    let c = |s: &str| CString::new(s).unwrap();
    eprintln!("exfat write fixture: anchor_mode={}", fs.anchor_mode());

    // Create and write through FUSE.
    const LINUX_O_RDWR_FLAGS: u32 = 2;
    let (created, handle, _) = fs
        .create(
            ctx,
            ROOT_INODE,
            &c("created.txt"),
            0o644,
            false,
            LINUX_O_RDWR_FLAGS,
            0,
            Extensions::default(),
        )
        .unwrap();
    let handle = handle.unwrap();
    let mut reader = MockZeroCopyReader::new(b"written-bytes".to_vec());
    let written = fs
        .write(
            ctx,
            created.inode,
            handle,
            &mut reader,
            13,
            0,
            None,
            false,
            false,
            0,
        )
        .unwrap();
    assert_eq!(written, 13);
    assert_eq!(
        std::fs::read(root.join("created.txt")).unwrap(),
        b"written-bytes"
    );

    // Rename the file: the host inode number must survive the move, or the
    // anchor-mode identity check would refuse every later reopen.
    let (before, _) = fs.getattr(ctx, created.inode, None).unwrap();
    fs.rename(
        ctx,
        ROOT_INODE,
        &c("created.txt"),
        ROOT_INODE,
        &c("renamed.txt"),
        0,
    )
    .unwrap();
    let (after, _) = fs.getattr(ctx, created.inode, None).unwrap();
    assert_eq!(after.st_ino, before.st_ino);
    assert_eq!(after.st_size, 13);

    // Rename a directory and read a file inside it through its old inode.
    let movable = fs.lookup(ctx, ROOT_INODE, &c("movable")).unwrap();
    let inner = fs.lookup(ctx, movable.inode, &c("inner.txt")).unwrap();
    fs.rename(ctx, ROOT_INODE, &c("movable"), ROOT_INODE, &c("moved"), 0)
        .unwrap();
    let (inner_handle, _) = fs.open(ctx, inner.inode, false, 0).unwrap();
    let mut writer = MockZeroCopyWriter::new();
    let n = fs
        .read(
            ctx,
            inner.inode,
            inner_handle.unwrap(),
            &mut writer,
            32,
            0,
            None,
            0,
        )
        .unwrap();
    let mut data = writer.into_data();
    data.truncate(n);
    assert_eq!(&data[..], b"inner");

    // Unlink with a handle open: the retained fd keeps the data readable.
    let doomed = fs.lookup(ctx, ROOT_INODE, &c("doomed.txt")).unwrap();
    let (doomed_handle, _) = fs.open(ctx, doomed.inode, false, 0).unwrap();
    fs.unlink(ctx, ROOT_INODE, &c("doomed.txt")).unwrap();
    assert!(!root.join("doomed.txt").exists());
    let mut writer = MockZeroCopyWriter::new();
    let n = fs
        .read(
            ctx,
            doomed.inode,
            doomed_handle.unwrap(),
            &mut writer,
            32,
            0,
            None,
            0,
        )
        .unwrap();
    let mut data = writer.into_data();
    data.truncate(n);
    assert_eq!(&data[..], b"doomed");

    // rmdir an empty directory.
    let empty = fs.lookup(ctx, ROOT_INODE, &c("emptydir")).unwrap();
    fs.rmdir(ctx, ROOT_INODE, &c("emptydir")).unwrap();
    assert!(!root.join("emptydir").exists());
    let _ = empty;

    // Hard link. exFAT has no hard links, so an unsupported answer is a pass
    // as long as it is reported honestly instead of creating a wrong entry.
    let linkme = fs.lookup(ctx, ROOT_INODE, &c("linkme.txt")).unwrap();
    match fs.link(ctx, linkme.inode, ROOT_INODE, &c("linked.txt")) {
        Ok(linked) => {
            assert_eq!(linked.inode, linkme.inode);
            let (linked_handle, _) = fs.open(ctx, linked.inode, false, 0).unwrap();
            let mut writer = MockZeroCopyWriter::new();
            let n = fs
                .read(
                    ctx,
                    linked.inode,
                    linked_handle.unwrap(),
                    &mut writer,
                    32,
                    0,
                    None,
                    0,
                )
                .unwrap();
            let mut data = writer.into_data();
            data.truncate(n);
            assert_eq!(&data[..], b"linkme");
            assert_eq!(std::fs::read(root.join("linked.txt")).unwrap(), b"linkme");
        }
        Err(err) => {
            // Only an honest "this volume cannot do that" is a pass. FSKit
            // exFAT on macOS 15 answers `linkat` with ENOTSUP (macOS 45),
            // which translates to Linux EOPNOTSUPP; a kext-backed exFAT can
            // answer EPERM. Any other code — a missing entry, a bad
            // descriptor, an I/O error — means the anchor resolution failed
            // and must not be read as "unsupported".
            let code = err.raw_os_error();
            assert!(
                code == Some(LINUX_EOPNOTSUPP) || code == Some(LINUX_EPERM),
                "hard link on exfat failed with an unexpected error: {err}"
            );
            eprintln!("exfat write fixture: hard link unsupported ({err})");
            assert!(!root.join("linked.txt").exists());
        }
    }
}

/// Files that the volume renumbers stay reachable through their guest inode.
///
/// FSKit exFAT on recent macOS numbers a regular file by its first data
/// cluster. A file without data gets a placeholder number, which is replaced
/// when the file gains data and by every other change to it: a rename, new
/// metadata, a truncate that leaves it empty. Each step below is one of
/// those, followed by an operation that has only the guest inode to work
/// from. On a host that keeps the numbers fixed, every step is a plain pass.
#[test]
fn test_exfat_volume_renumbered_files() {
    let tmp = tempfile::tempdir().unwrap();
    let Some(vol) = ExfatVolume::create(tmp.path()) else {
        eprintln!("skipping: hdiutil exFAT fixture unavailable");
        return;
    };

    let root = vol.mount.join("case");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("empty.txt"), b"").unwrap();
    std::fs::write(root.join("full.txt"), b"0123456789").unwrap();

    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: root.clone(),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let sb = TestSandbox {
        fs,
        _tmp: tempfile::tempdir().unwrap(),
        root: root.clone(),
    };
    let host_ino = |name: &str| std::fs::metadata(root.join(name)).unwrap().ino();
    let size_of = |inode: u64| sb.fs.getattr(sb.ctx(), inode, None).unwrap().0.st_size;
    let release = |inode: u64, handle: u64| {
        sb.fs
            .release(sb.ctx(), inode, 0, handle, false, false, None)
            .unwrap()
    };

    // First data through a handle on a file that was created empty.
    let (fresh, handle) = sb.fuse_create_root("fresh.txt").unwrap();
    let before = host_ino("fresh.txt");
    sb.fuse_write(fresh.inode, handle, b"first", 0).unwrap();
    eprintln!(
        "exfat renumber fixture: first write {before} -> {}",
        host_ino("fresh.txt")
    );
    assert_eq!(size_of(fresh.inode), 5);
    assert_eq!(sb.lookup_root("fresh.txt").unwrap().inode, fresh.inode);
    release(fresh.inode, handle);
    assert_eq!(size_of(fresh.inode), 5);

    // Rename an empty file inside its directory and then across directories,
    // then give it data.
    let empty = sb.lookup_root("empty.txt").unwrap();
    let sub = sb.lookup_root("sub").unwrap();
    let before = host_ino("empty.txt");
    sb.fs
        .rename(sb.ctx(), ROOT_INODE, c"empty.txt", ROOT_INODE, c"e2.txt", 0)
        .unwrap();
    assert_eq!(size_of(empty.inode), 0);
    sb.fs
        .rename(sb.ctx(), ROOT_INODE, c"e2.txt", sub.inode, c"e3.txt", 0)
        .unwrap();
    eprintln!(
        "exfat renumber fixture: empty rename {before} -> {}",
        host_ino("sub/e3.txt")
    );
    assert_eq!(size_of(empty.inode), 0);
    assert_eq!(sb.lookup(sub.inode, "e3.txt").unwrap().inode, empty.inode);
    let handle = sb.fuse_open(empty.inode, LINUX_O_RDWR).unwrap();
    sb.fuse_write(empty.inode, handle, b"data", 0).unwrap();
    release(empty.inode, handle);
    assert_eq!(size_of(empty.inode), 4);
    assert_eq!(sb.lookup(sub.inode, "e3.txt").unwrap().inode, empty.inode);

    // Truncate by inode, write again, then truncate with the open itself.
    let full = sb.lookup_root("full.txt").unwrap();
    let before = host_ino("full.txt");
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    sb.fs
        .setattr(sb.ctx(), full.inode, attr, None, SetattrValid::SIZE)
        .unwrap();
    assert_eq!(size_of(full.inode), 0);
    let handle = sb.fuse_open(full.inode, LINUX_O_RDWR).unwrap();
    sb.fuse_write(full.inode, handle, b"again", 0).unwrap();
    release(full.inode, handle);
    eprintln!(
        "exfat renumber fixture: truncate and rewrite {before} -> {}",
        host_ino("full.txt")
    );
    assert_eq!(size_of(full.inode), 5);
    assert_eq!(sb.lookup_root("full.txt").unwrap().inode, full.inode);
    let handle = sb
        .fuse_open(full.inode, LINUX_O_RDWR | LINUX_O_TRUNC)
        .unwrap();
    assert_eq!(size_of(full.inode), 0);
    sb.fuse_write(full.inode, handle, b"x", 0).unwrap();
    release(full.inode, handle);
    assert_eq!(size_of(full.inode), 1);
    assert_eq!(sb.lookup_root("full.txt").unwrap().inode, full.inode);

    // Grow an empty file with a truncate through its handle.
    let (grown, handle) = sb.fuse_create_root("grown.txt").unwrap();
    attr.st_size = 4096;
    sb.fs
        .setattr(
            sb.ctx(),
            grown.inode,
            attr,
            Some(handle),
            SetattrValid::SIZE,
        )
        .unwrap();
    release(grown.inode, handle);
    assert_eq!(size_of(grown.inode), 4096);
    assert_eq!(sb.lookup_root("grown.txt").unwrap().inode, grown.inode);

    // Metadata on a file without data renumbers it as well: mode, times, and
    // extended attributes, by inode and through a handle. This is what `touch`
    // and `chmod` do to an empty file, and what an archive tool does to each
    // empty file it unpacks.
    std::fs::write(root.join("meta.txt"), b"").unwrap();
    let meta = sb.lookup_root("meta.txt").unwrap();
    let before = host_ino("meta.txt");
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = 0o600;
    sb.fs
        .setattr(sb.ctx(), meta.inode, attr, None, SetattrValid::MODE)
        .unwrap();
    assert_eq!(size_of(meta.inode), 0);
    attr.st_atime = 1_000_000;
    attr.st_mtime = 1_000_000;
    sb.fs
        .setattr(
            sb.ctx(),
            meta.inode,
            attr,
            None,
            SetattrValid::ATIME | SetattrValid::MTIME,
        )
        .unwrap();
    assert_eq!(size_of(meta.inode), 0);
    sb.fs
        .setxattr(sb.ctx(), meta.inode, c"user.note", b"v", 0)
        .unwrap();
    assert_eq!(size_of(meta.inode), 0);
    sb.fs
        .removexattr(sb.ctx(), meta.inode, c"user.note")
        .unwrap();
    assert_eq!(size_of(meta.inode), 0);
    eprintln!(
        "exfat renumber fixture: metadata on empty file {before} -> {}",
        host_ino("meta.txt")
    );
    assert_eq!(sb.lookup_root("meta.txt").unwrap().inode, meta.inode);

    let (unpacked, handle) = sb.fuse_create_root("unpacked.txt").unwrap();
    sb.fs
        .setattr(
            sb.ctx(),
            unpacked.inode,
            attr,
            Some(handle),
            SetattrValid::MODE | SetattrValid::ATIME | SetattrValid::MTIME,
        )
        .unwrap();
    release(unpacked.inode, handle);
    assert_eq!(size_of(unpacked.inode), 0);
    assert_eq!(
        sb.lookup_root("unpacked.txt").unwrap().inode,
        unpacked.inode
    );

    // Unlink, then open the inode again. The volume keeps reporting one link
    // for the removed file, so this reopen cannot depend on a zero link count.
    let (gone, handle) = sb.fuse_create_root("gone.txt").unwrap();
    sb.fuse_write(gone.inode, handle, b"kept", 0).unwrap();
    release(gone.inode, handle);
    sb.fs.unlink(sb.ctx(), ROOT_INODE, c"gone.txt").unwrap();
    assert!(!root.join("gone.txt").exists());
    let handle = sb.fuse_open(gone.inode, LINUX_O_RDWR).unwrap();
    assert_eq!(sb.fuse_read(gone.inode, handle, 16, 0).unwrap(), b"kept");
    sb.fuse_write(gone.inode, handle, b"!", 4).unwrap();
    assert_eq!(sb.fuse_read(gone.inode, handle, 16, 0).unwrap(), b"kept!");
}
