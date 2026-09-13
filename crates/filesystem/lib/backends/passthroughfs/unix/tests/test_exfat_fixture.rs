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
