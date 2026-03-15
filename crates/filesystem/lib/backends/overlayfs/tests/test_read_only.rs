//! Tests for read-only overlay mode (no upper layer).

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests: Builder
//--------------------------------------------------------------------------------------------------

#[test]
fn test_builder_read_only_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let lower = tmp.path().join("lower");
    std::fs::create_dir(&lower).unwrap();

    let fs = OverlayFs::builder()
        .layer(&lower)
        .read_only()
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();
}

#[test]
fn test_builder_read_only_rejects_writable() {
    let tmp = tempfile::tempdir().unwrap();
    let lower = tmp.path().join("lower");
    let upper = tmp.path().join("upper");
    std::fs::create_dir(&lower).unwrap();
    std::fs::create_dir(&upper).unwrap();

    match OverlayFs::builder()
        .layer(&lower)
        .writable(&upper)
        .read_only()
        .build()
    {
        Ok(_) => panic!("expected read_only + writable to be rejected"),
        Err(e) => assert!(e.to_string().contains("must not be set")),
    }
}

#[test]
fn test_builder_read_only_rejects_staging() {
    let tmp = tempfile::tempdir().unwrap();
    let lower = tmp.path().join("lower");
    let staging = tmp.path().join("staging");
    std::fs::create_dir(&lower).unwrap();
    std::fs::create_dir(&staging).unwrap();

    match OverlayFs::builder()
        .layer(&lower)
        .staging(&staging)
        .read_only()
        .build()
    {
        Ok(_) => panic!("expected read_only + staging to be rejected"),
        Err(e) => assert!(e.to_string().contains("must not be set")),
    }
}

#[test]
fn test_builder_read_only_requires_lower() {
    match OverlayFs::builder().read_only().build() {
        Ok(_) => panic!("expected missing lower layer to be rejected"),
        Err(e) => assert!(e.to_string().contains("lower layer")),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests: EROFS on mutation operations
//--------------------------------------------------------------------------------------------------

#[test]
fn test_erofs_create() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|_| {});
    let result = sb.fs.create(
        sb.ctx(),
        ROOT_INODE,
        &ReadOnlyOverlayTestSandbox::cstr("new_file"),
        0o644,
        false,
        libc::O_RDWR as u32,
        0,
        Extensions::default(),
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result.map(|_| ()), LINUX_EROFS);
}

#[test]
fn test_erofs_mkdir() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|_| {});
    let result = sb.fs.mkdir(
        sb.ctx(),
        ROOT_INODE,
        &ReadOnlyOverlayTestSandbox::cstr("new_dir"),
        0o755,
        0,
        Extensions::default(),
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
}

#[test]
fn test_erofs_mknod() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|_| {});
    let result = sb.fs.mknod(
        sb.ctx(),
        ROOT_INODE,
        &ReadOnlyOverlayTestSandbox::cstr("new_node"),
        libc::S_IFREG as u32 | 0o644,
        0,
        0,
        Extensions::default(),
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
}

#[test]
fn test_erofs_symlink() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|_| {});
    let result = sb.fs.symlink(
        sb.ctx(),
        &ReadOnlyOverlayTestSandbox::cstr("/target"),
        ROOT_INODE,
        &ReadOnlyOverlayTestSandbox::cstr("new_link"),
        Extensions::default(),
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
}

#[test]
fn test_erofs_unlink() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"data").unwrap();
    });
    let result = sb.fs.unlink(
        sb.ctx(),
        ROOT_INODE,
        &ReadOnlyOverlayTestSandbox::cstr("file"),
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
}

#[test]
fn test_erofs_rmdir() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::create_dir(lower.join("subdir")).unwrap();
    });
    let result = sb.fs.rmdir(
        sb.ctx(),
        ROOT_INODE,
        &ReadOnlyOverlayTestSandbox::cstr("subdir"),
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
}

#[test]
fn test_erofs_rename() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("old"), b"data").unwrap();
    });
    let result = sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &ReadOnlyOverlayTestSandbox::cstr("old"),
        ROOT_INODE,
        &ReadOnlyOverlayTestSandbox::cstr("new"),
        0,
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
}

#[test]
fn test_erofs_setattr() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"data").unwrap();
    });
    let entry = sb.lookup_root("file").unwrap();
    let result = sb.fs.setattr(
        sb.ctx(),
        entry.inode,
        unsafe { std::mem::zeroed() },
        None,
        SetattrValid::MODE,
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
}

#[test]
fn test_erofs_setxattr() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"data").unwrap();
    });
    let entry = sb.lookup_root("file").unwrap();
    let result = sb.fs.setxattr(
        sb.ctx(),
        entry.inode,
        &ReadOnlyOverlayTestSandbox::cstr("user.test"),
        b"value",
        0,
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
}

#[test]
fn test_erofs_removexattr() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"data").unwrap();
    });
    let entry = sb.lookup_root("file").unwrap();
    let result = sb.fs.removexattr(
        sb.ctx(),
        entry.inode,
        &ReadOnlyOverlayTestSandbox::cstr("user.test"),
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
}

#[test]
fn test_erofs_write() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"data").unwrap();
    });
    let entry = sb.lookup_root("file").unwrap();
    let result = sb.fs.write(
        sb.ctx(),
        entry.inode,
        0,
        &mut MockZeroCopyReader::new(b"new data".to_vec()),
        8,
        0,
        None,
        false,
        false,
        0,
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
}

#[test]
fn test_erofs_link() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"data").unwrap();
    });
    let entry = sb.lookup_root("file").unwrap();
    let result = sb.fs.link(
        sb.ctx(),
        entry.inode,
        ROOT_INODE,
        &ReadOnlyOverlayTestSandbox::cstr("hardlink"),
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
}

#[test]
fn test_erofs_fallocate() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"data").unwrap();
    });
    let entry = sb.lookup_root("file").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let result = sb.fs.fallocate(sb.ctx(), entry.inode, handle, 0, 0, 1024);
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_erofs_copyfilerange() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("src"), b"data").unwrap();
        std::fs::write(lower.join("dst"), b"data").unwrap();
    });
    let src = sb.lookup_root("src").unwrap();
    let dst = sb.lookup_root("dst").unwrap();
    let src_handle = sb.fuse_open(src.inode, libc::O_RDONLY as u32).unwrap();
    let dst_handle = sb.fuse_open(dst.inode, libc::O_RDONLY as u32).unwrap();
    let result = sb.fs.copyfilerange(
        sb.ctx(),
        src.inode,
        src_handle,
        0,
        dst.inode,
        dst_handle,
        0,
        4,
        0,
    );
    ReadOnlyOverlayTestSandbox::assert_errno(result, LINUX_EROFS);
    sb.fs
        .release(sb.ctx(), src.inode, 0, src_handle, false, false, None)
        .unwrap();
    sb.fs
        .release(sb.ctx(), dst.inode, 0, dst_handle, false, false, None)
        .unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests: Open flags enforcement
//--------------------------------------------------------------------------------------------------

#[test]
fn test_erofs_open_write_mode() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"data").unwrap();
    });
    let entry = sb.lookup_root("file").unwrap();

    // O_WRONLY rejected.
    ReadOnlyOverlayTestSandbox::assert_errno(
        sb.fuse_open(entry.inode, libc::O_WRONLY as u32),
        LINUX_EROFS,
    );

    // O_RDWR rejected.
    ReadOnlyOverlayTestSandbox::assert_errno(
        sb.fuse_open(entry.inode, libc::O_RDWR as u32),
        LINUX_EROFS,
    );
}

#[test]
fn test_open_rdonly_works() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"hello").unwrap();
    });
    let entry = sb.lookup_root("file").unwrap();

    // O_RDONLY succeeds.
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests: access(W_OK)
//--------------------------------------------------------------------------------------------------

#[test]
fn test_erofs_access_w_ok() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"data").unwrap();
    });
    let entry = sb.lookup_root("file").unwrap();

    // W_OK returns EROFS.
    ReadOnlyOverlayTestSandbox::assert_errno(
        sb.fs.access(sb.ctx(), entry.inode, libc::W_OK as u32),
        LINUX_EROFS,
    );

    // R_OK still works.
    sb.fs
        .access(sb.ctx(), entry.inode, libc::R_OK as u32)
        .unwrap();

    // F_OK still works.
    sb.fs
        .access(sb.ctx(), entry.inode, libc::F_OK as u32)
        .unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests: Read operations work
//--------------------------------------------------------------------------------------------------

#[test]
fn test_read_only_lookup() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"hello").unwrap();
        std::fs::create_dir(lower.join("subdir")).unwrap();
    });

    let file_entry = sb.lookup_root("file").unwrap();
    assert_ne!(file_entry.inode, 0);

    let dir_entry = sb.lookup_root("subdir").unwrap();
    assert_ne!(dir_entry.inode, 0);

    // Nonexistent returns ENOENT.
    ReadOnlyOverlayTestSandbox::assert_errno(sb.lookup_root("missing"), LINUX_ENOENT);
}

#[test]
fn test_read_only_getattr() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"hello world").unwrap();
    });
    let entry = sb.lookup_root("file").unwrap();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_eq!(st.st_size, 11); // "hello world"
}

#[test]
fn test_read_only_read_file() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"hello world").unwrap();
    });
    let entry = sb.lookup_root("file").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(data, b"hello world");
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_read_only_readdir() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("a"), b"").unwrap();
        std::fs::write(lower.join("b"), b"").unwrap();
        std::fs::create_dir(lower.join("c")).unwrap();
    });
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(names.contains(&b"a".to_vec()));
    assert!(names.contains(&b"b".to_vec()));
    assert!(names.contains(&b"c".to_vec()));
}

#[test]
fn test_read_only_statfs() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|_| {});
    let st = sb.fs.statfs(sb.ctx(), ROOT_INODE).unwrap();
    // Should return valid statfs from the lower layer.
    assert!(st.f_bsize > 0);
}

#[test]
fn test_read_only_readlink() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::os::unix::fs::symlink("/target/path", lower.join("link")).unwrap();
    });
    let entry = sb.lookup_root("link").unwrap();
    let target = sb.fs.readlink(sb.ctx(), entry.inode).unwrap();
    assert_eq!(target, b"/target/path");
}

//--------------------------------------------------------------------------------------------------
// Tests: Multi-layer whiteout correctness
//--------------------------------------------------------------------------------------------------

#[test]
fn test_read_only_whiteout_masks_lower() {
    let sb = ReadOnlyOverlayTestSandbox::with_layers(2, |lowers| {
        // Layer 0 (bottom): has "file"
        std::fs::write(lowers[0].join("file"), b"base data").unwrap();
        // Layer 1 (top): has whiteout for "file"
        std::fs::write(lowers[1].join(".wh.file"), b"").unwrap();
    });

    // "file" should NOT be visible (masked by whiteout on top layer).
    ReadOnlyOverlayTestSandbox::assert_errno(sb.lookup_root("file"), LINUX_ENOENT);
}

#[test]
fn test_read_only_opaque_masks_all_below() {
    let sb = ReadOnlyOverlayTestSandbox::with_layers(2, |lowers| {
        // Layer 0 (bottom): has subdir with file
        std::fs::create_dir(lowers[0].join("subdir")).unwrap();
        std::fs::write(lowers[0].join("subdir").join("old_file"), b"data").unwrap();

        // Layer 1 (top): has opaque subdir with different file
        std::fs::create_dir(lowers[1].join("subdir")).unwrap();
        std::fs::write(lowers[1].join("subdir").join(".wh..wh..opq"), b"").unwrap();
        std::fs::write(lowers[1].join("subdir").join("new_file"), b"new").unwrap();
    });

    let subdir = sb.lookup_root("subdir").unwrap();

    // new_file should be visible via lookup (it's on the opaque layer).
    sb.lookup(subdir.inode, "new_file").unwrap();

    // old_file should NOT be visible (opaque dir hides everything below).
    ReadOnlyOverlayTestSandbox::assert_errno(sb.lookup(subdir.inode, "old_file"), LINUX_ENOENT);
}

#[test]
fn test_read_only_multi_layer_merge() {
    let sb = ReadOnlyOverlayTestSandbox::with_layers(3, |lowers| {
        // Layer 0: base files.
        std::fs::write(lowers[0].join("base"), b"base").unwrap();
        std::fs::write(lowers[0].join("override_me"), b"v1").unwrap();

        // Layer 1: overrides one file, adds another.
        std::fs::write(lowers[1].join("override_me"), b"v2").unwrap();
        std::fs::write(lowers[1].join("layer1_only"), b"l1").unwrap();

        // Layer 2: adds a file, whiteouts base.
        std::fs::write(lowers[2].join("layer2_only"), b"l2").unwrap();
        std::fs::write(lowers[2].join(".wh.base"), b"").unwrap();
    });

    // "base" is whiteout'd by layer 2.
    ReadOnlyOverlayTestSandbox::assert_errno(sb.lookup_root("base"), LINUX_ENOENT);

    // "override_me" comes from layer 1 (higher wins).
    let entry = sb.lookup_root("override_me").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(data, b"v2");
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    // Both layer-specific files visible.
    sb.lookup_root("layer1_only").unwrap();
    sb.lookup_root("layer2_only").unwrap();

    // Readdir shows correct set.
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(!names.contains(&b"base".to_vec()));
    assert!(names.contains(&b"override_me".to_vec()));
    assert!(names.contains(&b"layer1_only".to_vec()));
    assert!(names.contains(&b"layer2_only".to_vec()));
}

//--------------------------------------------------------------------------------------------------
// Tests: No-op sync operations
//--------------------------------------------------------------------------------------------------

#[test]
fn test_read_only_flush_noop() {
    let sb = ReadOnlyOverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file"), b"data").unwrap();
    });
    let entry = sb.lookup_root("file").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();

    // flush should succeed (no-op).
    sb.fs.flush(sb.ctx(), entry.inode, handle, 0).unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
}
