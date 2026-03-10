use super::*;

#[test]
fn test_strict_xattr_true_succeeds_on_xattr_fs() {
    // tmpdir supports xattrs, so strict+xattr should succeed.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.xattr = true;
        cfg.strict = true;
        cfg
    });
    // Filesystem is usable — create a file and read it back.
    let (entry, handle) = sb.fuse_create_root("test.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"ok", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"ok");
}

#[test]
fn test_xattr_false_strict_true_skips_probe() {
    // When xattr=false, the probe is skipped even if strict=true.
    // This should succeed regardless of xattr support.
    let _sb = TestSandbox::with_config(|mut cfg| {
        cfg.xattr = false;
        cfg.strict = true;
        cfg
    });
    // Construction succeeded — probe was skipped.
}

#[test]
fn test_xattr_false_strict_false_skips_probe() {
    let _sb = TestSandbox::with_config(|mut cfg| {
        cfg.xattr = false;
        cfg.strict = false;
        cfg
    });
}

#[test]
fn test_xattr_true_strict_false_skips_probe() {
    // When strict=false, the probe is skipped even if xattr=true.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.xattr = true;
        cfg.strict = false;
        cfg
    });
    // Should still be fully functional.
    let (entry, handle) = sb.fuse_create_root("test.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"data");
}

#[test]
fn test_writeback_cache_not_enabled_without_support() {
    // writeback=true in config, but init with no WRITEBACK_CACHE capability.
    let tmp = tempfile::tempdir().unwrap();
    let cfg = PassthroughConfig {
        root_dir: tmp.path().to_path_buf(),
        writeback: true,
        ..Default::default()
    };
    let fs = PassthroughFs::new(cfg).unwrap();
    // Init without WRITEBACK_CACHE flag — writeback should remain off.
    let _opts = fs.init(FsOptions::empty()).unwrap();
    assert!(
        !fs.writeback.load(std::sync::atomic::Ordering::Relaxed),
        "writeback should not be enabled when kernel doesn't offer WRITEBACK_CACHE"
    );
}

#[test]
fn test_writeback_cache_enabled_with_support() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = PassthroughConfig {
        root_dir: tmp.path().to_path_buf(),
        writeback: true,
        ..Default::default()
    };
    let fs = PassthroughFs::new(cfg).unwrap();
    let opts = fs.init(FsOptions::WRITEBACK_CACHE).unwrap();
    assert!(opts.contains(FsOptions::WRITEBACK_CACHE));
    assert!(
        fs.writeback.load(std::sync::atomic::Ordering::Relaxed),
        "writeback should be enabled when both config and kernel agree"
    );
}
