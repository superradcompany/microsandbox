use super::*;
use crate::backends::passthroughfs::{HostPermissions, StatVirtualization};

#[test]
fn test_strict_succeeds_on_xattr_capable_fs() {
    // tmpdir supports xattrs, so Strict should mount cleanly and operate fully.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Strict;
        cfg
    });
    let (entry, handle) = sb.fuse_create_root("test.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"ok", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"ok");
}

#[test]
fn test_relaxed_skips_eager_probe() {
    // Relaxed never probes the bind root.
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Relaxed;
        cfg
    });
    // Should still be fully functional.
    let (entry, handle) = sb.fuse_create_root("test.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"data");
}

#[test]
fn test_off_skips_eager_probe() {
    // Off does not require xattr support and skips the probe.
    let _sb = TestSandbox::with_config(|mut cfg| {
        cfg.stat_virtualization = StatVirtualization::Off;
        cfg
    });
    // Construction succeeded — probe was skipped.
}

#[test]
fn test_off_relaxed_strict_derived_booleans() {
    let strict = PassthroughConfig {
        stat_virtualization: StatVirtualization::Strict,
        ..Default::default()
    };
    assert!(strict.xattr_enabled());
    assert!(strict.strict_enabled());

    let relaxed = PassthroughConfig {
        stat_virtualization: StatVirtualization::Relaxed,
        ..Default::default()
    };
    assert!(relaxed.xattr_enabled());
    assert!(!relaxed.strict_enabled());

    let off = PassthroughConfig {
        stat_virtualization: StatVirtualization::Off,
        ..Default::default()
    };
    assert!(!off.xattr_enabled());
    assert!(!off.strict_enabled());
}

#[test]
fn test_host_permissions_defaults_private() {
    let cfg = PassthroughConfig::default();
    assert!(matches!(cfg.host_permissions, HostPermissions::Private));
    assert!(!cfg.mirror_host_permissions());

    let mirror = PassthroughConfig {
        host_permissions: HostPermissions::Mirror,
        ..Default::default()
    };
    assert!(mirror.mirror_host_permissions());
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
