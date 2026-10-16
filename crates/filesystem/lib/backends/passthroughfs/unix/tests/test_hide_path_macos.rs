//! macOS-specific hide_path-list path-pattern regression tests.
//!
//! These exercise the `/.vol/<dev>/<ino>` + `F_GETPATH` parent-path
//! resolution path, which is macOS-only. They are gated to macOS because the
//! mechanism they verify does not exist on Linux.

use std::os::unix::fs::MetadataExt;

use super::*;

/// A nested path pattern hides the matching path on macOS.
#[test]
fn test_macos_hide_path_path_pattern_lookup() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["sub/.env".to_string()],
        readonly: true,
        ..cfg
    });
    sb.host_create_dir("sub");
    sb.host_create_file("sub/.env", b"secret");
    sb.host_create_file("sub/visible.txt", b"ok");

    let dir = sb.lookup_root("sub").unwrap();
    TestSandbox::assert_errno(sb.lookup(dir.inode, ".env"), LINUX_ENOENT);
    let visible = sb.lookup(dir.inode, "visible.txt").unwrap();
    assert_ne!(visible.inode, 0);
}

/// A recursive path pattern hides nested matches on macOS.
#[test]
fn test_macos_hide_path_recursive_path_pattern() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["**/env.secret".to_string()],
        readonly: true,
        ..cfg
    });
    sb.host_create_dir("a");
    sb.host_create_dir("a/b");
    sb.host_create_file("a/b/env.secret", b"secret");

    let a = sb.lookup_root("a").unwrap();
    let b = sb.lookup(a.inode, "b").unwrap();
    TestSandbox::assert_errno(sb.lookup(b.inode, "env.secret"), LINUX_ENOENT);
}

/// A writable mount refuses a path pattern at construction; a read-only mount
/// accepts it. Path patterns are location-based and a writable mount can
/// launder them by renaming an ancestor directory.
#[test]
fn test_macos_hide_path_path_pattern_create() {
    let tmp = tempfile::tempdir().unwrap();

    let writable = PassthroughFs::new(PassthroughConfig {
        root_dir: tmp.path().to_path_buf(),
        hide_path: vec!["sub/.secret".to_string()],
        ..Default::default()
    });
    assert!(
        writable.is_err(),
        "a writable mount must refuse a path pattern"
    );

    let readonly = PassthroughFs::new(PassthroughConfig {
        root_dir: tmp.path().to_path_buf(),
        hide_path: vec!["sub/.secret".to_string()],
        readonly: true,
        ..Default::default()
    });
    assert!(
        readonly.is_ok(),
        "a read-only mount must accept a path pattern"
    );
}

/// `/.vol` resolution returns a real host path for a tracked inode.
#[test]
fn test_macos_vol_resolves_host_path() {
    let sb = TestSandbox::new();
    let path = sb.host_create_file("probe.txt", b"x");
    let meta = std::fs::metadata(&path).unwrap();
    let host = crate::backends::shared::platform::path_from_vol(meta.dev(), meta.ino()).unwrap();
    assert!(
        host.starts_with(&sb.root),
        "resolved {host:?} under root {:?}",
        sb.root
    );
}
