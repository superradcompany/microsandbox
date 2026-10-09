//! macOS-specific deny-list path-pattern regression tests.
//!
//! These exercise the `/.vol/<dev>/<ino>` + `F_GETPATH` parent-path
//! resolution path, which is macOS-only. They are gated to macOS because the
//! mechanism they verify does not exist on Linux.

use std::os::unix::fs::MetadataExt;

use super::*;

/// A nested path pattern hides the matching path on macOS.
#[test]
fn test_macos_deny_path_pattern_lookup() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["sub/.env".to_string()],
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
fn test_macos_deny_recursive_path_pattern() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["**/env.secret".to_string()],
        ..cfg
    });
    sb.host_create_dir("a");
    sb.host_create_dir("a/b");
    sb.host_create_file("a/b/env.secret", b"secret");

    let a = sb.lookup_root("a").unwrap();
    let b = sb.lookup(a.inode, "b").unwrap();
    TestSandbox::assert_errno(sb.lookup(b.inode, "env.secret"), LINUX_ENOENT);
}

/// Path-pattern create is rejected within a hidden subtree on macOS.
#[test]
fn test_macos_deny_path_pattern_create() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["sub/.secret".to_string()],
        ..cfg
    });
    sb.host_create_dir("sub");
    let dir = sb.lookup_root("sub").unwrap();
    TestSandbox::assert_errno(sb.fuse_create(dir.inode, ".secret", 0o644), LINUX_EACCES);
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
