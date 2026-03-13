use super::*;

#[test]
fn test_setxattr_getxattr_roundtrip() {
    let sb = OverlayTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("xattr_file.txt").unwrap();
    let key = OverlayTestSandbox::cstr("user.test_key");
    let value = b"test_value";
    sb.fs
        .setxattr(sb.ctx(), entry.inode, &key, value, 0)
        .unwrap();
    let reply = sb.fs.getxattr(sb.ctx(), entry.inode, &key, 256).unwrap();
    match reply {
        GetxattrReply::Value(v) => assert_eq!(&v[..], value),
        GetxattrReply::Count(_) => panic!("expected Value, got Count"),
    }
}

#[test]
fn test_getxattr_nonexistent() {
    let sb = OverlayTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let key = OverlayTestSandbox::cstr("user.nonexistent");
    let result = sb.fs.getxattr(sb.ctx(), entry.inode, &key, 256);
    OverlayTestSandbox::assert_errno(result, LINUX_ENODATA);
}

#[test]
fn test_listxattr() {
    let sb = OverlayTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let key = OverlayTestSandbox::cstr("user.myattr");
    sb.fs
        .setxattr(sb.ctx(), entry.inode, &key, b"val", 0)
        .unwrap();
    let reply = sb.fs.listxattr(sb.ctx(), entry.inode, 4096).unwrap();
    match reply {
        ListxattrReply::Names(data) => {
            let names_str = String::from_utf8_lossy(&data);
            assert!(
                names_str.contains("user.myattr"),
                "listxattr should include user.myattr, got: {names_str}"
            );
        }
        ListxattrReply::Count(_) => panic!("expected Names, got Count"),
    }
}

#[test]
fn test_removexattr() {
    let sb = OverlayTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let key = OverlayTestSandbox::cstr("user.removeme");
    sb.fs
        .setxattr(sb.ctx(), entry.inode, &key, b"val", 0)
        .unwrap();
    sb.fs.removexattr(sb.ctx(), entry.inode, &key).unwrap();
    let result = sb.fs.getxattr(sb.ctx(), entry.inode, &key, 256);
    OverlayTestSandbox::assert_errno(result, LINUX_ENODATA);
}

#[test]
fn test_listxattr_hides_internal() {
    let sb = OverlayTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let reply = sb.fs.listxattr(sb.ctx(), entry.inode, 4096).unwrap();
    match reply {
        ListxattrReply::Names(data) => {
            let names_str = String::from_utf8_lossy(&data);
            assert!(
                !names_str.contains("user.containers."),
                "internal xattrs should be hidden, got: {names_str}"
            );
        }
        ListxattrReply::Count(_) => {}
    }
}

#[test]
fn test_setxattr_on_lower_triggers_copy_up() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("lower.txt"), b"data").unwrap();
    });
    let entry = sb.lookup_root("lower.txt").unwrap();
    let key = OverlayTestSandbox::cstr("user.newattr");
    sb.fs
        .setxattr(sb.ctx(), entry.inode, &key, b"value", 0)
        .unwrap();
    // Should have been copied up.
    assert!(sb.upper_has_file("lower.txt"));
    // Verify xattr persists.
    let reply = sb.fs.getxattr(sb.ctx(), entry.inode, &key, 256).unwrap();
    match reply {
        GetxattrReply::Value(v) => assert_eq!(&v[..], b"value"),
        GetxattrReply::Count(_) => panic!("expected Value"),
    }
}

#[test]
fn test_xattr_init_rejected() {
    let sb = OverlayTestSandbox::new();
    let key = OverlayTestSandbox::cstr("user.test");
    let result = sb.fs.setxattr(sb.ctx(), INIT_INODE, &key, b"val", 0);
    OverlayTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_getxattr_size_query() {
    let sb = OverlayTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let key = OverlayTestSandbox::cstr("user.sizetest");
    let value = b"twelve_bytes";
    sb.fs
        .setxattr(sb.ctx(), entry.inode, &key, value, 0)
        .unwrap();
    // Query with size=0 should return the value length.
    let reply = sb.fs.getxattr(sb.ctx(), entry.inode, &key, 0).unwrap();
    match reply {
        GetxattrReply::Count(n) => assert_eq!(n as usize, value.len()),
        GetxattrReply::Value(_) => panic!("expected Count for size query"),
    }
}
