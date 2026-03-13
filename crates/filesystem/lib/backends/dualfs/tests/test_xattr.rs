use super::*;

#[test]
fn test_getxattr_backend_a() {
    let sb = DualFsTestSandbox::new();
    let ino = sb
        .create_file_with_content(ROOT_INODE, "xattr_a.txt", b"data")
        .unwrap();
    let xname = DualFsTestSandbox::cstr("user.test");
    sb.fs
        .setxattr(DualFsTestSandbox::ctx(), ino, &xname, b"value_a", 0)
        .unwrap();
    let reply = sb
        .fs
        .getxattr(DualFsTestSandbox::ctx(), ino, &xname, 256)
        .unwrap();
    match reply {
        GetxattrReply::Value(v) => assert_eq!(v, b"value_a"),
        _ => panic!("expected GetxattrReply::Value"),
    }
}

#[test]
fn test_setxattr_triggers_materialization() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_xattr.txt", b"data");
    });
    let entry = sb.lookup_root("b_xattr.txt").unwrap();
    let xname = DualFsTestSandbox::cstr("user.trigger");
    // setxattr on backend_b file should trigger materialization.
    sb.fs
        .setxattr(
            DualFsTestSandbox::ctx(),
            entry.inode,
            &xname,
            b"materialized",
            0,
        )
        .unwrap();
    // Verify xattr is readable.
    let reply = sb
        .fs
        .getxattr(DualFsTestSandbox::ctx(), entry.inode, &xname, 256)
        .unwrap();
    match reply {
        GetxattrReply::Value(v) => assert_eq!(v, b"materialized"),
        _ => panic!("expected GetxattrReply::Value"),
    }
}

#[test]
fn test_listxattr() {
    let sb = DualFsTestSandbox::new();
    let ino = sb
        .create_file_with_content(ROOT_INODE, "list_x.txt", b"data")
        .unwrap();
    let xname = DualFsTestSandbox::cstr("user.listme");
    sb.fs
        .setxattr(DualFsTestSandbox::ctx(), ino, &xname, b"val", 0)
        .unwrap();
    let reply = sb
        .fs
        .listxattr(DualFsTestSandbox::ctx(), ino, 4096)
        .unwrap();
    match reply {
        ListxattrReply::Names(names) => {
            let name_str = String::from_utf8_lossy(&names);
            assert!(
                name_str.contains("user.listme"),
                "listxattr should include the set xattr name"
            );
        }
        _ => panic!("expected ListxattrReply::Names"),
    }
}

#[test]
fn test_removexattr() {
    let sb = DualFsTestSandbox::new();
    let ino = sb
        .create_file_with_content(ROOT_INODE, "rm_x.txt", b"data")
        .unwrap();
    let xname = DualFsTestSandbox::cstr("user.removeme");
    sb.fs
        .setxattr(DualFsTestSandbox::ctx(), ino, &xname, b"val", 0)
        .unwrap();
    sb.fs
        .removexattr(DualFsTestSandbox::ctx(), ino, &xname)
        .unwrap();
    let result = sb.fs.getxattr(DualFsTestSandbox::ctx(), ino, &xname, 256);
    DualFsTestSandbox::assert_errno(result, LINUX_ENODATA);
}

#[test]
fn test_getxattr_backend_b() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        memfs_create_file(b, 1, "b_getx.txt", b"data");
        // Look up the file to get its inode.
        let cname = CString::new("b_getx.txt").unwrap();
        let entry = b.lookup(ctx, 1, &cname).unwrap();
        let xname = CString::new("user.battr").unwrap();
        b.setxattr(ctx, entry.inode, &xname, b"bval", 0).unwrap();
    });
    let entry = sb.lookup_root("b_getx.txt").unwrap();
    let xname = DualFsTestSandbox::cstr("user.battr");
    let reply = sb
        .fs
        .getxattr(DualFsTestSandbox::ctx(), entry.inode, &xname, 256)
        .unwrap();
    match reply {
        GetxattrReply::Value(v) => assert_eq!(v, b"bval"),
        _ => panic!("expected GetxattrReply::Value"),
    }
}
