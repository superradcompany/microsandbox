use super::*;

#[test]
fn test_setxattr_getxattr() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("xattr_file.txt").unwrap();
    sb.fs
        .setxattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            &MemFsTestSandbox::cstr("user.custom"),
            b"myvalue",
            0,
        )
        .unwrap();
    let reply = sb
        .fs
        .getxattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            &MemFsTestSandbox::cstr("user.custom"),
            256,
        )
        .unwrap();
    match reply {
        GetxattrReply::Value(val) => assert_eq!(&val[..], b"myvalue"),
        _ => panic!("expected GetxattrReply::Value"),
    }
}

#[test]
fn test_listxattr() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("list_xattr.txt").unwrap();
    sb.fs
        .setxattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            &MemFsTestSandbox::cstr("user.alpha"),
            b"a",
            0,
        )
        .unwrap();
    sb.fs
        .setxattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            &MemFsTestSandbox::cstr("user.beta"),
            b"b",
            0,
        )
        .unwrap();

    let reply = sb
        .fs
        .listxattr(MemFsTestSandbox::ctx(), entry.inode, 1024)
        .unwrap();
    match reply {
        ListxattrReply::Names(names) => {
            // Names are null-separated.
            let parts: Vec<&[u8]> = names.split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
            assert_eq!(parts.len(), 2);
            assert!(parts.contains(&&b"user.alpha"[..]));
            assert!(parts.contains(&&b"user.beta"[..]));
        }
        _ => panic!("expected ListxattrReply::Names"),
    }
}

#[test]
fn test_removexattr() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("remove_xattr.txt").unwrap();
    sb.fs
        .setxattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            &MemFsTestSandbox::cstr("user.gone"),
            b"val",
            0,
        )
        .unwrap();
    sb.fs
        .removexattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            &MemFsTestSandbox::cstr("user.gone"),
        )
        .unwrap();
    let result = sb.fs.getxattr(
        MemFsTestSandbox::ctx(),
        entry.inode,
        &MemFsTestSandbox::cstr("user.gone"),
        256,
    );
    MemFsTestSandbox::assert_errno(result, LINUX_ENODATA);
}

#[test]
fn test_xattr_create_flag() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("xattr_create.txt").unwrap();
    sb.fs
        .setxattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            &MemFsTestSandbox::cstr("user.dup"),
            b"first",
            0,
        )
        .unwrap();
    // XATTR_CREATE on existing key should fail.
    let result = sb.fs.setxattr(
        MemFsTestSandbox::ctx(),
        entry.inode,
        &MemFsTestSandbox::cstr("user.dup"),
        b"second",
        1, // XATTR_CREATE
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EEXIST);
}

#[test]
fn test_xattr_replace_flag() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("xattr_replace.txt").unwrap();
    // XATTR_REPLACE on missing key should fail.
    let result = sb.fs.setxattr(
        MemFsTestSandbox::ctx(),
        entry.inode,
        &MemFsTestSandbox::cstr("user.missing"),
        b"val",
        2, // XATTR_REPLACE
    );
    MemFsTestSandbox::assert_errno(result, LINUX_ENODATA);
}

#[test]
fn test_xattr_on_directory() {
    let sb = MemFsTestSandbox::new();
    let dir = sb.fuse_mkdir_root("xattr_dir").unwrap();
    sb.fs
        .setxattr(
            MemFsTestSandbox::ctx(),
            dir.inode,
            &MemFsTestSandbox::cstr("user.dirattr"),
            b"dirval",
            0,
        )
        .unwrap();
    let reply = sb
        .fs
        .getxattr(
            MemFsTestSandbox::ctx(),
            dir.inode,
            &MemFsTestSandbox::cstr("user.dirattr"),
            256,
        )
        .unwrap();
    match reply {
        GetxattrReply::Value(val) => assert_eq!(&val[..], b"dirval"),
        _ => panic!("expected GetxattrReply::Value"),
    }
}

#[test]
fn test_xattr_on_symlink() {
    let sb = MemFsTestSandbox::new();
    let entry = sb
        .fs
        .symlink(
            MemFsTestSandbox::ctx(),
            &MemFsTestSandbox::cstr("/target"),
            ROOT_INODE,
            &MemFsTestSandbox::cstr("xattr_link"),
            Extensions::default(),
        )
        .unwrap();
    sb.fs
        .setxattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            &MemFsTestSandbox::cstr("user.linkattr"),
            b"linkval",
            0,
        )
        .unwrap();
    let reply = sb
        .fs
        .getxattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            &MemFsTestSandbox::cstr("user.linkattr"),
            256,
        )
        .unwrap();
    match reply {
        GetxattrReply::Value(val) => assert_eq!(&val[..], b"linkval"),
        _ => panic!("expected GetxattrReply::Value"),
    }
}

#[test]
fn test_xattr_empty_value() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("xattr_empty.txt").unwrap();
    sb.fs
        .setxattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            &MemFsTestSandbox::cstr("user.empty"),
            b"",
            0,
        )
        .unwrap();
    let reply = sb
        .fs
        .getxattr(
            MemFsTestSandbox::ctx(),
            entry.inode,
            &MemFsTestSandbox::cstr("user.empty"),
            256,
        )
        .unwrap();
    match reply {
        GetxattrReply::Value(val) => assert!(val.is_empty()),
        _ => panic!("expected GetxattrReply::Value"),
    }
}
