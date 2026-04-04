use super::*;
use crate::backends::shared::stat_override::OVERRIDE_XATTR_KEY;

#[test]
fn test_setxattr_getxattr_roundtrip() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("xattr.txt").unwrap();
    let value = b"my_value";
    sb.fs
        .setxattr(
            sb.ctx(),
            entry.inode,
            &TestSandbox::cstr("user.test"),
            value,
            0,
        )
        .unwrap();
    let reply = sb
        .fs
        .getxattr(
            sb.ctx(),
            entry.inode,
            &TestSandbox::cstr("user.test"),
            value.len() as u32 + 16,
        )
        .unwrap();
    match reply {
        GetxattrReply::Value(v) => assert_eq!(&v[..], value),
        GetxattrReply::Count(_) => panic!("expected Value, got Count"),
    }
}

#[test]
fn test_getxattr_size_query() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("xattr.txt").unwrap();
    let value = b"hello_xattr";
    sb.fs
        .setxattr(
            sb.ctx(),
            entry.inode,
            &TestSandbox::cstr("user.test"),
            value,
            0,
        )
        .unwrap();
    // size=0 should return Count(value_len).
    let reply = sb
        .fs
        .getxattr(sb.ctx(), entry.inode, &TestSandbox::cstr("user.test"), 0)
        .unwrap();
    match reply {
        GetxattrReply::Count(n) => assert_eq!(n, value.len() as u32),
        GetxattrReply::Value(_) => panic!("expected Count, got Value"),
    }
}

#[test]
fn test_getxattr_nonexistent_key() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("xattr.txt").unwrap();
    let result = sb.fs.getxattr(
        sb.ctx(),
        entry.inode,
        &TestSandbox::cstr("user.nonexistent"),
        256,
    );
    TestSandbox::assert_errno(result, LINUX_ENODATA);
}

#[test]
fn test_listxattr_custom_present() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("xattr.txt").unwrap();
    sb.fs
        .setxattr(
            sb.ctx(),
            entry.inode,
            &TestSandbox::cstr("user.custom"),
            b"val",
            0,
        )
        .unwrap();
    let reply = sb.fs.listxattr(sb.ctx(), entry.inode, 4096).unwrap();
    match reply {
        ListxattrReply::Names(names) => {
            // Names are nul-separated.
            let name_list: Vec<&[u8]> =
                names.split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
            assert!(
                name_list.iter().any(|n| *n == b"user.custom"),
                "user.custom should be in xattr list"
            );
        }
        ListxattrReply::Count(_) => panic!("expected Names, got Count"),
    }
}

#[test]
fn test_listxattr_hides_override() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("xattr.txt").unwrap();
    // The create operation sets the override xattr internally.
    let reply = sb.fs.listxattr(sb.ctx(), entry.inode, 4096).unwrap();
    match reply {
        ListxattrReply::Names(names) => {
            let name_list: Vec<&[u8]> =
                names.split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
            let override_key = OVERRIDE_XATTR_KEY.to_bytes();
            assert!(
                !name_list.iter().any(|n| *n == override_key),
                "override xattr should be hidden from listing"
            );
        }
        ListxattrReply::Count(_) => panic!("expected Names, got Count"),
    }
}

#[test]
fn test_listxattr_size_query_hides_override() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("xattr.txt").unwrap();
    // Set a custom xattr so we have something to list.
    sb.fs
        .setxattr(
            sb.ctx(),
            entry.inode,
            &TestSandbox::cstr("user.custom"),
            b"v",
            0,
        )
        .unwrap();

    // Get the filtered names (full query) and the size query independently.
    let names_reply = sb.fs.listxattr(sb.ctx(), entry.inode, 4096).unwrap();
    let count_reply = sb.fs.listxattr(sb.ctx(), entry.inode, 0).unwrap();

    let names = match names_reply {
        ListxattrReply::Names(n) => n,
        ListxattrReply::Count(_) => panic!("expected Names for non-zero size query"),
    };
    let count = match count_reply {
        ListxattrReply::Count(c) => c,
        ListxattrReply::Names(_) => panic!("expected Count for size=0 query"),
    };

    // The size-query count must exactly match the filtered names byte length.
    // If the size-query path leaked the hidden override xattr, count would
    // be larger than names.len() by at least override_key_bytes.
    assert_eq!(
        count as usize,
        names.len(),
        "size-query count must match filtered names length"
    );

    // Verify the override key is absent from the names list.
    let override_key = OVERRIDE_XATTR_KEY.to_bytes();
    let name_list: Vec<&[u8]> = names.split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
    assert!(
        !name_list.iter().any(|n| *n == override_key),
        "override xattr must not appear in filtered names"
    );

    // user.custom must be present.
    assert!(
        name_list.iter().any(|n| *n == b"user.custom"),
        "user.custom should be in the filtered names"
    );
}

#[test]
fn test_removexattr_works() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("xattr.txt").unwrap();
    sb.fs
        .setxattr(
            sb.ctx(),
            entry.inode,
            &TestSandbox::cstr("user.removeme"),
            b"val",
            0,
        )
        .unwrap();
    sb.fs
        .removexattr(sb.ctx(), entry.inode, &TestSandbox::cstr("user.removeme"))
        .unwrap();
    let result = sb.fs.getxattr(
        sb.ctx(),
        entry.inode,
        &TestSandbox::cstr("user.removeme"),
        256,
    );
    assert!(result.is_err(), "removed xattr should not be accessible");
}

#[test]
fn test_setxattr_override_rejected() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("xattr.txt").unwrap();
    let result = sb
        .fs
        .setxattr(sb.ctx(), entry.inode, OVERRIDE_XATTR_KEY, b"fake", 0);
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_getxattr_override_rejected() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("xattr.txt").unwrap();
    let result = sb
        .fs
        .getxattr(sb.ctx(), entry.inode, OVERRIDE_XATTR_KEY, 256);
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_removexattr_override_rejected() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("xattr.txt").unwrap();
    let result = sb.fs.removexattr(sb.ctx(), entry.inode, OVERRIDE_XATTR_KEY);
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_setxattr_init_rejected() {
    let sb = TestSandbox::new();
    let result = sb.fs.setxattr(
        sb.ctx(),
        INIT_INODE,
        &TestSandbox::cstr("user.test"),
        b"value",
        0,
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_getxattr_init_enodata() {
    let sb = TestSandbox::new();
    let result = sb
        .fs
        .getxattr(sb.ctx(), INIT_INODE, &TestSandbox::cstr("user.test"), 256);
    TestSandbox::assert_errno(result, LINUX_ENODATA);
}

#[test]
fn test_listxattr_init_empty() {
    let sb = TestSandbox::new();

    match sb.fs.listxattr(sb.ctx(), INIT_INODE, 0).unwrap() {
        ListxattrReply::Count(count) => assert_eq!(count, 0),
        ListxattrReply::Names(_) => panic!("expected Count for size=0 query"),
    }

    match sb.fs.listxattr(sb.ctx(), INIT_INODE, 256).unwrap() {
        ListxattrReply::Names(names) => assert!(names.is_empty()),
        ListxattrReply::Count(_) => panic!("expected Names for non-zero size query"),
    }
}

#[test]
fn test_removexattr_init_rejected() {
    let sb = TestSandbox::new();
    let result = sb
        .fs
        .removexattr(sb.ctx(), INIT_INODE, &TestSandbox::cstr("user.test"));
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
#[cfg(target_os = "macos")]
fn test_symlink_xattr_roundtrip() {
    let sb = TestSandbox::new();
    let entry = sb
        .fs
        .symlink(
            sb.ctx(),
            &TestSandbox::cstr("/target/path"),
            ROOT_INODE,
            &TestSandbox::cstr("xattr-link"),
            Extensions::default(),
        )
        .unwrap();
    let key = TestSandbox::cstr("user.linkattr");
    let value = b"link-value";

    sb.fs
        .setxattr(sb.ctx(), entry.inode, &key, value, 0)
        .unwrap();

    match sb.fs.getxattr(sb.ctx(), entry.inode, &key, 256).unwrap() {
        GetxattrReply::Value(v) => assert_eq!(&v[..], value),
        GetxattrReply::Count(_) => panic!("expected Value, got Count"),
    }

    match sb.fs.listxattr(sb.ctx(), entry.inode, 4096).unwrap() {
        ListxattrReply::Names(names) => {
            let name_list: Vec<&[u8]> =
                names.split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
            assert!(
                name_list.iter().any(|n| *n == b"user.linkattr"),
                "user.linkattr should be in xattr list"
            );
        }
        ListxattrReply::Count(_) => panic!("expected Names, got Count"),
    }

    sb.fs.removexattr(sb.ctx(), entry.inode, &key).unwrap();
    TestSandbox::assert_errno(
        sb.fs.getxattr(sb.ctx(), entry.inode, &key, 256),
        LINUX_ENODATA,
    );
}
