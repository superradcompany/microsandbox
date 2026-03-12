use super::*;

#[test]
fn test_delegation_lookup() {
    let sb = ProxyFsTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let looked_up = sb.lookup_root("file.txt").unwrap();
    assert_eq!(looked_up.inode, entry.inode);
}

#[test]
fn test_delegation_create() {
    let sb = ProxyFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("created.txt").unwrap();
    assert!(entry.inode >= 3);
    assert!(handle.is_some());
}

#[test]
fn test_delegation_mkdir() {
    let sb = ProxyFsTestSandbox::new();
    let entry = sb.fuse_mkdir_root("mydir").unwrap();
    assert!(entry.inode >= 3);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
}

#[test]
fn test_delegation_read_write() {
    let sb = ProxyFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("rw.txt").unwrap();
    let handle = handle.unwrap();
    let data = b"hello proxy world";
    let written = sb.fuse_write(entry.inode, handle, data, 0).unwrap();
    assert_eq!(written, data.len());
    let read_data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&read_data[..], data);
}

#[test]
fn test_delegation_readdir() {
    let sb = ProxyFsTestSandbox::new();
    sb.fuse_create_root("a.txt").unwrap();
    sb.fuse_create_root("b.txt").unwrap();
    sb.fuse_mkdir_root("c_dir").unwrap();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(names.contains(&"a.txt".to_string()));
    assert!(names.contains(&"b.txt".to_string()));
    assert!(names.contains(&"c_dir".to_string()));
    // Should also contain "." and ".." and "init.krun".
    assert!(names.contains(&".".to_string()));
    assert!(names.contains(&"..".to_string()));
    assert!(names.contains(&"init.krun".to_string()));
}

#[test]
fn test_delegation_unlink() {
    let sb = ProxyFsTestSandbox::new();
    sb.fuse_create_root("delete_me.txt").unwrap();
    sb.fs
        .unlink(
            ProxyFsTestSandbox::ctx(),
            ROOT_INODE,
            &ProxyFsTestSandbox::cstr("delete_me.txt"),
        )
        .unwrap();
    let result = sb.lookup_root("delete_me.txt");
    ProxyFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_delegation_rmdir() {
    let sb = ProxyFsTestSandbox::new();
    sb.fuse_mkdir_root("empty_dir").unwrap();
    sb.fs
        .rmdir(
            ProxyFsTestSandbox::ctx(),
            ROOT_INODE,
            &ProxyFsTestSandbox::cstr("empty_dir"),
        )
        .unwrap();
    let result = sb.lookup_root("empty_dir");
    ProxyFsTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_delegation_rename() {
    let sb = ProxyFsTestSandbox::new();
    sb.fuse_create_root("old_name.txt").unwrap();
    sb.fs
        .rename(
            ProxyFsTestSandbox::ctx(),
            ROOT_INODE,
            &ProxyFsTestSandbox::cstr("old_name.txt"),
            ROOT_INODE,
            &ProxyFsTestSandbox::cstr("new_name.txt"),
            0,
        )
        .unwrap();
    let result = sb.lookup_root("old_name.txt");
    ProxyFsTestSandbox::assert_errno(result, LINUX_ENOENT);
    let entry = sb.lookup_root("new_name.txt").unwrap();
    assert!(entry.inode >= 3);
}

#[test]
fn test_delegation_getattr_setattr() {
    let sb = ProxyFsTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("meta.txt").unwrap();
    let (st, _dur) = sb
        .fs
        .getattr(ProxyFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    assert_eq!(st.st_ino, entry.inode);

    // Set size via setattr.
    let mut new_attr = st;
    new_attr.st_size = 42;
    let (updated, _dur) = sb
        .fs
        .setattr(
            ProxyFsTestSandbox::ctx(),
            entry.inode,
            new_attr,
            None,
            SetattrValid::SIZE,
        )
        .unwrap();
    assert_eq!(updated.st_size, 42);
}

#[test]
fn test_delegation_xattr() {
    let sb = ProxyFsTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("xattr_file.txt").unwrap();
    let key = ProxyFsTestSandbox::cstr("user.test_key");
    let value = b"test_value";

    // setxattr
    sb.fs
        .setxattr(ProxyFsTestSandbox::ctx(), entry.inode, &key, value, 0)
        .unwrap();

    // getxattr
    let reply = sb
        .fs
        .getxattr(ProxyFsTestSandbox::ctx(), entry.inode, &key, 256)
        .unwrap();
    match reply {
        GetxattrReply::Value(v) => assert_eq!(&v[..], value),
        GetxattrReply::Count(_) => panic!("expected Value, got Count"),
    }

    // listxattr
    let reply = sb
        .fs
        .listxattr(ProxyFsTestSandbox::ctx(), entry.inode, 4096)
        .unwrap();
    match reply {
        ListxattrReply::Names(data) => {
            let names_str = String::from_utf8_lossy(&data);
            assert!(
                names_str.contains("user.test_key"),
                "listxattr should include user.test_key, got: {names_str}"
            );
        }
        ListxattrReply::Count(_) => panic!("expected Names, got Count"),
    }

    // removexattr
    sb.fs
        .removexattr(ProxyFsTestSandbox::ctx(), entry.inode, &key)
        .unwrap();
    let result = sb
        .fs
        .getxattr(ProxyFsTestSandbox::ctx(), entry.inode, &key, 256);
    ProxyFsTestSandbox::assert_errno(result, LINUX_ENODATA);
}

#[test]
#[cfg(target_os = "linux")]
fn test_delegation_symlink_readlink() {
    let sb = ProxyFsTestSandbox::new();
    let entry = sb
        .fs
        .symlink(
            ProxyFsTestSandbox::ctx(),
            &ProxyFsTestSandbox::cstr("/target/path"),
            ROOT_INODE,
            &ProxyFsTestSandbox::cstr("mylink"),
            Extensions::default(),
        )
        .unwrap();
    assert!(entry.inode >= 3);
    let target = sb.fs.readlink(ProxyFsTestSandbox::ctx(), entry.inode).unwrap();
    assert_eq!(&target[..], b"/target/path");
}

#[test]
fn test_delegation_mknod() {
    let sb = ProxyFsTestSandbox::new();
    // Create a regular file via mknod (S_IFREG | 0o644).
    let mode = libc::S_IFREG as u32 | 0o644;
    let entry = sb
        .fs
        .mknod(
            ProxyFsTestSandbox::ctx(),
            ROOT_INODE,
            &ProxyFsTestSandbox::cstr("node_file"),
            mode,
            0,
            0,
            Extensions::default(),
        )
        .unwrap();
    assert!(entry.inode >= 3);
    let looked_up = sb.lookup_root("node_file").unwrap();
    assert_eq!(looked_up.inode, entry.inode);
}

#[test]
fn test_delegation_link() {
    let sb = ProxyFsTestSandbox::new();
    let ino = sb.create_file_with_content(ROOT_INODE, "original.txt", b"link data").unwrap();
    let link_entry = sb
        .fs
        .link(
            ProxyFsTestSandbox::ctx(),
            ino,
            ROOT_INODE,
            &ProxyFsTestSandbox::cstr("hard_link.txt"),
        )
        .unwrap();
    assert!(link_entry.inode >= 3);
    // Read via the link.
    let (handle, _opts) = sb
        .fuse_open(link_entry.inode, libc::O_RDONLY as u32)
        .unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(link_entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"link data");
}

#[test]
fn test_delegation_init() {
    // init is called during sandbox construction; verify the negotiated options.
    let memfs = MemFs::builder().build().unwrap();
    let fs = ProxyFs::builder(Box::new(memfs)).build().unwrap();
    let opts = fs.init(FsOptions::empty()).unwrap();
    // With empty capabilities, expect empty result (or at least no panic).
    // Just verify init returns Ok.
    let _ = opts;
}

#[test]
fn test_delegation_statfs() {
    let sb = ProxyFsTestSandbox::new();
    let st = sb
        .fs
        .statfs(ProxyFsTestSandbox::ctx(), ROOT_INODE)
        .unwrap();
    assert!(st.f_bsize > 0);
}
