use super::*;

#[test]
fn test_getattr_backend_a() {
    let sb = DualFsTestSandbox::new();
    let ino = sb
        .create_file_with_content(ROOT_INODE, "a_meta.txt", b"data")
        .unwrap();
    let (st, _) = sb.fs.getattr(DualFsTestSandbox::ctx(), ino, None).unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert!(st.st_size >= 4, "file should have at least 4 bytes");
}

#[test]
fn test_getattr_backend_b() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_meta.txt", b"backend_b_content");
    });
    let entry = sb.lookup_root("b_meta.txt").unwrap();
    let (st, _) = sb
        .fs
        .getattr(DualFsTestSandbox::ctx(), entry.inode, None)
        .unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert!(st.st_size >= 17, "file should have backend_b_content bytes");
}

#[test]
fn test_setattr_mode() {
    let sb = DualFsTestSandbox::new();
    let ino = sb
        .create_file_with_content(ROOT_INODE, "chmod.txt", b"data")
        .unwrap();
    let mut attr: crate::stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = 0o600 as _;
    let (st, _) = sb
        .fs
        .setattr(
            DualFsTestSandbox::ctx(),
            ino,
            attr,
            None,
            SetattrValid::MODE,
        )
        .unwrap();
    assert_eq!(st.st_mode as u32 & 0o777, 0o600, "mode should be updated");
}

#[test]
fn test_setattr_size() {
    let sb = DualFsTestSandbox::new();
    let ino = sb
        .create_file_with_content(ROOT_INODE, "truncate.txt", b"hello world")
        .unwrap();
    let mut attr: crate::stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 5;
    let (st, _) = sb
        .fs
        .setattr(
            DualFsTestSandbox::ctx(),
            ino,
            attr,
            None,
            SetattrValid::SIZE,
        )
        .unwrap();
    assert_eq!(st.st_size, 5, "file should be truncated to 5 bytes");
}

#[test]
fn test_setattr_init_krun() {
    let sb = DualFsTestSandbox::new();
    let attr: crate::stat64 = unsafe { std::mem::zeroed() };
    let result = sb.fs.setattr(
        DualFsTestSandbox::ctx(),
        INIT_INODE,
        attr,
        None,
        SetattrValid::MODE,
    );
    DualFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_access_dispatches() {
    let sb = DualFsTestSandbox::new();
    let ino = sb
        .create_file_with_content(ROOT_INODE, "access.txt", b"data")
        .unwrap();
    let result = sb
        .fs
        .access(DualFsTestSandbox::ctx(), ino, libc::R_OK as u32);
    assert!(result.is_ok(), "access check should succeed for owner");
}

#[test]
fn test_setattr_triggers_materialization() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "b_setattr.txt", b"original");
    });
    let entry = sb.lookup_root("b_setattr.txt").unwrap();
    let mut attr: crate::stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = 0o600 as _;
    // setattr on backend_b file should trigger materialization.
    let (st, _) = sb
        .fs
        .setattr(
            DualFsTestSandbox::ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::MODE,
        )
        .unwrap();
    assert_eq!(
        st.st_mode as u32 & 0o777,
        0o600,
        "mode should be updated after materialization"
    );
    // File should still be readable.
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(
        &data[..],
        b"original",
        "data should be preserved after materialization"
    );
    sb.fs
        .release(
            DualFsTestSandbox::ctx(),
            entry.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
}

#[test]
fn test_getattr_metadata_backend() {
    // getattr dispatches to the backend indicated by metadata_backend.
    // For a backend_a file, metadata_backend is BackendA and getattr should return
    // the attributes from backend_a. For a backend_b file, it should return
    // attributes from backend_b. After materialization, the metadata_backend
    // switches to the target (backend_a).

    // Test 1: backend_a file.
    let sb = DualFsTestSandbox::new();
    let ino_a = sb
        .create_file_with_content(ROOT_INODE, "meta_a.txt", b"hello_a")
        .unwrap();
    let (st_a, _) = sb
        .fs
        .getattr(DualFsTestSandbox::ctx(), ino_a, None)
        .unwrap();
    assert_eq!(
        st_a.st_ino, ino_a,
        "getattr should rewrite st_ino to guest inode"
    );
    let mode_a = st_a.st_mode as u32;
    assert_eq!(
        mode_a & libc::S_IFMT as u32,
        libc::S_IFREG as u32,
        "should be a regular file"
    );
    assert!(st_a.st_size >= 7, "size should reflect written content");

    // Test 2: backend_b file.
    let sb2 = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "meta_b.txt", b"hello_b_longer");
    });
    let entry_b = sb2.lookup_root("meta_b.txt").unwrap();
    let (st_b, _) = sb2
        .fs
        .getattr(DualFsTestSandbox::ctx(), entry_b.inode, None)
        .unwrap();
    assert_eq!(
        st_b.st_ino, entry_b.inode,
        "getattr should rewrite st_ino to guest inode"
    );
    let mode_b = st_b.st_mode as u32;
    assert_eq!(
        mode_b & libc::S_IFMT as u32,
        libc::S_IFREG as u32,
        "should be a regular file from backend_b"
    );
    assert!(st_b.st_size >= 14, "size should reflect backend_b content");

    // Test 3: after materialization, getattr should still work and reflect backend_a attrs.
    let handle = sb2.fuse_open(entry_b.inode, libc::O_RDWR as u32).unwrap();
    sb2.fs
        .release(
            DualFsTestSandbox::ctx(),
            entry_b.inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
    let (st_after, _) = sb2
        .fs
        .getattr(DualFsTestSandbox::ctx(), entry_b.inode, None)
        .unwrap();
    assert_eq!(
        st_after.st_ino, entry_b.inode,
        "guest inode should be stable after materialization"
    );
    let mode_after = st_after.st_mode as u32;
    assert_eq!(
        mode_after & libc::S_IFMT as u32,
        libc::S_IFREG as u32,
        "should still be a regular file after materialization"
    );
}
