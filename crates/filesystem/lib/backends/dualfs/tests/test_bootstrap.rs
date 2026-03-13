use super::*;

#[test]
fn test_build_default() {
    let backend_a = MemFs::builder().build().unwrap();
    let backend_b = MemFs::builder().build().unwrap();
    let fs = DualFs::builder()
        .backend_a(backend_a)
        .backend_b(backend_b)
        .build();
    assert!(fs.is_ok(), "default builder should succeed");
}

#[test]
fn test_build_missing_backend_a() {
    let backend_b = MemFs::builder().build().unwrap();
    let result = DualFs::builder().backend_b(backend_b).build();
    assert!(result.is_err(), "should fail without backend_a");
}

#[test]
fn test_build_missing_backend_b() {
    let backend_a = MemFs::builder().build().unwrap();
    let result = DualFs::builder().backend_a(backend_a).build();
    assert!(result.is_err(), "should fail without backend_b");
}

#[test]
fn test_init_negotiates_intersection() {
    let backend_a = MemFs::builder().build().unwrap();
    let backend_b = MemFs::builder().build().unwrap();
    let fs = DualFs::builder()
        .backend_a(backend_a)
        .backend_b(backend_b)
        .build()
        .unwrap();
    let caps = FsOptions::ASYNC_READ | FsOptions::BIG_WRITES | FsOptions::HANDLE_KILLPRIV_V2;
    let opts = fs.init(caps).unwrap();
    // These features are supported by both MemFs backends.
    assert!(opts.contains(FsOptions::ASYNC_READ));
    assert!(opts.contains(FsOptions::BIG_WRITES));
    assert!(opts.contains(FsOptions::HANDLE_KILLPRIV_V2));
}

#[test]
fn test_init_writeback() {
    let backend_a = MemFs::builder().writeback(true).build().unwrap();
    let backend_b = MemFs::builder().writeback(true).build().unwrap();
    let fs = DualFs::builder()
        .backend_a(backend_a)
        .backend_b(backend_b)
        .writeback(true)
        .build()
        .unwrap();
    let opts = fs.init(FsOptions::WRITEBACK_CACHE).unwrap();
    assert!(
        opts.contains(FsOptions::WRITEBACK_CACHE),
        "writeback should be negotiated when both backends support it"
    );
}

#[test]
fn test_init_writeback_one_child_unsupported() {
    // backend_a does NOT enable writeback, backend_b does.
    let backend_a = MemFs::builder().writeback(false).build().unwrap();
    let backend_b = MemFs::builder().writeback(true).build().unwrap();
    let fs = DualFs::builder()
        .backend_a(backend_a)
        .backend_b(backend_b)
        .writeback(true)
        .build()
        .unwrap();
    let opts = fs.init(FsOptions::WRITEBACK_CACHE).unwrap();
    assert!(
        !opts.contains(FsOptions::WRITEBACK_CACHE),
        "writeback should NOT be negotiated when one child lacks support"
    );
}

#[test]
fn test_root_exists_after_init() {
    let sb = DualFsTestSandbox::new();
    let (st, _) = sb
        .fs
        .getattr(DualFsTestSandbox::ctx(), ROOT_INODE, None)
        .unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(
        mode & libc::S_IFMT as u32,
        libc::S_IFDIR as u32,
        "root should be a directory"
    );
}

#[test]
fn test_init_creates_staging_dirs() {
    let sb = DualFsTestSandbox::new();
    // After init, the staging dirs should be created in both backends.
    // Verify by checking that the staging dir inodes are registered.
    // We cannot look up ".dualfs_staging" through DualFs (it is hidden),
    // but we can verify root readdir does not contain it.
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(
        !names.contains(&".dualfs_staging".to_string()),
        "staging dir should be hidden from readdir"
    );
}
