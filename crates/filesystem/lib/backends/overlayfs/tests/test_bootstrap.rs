use super::*;

#[test]
fn test_build_no_lower_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let upper = tmp.path().join("upper");
    let state = tmp.path().join("state");
    std::fs::create_dir(&upper).unwrap();
    std::fs::create_dir(&state).unwrap();
    let result = OverlayFs::builder()
        .writable(&upper)
        .work_dir(&state)
        .build();
    assert!(result.is_err(), "should fail without lower layers");
}

#[test]
fn test_build_no_upper_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let lower = tmp.path().join("lower");
    let state = tmp.path().join("state");
    std::fs::create_dir(&lower).unwrap();
    std::fs::create_dir(&state).unwrap();
    let result = OverlayFs::builder().layer(&lower).work_dir(&state).build();
    assert!(result.is_err(), "should fail without upper layer");
}

#[test]
fn test_build_no_state_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let lower = tmp.path().join("lower");
    let upper = tmp.path().join("upper");
    std::fs::create_dir(&lower).unwrap();
    std::fs::create_dir(&upper).unwrap();
    let result = OverlayFs::builder()
        .layer(&lower)
        .writable(&upper)
        .build();
    assert!(result.is_err(), "should fail without work dir");
}

#[test]
fn test_build_single_lower() {
    let sb = OverlayTestSandbox::new();
    // Should successfully build and init.
    let result = sb.fs.getattr(sb.ctx(), ROOT_INODE, None);
    assert!(result.is_ok());
}

#[test]
fn test_build_multiple_lowers() {
    let sb = OverlayTestSandbox::with_layers(3, |_, _| {});
    let result = sb.fs.getattr(sb.ctx(), ROOT_INODE, None);
    assert!(result.is_ok());
}

#[test]
fn test_init_registers_root() {
    let sb = OverlayTestSandbox::new();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), ROOT_INODE, None).unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(
        mode & libc::S_IFMT as u32,
        libc::S_IFDIR as u32,
        "root should be a directory"
    );
}

#[test]
fn test_destroy_clears_state() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("file.txt").unwrap();
    sb.fs.destroy();
    // After destroy, getattr should fail.
    let result = sb.fs.getattr(sb.ctx(), ROOT_INODE, None);
    assert!(result.is_err());
}

#[test]
fn test_init_flag_negotiation() {
    let tmp = tempfile::tempdir().unwrap();
    let lower = tmp.path().join("lower");
    let upper = tmp.path().join("upper");
    let state = tmp.path().join("state");
    std::fs::create_dir(&lower).unwrap();
    std::fs::create_dir(&upper).unwrap();
    std::fs::create_dir(&state).unwrap();
    let fs = OverlayFs::builder()
        .layer(&lower)
        .writable(&upper)
        .work_dir(&state)
        .build()
        .unwrap();
    let caps = FsOptions::ASYNC_READ | FsOptions::BIG_WRITES | FsOptions::HANDLE_KILLPRIV_V2;
    let opts = fs.init(caps).unwrap();
    assert!(opts.contains(FsOptions::ASYNC_READ));
    assert!(opts.contains(FsOptions::BIG_WRITES));
    assert!(opts.contains(FsOptions::HANDLE_KILLPRIV_V2));
}
