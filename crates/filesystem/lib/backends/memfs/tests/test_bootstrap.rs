use std::sync::atomic::Ordering;

use super::*;

#[test]
fn test_build_default() {
    let fs = MemFs::builder().build().unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let (st, _) = fs.getattr(MemFsTestSandbox::ctx(), ROOT_INODE, None).unwrap();
    assert_eq!(st.st_mode as u32 & libc::S_IFMT as u32, libc::S_IFDIR as u32);
}

#[test]
fn test_build_with_capacity() {
    let fs = MemFs::builder().capacity(1024 * 1024).build().unwrap();
    assert_eq!(fs.cfg.capacity, Some(1024 * 1024));
}

#[test]
fn test_build_with_max_inodes() {
    let fs = MemFs::builder().max_inodes(500).build().unwrap();
    assert_eq!(fs.cfg.max_inodes, Some(500));
}

#[test]
fn test_build_with_cache_policy_never() {
    let fs = MemFs::builder()
        .cache_policy(CachePolicy::Never)
        .build()
        .unwrap();
    assert_eq!(fs.cfg.cache_policy, CachePolicy::Never);
}

#[test]
fn test_build_with_cache_policy_auto() {
    let fs = MemFs::builder()
        .cache_policy(CachePolicy::Auto)
        .build()
        .unwrap();
    assert_eq!(fs.cfg.cache_policy, CachePolicy::Auto);
}

#[test]
fn test_build_with_cache_policy_always() {
    let fs = MemFs::builder()
        .cache_policy(CachePolicy::Always)
        .build()
        .unwrap();
    assert_eq!(fs.cfg.cache_policy, CachePolicy::Always);
}

#[test]
fn test_init_negotiates_features() {
    let fs = MemFs::builder().build().unwrap();
    let caps = FsOptions::ASYNC_READ | FsOptions::BIG_WRITES | FsOptions::HANDLE_KILLPRIV_V2;
    let opts = fs.init(caps).unwrap();
    assert!(opts.contains(FsOptions::ASYNC_READ));
    assert!(opts.contains(FsOptions::BIG_WRITES));
    assert!(opts.contains(FsOptions::HANDLE_KILLPRIV_V2));
}

#[test]
fn test_init_writeback() {
    let fs = MemFs::builder().writeback(true).build().unwrap();
    let opts = fs.init(FsOptions::WRITEBACK_CACHE).unwrap();
    assert!(opts.contains(FsOptions::WRITEBACK_CACHE));
    assert!(fs.writeback.load(Ordering::Relaxed));
}

#[test]
fn test_init_no_writeback() {
    let fs = MemFs::builder().writeback(false).build().unwrap();
    let opts = fs.init(FsOptions::WRITEBACK_CACHE).unwrap();
    assert!(!opts.contains(FsOptions::WRITEBACK_CACHE));
    assert!(!fs.writeback.load(Ordering::Relaxed));
}

#[test]
fn test_root_exists_after_init() {
    let sb = MemFsTestSandbox::new();
    let (st, _) = sb.fs.getattr(MemFsTestSandbox::ctx(), ROOT_INODE, None).unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
    assert_eq!(mode & 0o777, 0o755);
    assert_eq!(st.st_uid, 0);
    assert_eq!(st.st_gid, 0);
}

#[test]
fn test_root_nlink() {
    let sb = MemFsTestSandbox::new();
    let (st, _) = sb.fs.getattr(MemFsTestSandbox::ctx(), ROOT_INODE, None).unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(st.st_nlink, 2);
    #[cfg(target_os = "macos")]
    assert_eq!(st.st_nlink, 2);
}
