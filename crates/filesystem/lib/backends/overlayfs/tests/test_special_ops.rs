use super::*;

#[test]
fn test_fsync() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("sync.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    let result = sb.fs.fsync(sb.ctx(), entry.inode, false, handle);
    assert!(result.is_ok());
}

#[test]
fn test_fsyncdir() {
    let sb = OverlayTestSandbox::new();
    let dir = sb.fuse_mkdir_root("syncdir").unwrap();
    let handle = sb.fuse_opendir(dir.inode).unwrap();
    let result = sb.fs.fsyncdir(sb.ctx(), dir.inode, false, handle);
    assert!(result.is_ok());
}

#[test]
fn test_fallocate() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("alloc.txt").unwrap();
    sb.fs
        .fallocate(sb.ctx(), entry.inode, handle, 0, 0, 1024)
        .unwrap();
    let (st, _) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert!(st.st_size >= 1024);
}

#[test]
fn test_lseek() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("seek.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"hello", 0).unwrap();
    // SEEK_SET = 0
    let offset = sb.fs.lseek(sb.ctx(), entry.inode, handle, 0, 0).unwrap();
    assert_eq!(offset, 0);
}

#[test]
fn test_statfs_root() {
    let sb = OverlayTestSandbox::new();
    let st = sb.fs.statfs(sb.ctx(), ROOT_INODE).unwrap();
    assert!(st.f_bsize > 0);
    assert!(st.f_blocks > 0);
}

#[test]
fn test_init_binary_read() {
    let sb = OverlayTestSandbox::new();
    let entry = sb.lookup_root("init.krun").unwrap();
    assert_eq!(entry.inode, INIT_INODE);
    let (handle, _opts) = sb
        .fs
        .open(sb.ctx(), INIT_INODE, false, libc::O_RDONLY as u32)
        .unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(INIT_INODE, handle, 4096, 0).unwrap();
    assert!(!data.is_empty(), "init binary should return data");
}
