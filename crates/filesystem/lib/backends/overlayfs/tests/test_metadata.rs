use super::*;

#[test]
fn test_getattr_upper_file() {
    let sb = OverlayTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("upper.txt").unwrap();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
}

#[test]
fn test_getattr_lower_file() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("lower.txt"), b"data").unwrap();
    });
    let entry = sb.lookup_root("lower.txt").unwrap();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
}

#[test]
fn test_getattr_root() {
    let sb = OverlayTestSandbox::new();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), ROOT_INODE, None).unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
}

#[test]
fn test_getattr_init() {
    let sb = OverlayTestSandbox::new();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), INIT_INODE, None).unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert!(st.st_size > 0, "init binary should have non-zero size");
}

#[test]
fn test_setattr_mode() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file.txt"), b"data").unwrap();
    });
    let entry = sb.lookup_root("file.txt").unwrap();
    let mut attr: crate::stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = 0o755;
    let (st, _) = sb
        .fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();
    assert_eq!(st.st_mode as u32 & 0o7777, 0o755);
    // Should have been copied up to upper.
    assert!(sb.upper_has_file("file.txt"));
}

#[test]
fn test_setattr_size_truncate() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("trunc.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"hello world", 0)
        .unwrap();
    let mut attr: crate::stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 5;
    sb.fs
        .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::SIZE)
        .unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(data.len(), 5);
    assert_eq!(&data[..], b"hello");
}

#[test]
fn test_setattr_timestamps() {
    let sb = OverlayTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("ts.txt").unwrap();
    let mut attr: crate::stat64 = unsafe { std::mem::zeroed() };
    attr.st_atime = 1000;
    attr.st_mtime = 2000;
    let (st, _) = sb
        .fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::ATIME | SetattrValid::MTIME,
        )
        .unwrap();
    assert_eq!(st.st_atime, 1000);
    assert_eq!(st.st_mtime, 2000);
}

#[test]
fn test_access_root() {
    let sb = OverlayTestSandbox::new();
    sb.fs
        .access(sb.ctx(), ROOT_INODE, libc::F_OK as u32)
        .unwrap();
}

#[test]
fn test_access_lower_file() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("accessible.txt"), b"data").unwrap();
    });
    let entry = sb.lookup_root("accessible.txt").unwrap();
    sb.fs
        .access(sb.ctx(), entry.inode, libc::F_OK as u32)
        .unwrap();
}

#[test]
fn test_statfs() {
    let sb = OverlayTestSandbox::new();
    let st = sb.fs.statfs(sb.ctx(), ROOT_INODE).unwrap();
    assert!(st.f_bsize > 0);
}
