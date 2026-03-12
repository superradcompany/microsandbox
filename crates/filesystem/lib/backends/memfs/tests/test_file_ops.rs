use super::*;

#[test]
fn test_read_basic() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("read_basic.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"hello world", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"hello world");
}

#[test]
fn test_read_partial() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("partial.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"hello world", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 5, 6).unwrap();
    assert_eq!(&data[..], b"world");
}

#[test]
fn test_read_beyond_eof() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("short.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"hi", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(data.len(), 2);
    assert_eq!(&data[..], b"hi");
}

#[test]
fn test_read_empty_file() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("empty.txt").unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn test_write_basic() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("write_basic.txt").unwrap();
    let handle = handle.unwrap();
    let n = sb.fuse_write(entry.inode, handle, b"content", 0).unwrap();
    assert_eq!(n, 7);
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"content");
}

#[test]
fn test_write_at_offset() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("offset.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 10).unwrap();
    let full = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(full.len(), 14);
    // First 10 bytes should be zeros.
    assert!(full[..10].iter().all(|&b| b == 0));
    assert_eq!(&full[10..], b"data");
}

#[test]
fn test_write_multiple() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("multi.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"hello ", 0).unwrap();
    sb.fuse_write(entry.inode, handle, b"world", 6).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"hello world");
}

#[test]
fn test_write_large() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("large.bin").unwrap();
    let handle = handle.unwrap();
    let big_data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    let n = sb.fuse_write(entry.inode, handle, &big_data, 0).unwrap();
    assert_eq!(n, big_data.len());
    let read_back = sb.fuse_read(entry.inode, handle, big_data.len() as u32, 0).unwrap();
    assert_eq!(read_back.len(), big_data.len());
    assert_eq!(&read_back[..], &big_data[..]);
}

#[test]
fn test_write_sparse() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("sparse.bin").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"end", 1000).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 2048, 0).unwrap();
    assert_eq!(data.len(), 1003);
    assert!(data[..1000].iter().all(|&b| b == 0));
    assert_eq!(&data[1000..], b"end");
}

#[test]
fn test_read_invalid_handle() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("nohandle.txt").unwrap();
    let result = sb.fuse_read(entry.inode, 999999, 1024, 0);
    MemFsTestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_write_invalid_handle() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("nohandle_w.txt").unwrap();
    let result = sb.fuse_write(entry.inode, 999999, b"data", 0);
    MemFsTestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_open_truncate() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("truncate.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"initial content", 0).unwrap();
    sb.fs
        .release(MemFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    // Open with O_TRUNC (use libc constant for platform portability).
    let (new_handle, _) = sb.fuse_open(entry.inode, libc::O_TRUNC as u32).unwrap();
    let new_handle = new_handle.unwrap();
    let data = sb.fuse_read(entry.inode, new_handle, 1024, 0).unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn test_open_directory_fails() {
    let sb = MemFsTestSandbox::new();
    let dir = sb.fuse_mkdir_root("noopen").unwrap();
    let result = sb.fuse_open(dir.inode, libc::O_RDONLY as u32);
    MemFsTestSandbox::assert_errno(result, LINUX_EISDIR);
}

#[test]
fn test_release_handle() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("release_test.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    sb.fs
        .release(MemFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // After release, using the old handle should fail.
    let result = sb.fuse_read(entry.inode, handle, 1024, 0);
    MemFsTestSandbox::assert_errno(result, LINUX_EBADF);
}

const LINUX_EFBIG: i32 = 27;

#[test]
fn test_write_efbig() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("efbig.txt").unwrap();
    let handle = handle.unwrap();

    // Writing at an offset that, combined with the data size, exceeds i64::MAX should fail.
    let huge_offset = i64::MAX as u64;
    let result = sb.fuse_write(entry.inode, handle, b"x", huge_offset);
    MemFsTestSandbox::assert_errno(result, LINUX_EFBIG);
}
