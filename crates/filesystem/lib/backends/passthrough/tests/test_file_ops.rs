use super::*;

#[test]
fn test_open_rdonly() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    assert!(handle > 0);
}

#[test]
fn test_open_rdwr() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDWR as u32).unwrap();
    assert!(handle > 0);
}

#[test]
fn test_write_read_roundtrip() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("rw.txt").unwrap();
    let data = b"hello world 12345";
    let written = sb.fuse_write(entry.inode, handle, data, 0).unwrap();
    assert_eq!(written, data.len());
    let read_data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&read_data[..], data);
}

#[test]
fn test_write_at_offset() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("offset.txt").unwrap();
    let data = b"offset_data";
    sb.fuse_write(entry.inode, handle, data, 100).unwrap();
    let read_data = sb
        .fuse_read(entry.inode, handle, data.len() as u32, 100)
        .unwrap();
    assert_eq!(&read_data[..], data);
}

#[test]
fn test_read_empty_file() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("empty.txt").unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn test_read_beyond_eof() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("small.txt").unwrap();
    sb.fuse_write(entry.inode, handle, &[0xBB; 10], 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 100).unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn test_read_partial() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("partial.txt").unwrap();
    let full_data: Vec<u8> = (0..100u8).collect();
    sb.fuse_write(entry.inode, handle, &full_data, 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 10, 0).unwrap();
    assert_eq!(data.len(), 10);
    assert_eq!(&data[..], &full_data[..10]);
}

#[test]
fn test_multiple_writes() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("multi.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"aaaaaaaaaa", 0)
        .unwrap();
    sb.fuse_write(entry.inode, handle, b"bbbbbbbbbb", 10)
        .unwrap();
    let data = sb.fuse_read(entry.inode, handle, 20, 0).unwrap();
    assert_eq!(data.len(), 20);
    assert_eq!(&data[..10], b"aaaaaaaaaa");
    assert_eq!(&data[10..], b"bbbbbbbbbb");
}

#[test]
fn test_large_write() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("large.txt").unwrap();
    let data = vec![0xCCu8; 1_000_000];
    let written = sb.fuse_write(entry.inode, handle, &data, 0).unwrap();
    assert_eq!(written, data.len());
    let read_data = sb
        .fuse_read(entry.inode, handle, data.len() as u32, 0)
        .unwrap();
    assert_eq!(read_data.len(), data.len());
    assert_eq!(read_data, data);
}

#[test]
fn test_write_init_rejected() {
    let sb = TestSandbox::new();
    let mut reader = MockZeroCopyReader::new(vec![0u8; 10]);
    let result = sb.fs.write(
        sb.ctx(),
        INIT_INODE,
        INIT_HANDLE,
        &mut reader,
        10,
        0,
        None,
        false,
        false,
        0,
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_read_invalid_handle() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let result = sb.fuse_read(entry.inode, 99999, 1024, 0);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_write_invalid_handle() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let result = sb.fuse_write(entry.inode, 99999, b"data", 0);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_flush() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("flush.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    let result = sb.fs.flush(sb.ctx(), entry.inode, handle, 0);
    assert!(result.is_ok());
}

#[test]
fn test_flush_init_noop() {
    let sb = TestSandbox::new();
    let result = sb.fs.flush(sb.ctx(), INIT_INODE, INIT_HANDLE, 0);
    assert!(result.is_ok());
}

#[test]
fn test_release_removes_handle() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("release.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // After release, reading with the old handle should fail.
    let result = sb.fuse_read(entry.inode, handle, 1024, 0);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_open_host_file() {
    let sb = TestSandbox::new();
    sb.host_create_file("hostfile.txt", b"host content");
    let entry = sb.lookup_root("hostfile.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"host content");
}
