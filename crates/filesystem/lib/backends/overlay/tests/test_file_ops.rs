use super::*;

#[test]
fn test_read_lower_file() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("readme.txt"), b"hello from lower").unwrap();
    });
    let entry = sb.lookup_root("readme.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"hello from lower");
}

#[test]
fn test_write_upper_file() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("new.txt").unwrap();
    let written = sb.fuse_write(entry.inode, handle, b"hello", 0).unwrap();
    assert_eq!(written, 5);
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"hello");
}

#[test]
fn test_write_triggers_copy_up() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("lower_file.txt"), b"original").unwrap();
    });
    let entry = sb.lookup_root("lower_file.txt").unwrap();
    let handle = sb
        .fuse_open(entry.inode, libc::O_RDWR as u32)
        .unwrap();
    // Write triggers copy-up.
    sb.fuse_write(entry.inode, handle, b"modified", 0).unwrap();
    // File should now exist on upper.
    assert!(
        sb.upper_has_file("lower_file.txt"),
        "copy-up should create file on upper layer"
    );
}

#[test]
fn test_copy_up_preserves_data() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("data.txt"), b"preserve me").unwrap();
    });
    let entry = sb.lookup_root("data.txt").unwrap();
    // Read the original data first.
    let handle = sb
        .fuse_open(entry.inode, libc::O_RDONLY as u32)
        .unwrap();
    let original = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&original[..], b"preserve me");
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    // Open for write (triggers copy-up), then read back.
    let handle = sb
        .fuse_open(entry.inode, libc::O_RDWR as u32)
        .unwrap();
    // Write at offset 11 so original data is preserved.
    sb.fuse_write(entry.inode, handle, b" more", 11).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"preserve me more");
}

#[test]
fn test_write_after_copy_up() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file.txt"), b"old").unwrap();
    });
    let entry = sb.lookup_root("file.txt").unwrap();
    let handle = sb
        .fuse_open(entry.inode, libc::O_RDWR as u32)
        .unwrap();
    sb.fuse_write(entry.inode, handle, b"new data", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"new data");
}

#[test]
fn test_read_after_write() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("rw.txt").unwrap();
    let data = b"hello world 12345";
    sb.fuse_write(entry.inode, handle, data, 0).unwrap();
    let read_data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&read_data[..], data);
}

#[test]
fn test_large_write() {
    let sb = OverlayTestSandbox::new();
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
fn test_write_at_offset() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("offset.txt").unwrap();
    let data = b"offset_data";
    sb.fuse_write(entry.inode, handle, data, 100).unwrap();
    let read_data = sb
        .fuse_read(entry.inode, handle, data.len() as u32, 100)
        .unwrap();
    assert_eq!(&read_data[..], data);
}

#[test]
fn test_read_empty() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("empty.txt").unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn test_read_beyond_eof() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("small.txt").unwrap();
    sb.fuse_write(entry.inode, handle, &[0xBB; 10], 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 100).unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn test_flush_and_release() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("flush.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    sb.fs.flush(sb.ctx(), entry.inode, handle, 0).unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // After release, reading with the old handle should fail.
    let result = sb.fuse_read(entry.inode, handle, 1024, 0);
    OverlayTestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_open_invalid_handle() {
    let sb = OverlayTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let result = sb.fuse_read(entry.inode, 99999, 1024, 0);
    OverlayTestSandbox::assert_errno(result, LINUX_EBADF);
}
