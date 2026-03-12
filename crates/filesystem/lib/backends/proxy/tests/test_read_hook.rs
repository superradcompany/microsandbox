use super::*;

#[test]
fn test_read_identity() {
    let sb = ProxyFsTestSandbox::with_read_transform(|_path, data| data.to_vec());
    let ino = sb
        .create_file_with_content(ROOT_INODE, "identity.txt", b"original data")
        .unwrap();
    let (handle, _opts) = sb.fuse_open(ino, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(ino, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"original data");
}

#[test]
fn test_read_transform_uppercase() {
    let sb = ProxyFsTestSandbox::with_read_transform(|_path, data| {
        data.iter()
            .map(|b| {
                if b.is_ascii_lowercase() {
                    b.to_ascii_uppercase()
                } else {
                    *b
                }
            })
            .collect()
    });
    let ino = sb
        .create_file_with_content(ROOT_INODE, "upper.txt", b"hello world")
        .unwrap();
    let (handle, _opts) = sb.fuse_open(ino, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(ino, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"HELLO WORLD");
}

#[test]
fn test_read_transform_expand() {
    // Double every byte.
    let sb = ProxyFsTestSandbox::with_read_transform(|_path, data| {
        let mut out = Vec::with_capacity(data.len() * 2);
        for &b in data {
            out.push(b);
            out.push(b);
        }
        out
    });
    let ino = sb
        .create_file_with_content(ROOT_INODE, "expand.txt", b"abc")
        .unwrap();
    let (handle, _opts) = sb.fuse_open(ino, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(ino, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"aabbcc");
}

#[test]
fn test_read_transform_shrink() {
    // Take only every other byte.
    let sb = ProxyFsTestSandbox::with_read_transform(|_path, data| {
        data.iter().step_by(2).copied().collect()
    });
    let ino = sb
        .create_file_with_content(ROOT_INODE, "shrink.txt", b"abcdef")
        .unwrap();
    let (handle, _opts) = sb.fuse_open(ino, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(ino, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"ace");
}

#[test]
fn test_read_transform_empty() {
    // Return empty from hook.
    let sb = ProxyFsTestSandbox::with_read_transform(|_path, _data| Vec::new());
    let ino = sb
        .create_file_with_content(ROOT_INODE, "empty.txt", b"some content")
        .unwrap();
    let (handle, _opts) = sb.fuse_open(ino, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(ino, handle, 4096, 0).unwrap();
    assert_eq!(data.len(), 0, "empty hook should return 0 bytes");
}

#[test]
fn test_read_hook_receives_path() {
    let sb = ProxyFsTestSandbox::with_read_log();
    let dir = sb.fuse_mkdir_root("subdir").unwrap();
    let _ino = sb
        .create_file_with_content(dir.inode, "nested.txt", b"content")
        .unwrap();
    // Need to lookup to register path since create_file_with_content does create+release.
    let entry = sb.lookup(dir.inode, "nested.txt").unwrap();
    let (handle, _opts) = sb
        .fuse_open(entry.inode, libc::O_RDONLY as u32)
        .unwrap();
    let handle = handle.unwrap();
    let _data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    let log = sb.read_log.lock().unwrap();
    assert!(
        log.iter().any(|(path, _)| path == "subdir/nested.txt"),
        "read hook should receive path 'subdir/nested.txt', got: {:?}",
        log.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn test_read_hook_receives_data() {
    let sb = ProxyFsTestSandbox::with_read_log();
    let ino = sb
        .create_file_with_content(ROOT_INODE, "data.txt", b"exact bytes")
        .unwrap();
    let (handle, _opts) = sb.fuse_open(ino, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let _data = sb.fuse_read(ino, handle, 4096, 0).unwrap();
    let log = sb.read_log.lock().unwrap();
    assert!(
        log.iter().any(|(_, data)| data == b"exact bytes"),
        "read hook should receive the actual data from inner"
    );
}

#[test]
fn test_read_no_hook_zero_copy() {
    // No on_read hook → zero-copy path, read should still work.
    let sb = ProxyFsTestSandbox::new();
    let ino = sb
        .create_file_with_content(ROOT_INODE, "zerocopy.txt", b"fast path data")
        .unwrap();
    let (handle, _opts) = sb.fuse_open(ino, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let data = sb.fuse_read(ino, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"fast path data");
}

#[test]
fn test_read_partial_offset() {
    let sb = ProxyFsTestSandbox::with_read_transform(|_path, data| data.to_vec());
    let ino = sb
        .create_file_with_content(ROOT_INODE, "offset.txt", b"0123456789")
        .unwrap();
    let (handle, _opts) = sb.fuse_open(ino, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    // Read 5 bytes starting at offset 3.
    let data = sb.fuse_read(ino, handle, 5, 3).unwrap();
    assert_eq!(&data[..], b"34567");
}
