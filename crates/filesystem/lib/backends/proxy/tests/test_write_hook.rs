use super::*;

#[test]
fn test_write_identity() {
    let sb = ProxyFsTestSandbox::with_write_transform(|_path, data| data.to_vec());
    let (entry, handle) = sb.fuse_create_root("identity.txt").unwrap();
    let handle = handle.unwrap();
    let data = b"unchanged data";
    sb.fuse_write(entry.inode, handle, data, 0).unwrap();
    // Read back without a read hook — should get the original data.
    let read_data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&read_data[..], data);
}

#[test]
fn test_write_transform() {
    // Transform: uppercase all bytes.
    let sb = ProxyFsTestSandbox::with_write_transform(|_path, data| {
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
    let (entry, handle) = sb.fuse_create_root("transform.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"hello world", 0)
        .unwrap();
    // Read back — inner stored uppercased data.
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"HELLO WORLD");
}

#[test]
fn test_write_transform_expand() {
    // Transform: double every byte.
    let sb = ProxyFsTestSandbox::with_write_transform(|_path, data| {
        let mut out = Vec::with_capacity(data.len() * 2);
        for &b in data {
            out.push(b);
            out.push(b);
        }
        out
    });
    let (entry, handle) = sb.fuse_create_root("expand.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"abc", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"aabbcc");
}

#[test]
fn test_write_transform_shrink() {
    // Transform: take only every other byte.
    let sb = ProxyFsTestSandbox::with_write_transform(|_path, data| {
        data.iter().step_by(2).copied().collect()
    });
    let (entry, handle) = sb.fuse_create_root("shrink.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"abcdef", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"ace");
}

#[test]
fn test_write_return_value() {
    // Write hook expands data (doubles it), but return value should be the
    // number of bytes consumed from the guest's perspective (original length).
    let sb = ProxyFsTestSandbox::with_write_transform(|_path, data| {
        let mut out = Vec::with_capacity(data.len() * 2);
        for &b in data {
            out.push(b);
            out.push(b);
        }
        out
    });
    let (entry, handle) = sb.fuse_create_root("retval.txt").unwrap();
    let handle = handle.unwrap();
    let written = sb.fuse_write(entry.inode, handle, b"hello", 0).unwrap();
    assert_eq!(
        written, 5,
        "write should return guest bytes consumed (5), not transformed length (10)"
    );
}

#[test]
fn test_write_hook_receives_path() {
    let sb = ProxyFsTestSandbox::with_write_log();
    let dir = sb.fuse_mkdir_root("wdir").unwrap();
    let (entry, handle) = sb.fuse_create(dir.inode, "nested.txt", 0o644).unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"content", 0).unwrap();
    let log = sb.write_log.lock().unwrap();
    assert!(
        log.iter().any(|(path, _)| path == "wdir/nested.txt"),
        "write hook should receive path 'wdir/nested.txt', got: {:?}",
        log.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn test_write_hook_receives_data() {
    let sb = ProxyFsTestSandbox::with_write_log();
    let (entry, handle) = sb.fuse_create_root("data.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"guest data", 0)
        .unwrap();
    let log = sb.write_log.lock().unwrap();
    assert!(
        log.iter().any(|(_, data)| data == b"guest data"),
        "write hook should receive the guest's original data"
    );
}

#[test]
fn test_write_no_hook_zero_copy() {
    // No on_write hook → zero-copy path, write should still work.
    let sb = ProxyFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("zerocopy.txt").unwrap();
    let handle = handle.unwrap();
    let data = b"fast path write";
    let written = sb.fuse_write(entry.inode, handle, data, 0).unwrap();
    assert_eq!(written, data.len());
    let read_data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&read_data[..], data);
}
