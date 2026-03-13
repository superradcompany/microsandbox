use super::*;

#[test]
fn test_roundtrip_identity() {
    let sb = ProxyFsTestSandbox::with_read_write_transforms(
        |_path, data| data.to_vec(),
        |_path, data| data.to_vec(),
    );
    let (entry, handle) = sb.fuse_create_root("identity.txt").unwrap();
    let handle = handle.unwrap();
    let original = b"roundtrip identity data";
    sb.fuse_write(entry.inode, handle, original, 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], original);
}

#[test]
fn test_roundtrip_xor_cipher() {
    let key = 0x42u8;
    let sb = ProxyFsTestSandbox::with_read_write_transforms(
        // on_read: XOR to decrypt.
        move |_path, data| data.iter().map(|b| b ^ key).collect(),
        // on_write: XOR to encrypt.
        move |_path, data| data.iter().map(|b| b ^ key).collect(),
    );
    let (entry, handle) = sb.fuse_create_root("xor.txt").unwrap();
    let handle = handle.unwrap();
    let original = b"secret message";
    sb.fuse_write(entry.inode, handle, original, 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(
        &data[..],
        original,
        "XOR encrypt on write + XOR decrypt on read should recover original"
    );
}

#[test]
fn test_roundtrip_byte_shift() {
    // Simulate a simple "encoding": shift every byte up by 1 on write,
    // shift down by 1 on read.
    let sb = ProxyFsTestSandbox::with_read_write_transforms(
        // on_read: shift down (decode).
        |_path, data| data.iter().map(|b| b.wrapping_sub(1)).collect(),
        // on_write: shift up (encode).
        |_path, data| data.iter().map(|b| b.wrapping_add(1)).collect(),
    );
    let (entry, handle) = sb.fuse_create_root("shift.txt").unwrap();
    let handle = handle.unwrap();
    let original = b"hello shift cipher";
    sb.fuse_write(entry.inode, handle, original, 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(
        &data[..],
        original,
        "shift encode on write + shift decode on read should recover original"
    );
}

#[test]
fn test_roundtrip_compress_decompress() {
    // Simple RLE-like transform: on write, replace runs of same byte with
    // (byte, count). On read, expand back. Limited to counts < 256.
    fn rle_encode(_path: &str, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let b = data[i];
            let mut count = 1u8;
            while i + (count as usize) < data.len() && data[i + count as usize] == b && count < 255
            {
                count += 1;
            }
            out.push(b);
            out.push(count);
            i += count as usize;
        }
        out
    }

    fn rle_decode(_path: &str, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 1 < data.len() {
            let b = data[i];
            let count = data[i + 1];
            for _ in 0..count {
                out.push(b);
            }
            i += 2;
        }
        out
    }

    let sb = ProxyFsTestSandbox::with_read_write_transforms(rle_decode, rle_encode);
    let (entry, handle) = sb.fuse_create_root("rle.txt").unwrap();
    let handle = handle.unwrap();
    let original = b"aaabbccccdddddd";
    sb.fuse_write(entry.inode, handle, original, 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(
        &data[..],
        &original[..],
        "RLE encode/decode roundtrip should recover original"
    );
}

#[test]
fn test_roundtrip_partial_read() {
    let sb = ProxyFsTestSandbox::with_read_write_transforms(
        |_path, data| data.to_vec(),
        |_path, data| data.to_vec(),
    );
    let (entry, handle) = sb.fuse_create_root("partial.txt").unwrap();
    let handle = handle.unwrap();
    let original = b"0123456789abcdef";
    sb.fuse_write(entry.inode, handle, original, 0).unwrap();
    // Read only 4 bytes from offset 4.
    let data = sb.fuse_read(entry.inode, handle, 4, 4).unwrap();
    assert_eq!(&data[..], b"4567");
}

#[test]
fn test_inner_stores_transformed() {
    // Verify that the inner backend received the transformed data.
    // We use a write_log to capture what was written (the hook returns the same
    // transformed data, so inner stores it).
    let write_log = Arc::new(Mutex::new(Vec::new()));
    let write_log_clone = write_log.clone();

    let memfs = MemFs::builder().build().unwrap();
    let fs = ProxyFs::builder(Box::new(memfs))
        .on_write(move |path, data| {
            // Transform: XOR with 0xFF.
            let transformed: Vec<u8> = data.iter().map(|b| b ^ 0xFF).collect();
            write_log_clone
                .lock()
                .unwrap()
                .push((path.to_string(), transformed.clone()));
            transformed
        })
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let sb = ProxyFsTestSandbox {
        fs,
        access_log: Arc::new(Mutex::new(Vec::new())),
        read_log: Arc::new(Mutex::new(Vec::new())),
        write_log: write_log.clone(),
    };

    let (entry, handle) = sb.fuse_create_root("transformed.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"hello", 0).unwrap();

    // The write_log recorded the transformed data.
    let log = write_log.lock().unwrap();
    let expected_transformed: Vec<u8> = b"hello".iter().map(|b| b ^ 0xFF).collect();
    assert!(
        log.iter().any(|(_, data)| *data == expected_transformed),
        "inner should store XOR-transformed data"
    );

    // Read back without on_read hook — should get the transformed data.
    let read_data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(
        read_data, expected_transformed,
        "reading without on_read should return inner's transformed data"
    );
}
