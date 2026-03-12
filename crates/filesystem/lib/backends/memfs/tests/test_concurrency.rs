use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::*;

#[test]
fn test_concurrent_writes_same_file() {
    let sb = Arc::new(MemFsTestSandbox::new());
    let (entry, handle) = sb.fuse_create_root("concurrent_w.txt").unwrap();
    let handle = handle.unwrap();
    let ino = entry.inode;

    std::thread::scope(|s| {
        for i in 0..8u64 {
            let sb = &sb;
            s.spawn(move || {
                let data = vec![i as u8; 100];
                sb.fuse_write(ino, handle, &data, i * 100).unwrap();
            });
        }
    });

    // File should be 800 bytes with no corruption.
    let data = sb.fuse_read(ino, handle, 4096, 0).unwrap();
    assert_eq!(data.len(), 800);
    // Each 100-byte region should be filled with its writer's byte value.
    for i in 0..8u64 {
        let region = &data[(i * 100) as usize..((i + 1) * 100) as usize];
        assert!(
            region.iter().all(|&b| b == i as u8),
            "region {i} corrupted"
        );
    }
}

#[test]
fn test_concurrent_creates_same_dir() {
    let sb = Arc::new(MemFsTestSandbox::new());

    std::thread::scope(|s| {
        for i in 0..8 {
            let sb = &sb;
            s.spawn(move || {
                let name = format!("conc_file_{i}.txt");
                sb.fuse_create_root(&name).unwrap();
            });
        }
    });

    // All 8 files should exist.
    for i in 0..8 {
        let name = format!("conc_file_{i}.txt");
        let entry = sb.lookup_root(&name).unwrap();
        assert!(entry.inode >= 3, "file {name} should exist");
    }
}

#[test]
fn test_concurrent_readdir_during_create() {
    let sb = Arc::new(MemFsTestSandbox::new());

    std::thread::scope(|s| {
        let sb_ref = &sb;
        // Reader thread.
        s.spawn(move || {
            for _ in 0..5 {
                let _ = sb_ref.readdir_names(ROOT_INODE);
            }
        });
        // Creator threads.
        for i in 0..8 {
            let sb_ref = &sb;
            s.spawn(move || {
                let name = format!("conc_rd_{i}.txt");
                let _ = sb_ref.fuse_create_root(&name);
            });
        }
    });

    // After all creates, all files should be discoverable.
    for i in 0..8 {
        let name = format!("conc_rd_{i}.txt");
        let entry = sb.lookup_root(&name).unwrap();
        assert!(entry.inode >= 3, "file {name} should exist");
    }
}

#[test]
fn test_concurrent_forget_lookup() {
    let sb = Arc::new(MemFsTestSandbox::new());
    let (entry, handle) = sb.fuse_create_root("contested.txt").unwrap();
    let handle = handle.unwrap();
    sb.fs
        .release(MemFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    std::thread::scope(|s| {
        let sb_ref = &sb;
        // Lookup threads.
        for _ in 0..4 {
            s.spawn(move || {
                let _ = sb_ref.lookup_root("contested.txt");
            });
        }
        // Forget threads.
        for _ in 0..4 {
            let ino = entry.inode;
            s.spawn(move || {
                sb_ref.fs.forget(MemFsTestSandbox::ctx(), ino, 1);
            });
        }
    });

    // File is still linked, so lookup should succeed regardless of forgets.
    let result = sb.lookup_root("contested.txt");
    assert!(result.is_ok());
}

#[test]
fn test_concurrent_capacity_accounting() {
    let sb = Arc::new(MemFsTestSandbox::with_capacity(1024 * 1024));

    std::thread::scope(|s| {
        for i in 0..8 {
            let sb_ref = &sb;
            s.spawn(move || {
                let name = format!("cap_conc_{i}.txt");
                let _ = sb_ref.create_file_with_content(ROOT_INODE, &name, &[0u8; 1024]);
            });
        }
    });

    let used = sb.fs.used_bytes.load(Ordering::Relaxed);
    assert_eq!(used, 8 * 1024, "used_bytes should be exactly 8 * 1024");
}
