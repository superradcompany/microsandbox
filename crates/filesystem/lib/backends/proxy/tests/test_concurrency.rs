use super::*;

#[test]
fn test_concurrent_reads_with_hook() {
    let sb = ProxyFsTestSandbox::with_read_transform(|_path, data| data.to_vec());
    let ino = sb
        .create_file_with_content(ROOT_INODE, "shared.txt", b"shared content")
        .unwrap();

    std::thread::scope(|s| {
        let sb = &sb;
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(s.spawn(move || {
                let (handle, _opts) = sb
                    .fuse_open(ino, libc::O_RDONLY as u32)
                    .unwrap();
                let handle = handle.unwrap();
                let data = sb.fuse_read(ino, handle, 4096, 0).unwrap();
                sb.fs
                    .release(
                        ProxyFsTestSandbox::ctx(),
                        ino,
                        0,
                        handle,
                        false,
                        false,
                        None,
                    )
                    .unwrap();
                data
            }));
        }
        for h in handles {
            let data = h.join().unwrap();
            assert_eq!(
                &data[..],
                b"shared content",
                "all concurrent readers should see the same data"
            );
        }
    });
}

#[test]
fn test_concurrent_writes_with_hook() {
    let sb = ProxyFsTestSandbox::with_write_transform(|_path, data| data.to_vec());

    std::thread::scope(|s| {
        let sb = &sb;
        let mut handles = Vec::new();
        for i in 0..8u8 {
            handles.push(s.spawn(move || {
                let name = format!("concurrent_{i}.txt");
                let (entry, handle) = sb.fuse_create_root(&name).unwrap();
                let handle = handle.unwrap();
                let data = vec![i; 100];
                let written = sb.fuse_write(entry.inode, handle, &data, 0).unwrap();
                assert_eq!(written, 100);
                // Read back.
                let read_data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
                assert_eq!(read_data, data, "each writer should read back its own data");
                sb.fs
                    .release(
                        ProxyFsTestSandbox::ctx(),
                        entry.inode,
                        0,
                        handle,
                        false,
                        false,
                        None,
                    )
                    .unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    });

    // Verify all files exist.
    for i in 0..8u8 {
        let name = format!("concurrent_{i}.txt");
        let entry = sb.lookup_root(&name).unwrap();
        assert!(entry.inode >= 3, "file {name} should exist");
    }
}

#[test]
fn test_concurrent_access_checks() {
    let access_count = Arc::new(Mutex::new(0u32));
    let count_clone = access_count.clone();
    let memfs = MemFs::builder().build().unwrap();
    let fs = ProxyFs::builder(Box::new(memfs))
        .on_access(move |_path, _mode| {
            *count_clone.lock().unwrap() += 1;
            Ok(())
        })
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let sb = ProxyFsTestSandbox {
        fs,
        access_log: Arc::new(Mutex::new(Vec::new())),
        read_log: Arc::new(Mutex::new(Vec::new())),
        write_log: Arc::new(Mutex::new(Vec::new())),
    };

    // Create 8 files first (each create calls the access hook).
    let mut inodes = Vec::new();
    for i in 0..8u8 {
        let name = format!("access_{i}.txt");
        let mode = libc::S_IFREG as u32 | 0o644;
        let entry = sb
            .fs
            .mknod(
                ProxyFsTestSandbox::ctx(),
                ROOT_INODE,
                &ProxyFsTestSandbox::cstr(&name),
                mode,
                0,
                0,
                Extensions::default(),
            )
            .unwrap();
        let _ = sb.lookup_root(&name).unwrap();
        inodes.push(entry.inode);
    }
    *access_count.lock().unwrap() = 0;

    std::thread::scope(|s| {
        let sb = &sb;
        let mut handles = Vec::new();
        for &ino in &inodes {
            handles.push(s.spawn(move || {
                let (handle, _opts) = sb
                    .fuse_open(ino, libc::O_RDONLY as u32)
                    .unwrap();
                let handle = handle.unwrap();
                sb.fs
                    .release(
                        ProxyFsTestSandbox::ctx(),
                        ino,
                        0,
                        handle,
                        false,
                        false,
                        None,
                    )
                    .unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    });

    let count = *access_count.lock().unwrap();
    assert_eq!(
        count, 8,
        "each open should call access hook exactly once, got {count}"
    );
}

#[test]
fn test_concurrent_path_tracking() {
    let sb = ProxyFsTestSandbox::with_access_log();

    // Create files and lookup them concurrently.
    std::thread::scope(|s| {
        let sb = &sb;
        // Half threads create+lookup files.
        for i in 0..8u32 {
            s.spawn(move || {
                let name = format!("tracked_{i}.txt");
                let mode = libc::S_IFREG as u32 | 0o644;
                let _ = sb.fs.mknod(
                    ProxyFsTestSandbox::ctx(),
                    ROOT_INODE,
                    &ProxyFsTestSandbox::cstr(&name),
                    mode,
                    0,
                    0,
                    Extensions::default(),
                );
                let _ = sb.lookup_root(&name);
            });
        }
    });

    // After concurrent operations, lookups should still work.
    for i in 0..8u32 {
        let name = format!("tracked_{i}.txt");
        let entry = sb.lookup_root(&name).unwrap();
        assert!(
            entry.inode >= 3,
            "file {name} should be discoverable after concurrent ops"
        );
    }

    // Concurrent forgets should not crash.
    let inodes: Vec<u64> = (0..8u32)
        .map(|i| {
            let name = format!("tracked_{i}.txt");
            sb.lookup_root(&name).unwrap().inode
        })
        .collect();

    std::thread::scope(|s| {
        let sb = &sb;
        for &ino in &inodes {
            s.spawn(move || {
                sb.fs.forget(ProxyFsTestSandbox::ctx(), ino, 1);
            });
        }
    });
    // Main assertion: no panic or deadlock.
}
