use super::*;

#[test]
fn test_concurrent_lookups() {
    let sb = TestSandbox::new();
    sb.host_create_file("shared.txt", b"shared");

    std::thread::scope(|s| {
        let sb = &sb;
        let mut handles = Vec::new();
        for _ in 0..10 {
            handles.push(s.spawn(move || sb.lookup_root("shared.txt").unwrap()));
        }
        let inodes: Vec<u64> = handles
            .into_iter()
            .map(|h| h.join().unwrap().inode)
            .collect();
        // All should get the same inode.
        assert!(
            inodes.iter().all(|&i| i == inodes[0]),
            "all lookups should return same inode"
        );
    });
}

#[test]
fn test_concurrent_creates() {
    let sb = TestSandbox::new();

    std::thread::scope(|s| {
        let sb = &sb;
        let mut handles = Vec::new();
        for i in 0..10 {
            handles.push(s.spawn(move || {
                let name = format!("concurrent_{i}.txt");
                sb.fuse_create_root(&name).unwrap()
            }));
        }
        let inodes: Vec<u64> = handles
            .into_iter()
            .map(|h| h.join().unwrap().0.inode)
            .collect();
        // All inodes should be unique.
        let mut sorted = inodes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), inodes.len(), "all inodes should be unique");
    });
}

#[test]
fn test_concurrent_lookup_forget() {
    let sb = TestSandbox::new();
    sb.host_create_file("contested.txt", b"data");

    std::thread::scope(|s| {
        let sb = &sb;
        // Half threads do lookups, half do forgets.
        for _ in 0..5 {
            s.spawn(move || {
                let _ = sb.lookup_root("contested.txt");
            });
        }
        for _ in 0..5 {
            s.spawn(move || {
                if let Ok(entry) = sb.lookup_root("contested.txt") {
                    sb.fs.forget(sb.ctx(), entry.inode, 1);
                }
            });
        }
    });

    // After concurrent lookup/forget, a fresh lookup must still succeed
    // (the file exists on disk, so a new inode can always be allocated).
    let entry = sb.lookup_root("contested.txt").unwrap();
    assert!(
        entry.inode >= 3,
        "file should still be discoverable after concurrent forget"
    );
}

#[test]
fn test_concurrent_read_write() {
    let sb = TestSandbox::new();
    let (entry, _) = sb.fuse_create_root("rw.txt").unwrap();
    let inode = entry.inode;

    std::thread::scope(|s| {
        let sb = &sb;
        // Writers: each writes 100 bytes of its own value at a unique offset.
        for i in 0..5u64 {
            s.spawn(move || {
                let handle = sb.fuse_open(inode, libc::O_RDWR as u32).unwrap();
                let data = vec![i as u8; 100];
                let written = sb.fuse_write(inode, handle, &data, i * 100).unwrap();
                assert_eq!(written, 100, "each writer should write exactly 100 bytes");
                sb.fs
                    .release(sb.ctx(), inode, 0, handle, false, false, None)
                    .unwrap();
            });
        }
        // Readers
        for _ in 0..5 {
            s.spawn(move || {
                let handle = sb.fuse_open(inode, libc::O_RDONLY as u32).unwrap();
                let _ = sb.fuse_read(inode, handle, 4096, 0);
                sb.fs
                    .release(sb.ctx(), inode, 0, handle, false, false, None)
                    .unwrap();
            });
        }
    });

    // After all writers finish, the file should contain all 500 bytes.
    // Each 100-byte region should be filled with the writer's byte value.
    let handle = sb.fuse_open(inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(inode, handle, 4096, 0).unwrap();
    assert_eq!(data.len(), 500, "file should be 500 bytes after 5 writers");
    for i in 0..5u64 {
        let region = &data[(i * 100) as usize..((i + 1) * 100) as usize];
        assert!(
            region.iter().all(|&b| b == i as u8),
            "region {i} should be all {i}-bytes, got {:?}",
            &region[..4]
        );
    }
    sb.fs
        .release(sb.ctx(), inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn test_concurrent_readdir_create() {
    let sb = TestSandbox::new();

    std::thread::scope(|s| {
        let sb = &sb;
        // One thread reads the directory.
        s.spawn(move || {
            for _ in 0..5 {
                if let Ok(handle) = sb.fuse_opendir(ROOT_INODE) {
                    let _ = sb.fs.readdir(sb.ctx(), ROOT_INODE, handle, 65536, 0);
                    let _ = sb.fs.releasedir(sb.ctx(), ROOT_INODE, 0, handle);
                }
            }
        });
        // Other threads create files.
        for i in 0..5 {
            s.spawn(move || {
                let name = format!("conc_dir_{i}.txt");
                let _ = sb.fuse_create_root(&name);
            });
        }
    });

    // After all creates complete, every file should be discoverable via lookup.
    for i in 0..5 {
        let name = format!("conc_dir_{i}.txt");
        let entry = sb.lookup_root(&name).unwrap();
        assert!(
            entry.inode >= 3,
            "created file {name} should be discoverable"
        );
    }
}

#[test]
fn test_concurrent_open_release() {
    let sb = TestSandbox::new();
    let (entry, initial_handle) = sb.fuse_create_root("shared.txt").unwrap();
    let inode = entry.inode;
    sb.fuse_write(inode, initial_handle, b"shared_content", 0)
        .unwrap();
    sb.fs
        .release(sb.ctx(), inode, 0, initial_handle, false, false, None)
        .unwrap();

    std::thread::scope(|s| {
        let sb = &sb;
        for _ in 0..10 {
            s.spawn(move || {
                let handle = sb.fuse_open(inode, libc::O_RDONLY as u32).unwrap();
                let data = sb.fuse_read(inode, handle, 1024, 0).unwrap();
                // Every reader should see the same content — no stale or corrupt data.
                assert_eq!(
                    &data[..],
                    b"shared_content",
                    "concurrent reader got wrong data"
                );
                sb.fs
                    .release(sb.ctx(), inode, 0, handle, false, false, None)
                    .unwrap();
            });
        }
    });

    // After all open/release cycles, the file should still be readable.
    let handle = sb.fuse_open(inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(inode, handle, 1024, 0).unwrap();
    assert_eq!(
        &data[..],
        b"shared_content",
        "file should be intact after concurrent open/release"
    );
    sb.fs
        .release(sb.ctx(), inode, 0, handle, false, false, None)
        .unwrap();
}
