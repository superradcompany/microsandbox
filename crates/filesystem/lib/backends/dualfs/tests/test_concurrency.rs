use super::*;

#[test]
fn test_concurrent_lookups_same_file() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "shared.txt", b"shared");
    });

    // Do one lookup first to register the dentry, then concurrent lookups
    // should all see the same guest inode.
    let first = sb.lookup_root("shared.txt").unwrap();

    std::thread::scope(|s| {
        let sb = &sb;
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(s.spawn(move || sb.lookup_root("shared.txt").unwrap()));
        }
        let inodes: Vec<u64> = handles
            .into_iter()
            .map(|h| h.join().unwrap().inode)
            .collect();
        // All should get the same guest inode as the first lookup.
        assert!(
            inodes.iter().all(|&i| i == first.inode),
            "all lookups should return same guest inode"
        );
    });
}

#[test]
fn test_concurrent_materialization() {
    let sb = DualFsTestSandbox::with_backend_b(|b| {
        memfs_create_file(b, 1, "race.txt", b"concurrent data");
    });
    let entry = sb.lookup_root("race.txt").unwrap();
    let inode = entry.inode;

    std::thread::scope(|s| {
        let sb = &sb;
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(s.spawn(move || sb.fuse_open(inode, libc::O_RDWR as u32)));
        }
        for h in handles {
            let result = h.join().unwrap();
            if let Ok(handle) = result {
                sb.fs
                    .release(
                        DualFsTestSandbox::ctx(),
                        inode,
                        0,
                        handle,
                        false,
                        false,
                        None,
                    )
                    .unwrap();
            }
        }
    });

    // File should still be readable.
    let handle = sb.fuse_open(inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"concurrent data");
    sb.fs
        .release(
            DualFsTestSandbox::ctx(),
            inode,
            0,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
}

#[test]
fn test_concurrent_creates_different_files() {
    let sb = DualFsTestSandbox::new();

    std::thread::scope(|s| {
        let sb = &sb;
        let mut handles = Vec::new();
        for i in 0..8 {
            handles.push(s.spawn(move || {
                let name = format!("concurrent_{i}.txt");
                sb.fuse_create_root(&name).unwrap()
            }));
        }
        let inodes: Vec<u64> = handles
            .into_iter()
            .map(|h| {
                let (entry, handle) = h.join().unwrap();
                sb.fs
                    .release(
                        DualFsTestSandbox::ctx(),
                        entry.inode,
                        0,
                        handle,
                        false,
                        false,
                        None,
                    )
                    .unwrap();
                entry.inode
            })
            .collect();
        // All inodes should be unique.
        let mut sorted = inodes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), inodes.len(), "all inodes should be unique");
    });

    // Verify all files exist.
    for i in 0..8 {
        let name = format!("concurrent_{i}.txt");
        let entry = sb.lookup_root(&name).unwrap();
        assert!(
            entry.inode >= 3,
            "created file {name} should be discoverable"
        );
    }
}

#[test]
fn test_concurrent_readdir_during_create() {
    let sb = DualFsTestSandbox::new();

    std::thread::scope(|s| {
        let sb = &sb;
        // Thread A: readdir loop.
        s.spawn(move || {
            for _ in 0..5 {
                if let Ok(handle) = sb.fuse_opendir(ROOT_INODE) {
                    let _ = sb
                        .fs
                        .readdir(DualFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 0);
                    let _ = sb
                        .fs
                        .releasedir(DualFsTestSandbox::ctx(), ROOT_INODE, 0, handle);
                }
            }
        });
        // Thread B: create files.
        for i in 0..5 {
            s.spawn(move || {
                let name = format!("conc_create_{i}.txt");
                let _ = sb.fuse_create_root(&name);
            });
        }
    });

    // After all creates, every file should be discoverable.
    for i in 0..5 {
        let name = format!("conc_create_{i}.txt");
        let entry = sb.lookup_root(&name).unwrap();
        assert!(
            entry.inode >= 3,
            "created file {name} should be discoverable after concurrent readdir"
        );
    }
}

#[test]
fn test_concurrent_policy_plan() {
    // Verify that calling policy.plan() concurrently doesn't crash.
    let sb = DualFsTestSandbox::new();
    // Create some files first.
    for i in 0..4 {
        sb.create_file_with_content(ROOT_INODE, &format!("pre_{i}.txt"), b"data")
            .unwrap();
    }

    std::thread::scope(|s| {
        let sb = &sb;
        for i in 0..8 {
            s.spawn(move || {
                // Each thread does lookup (which invokes policy.plan()).
                let name = format!("pre_{}.txt", i % 4);
                let _ = sb.lookup_root(&name);
            });
        }
    });

    // No crash or deadlock means success.
    let entry = sb.lookup_root("pre_0.txt").unwrap();
    assert!(
        entry.inode >= 3,
        "filesystem should be functional after concurrent plans"
    );
}
