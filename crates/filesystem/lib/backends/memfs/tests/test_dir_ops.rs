use super::*;

#[test]
fn test_readdir_basic() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_create_root("file1.txt").unwrap();
    sb.fuse_create_root("file2.txt").unwrap();
    sb.fuse_mkdir_root("subdir").unwrap();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(names.contains(&".".to_string()));
    assert!(names.contains(&"..".to_string()));
    assert!(names.contains(&"file1.txt".to_string()));
    assert!(names.contains(&"file2.txt".to_string()));
    assert!(names.contains(&"subdir".to_string()));
    assert!(names.contains(&"init.krun".to_string()));
}

#[test]
fn test_readdir_empty() {
    let sb = MemFsTestSandbox::new();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    // Root should have ., .., and init.krun.
    assert!(names.contains(&".".to_string()));
    assert!(names.contains(&"..".to_string()));
    assert!(names.contains(&"init.krun".to_string()));
}

#[test]
fn test_readdir_types() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_create_root("reg.txt").unwrap();
    sb.fuse_mkdir_root("dir").unwrap();
    sb.fs.symlink(
        MemFsTestSandbox::ctx(),
        &MemFsTestSandbox::cstr("/target"),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("link"),
        Extensions::default(),
    ).unwrap();

    let (handle, _) = sb.fuse_opendir(ROOT_INODE).unwrap();
    let handle = handle.unwrap();
    let entries = sb.fs.readdir(MemFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 0).unwrap();

    for e in &entries {
        let name = String::from_utf8_lossy(e.name).to_string();
        match name.as_str() {
            "reg.txt" => assert_eq!(e.type_, libc::DT_REG as u32),
            "dir" => assert_eq!(e.type_, libc::DT_DIR as u32),
            "link" => assert_eq!(e.type_, libc::DT_LNK as u32),
            "." | ".." => assert_eq!(e.type_, libc::DT_DIR as u32),
            "init.krun" => assert_eq!(e.type_, libc::DT_REG as u32),
            _ => {}
        }
    }
    sb.fs.releasedir(MemFsTestSandbox::ctx(), ROOT_INODE, 0, handle).unwrap();
}

#[test]
fn test_readdir_special_types() {
    let sb = MemFsTestSandbox::new();
    sb.fs.mknod(
        MemFsTestSandbox::ctx(), ROOT_INODE, &MemFsTestSandbox::cstr("fifo"),
        libc::S_IFIFO as u32 | 0o644, 0, 0, Extensions::default(),
    ).unwrap();
    sb.fs.mknod(
        MemFsTestSandbox::ctx(), ROOT_INODE, &MemFsTestSandbox::cstr("sock"),
        libc::S_IFSOCK as u32 | 0o644, 0, 0, Extensions::default(),
    ).unwrap();
    sb.fs.mknod(
        MemFsTestSandbox::ctx(), ROOT_INODE, &MemFsTestSandbox::cstr("blk"),
        libc::S_IFBLK as u32 | 0o660, 42, 0, Extensions::default(),
    ).unwrap();
    sb.fs.mknod(
        MemFsTestSandbox::ctx(), ROOT_INODE, &MemFsTestSandbox::cstr("chr"),
        libc::S_IFCHR as u32 | 0o660, 99, 0, Extensions::default(),
    ).unwrap();

    let (handle, _) = sb.fuse_opendir(ROOT_INODE).unwrap();
    let handle = handle.unwrap();
    let entries = sb.fs.readdir(MemFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 0).unwrap();

    for e in &entries {
        let name = String::from_utf8_lossy(e.name).to_string();
        match name.as_str() {
            "fifo" => assert_eq!(e.type_, libc::DT_FIFO as u32),
            "sock" => assert_eq!(e.type_, libc::DT_SOCK as u32),
            "blk" => assert_eq!(e.type_, libc::DT_BLK as u32),
            "chr" => assert_eq!(e.type_, libc::DT_CHR as u32),
            _ => {}
        }
    }
    sb.fs.releasedir(MemFsTestSandbox::ctx(), ROOT_INODE, 0, handle).unwrap();
}

#[test]
fn test_readdir_offset() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_create_root("a.txt").unwrap();
    sb.fuse_create_root("b.txt").unwrap();
    sb.fuse_create_root("c.txt").unwrap();

    let (handle, _) = sb.fuse_opendir(ROOT_INODE).unwrap();
    let handle = handle.unwrap();

    // Get all entries.
    let all = sb.fs.readdir(MemFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 0).unwrap();
    assert!(all.len() >= 3);

    // Read from offset 2 (skip first 2 entries).
    let from_offset = sb.fs.readdir(MemFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 2).unwrap();
    assert!(from_offset.len() < all.len());

    sb.fs.releasedir(MemFsTestSandbox::ctx(), ROOT_INODE, 0, handle).unwrap();
}

#[test]
fn test_readdir_large_directory() {
    let sb = MemFsTestSandbox::new();
    for i in 0..1000 {
        let name = format!("file_{i:04}.txt");
        sb.fuse_create_root(&name).unwrap();
    }
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    // Should have 1000 files + "." + ".." + "init.krun" = 1003.
    assert_eq!(names.len(), 1003);
    for i in 0..1000 {
        let name = format!("file_{i:04}.txt");
        assert!(names.contains(&name), "missing entry: {}", name);
    }
}

#[test]
fn test_readdir_snapshot_immutable() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_create_root("before.txt").unwrap();

    // Open dir handle and trigger snapshot.
    let (handle, _) = sb.fuse_opendir(ROOT_INODE).unwrap();
    let handle = handle.unwrap();
    let entries_before = sb.fs.readdir(MemFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 0).unwrap();

    // Now create another file.
    sb.fuse_create_root("after.txt").unwrap();

    // Readdir with same handle should return same snapshot (no "after.txt").
    let entries_after = sb.fs.readdir(MemFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 0).unwrap();
    assert_eq!(entries_before.len(), entries_after.len());

    sb.fs.releasedir(MemFsTestSandbox::ctx(), ROOT_INODE, 0, handle).unwrap();
}

#[test]
fn test_readdirplus_basic() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_create_root("plus.txt").unwrap();

    let (handle, _) = sb.fuse_opendir(ROOT_INODE).unwrap();
    let handle = handle.unwrap();
    let entries = sb.fs.readdirplus(MemFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 0).unwrap();

    // Should have at least the created file and init.krun (. and .. are skipped in readdirplus).
    let names: Vec<String> = entries.iter().map(|(de, _)| String::from_utf8_lossy(de.name).to_string()).collect();
    assert!(names.contains(&"plus.txt".to_string()));
    assert!(names.contains(&"init.krun".to_string()));

    // Each entry should have valid attrs.
    for (de, entry) in &entries {
        let name = String::from_utf8_lossy(de.name).to_string();
        if name == "plus.txt" {
            assert_eq!(entry.attr.st_mode as u32 & libc::S_IFMT as u32, libc::S_IFREG as u32);
        }
    }

    sb.fs.releasedir(MemFsTestSandbox::ctx(), ROOT_INODE, 0, handle).unwrap();
}

#[test]
fn test_readdirplus_init_krun() {
    let sb = MemFsTestSandbox::new();
    let (handle, _) = sb.fuse_opendir(ROOT_INODE).unwrap();
    let handle = handle.unwrap();
    let entries = sb.fs.readdirplus(MemFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 0).unwrap();

    let init_entry = entries.iter().find(|(de, _)| de.name == b"init.krun");
    assert!(init_entry.is_some(), "init.krun should be in readdirplus");
    let (_, entry) = init_entry.unwrap();
    assert_eq!(entry.inode, INIT_INODE);
    assert_eq!(entry.attr.st_mode as u32 & 0o777, 0o755);

    sb.fs.releasedir(MemFsTestSandbox::ctx(), ROOT_INODE, 0, handle).unwrap();
}

#[test]
fn test_releasedir() {
    let sb = MemFsTestSandbox::new();
    let (handle, _) = sb.fuse_opendir(ROOT_INODE).unwrap();
    let handle = handle.unwrap();
    sb.fs.releasedir(MemFsTestSandbox::ctx(), ROOT_INODE, 0, handle).unwrap();

    // After release, readdir with same handle should fail.
    let result = sb.fs.readdir(MemFsTestSandbox::ctx(), ROOT_INODE, handle, 65536, 0);
    MemFsTestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_readdir_root_has_init() {
    let sb = MemFsTestSandbox::new();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(names.contains(&"init.krun".to_string()));
}
