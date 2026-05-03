use super::*;

#[test]
fn test_opendir_root() {
    let sb = TestSandbox::new();
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    assert!(handle > 0); // handle 0 is reserved for init
}

#[test]
fn test_readdir_empty_root() {
    let sb = TestSandbox::new();
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    let names: Vec<&[u8]> = entries.iter().map(|e| e.name).collect();
    // Should have at least ".", "..", and "init.krun".
    assert!(names.iter().any(|n| *n == b"."), "missing '.' entry");
    assert!(names.iter().any(|n| *n == b".."), "missing '..' entry");
    assert!(
        names.iter().any(|n| *n == b"init.krun"),
        "missing 'init.krun' entry"
    );
}

#[test]
fn test_readdir_with_files() {
    let sb = TestSandbox::new();
    sb.fuse_create_root("alpha.txt").unwrap();
    sb.fuse_create_root("beta.txt").unwrap();
    sb.fuse_create_root("gamma.txt").unwrap();
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    let names: Vec<&[u8]> = entries.iter().map(|e| e.name).collect();
    assert!(
        names.iter().any(|n| *n == b"alpha.txt"),
        "missing alpha.txt"
    );
    assert!(names.iter().any(|n| *n == b"beta.txt"), "missing beta.txt");
    assert!(
        names.iter().any(|n| *n == b"gamma.txt"),
        "missing gamma.txt"
    );
    assert!(
        names.iter().any(|n| *n == b"init.krun"),
        "missing init.krun"
    );
}

#[test]
fn test_readdir_init_injected() {
    let sb = TestSandbox::new();
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    let init_entry = entries.iter().find(|e| e.name == b"init.krun");
    assert!(init_entry.is_some(), "init.krun should be injected");
    assert_eq!(init_entry.unwrap().ino, INIT_INODE);
}

#[test]
fn test_readdir_no_duplicate_init() {
    let sb = TestSandbox::new();
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    let init_count = entries.iter().filter(|e| e.name == b"init.krun").count();
    assert_eq!(init_count, 1, "exactly one init.krun entry expected");
}

#[test]
fn test_readdir_subdir_no_init() {
    let sb = TestSandbox::new();
    let dir_entry = sb.fuse_mkdir_root("subdir").unwrap();
    let handle = sb.fuse_opendir(dir_entry.inode).unwrap();
    let entries = sb
        .fs
        .readdir(sb.ctx(), dir_entry.inode, handle, 65536, 0)
        .unwrap();
    let init_present = entries.iter().any(|e| e.name == b"init.krun");
    assert!(!init_present, "init.krun should NOT be in non-root dirs");
}

#[test]
fn test_readdirplus_root() {
    let sb = TestSandbox::new();
    sb.fuse_create_root("file.txt").unwrap();
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdirplus(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    // readdirplus filters out . and ..
    for (de, _entry) in &entries {
        assert_ne!(de.name, b".", "readdirplus should filter '.'");
        assert_ne!(de.name, b"..", "readdirplus should filter '..'");
    }
    // Should have init.krun and file.txt.
    let names: Vec<&[u8]> = entries.iter().map(|(de, _)| de.name).collect();
    assert!(names.iter().any(|n| *n == b"init.krun"));
    assert!(names.iter().any(|n| *n == b"file.txt"));
}

#[test]
fn test_readdirplus_init_entry() {
    let sb = TestSandbox::new();
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdirplus(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    let init = entries.iter().find(|(de, _)| de.name == b"init.krun");
    assert!(init.is_some(), "init.krun should be in readdirplus");
    let (_de, entry) = init.unwrap();
    assert_eq!(entry.inode, INIT_INODE);
}

#[test]
fn test_releasedir() {
    let sb = TestSandbox::new();
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let result = sb.fs.releasedir(sb.ctx(), ROOT_INODE, 0, handle);
    assert!(result.is_ok());
}

#[test]
fn test_readdir_invalid_handle() {
    let sb = TestSandbox::new();
    let result = sb.fs.readdir(sb.ctx(), ROOT_INODE, 99999, 65536, 0);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_readdir_large_dir() {
    let sb = TestSandbox::new();
    for i in 0..100 {
        sb.fuse_create_root(&format!("file_{i:03}.txt")).unwrap();
    }
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    let names: Vec<&[u8]> = entries.iter().map(|e| e.name).collect();
    // Should have all 100 files + init.krun + . + ..
    for i in 0..100 {
        let expected = format!("file_{i:03}.txt");
        assert!(names.contains(&expected.as_bytes()), "missing {expected}");
    }
    assert!(names.iter().any(|n| *n == b"init.krun"));
}

#[test]
fn test_readdir_offset_resume() {
    let sb = TestSandbox::new();
    sb.fuse_create_root("a.txt").unwrap();
    sb.fuse_create_root("b.txt").unwrap();
    sb.fuse_create_root("c.txt").unwrap();

    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let all_entries = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    assert!(all_entries.len() >= 4, "expected . .. init.krun and files");

    let resume_after = all_entries[2].offset;
    let resumed = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 65536, resume_after)
        .unwrap();

    let expected_names: Vec<&[u8]> = all_entries
        .iter()
        .filter(|entry| entry.offset > resume_after)
        .map(|entry| entry.name)
        .collect();
    let resumed_names: Vec<&[u8]> = resumed.iter().map(|entry| entry.name).collect();

    assert_eq!(resumed_names, expected_names);
}

#[test]
fn test_readdir_snapshot_is_handle_local() {
    let sb = TestSandbox::new();
    sb.fuse_create_root("before.txt").unwrap();

    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let before = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    assert!(before.iter().any(|entry| entry.name == b"before.txt"));

    sb.host_create_file("after.txt", b"new");

    let same_handle = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    assert!(!same_handle.iter().any(|entry| entry.name == b"after.txt"));

    let next_handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let next_handle_entries = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, next_handle, 65536, 0)
        .unwrap();
    assert!(
        next_handle_entries
            .iter()
            .any(|entry| entry.name == b"after.txt")
    );
}

#[test]
fn test_readdir_root_without_init_when_disabled() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.inject_init = false;
        cfg
    });

    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();

    assert!(!entries.iter().any(|entry| entry.name == b"init.krun"));
}

#[test]
fn test_root_init_name_is_not_reserved_when_disabled() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.inject_init = false;
        cfg
    });

    let (entry, handle) = sb.fuse_create_root("init.krun").unwrap();
    assert_ne!(entry.inode, INIT_INODE);
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    let looked_up = sb.lookup_root("init.krun").unwrap();
    assert_eq!(looked_up.inode, entry.inode);
}

#[test]
fn test_readdirplus_skips_dot_dotdot() {
    let sb = TestSandbox::new();
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdirplus(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    for (de, _entry) in &entries {
        assert_ne!(de.name, b".");
        assert_ne!(de.name, b"..");
    }
}
