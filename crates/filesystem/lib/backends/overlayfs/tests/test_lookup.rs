use super::*;

#[test]
fn test_lookup_upper_file() {
    let sb = OverlayTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("upper_only.txt").unwrap();
    let e = sb.lookup_root("upper_only.txt").unwrap();
    assert_eq!(e.inode, entry.inode);
    let mode = e.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
}

#[test]
fn test_lookup_lower_file() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("lower_file.txt"), b"lower data").unwrap();
    });
    let entry = sb.lookup_root("lower_file.txt").unwrap();
    assert!(entry.inode >= 3);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
}

#[test]
fn test_lookup_upper_shadows_lower() {
    let sb = OverlayTestSandbox::with_layers(1, |lowers, upper| {
        std::fs::write(lowers[0].join("shared.txt"), b"lower").unwrap();
        std::fs::write(upper.join("shared.txt"), b"upper").unwrap();
    });
    // Both exist — lookup should succeed, upper data should be visible.
    let entry = sb.lookup_root("shared.txt").unwrap();
    assert!(entry.inode >= 3);
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"upper");
}

#[test]
fn test_lookup_nonexistent() {
    let sb = OverlayTestSandbox::new();
    let result = sb.lookup_root("does_not_exist");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_lookup_whiteout_hides_lower() {
    let sb = OverlayTestSandbox::with_layers(1, |lowers, upper| {
        std::fs::write(lowers[0].join("hidden.txt"), b"hidden data").unwrap();
        // Create whiteout in upper.
        std::fs::write(upper.join(".wh.hidden.txt"), b"").unwrap();
    });
    let result = sb.lookup_root("hidden.txt");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_lookup_opaque_hides_lower_children() {
    let sb = OverlayTestSandbox::with_layers(1, |lowers, upper| {
        // Lower has dir with a child.
        std::fs::create_dir(lowers[0].join("mydir")).unwrap();
        std::fs::write(lowers[0].join("mydir/child.txt"), b"child").unwrap();
        // Upper has same dir, marked opaque.
        std::fs::create_dir(upper.join("mydir")).unwrap();
        std::fs::write(upper.join("mydir/.wh..wh..opq"), b"").unwrap();
    });
    let dir_entry = sb.lookup_root("mydir").unwrap();
    // Child from lower should be hidden by opaque marker.
    let result = sb.lookup(dir_entry.inode, "child.txt");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_lookup_nested_lower() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::create_dir(lower.join("subdir")).unwrap();
        std::fs::write(lower.join("subdir/nested.txt"), b"nested").unwrap();
    });
    let dir_entry = sb.lookup_root("subdir").unwrap();
    let file_entry = sb.lookup(dir_entry.inode, "nested.txt").unwrap();
    assert!(file_entry.inode >= 3);
    let mode = file_entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
}

#[test]
fn test_lookup_nested_mixed() {
    let sb = OverlayTestSandbox::with_layers(1, |lowers, upper| {
        // Parent directory in lower only.
        std::fs::create_dir(lowers[0].join("parent")).unwrap();
        // Child file in upper.
        std::fs::create_dir(upper.join("parent")).unwrap();
        std::fs::write(upper.join("parent/child.txt"), b"upper child").unwrap();
    });
    let dir_entry = sb.lookup_root("parent").unwrap();
    let file_entry = sb.lookup(dir_entry.inode, "child.txt").unwrap();
    assert!(file_entry.inode >= 3);
}

#[test]
fn test_lookup_same_inode_stability() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("stable.txt"), b"data").unwrap();
    });
    let e1 = sb.lookup_root("stable.txt").unwrap();
    let e2 = sb.lookup_root("stable.txt").unwrap();
    assert_eq!(e1.inode, e2.inode, "same file should return same inode");
}

#[test]
fn test_lookup_init_binary() {
    let sb = OverlayTestSandbox::new();
    let entry = sb.lookup_root("init.krun").unwrap();
    assert_eq!(entry.inode, INIT_INODE);
}

#[test]
fn test_lookup_dir_in_lower() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::create_dir(lower.join("lower_dir")).unwrap();
    });
    let entry = sb.lookup_root("lower_dir").unwrap();
    assert!(entry.inode >= 3);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
}

#[test]
fn test_lookup_refcount_and_forget() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file.txt"), b"data").unwrap();
    });
    let e1 = sb.lookup_root("file.txt").unwrap();
    let _e2 = sb.lookup_root("file.txt").unwrap();
    // After two lookups, refcount is 2. Forget once — inode should still exist.
    sb.fs.forget(sb.ctx(), e1.inode, 1);
    let result = sb.fs.getattr(sb.ctx(), e1.inode, None);
    assert!(
        result.is_ok(),
        "inode should still exist after partial forget"
    );
}

#[test]
fn test_batch_forget() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("a.txt"), b"a").unwrap();
        std::fs::write(lower.join("b.txt"), b"b").unwrap();
    });
    let ea = sb.lookup_root("a.txt").unwrap();
    let eb = sb.lookup_root("b.txt").unwrap();
    sb.fs
        .batch_forget(sb.ctx(), vec![(ea.inode, 1), (eb.inode, 1)]);
    assert!(sb.fs.getattr(sb.ctx(), ea.inode, None).is_err());
    assert!(sb.fs.getattr(sb.ctx(), eb.inode, None).is_err());
}

#[test]
fn test_lookup_after_forget_new_inode() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("file.txt"), b"data").unwrap();
    });
    let e1 = sb.lookup_root("file.txt").unwrap();
    let old_inode = e1.inode;
    sb.fs.forget(sb.ctx(), old_inode, 1);
    let e2 = sb.lookup_root("file.txt").unwrap();
    assert_ne!(
        e2.inode, old_inode,
        "re-lookup after full forget should allocate a fresh inode"
    );
}

#[test]
fn test_nested_lookup_survives_ancestor_forget() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::create_dir(lower.join("dir")).unwrap();
        std::fs::create_dir(lower.join("dir/sub")).unwrap();
        std::fs::write(lower.join("dir/sub/file.txt"), b"nested data").unwrap();
    });

    let dir = sb.lookup_root("dir").unwrap();
    let subdir = sb.lookup(dir.inode, "sub").unwrap();
    let file = sb.lookup(subdir.inode, "file.txt").unwrap();

    sb.fs.forget(sb.ctx(), dir.inode, 1);
    sb.fs.forget(sb.ctx(), subdir.inode, 1);

    let (st, _) = sb.fs.getattr(sb.ctx(), file.inode, None).unwrap();
    assert_eq!(st.st_size, 11);

    let handle = sb.fuse_open(file.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(file.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"nested data");
}
