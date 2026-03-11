use super::*;

#[test]
fn test_three_layers_priority() {
    let sb = OverlayTestSandbox::with_layers(3, |lowers, upper| {
        // Same file in all layers — upper should win.
        std::fs::write(lowers[0].join("shared.txt"), b"bottom").unwrap();
        std::fs::write(lowers[1].join("shared.txt"), b"middle").unwrap();
        std::fs::write(lowers[2].join("shared.txt"), b"top_lower").unwrap();
        std::fs::write(upper.join("shared.txt"), b"upper").unwrap();
    });
    let entry = sb.lookup_root("shared.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"upper");
}

#[test]
fn test_topmost_lower_wins() {
    let sb = OverlayTestSandbox::with_layers(3, |lowers, _upper| {
        // Same file in all lower layers — topmost (index 2) should win.
        std::fs::write(lowers[0].join("shared.txt"), b"bottom").unwrap();
        std::fs::write(lowers[1].join("shared.txt"), b"middle").unwrap();
        std::fs::write(lowers[2].join("shared.txt"), b"top").unwrap();
    });
    let entry = sb.lookup_root("shared.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"top");
}

#[test]
fn test_lower_whiteout_hides_deeper() {
    let sb = OverlayTestSandbox::with_layers(2, |lowers, _upper| {
        // Bottom layer has a file.
        std::fs::write(lowers[0].join("hidden.txt"), b"deep").unwrap();
        // Middle layer whiteouts it.
        std::fs::write(lowers[1].join(".wh.hidden.txt"), b"").unwrap();
    });
    let result = sb.lookup_root("hidden.txt");
    OverlayTestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_opaque_in_middle_stops() {
    let sb = OverlayTestSandbox::with_layers(2, |lowers, upper| {
        // Bottom layer has dir with child.
        std::fs::create_dir(lowers[0].join("mydir")).unwrap();
        std::fs::write(lowers[0].join("mydir/deep.txt"), b"deep").unwrap();
        // Top lower layer has same dir, opaque.
        std::fs::create_dir(lowers[1].join("mydir")).unwrap();
        std::fs::write(lowers[1].join("mydir/.wh..wh..opq"), b"").unwrap();
        std::fs::write(lowers[1].join("mydir/top.txt"), b"top").unwrap();
        // Upper has same dir too.
        std::fs::create_dir(upper.join("mydir")).unwrap();
        std::fs::write(upper.join("mydir/upper.txt"), b"upper").unwrap();
    });
    let dir_entry = sb.lookup_root("mydir").unwrap();
    // upper.txt should be visible.
    let upper_child = sb.lookup(dir_entry.inode, "upper.txt");
    assert!(upper_child.is_ok());
    // top.txt from top lower should be visible.
    let top_child = sb.lookup(dir_entry.inode, "top.txt");
    assert!(top_child.is_ok());
    // deep.txt from bottom lower should be hidden by opaque.
    let deep_child = sb.lookup(dir_entry.inode, "deep.txt");
    OverlayTestSandbox::assert_errno(deep_child, LINUX_ENOENT);
}

#[test]
fn test_readdir_three_layers_merged() {
    let sb = OverlayTestSandbox::with_layers(3, |lowers, _upper| {
        std::fs::write(lowers[0].join("a.txt"), b"a").unwrap();
        std::fs::write(lowers[1].join("b.txt"), b"b").unwrap();
        std::fs::write(lowers[2].join("c.txt"), b"c").unwrap();
    });
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(names.iter().any(|n| n == b"a.txt"));
    assert!(names.iter().any(|n| n == b"b.txt"));
    assert!(names.iter().any(|n| n == b"c.txt"));
}

#[test]
fn test_readdir_three_layers_dedup() {
    let sb = OverlayTestSandbox::with_layers(3, |lowers, _upper| {
        std::fs::write(lowers[0].join("shared.txt"), b"0").unwrap();
        std::fs::write(lowers[1].join("shared.txt"), b"1").unwrap();
        std::fs::write(lowers[2].join("shared.txt"), b"2").unwrap();
    });
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    let count = names
        .iter()
        .filter(|n| n.as_slice() == b"shared.txt")
        .count();
    assert_eq!(count, 1, "shared name should appear exactly once");
}

#[test]
fn test_lookup_through_layers() {
    let sb = OverlayTestSandbox::with_layers(2, |lowers, _upper| {
        // Directory in bottom layer.
        std::fs::create_dir(lowers[0].join("dir")).unwrap();
        // File inside that dir in top layer.
        std::fs::create_dir(lowers[1].join("dir")).unwrap();
        std::fs::write(lowers[1].join("dir/file.txt"), b"data").unwrap();
    });
    let dir_entry = sb.lookup_root("dir").unwrap();
    let file_entry = sb.lookup(dir_entry.inode, "file.txt").unwrap();
    assert!(file_entry.inode >= 3);
}

#[test]
fn test_write_in_multi_layer() {
    let sb = OverlayTestSandbox::with_layers(3, |lowers, _upper| {
        // File in bottom layer.
        std::fs::write(lowers[0].join("deep.txt"), b"deep").unwrap();
    });
    let entry = sb.lookup_root("deep.txt").unwrap();
    let handle = sb
        .fuse_open(entry.inode, libc::O_RDWR as u32)
        .unwrap();
    sb.fuse_write(entry.inode, handle, b"MODIFIED", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"MODIFIED");
    assert!(sb.upper_has_file("deep.txt"));
}
