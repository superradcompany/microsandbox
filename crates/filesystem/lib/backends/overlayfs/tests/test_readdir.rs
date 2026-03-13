use super::*;

#[test]
fn test_readdir_empty_root() {
    let sb = OverlayTestSandbox::new();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    // Overlay readdir filters . and .. (merged snapshot omits them).
    assert!(
        names.iter().any(|n| n == b"init.krun"),
        "missing 'init.krun' entry"
    );
}

#[test]
fn test_readdir_upper_only() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("upper_file.txt").unwrap();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(names.iter().any(|n| n == b"upper_file.txt"));
}

#[test]
fn test_readdir_lower_only() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("lower_file.txt"), b"data").unwrap();
    });
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(
        names.iter().any(|n| n == b"lower_file.txt"),
        "lower file should appear in readdir"
    );
}

#[test]
fn test_readdir_merged() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::write(lower.join("from_lower.txt"), b"lower").unwrap();
    });
    sb.fuse_create_root("from_upper.txt").unwrap();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(names.iter().any(|n| n == b"from_lower.txt"));
    assert!(names.iter().any(|n| n == b"from_upper.txt"));
}

#[test]
fn test_readdir_upper_shadows_lower() {
    let sb = OverlayTestSandbox::with_layers(1, |lowers, upper| {
        std::fs::write(lowers[0].join("shared.txt"), b"lower").unwrap();
        std::fs::write(upper.join("shared.txt"), b"upper").unwrap();
    });
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    // Should appear exactly once.
    let count = names
        .iter()
        .filter(|n| n.as_slice() == b"shared.txt")
        .count();
    assert_eq!(count, 1, "same name should appear exactly once");
}

#[test]
fn test_readdir_whiteout_hides() {
    let sb = OverlayTestSandbox::with_layers(1, |lowers, upper| {
        std::fs::write(lowers[0].join("hidden.txt"), b"data").unwrap();
        std::fs::write(upper.join(".wh.hidden.txt"), b"").unwrap();
    });
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(
        !names.iter().any(|n| n == b"hidden.txt"),
        "whiteout should hide lower entry from readdir"
    );
    // The whiteout file itself should not appear.
    assert!(
        !names.iter().any(|n| n.starts_with(b".wh.")),
        "whiteout markers should not appear in readdir"
    );
}

#[test]
fn test_readdir_opaque_stops_lower() {
    let sb = OverlayTestSandbox::with_layers(1, |lowers, upper| {
        // Lower has a dir with children.
        std::fs::create_dir(lowers[0].join("odir")).unwrap();
        std::fs::write(lowers[0].join("odir/lower_child.txt"), b"lc").unwrap();
        // Upper has same dir, opaque, with its own child.
        std::fs::create_dir(upper.join("odir")).unwrap();
        std::fs::write(upper.join("odir/.wh..wh..opq"), b"").unwrap();
        std::fs::write(upper.join("odir/upper_child.txt"), b"uc").unwrap();
    });
    let dir_entry = sb.lookup_root("odir").unwrap();
    let names = sb.readdir_names(dir_entry.inode).unwrap();
    assert!(
        names.iter().any(|n| n == b"upper_child.txt"),
        "upper child should appear"
    );
    assert!(
        !names.iter().any(|n| n == b"lower_child.txt"),
        "lower child should be hidden by opaque marker"
    );
}

#[test]
fn test_readdir_init_injected() {
    let sb = OverlayTestSandbox::new();
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(
        names.iter().any(|n| n == b"init.krun"),
        "init.krun should be injected into root readdir"
    );
}

#[test]
fn test_readdir_subdir_no_init() {
    let sb = OverlayTestSandbox::new();
    let dir_entry = sb.fuse_mkdir_root("subdir").unwrap();
    let names = sb.readdir_names(dir_entry.inode).unwrap();
    assert!(
        !names.iter().any(|n| n == b"init.krun"),
        "init.krun should NOT be in non-root dirs"
    );
}

#[test]
fn test_readdirplus_filters_dots() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("file.txt").unwrap();
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdirplus(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    for (de, _entry) in &entries {
        assert_ne!(de.name, b".", "readdirplus should filter '.'");
        assert_ne!(de.name, b"..", "readdirplus should filter '..'");
    }
    let names: Vec<&[u8]> = entries.iter().map(|(de, _)| de.name).collect();
    assert!(names.iter().any(|n| *n == b"init.krun"));
    assert!(names.iter().any(|n| *n == b"file.txt"));
}

#[test]
fn test_readdir_multi_layer() {
    let sb = OverlayTestSandbox::with_layers(3, |lowers, _upper| {
        std::fs::write(lowers[0].join("bottom.txt"), b"0").unwrap();
        std::fs::write(lowers[1].join("middle.txt"), b"1").unwrap();
        std::fs::write(lowers[2].join("top.txt"), b"2").unwrap();
    });
    let names = sb.readdir_names(ROOT_INODE).unwrap();
    assert!(names.iter().any(|n| n == b"bottom.txt"));
    assert!(names.iter().any(|n| n == b"middle.txt"));
    assert!(names.iter().any(|n| n == b"top.txt"));
}

#[test]
fn test_releasedir() {
    let sb = OverlayTestSandbox::new();
    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let result = sb.fs.releasedir(sb.ctx(), ROOT_INODE, 0, handle);
    assert!(result.is_ok());
}
