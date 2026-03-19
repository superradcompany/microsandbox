use super::*;

#[test]
fn test_create_file_in_root() {
    let sb = OverlayTestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("new_file.txt").unwrap();
    assert!(entry.inode >= 3);
    let e = sb.lookup_root("new_file.txt").unwrap();
    assert_eq!(e.inode, entry.inode);
}

#[test]
fn test_create_file_guest_ownership() {
    let sb = OverlayTestSandbox::new();
    let (entry, _handle, _opts) = sb
        .fs
        .create(
            sb.ctx_as(1000, 1000),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("owned.txt"),
            0o644,
            false,
            libc::O_RDWR as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let (st, _) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 1000);
    assert_eq!(st.st_gid, 1000);
}

#[test]
fn test_create_file_on_upper() {
    let sb = OverlayTestSandbox::new();
    sb.fuse_create_root("upper_file.txt").unwrap();
    assert!(
        sb.upper_has_file("upper_file.txt"),
        "created file should exist on upper layer"
    );
}

#[test]
fn test_mkdir_in_root() {
    let sb = OverlayTestSandbox::new();
    let entry = sb.fuse_mkdir_root("new_dir").unwrap();
    assert!(entry.inode >= 3);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
}

#[test]
fn test_mkdir_nested() {
    let sb = OverlayTestSandbox::new();
    let parent = sb.fuse_mkdir_root("parent").unwrap();
    let child = sb.fuse_mkdir(parent.inode, "child", 0o755).unwrap();
    assert!(child.inode >= 3);
    assert_ne!(parent.inode, child.inode);
}

#[test]
fn test_create_in_lower_dir() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::fs::create_dir(lower.join("lower_dir")).unwrap();
    });
    let dir_entry = sb.lookup_root("lower_dir").unwrap();
    // Creating a file in a lower-only dir should trigger parent copy-up.
    let (file_entry, _handle) = sb
        .fuse_create(dir_entry.inode, "new_child.txt", 0o644)
        .unwrap();
    assert!(file_entry.inode >= 3);
    // Verify the new child is accessible.
    let e = sb.lookup(dir_entry.inode, "new_child.txt").unwrap();
    assert_eq!(e.inode, file_entry.inode);
}

#[test]
#[cfg(target_os = "linux")]
fn test_symlink() {
    let sb = OverlayTestSandbox::new();
    let entry = sb
        .fs
        .symlink(
            sb.ctx(),
            &OverlayTestSandbox::cstr("/target/path"),
            ROOT_INODE,
            &OverlayTestSandbox::cstr("mylink"),
            Extensions::default(),
        )
        .unwrap();
    assert!(entry.inode >= 3);
    let target = sb.fs.readlink(sb.ctx(), entry.inode).unwrap();
    assert_eq!(&target[..], b"/target/path");
}

#[test]
#[cfg(target_os = "linux")]
fn test_lower_host_symlink_open_rejected_but_readlink_allowed() {
    let sb = OverlayTestSandbox::with_lower(|lower| {
        std::os::unix::fs::symlink("/host/target", lower.join("host-link")).unwrap();
    });

    let entry = sb.lookup_root("host-link").unwrap();
    OverlayTestSandbox::assert_errno(
        sb.fuse_open(entry.inode, libc::O_RDONLY as u32),
        LINUX_ELOOP,
    );

    let target = sb.fs.readlink(sb.ctx(), entry.inode).unwrap();
    assert_eq!(&target[..], b"/host/target");
}

#[test]
fn test_link_upper_file() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("original.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"link data", 0).unwrap();
    let link_entry = sb
        .fs
        .link(
            sb.ctx(),
            entry.inode,
            ROOT_INODE,
            &OverlayTestSandbox::cstr("hard_link.txt"),
        )
        .unwrap();
    assert!(link_entry.inode >= 3);
    // Read via the link.
    let link_handle = sb
        .fuse_open(link_entry.inode, libc::O_RDONLY as u32)
        .unwrap();
    let data = sb
        .fuse_read(link_entry.inode, link_handle, 4096, 0)
        .unwrap();
    assert_eq!(&data[..], b"link data");
}

#[test]
fn test_create_write_read() {
    let sb = OverlayTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("roundtrip.txt").unwrap();
    let data = b"create-write-read roundtrip";
    sb.fuse_write(entry.inode, handle, data, 0).unwrap();
    sb.fs.flush(sb.ctx(), entry.inode, handle, 0).unwrap();
    let read_data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&read_data[..], data);
}
