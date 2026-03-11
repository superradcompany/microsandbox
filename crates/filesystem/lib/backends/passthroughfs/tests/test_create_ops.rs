use super::*;

#[test]
fn test_create_basic() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("newfile.txt").unwrap();
    assert!(entry.inode >= 3);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert_eq!(mode & 0o777, 0o644);
    assert!(handle > 0); // handle 0 is reserved for init
}

#[test]
fn test_create_guest_ownership() {
    let sb = TestSandbox::new();
    // Create with uid=1000, gid=2000 context.
    let (entry, _handle, _opts) = sb
        .fs
        .create(
            sb.ctx_as(1000, 2000),
            ROOT_INODE,
            &TestSandbox::cstr("owned.txt"),
            0o644,
            false,
            libc::O_RDWR as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 1000);
    assert_eq!(st.st_gid, 2000);
}

#[test]
fn test_create_umask() {
    let sb = TestSandbox::new();
    // mode 0o777 with umask 0o022 should give 0o755.
    let (entry, _handle, _opts) = sb
        .fs
        .create(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("masked.txt"),
            0o777,
            false,
            libc::O_RDWR as u32,
            0o022,
            Extensions::default(),
        )
        .unwrap();
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & 0o777, 0o755);
}

#[test]
fn test_create_write_then_read() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("roundtrip.txt").unwrap();
    let data = b"hello world";
    sb.fuse_write(entry.inode, handle, data, 0).unwrap();
    // Flush and release.
    sb.fs.flush(sb.ctx(), entry.inode, handle, 0).unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // Re-open and read.
    let handle2 = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let read_data = sb.fuse_read(entry.inode, handle2, 4096, 0).unwrap();
    assert_eq!(&read_data[..], data);
}

#[test]
fn test_mkdir_basic() {
    let sb = TestSandbox::new();
    let entry = sb.fuse_mkdir_root("subdir").unwrap();
    assert!(entry.inode >= 3);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
    assert_eq!(mode & 0o777, 0o755);
}

#[test]
fn test_mkdir_nested() {
    let sb = TestSandbox::new();
    let parent = sb.fuse_mkdir_root("parent").unwrap();
    let child = sb.fuse_mkdir(parent.inode, "child", 0o755).unwrap();
    let mode = child.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
}

#[test]
fn test_mkdir_ownership() {
    let sb = TestSandbox::new();
    let entry = sb
        .fs
        .mkdir(
            sb.ctx_as(1000, 2000),
            ROOT_INODE,
            &TestSandbox::cstr("owned_dir"),
            0o755,
            0,
            Extensions::default(),
        )
        .unwrap();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 1000);
    assert_eq!(st.st_gid, 2000);
}

#[test]
fn test_mknod_regular() {
    let sb = TestSandbox::new();
    let entry = sb
        .fs
        .mknod(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("regular"),
            libc::S_IFREG as u32 | 0o644,
            0,
            0,
            Extensions::default(),
        )
        .unwrap();
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
    assert_eq!(mode & 0o777, 0o644);
}

#[test]
fn test_mknod_fifo() {
    let sb = TestSandbox::new();
    let entry = sb
        .fs
        .mknod(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("myfifo"),
            libc::S_IFIFO as u32 | 0o644,
            0,
            0,
            Extensions::default(),
        )
        .unwrap();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    let mode = st.st_mode as u32;
    // File type should be FIFO (stored in xattr override).
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFIFO as u32);
}

#[test]
fn test_mknod_block_device() {
    let sb = TestSandbox::new();
    let rdev = 0x0801u32; // major=8, minor=1 (e.g. sda1)
    let entry = sb
        .fs
        .mknod(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("blkdev"),
            libc::S_IFBLK as u32 | 0o660,
            rdev,
            0,
            Extensions::default(),
        )
        .unwrap();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFBLK as u32);
    assert_eq!(st.st_rdev as u32, rdev);
}

#[test]
fn test_mknod_char_device() {
    let sb = TestSandbox::new();
    let rdev = 0x0501u32; // major=5, minor=1 (e.g. console)
    let entry = sb
        .fs
        .mknod(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("chrdev"),
            libc::S_IFCHR as u32 | 0o666,
            rdev,
            0,
            Extensions::default(),
        )
        .unwrap();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFCHR as u32);
    assert_eq!(st.st_rdev as u32, rdev);
}

#[test]
fn test_symlink_and_readlink() {
    let sb = TestSandbox::new();
    let entry = sb
        .fs
        .symlink(
            sb.ctx(),
            &TestSandbox::cstr("/target/path"),
            ROOT_INODE,
            &TestSandbox::cstr("mylink"),
            Extensions::default(),
        )
        .unwrap();
    assert!(entry.inode >= 3);
    let target = sb.fs.readlink(sb.ctx(), entry.inode).unwrap();
    assert_eq!(&target[..], b"/target/path");
}

#[test]
fn test_symlink_stat_shows_link() {
    let sb = TestSandbox::new();
    let entry = sb
        .fs
        .symlink(
            sb.ctx(),
            &TestSandbox::cstr("/somewhere"),
            ROOT_INODE,
            &TestSandbox::cstr("link2"),
            Extensions::default(),
        )
        .unwrap();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    let mode = st.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFLNK as u32);
}

#[test]
fn test_readlink_non_symlink() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("regular.txt").unwrap();
    let result = sb.fs.readlink(sb.ctx(), entry.inode);
    TestSandbox::assert_errno(result, LINUX_EINVAL);
}

#[test]
fn test_link_basic() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("original.txt").unwrap();
    let link_entry = sb
        .fs
        .link(
            sb.ctx(),
            entry.inode,
            ROOT_INODE,
            &TestSandbox::cstr("hardlink.txt"),
        )
        .unwrap();
    // The link should be accessible via lookup.
    let looked_up = sb.lookup_root("hardlink.txt").unwrap();
    assert!(looked_up.inode >= 3);
    // Link entry should have same attributes.
    let mode = link_entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
}

#[test]
fn test_link_shares_data() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("source.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"shared data", 0)
        .unwrap();
    sb.fs.flush(sb.ctx(), entry.inode, handle, 0).unwrap();

    // Create a hard link.
    let link_entry = sb
        .fs
        .link(
            sb.ctx(),
            entry.inode,
            ROOT_INODE,
            &TestSandbox::cstr("link.txt"),
        )
        .unwrap();

    // Read through the link — should see the same data.
    let link_handle = sb
        .fuse_open(link_entry.inode, libc::O_RDONLY as u32)
        .unwrap();
    let data = sb
        .fuse_read(link_entry.inode, link_handle, 4096, 0)
        .unwrap();
    assert_eq!(&data[..], b"shared data");
}

#[test]
fn test_link_init_inode_rejected() {
    let sb = TestSandbox::new();
    let result = sb.fs.link(
        sb.ctx(),
        INIT_INODE,
        ROOT_INODE,
        &TestSandbox::cstr("link_to_init"),
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_link_init_name_rejected() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("source").unwrap();
    let result = sb.fs.link(
        sb.ctx(),
        entry.inode,
        ROOT_INODE,
        &TestSandbox::cstr("init.krun"),
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}
