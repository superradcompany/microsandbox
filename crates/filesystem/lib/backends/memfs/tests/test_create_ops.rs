use super::*;

#[test]
fn test_create_file() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("newfile.txt").unwrap();
    assert!(entry.inode >= 3);
    assert!(handle.is_some());
    let looked = sb.lookup_root("newfile.txt").unwrap();
    assert_eq!(looked.inode, entry.inode);
}

#[test]
fn test_create_file_with_content() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("data.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"hello world", 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"hello world");
}

#[test]
fn test_create_with_umask() {
    let sb = MemFsTestSandbox::new();
    let (entry, _handle, _opts) = sb.fs.create(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("masked.txt"),
        0o777,
        false,
        libc::O_RDWR as u32,
        0o022,
        Extensions::default(),
    ).unwrap();
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & 0o777, 0o755);
}

#[test]
fn test_create_context_ownership() {
    let sb = MemFsTestSandbox::new();
    let (entry, _) = sb.fuse_create_root("owned.txt").unwrap();
    assert_eq!(entry.attr.st_uid, 1000);
    assert_eq!(entry.attr.st_gid, 1000);
}

#[test]
fn test_create_duplicate() {
    let sb = MemFsTestSandbox::new();
    sb.fuse_create_root("dup.txt").unwrap();
    let result = sb.fuse_create_root("dup.txt");
    MemFsTestSandbox::assert_errno(result, LINUX_EEXIST);
}

#[test]
fn test_mkdir() {
    let sb = MemFsTestSandbox::new();
    // Get root nlink before.
    let (st_before, _) = sb.fs.getattr(MemFsTestSandbox::ctx(), ROOT_INODE, None).unwrap();
    let nlink_before = st_before.st_nlink;

    let entry = sb.fuse_mkdir_root("mydir").unwrap();
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
    #[cfg(target_os = "linux")]
    assert_eq!(entry.attr.st_nlink, 2);
    #[cfg(target_os = "macos")]
    assert_eq!(entry.attr.st_nlink, 2);

    // Parent nlink should have been incremented.
    let (st_after, _) = sb.fs.getattr(MemFsTestSandbox::ctx(), ROOT_INODE, None).unwrap();
    assert_eq!(st_after.st_nlink, nlink_before + 1);
}

#[test]
fn test_mkdir_nested() {
    let sb = MemFsTestSandbox::new();
    let dir_a = sb.fuse_mkdir_root("a").unwrap();
    let dir_b = sb.fuse_mkdir(dir_a.inode, "b", 0o755).unwrap();
    let dir_c = sb.fuse_mkdir(dir_b.inode, "c", 0o755).unwrap();
    assert!(dir_c.inode >= 3);
    let looked = sb.lookup(dir_b.inode, "c").unwrap();
    assert_eq!(looked.inode, dir_c.inode);
}

#[test]
fn test_mknod_fifo() {
    let sb = MemFsTestSandbox::new();
    let entry = sb.fs.mknod(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("myfifo"),
        libc::S_IFIFO as u32 | 0o644,
        0,
        0,
        Extensions::default(),
    ).unwrap();
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFIFO as u32);
}

#[test]
fn test_mknod_socket() {
    let sb = MemFsTestSandbox::new();
    let entry = sb.fs.mknod(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("mysock"),
        libc::S_IFSOCK as u32 | 0o644,
        0,
        0,
        Extensions::default(),
    ).unwrap();
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFSOCK as u32);
}

#[test]
fn test_mknod_block_device() {
    let sb = MemFsTestSandbox::new();
    let entry = sb.fs.mknod(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("blkdev"),
        libc::S_IFBLK as u32 | 0o660,
        42,
        0,
        Extensions::default(),
    ).unwrap();
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFBLK as u32);
    #[cfg(target_os = "linux")]
    assert_eq!(entry.attr.st_rdev, 42);
    #[cfg(target_os = "macos")]
    assert_eq!(entry.attr.st_rdev, 42);
}

#[test]
fn test_mknod_char_device() {
    let sb = MemFsTestSandbox::new();
    let entry = sb.fs.mknod(
        MemFsTestSandbox::ctx(),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("chrdev"),
        libc::S_IFCHR as u32 | 0o660,
        99,
        0,
        Extensions::default(),
    ).unwrap();
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFCHR as u32);
    #[cfg(target_os = "linux")]
    assert_eq!(entry.attr.st_rdev, 99);
    #[cfg(target_os = "macos")]
    assert_eq!(entry.attr.st_rdev, 99);
}

#[test]
fn test_symlink() {
    let sb = MemFsTestSandbox::new();
    let entry = sb.fs.symlink(
        MemFsTestSandbox::ctx(),
        &MemFsTestSandbox::cstr("/target/path"),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("mylink"),
        Extensions::default(),
    ).unwrap();
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFLNK as u32);
    let target = sb.fs.readlink(MemFsTestSandbox::ctx(), entry.inode).unwrap();
    assert_eq!(&target[..], b"/target/path");
}

#[test]
fn test_symlink_size() {
    let sb = MemFsTestSandbox::new();
    let target = "/some/long/target/path";
    let entry = sb.fs.symlink(
        MemFsTestSandbox::ctx(),
        &MemFsTestSandbox::cstr(target),
        ROOT_INODE,
        &MemFsTestSandbox::cstr("sizelink"),
        Extensions::default(),
    ).unwrap();
    assert_eq!(entry.attr.st_size, target.len() as i64);
}

#[test]
fn test_link() {
    let sb = MemFsTestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("original.txt").unwrap();
    let handle = handle.unwrap();
    sb.fs
        .release(MemFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    let link_entry = sb.fs.link(
        MemFsTestSandbox::ctx(),
        entry.inode,
        ROOT_INODE,
        &MemFsTestSandbox::cstr("hardlink.txt"),
    ).unwrap();
    // Same inode.
    assert_eq!(link_entry.inode, entry.inode);
    // nlink should be 2 now.
    let (st, _) = sb.fs.getattr(MemFsTestSandbox::ctx(), entry.inode, None).unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(st.st_nlink, 2);
    #[cfg(target_os = "macos")]
    assert_eq!(st.st_nlink, 2);
}

#[test]
fn test_link_to_directory() {
    let sb = MemFsTestSandbox::new();
    let dir = sb.fuse_mkdir_root("dir_for_link").unwrap();
    let result = sb.fs.link(
        MemFsTestSandbox::ctx(),
        dir.inode,
        ROOT_INODE,
        &MemFsTestSandbox::cstr("dir_hardlink"),
    );
    MemFsTestSandbox::assert_errno(result, LINUX_EPERM);
}

#[test]
fn test_link_shared_content() {
    let sb = MemFsTestSandbox::new();

    // Create a file and write through it.
    let (entry, handle) = sb.fuse_create_root("original.txt").unwrap();
    let handle = handle.unwrap();
    sb.fuse_write(entry.inode, handle, b"shared data", 0).unwrap();
    sb.fs
        .release(MemFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();

    // Create a hardlink to the same inode.
    let link_entry = sb.fs.link(
        MemFsTestSandbox::ctx(),
        entry.inode,
        ROOT_INODE,
        &MemFsTestSandbox::cstr("hardlink.txt"),
    ).unwrap();
    assert_eq!(link_entry.inode, entry.inode);

    // Open the hardlink and read — should see the same content.
    let (handle2, _) = sb.fuse_open(link_entry.inode, libc::O_RDWR as u32).unwrap();
    let handle2 = handle2.unwrap();
    let data = sb.fuse_read(link_entry.inode, handle2, 1024, 0).unwrap();
    assert_eq!(&data[..], b"shared data");

    // Write new content through the hardlink.
    sb.fuse_write(link_entry.inode, handle2, b"updated", 0).unwrap();
    sb.fs
        .release(MemFsTestSandbox::ctx(), link_entry.inode, 0, handle2, false, false, None)
        .unwrap();

    // Open the original name and verify the update is visible.
    let looked = sb.lookup_root("original.txt").unwrap();
    let (handle3, _) = sb.fuse_open(looked.inode, libc::O_RDONLY as u32).unwrap();
    let handle3 = handle3.unwrap();
    let data2 = sb.fuse_read(looked.inode, handle3, 1024, 0).unwrap();
    assert_eq!(&data2[..7], b"updated");
}
