use super::*;

fn readonly_sandbox() -> TestSandbox {
    TestSandbox::with_config(|mut cfg| {
        cfg.readonly = true;
        cfg
    })
}

#[test]
fn test_readonly_allows_read_only_open_and_read() {
    let sb = readonly_sandbox();
    sb.host_create_file("data.txt", b"readonly data");

    let entry = sb.lookup_root("data.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();

    assert_eq!(&data[..], b"readonly data");
}

#[test]
fn test_readonly_rejects_write_open_modes() {
    let sb = readonly_sandbox();
    sb.host_create_file("data.txt", b"readonly data");

    let entry = sb.lookup_root("data.txt").unwrap();
    TestSandbox::assert_errno(
        sb.fuse_open(entry.inode, libc::O_WRONLY as u32),
        LINUX_EROFS,
    );
    TestSandbox::assert_errno(sb.fuse_open(entry.inode, LINUX_O_RDWR), LINUX_EROFS);
    TestSandbox::assert_errno(
        sb.fuse_open(entry.inode, libc::O_RDONLY as u32 | LINUX_O_TRUNC),
        LINUX_EROFS,
    );
}

#[test]
fn test_readonly_rejects_create_and_mkdir() {
    let sb = readonly_sandbox();

    TestSandbox::assert_errno(sb.fuse_create_root("new.txt"), LINUX_EROFS);
    TestSandbox::assert_errno(sb.fuse_mkdir_root("new-dir"), LINUX_EROFS);
}

#[test]
fn test_readonly_rejects_write_and_setattr() {
    let sb = readonly_sandbox();
    sb.host_create_file("data.txt", b"readonly data");

    let entry = sb.lookup_root("data.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    TestSandbox::assert_errno(
        sb.fuse_write(entry.inode, handle, b"mutate", 0),
        LINUX_EROFS,
    );

    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = 0o755;
    TestSandbox::assert_errno(
        sb.fs
            .setattr(sb.ctx(), entry.inode, attr, None, SetattrValid::MODE),
        LINUX_EROFS,
    );
}

#[test]
fn test_readonly_rejects_fallocate_and_copyfilerange() {
    let sb = readonly_sandbox();
    sb.host_create_file("src.txt", b"copy this data");
    sb.host_create_file("dst.txt", b"");

    let src = sb.lookup_root("src.txt").unwrap();
    let dst = sb.lookup_root("dst.txt").unwrap();
    let src_handle = sb.fuse_open(src.inode, libc::O_RDONLY as u32).unwrap();
    let dst_handle = sb.fuse_open(dst.inode, libc::O_RDONLY as u32).unwrap();

    TestSandbox::assert_errno(
        sb.fs.fallocate(sb.ctx(), dst.inode, dst_handle, 0, 0, 4096),
        LINUX_EROFS,
    );
    TestSandbox::assert_errno(
        sb.fs.copyfilerange(
            sb.ctx(),
            src.inode,
            src_handle,
            0,
            dst.inode,
            dst_handle,
            0,
            14,
            0,
        ),
        LINUX_EROFS,
    );
}
