//! DAX window mapping tests (`setupmapping`/`removemapping`).

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Set up and tear down a DAX mapping over a regular file.
#[test]
#[cfg(target_os = "linux")]
fn setupmapping_maps_file_into_window() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.inject_init = false;
        cfg
    });
    let len = 4096usize;
    let content: Vec<u8> = (0..len).map(|i| i as u8).collect();
    sb.host_create_file("data", &content);
    let entry = sb.lookup_root("data").unwrap();

    // Stand-in for the VMM's DAX window: page-aligned, `len` bytes.
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(base, libc::MAP_FAILED, "window mmap failed");
    let host_shm_base = base as u64;

    sb.fs
        .setupmapping(
            sb.ctx(),
            entry.inode,
            0,
            0,
            len as u64,
            0,
            0,
            host_shm_base,
            len as u64,
        )
        .expect("setupmapping");

    // The window now exposes the file contents.
    let mapped = unsafe { std::slice::from_raw_parts(base as *const u8, len) };
    assert_eq!(mapped, &content[..]);

    sb.fs
        .removemapping(
            sb.ctx(),
            vec![crate::RemovemappingOne {
                moffset: 0,
                len: len as u64,
            }],
            host_shm_base,
            len as u64,
        )
        .expect("removemapping");

    unsafe { libc::munmap(base, len) };
}

/// A mapping that runs past the window is rejected before `mmap`.
#[test]
#[cfg(target_os = "linux")]
fn setupmapping_rejects_out_of_window_mapping() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.inject_init = false;
        cfg
    });
    sb.host_create_file("data", &[0u8; 4096]);
    let entry = sb.lookup_root("data").unwrap();

    let len = 4096usize;
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(base, libc::MAP_FAILED);

    let result = sb.fs.setupmapping(
        sb.ctx(),
        entry.inode,
        0,
        0,
        len as u64,
        0,
        len as u64, // moffset + len == 2 * len > shm_size
        base as u64,
        len as u64,
    );
    TestSandbox::assert_errno(result, LINUX_EINVAL);

    unsafe { libc::munmap(base, len) };
}

/// A read-only mount refuses writable mappings but still serves read-only ones.
#[test]
#[cfg(target_os = "linux")]
fn setupmapping_honors_readonly() {
    const SETUPMAPPING_FLAG_WRITE: u64 = 0x1;

    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.inject_init = false;
        cfg.readonly = true;
        cfg
    });
    let len = 4096usize;
    sb.host_create_file("data", &[0u8; 4096]);
    let entry = sb.lookup_root("data").unwrap();

    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(base, libc::MAP_FAILED);
    let host_shm_base = base as u64;

    let writable = sb.fs.setupmapping(
        sb.ctx(),
        entry.inode,
        0,
        0,
        len as u64,
        SETUPMAPPING_FLAG_WRITE,
        0,
        host_shm_base,
        len as u64,
    );
    TestSandbox::assert_errno(writable, LINUX_EROFS);

    // A read-only request is still honored.
    sb.fs
        .setupmapping(
            sb.ctx(),
            entry.inode,
            0,
            0,
            len as u64,
            0,
            0,
            host_shm_base,
            len as u64,
        )
        .expect("read-only mapping");

    sb.fs
        .removemapping(
            sb.ctx(),
            vec![crate::RemovemappingOne {
                moffset: 0,
                len: len as u64,
            }],
            host_shm_base,
            len as u64,
        )
        .expect("removemapping");

    unsafe { libc::munmap(base, len) };
}

/// A writable mapping must not upgrade a read-only handle's access.
#[test]
#[cfg(target_os = "linux")]
fn setupmapping_requires_a_writable_handle() {
    const SETUPMAPPING_FLAG_WRITE: u64 = 0x1;

    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.inject_init = false;
        cfg
    });
    let len = 4096usize;
    sb.host_create_file("data", &[0u8; 4096]);
    let entry = sb.lookup_root("data").unwrap();

    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(base, libc::MAP_FAILED);
    let host_shm_base = base as u64;

    let readonly_handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let writable = sb.fs.setupmapping(
        sb.ctx(),
        entry.inode,
        readonly_handle,
        0,
        len as u64,
        SETUPMAPPING_FLAG_WRITE,
        0,
        host_shm_base,
        len as u64,
    );
    TestSandbox::assert_errno(writable, LINUX_EACCES);

    // The same read-only handle may still install a read-only mapping.
    sb.fs
        .setupmapping(
            sb.ctx(),
            entry.inode,
            readonly_handle,
            0,
            len as u64,
            0,
            0,
            host_shm_base,
            len as u64,
        )
        .expect("read-only mapping");

    sb.fs
        .removemapping(
            sb.ctx(),
            vec![crate::RemovemappingOne {
                moffset: 0,
                len: len as u64,
            }],
            host_shm_base,
            len as u64,
        )
        .expect("removemapping");

    unsafe { libc::munmap(base, len) };
}

/// A write-only handle must not authorize a read+write mapping.
#[test]
#[cfg(target_os = "linux")]
fn setupmapping_rejects_a_write_only_handle() {
    const SETUPMAPPING_FLAG_WRITE: u64 = 0x1;

    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.inject_init = false;
        cfg
    });
    let len = 4096usize;
    sb.host_create_file("data", &[0u8; 4096]);
    let entry = sb.lookup_root("data").unwrap();

    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(base, libc::MAP_FAILED);
    let host_shm_base = base as u64;

    let write_only_handle = sb.fuse_open(entry.inode, libc::O_WRONLY as u32).unwrap();
    let result = sb.fs.setupmapping(
        sb.ctx(),
        entry.inode,
        write_only_handle,
        0,
        len as u64,
        SETUPMAPPING_FLAG_WRITE,
        0,
        host_shm_base,
        len as u64,
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);

    unsafe { libc::munmap(base, len) };
}

/// A handle for one file must not authorize a mapping of another.
#[test]
#[cfg(target_os = "linux")]
fn setupmapping_rejects_a_handle_for_another_inode() {
    const SETUPMAPPING_FLAG_WRITE: u64 = 0x1;

    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.inject_init = false;
        cfg
    });
    let len = 4096usize;
    sb.host_create_file("a", &[0u8; 4096]);
    sb.host_create_file("b", &[0u8; 4096]);
    let a = sb.lookup_root("a").unwrap();
    let b = sb.lookup_root("b").unwrap();

    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(base, libc::MAP_FAILED);
    let host_shm_base = base as u64;

    let handle_a = sb.fuse_open(a.inode, libc::O_RDWR as u32).unwrap();
    let result = sb.fs.setupmapping(
        sb.ctx(),
        b.inode,
        handle_a,
        0,
        len as u64,
        SETUPMAPPING_FLAG_WRITE,
        0,
        host_shm_base,
        len as u64,
    );
    TestSandbox::assert_errno(result, LINUX_EBADF);

    unsafe { libc::munmap(base, len) };
}
