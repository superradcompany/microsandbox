use super::*;

#[test]
fn test_open_rdonly() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    assert!(handle > 0);
}

#[test]
fn test_open_rdwr() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDWR as u32).unwrap();
    assert!(handle > 0);
}

#[test]
fn test_write_read_roundtrip() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("rw.txt").unwrap();
    let data = b"hello world 12345";
    let written = sb.fuse_write(entry.inode, handle, data, 0).unwrap();
    assert_eq!(written, data.len());
    let read_data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&read_data[..], data);
}

#[test]
fn test_write_at_offset() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("offset.txt").unwrap();
    let data = b"offset_data";
    sb.fuse_write(entry.inode, handle, data, 100).unwrap();
    let read_data = sb
        .fuse_read(entry.inode, handle, data.len() as u32, 100)
        .unwrap();
    assert_eq!(&read_data[..], data);
}

#[test]
fn test_read_empty_file() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("empty.txt").unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn test_read_beyond_eof() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("small.txt").unwrap();
    sb.fuse_write(entry.inode, handle, &[0xBB; 10], 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 1024, 100).unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn test_read_partial() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("partial.txt").unwrap();
    let full_data: Vec<u8> = (0..100u8).collect();
    sb.fuse_write(entry.inode, handle, &full_data, 0).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 10, 0).unwrap();
    assert_eq!(data.len(), 10);
    assert_eq!(&data[..], &full_data[..10]);
}

#[test]
fn test_multiple_writes() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("multi.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"aaaaaaaaaa", 0)
        .unwrap();
    sb.fuse_write(entry.inode, handle, b"bbbbbbbbbb", 10)
        .unwrap();
    let data = sb.fuse_read(entry.inode, handle, 20, 0).unwrap();
    assert_eq!(data.len(), 20);
    assert_eq!(&data[..10], b"aaaaaaaaaa");
    assert_eq!(&data[10..], b"bbbbbbbbbb");
}

#[test]
fn test_large_write() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("large.txt").unwrap();
    let data = vec![0xCCu8; 1_000_000];
    let written = sb.fuse_write(entry.inode, handle, &data, 0).unwrap();
    assert_eq!(written, data.len());
    let read_data = sb
        .fuse_read(entry.inode, handle, data.len() as u32, 0)
        .unwrap();
    assert_eq!(read_data.len(), data.len());
    assert_eq!(read_data, data);
}

#[test]
fn test_write_init_rejected() {
    let sb = TestSandbox::new();
    let mut reader = MockZeroCopyReader::new(vec![0u8; 10]);
    let result = sb.fs.write(
        sb.ctx(),
        INIT_INODE,
        INIT_HANDLE,
        &mut reader,
        10,
        0,
        None,
        false,
        false,
        0,
    );
    TestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_read_invalid_handle() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let result = sb.fuse_read(entry.inode, 99999, 1024, 0);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_write_invalid_handle() {
    let sb = TestSandbox::new();
    let (entry, _handle) = sb.fuse_create_root("file.txt").unwrap();
    let result = sb.fuse_write(entry.inode, 99999, b"data", 0);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_flush() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("flush.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    let result = sb.fs.flush(sb.ctx(), entry.inode, handle, 0);
    assert!(result.is_ok());
}

#[test]
fn test_flush_init_noop() {
    let sb = TestSandbox::new();
    let result = sb.fs.flush(sb.ctx(), INIT_INODE, INIT_HANDLE, 0);
    assert!(result.is_ok());
}

#[test]
fn test_release_removes_handle() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("release.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
    sb.fs
        .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // After release, reading with the old handle should fail.
    let result = sb.fuse_read(entry.inode, handle, 1024, 0);
    TestSandbox::assert_errno(result, LINUX_EBADF);
}

#[test]
fn test_open_host_file() {
    let sb = TestSandbox::new();
    sb.host_create_file("hostfile.txt", b"host content");
    let entry = sb.lookup_root("hostfile.txt").unwrap();
    let handle = sb.fuse_open(entry.inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(entry.inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"host content");
}

#[test]
fn test_getattr_via_handle_after_forget() {
    let sb = TestSandbox::new();
    let (entry, handle) = sb.fuse_create_root("handle_stat.txt").unwrap();
    sb.fuse_write(entry.inode, handle, b"abcdef", 0).unwrap();

    sb.fs.forget(sb.ctx(), entry.inode, 1);

    let result = sb.fs.getattr(sb.ctx(), entry.inode, None);
    TestSandbox::assert_errno(result, LINUX_EBADF);

    let (st, _) = sb.fs.getattr(sb.ctx(), entry.inode, Some(handle)).unwrap();
    assert_eq!(st.st_size, 6);
}

/// Trace the real handler sequence, including repeated guest closes on one
/// handle. Run on Linux with strace installed; no mock descriptor layer needed.
#[test]
#[cfg(target_os = "linux")]
fn test_create_write_close_budget() {
    const CHILD: &str = "MSB_TEST_CLOSE_BUDGET_CHILD";
    const TEST_NAME: &str =
        "backends::passthroughfs::unix::tests::test_file_ops::test_create_write_close_budget";

    if std::env::var_os(CHILD).is_some() {
        let sb = TestSandbox::new();
        let (entry, handle) = sb.fuse_create_root("close-budget.txt").unwrap();
        sb.fuse_write(entry.inode, handle, b"data", 0).unwrap();
        let mut attr: crate::stat64 = unsafe { std::mem::zeroed() };
        attr.st_size = 3;
        sb.fs
            .setattr(
                sb.ctx(),
                entry.inode,
                attr,
                Some(handle),
                SetattrValid::SIZE,
            )
            .unwrap();
        sb.fs
            .setxattr(sb.ctx(), entry.inode, c"user.budget", b"value", 0)
            .unwrap();
        assert!(matches!(
            sb.fs.getxattr(sb.ctx(), entry.inode, c"user.budget", 10).unwrap(),
            GetxattrReply::Value(value) if value == b"value"
        ));
        sb.fs.listxattr(sb.ctx(), entry.inode, 0).unwrap();
        sb.fs
            .removexattr(sb.ctx(), entry.inode, c"user.budget")
            .unwrap();
        for _ in 0..4 {
            sb.fs.flush(sb.ctx(), entry.inode, handle, 0).unwrap();
        }
        assert_eq!(sb.fuse_read(entry.inode, handle, 10, 0).unwrap(), b"dat");
        sb.fs.fsync(sb.ctx(), entry.inode, false, handle).unwrap();
        sb.fs.fsync(sb.ctx(), entry.inode, true, handle).unwrap();
        sb.fs
            .release(sb.ctx(), entry.inode, 0, handle, false, false, None)
            .unwrap();
        return;
    }

    assert!(
        std::process::Command::new("strace")
            .arg("--version")
            .status()
            .expect("Linux close-budget tests require strace (apt-get install strace)")
            .success()
    );
    let trace = tempfile::NamedTempFile::new().unwrap();
    let output = std::process::Command::new("strace")
        .args(["-f", "-yy", "-e", "trace=close,dup,fsync,fdatasync", "-o"])
        .arg(trace.path())
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = std::fs::read_to_string(trace.path()).unwrap();
    let file_calls: Vec<_> = calls
        .lines()
        .filter(|line| line.contains("/close-budget.txt>"))
        .collect();
    let closes = file_calls
        .iter()
        .filter(|line| line.contains("close("))
        .count();
    assert_eq!(closes, 5, "{calls}");
    assert!(
        file_calls.iter().any(|line| line.contains("fsync(")),
        "{calls}"
    );
    assert!(
        file_calls.iter().any(|line| line.contains("fdatasync(")),
        "{calls}"
    );
}

/// Inject a backing close error at the syscall boundary, without mocking the
/// filesystem handler. strace path filtering leaves unrelated closes alone.
#[test]
#[cfg(target_os = "linux")]
fn test_flush_reports_backing_close_errors_by_default() {
    const CHILD_ROOT: &str = "MSB_TEST_FLUSH_ERROR_ROOT";
    const CHILD_ERRNO: &str = "MSB_TEST_FLUSH_ERROR_ERRNO";
    const TEST_NAME: &str = "backends::passthroughfs::unix::tests::test_file_ops::test_flush_reports_backing_close_errors_by_default";

    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let errno = std::env::var(CHILD_ERRNO).unwrap();
        let sb = TestSandbox::with_config(|mut cfg| {
            cfg.root_dir = root.into();
            cfg
        });
        let (entry, handle) = sb.fuse_create_root("flush-error.txt").unwrap();
        sb.fuse_write(entry.inode, handle, b"pending write", 0)
            .unwrap();
        let result = sb.fs.flush(sb.ctx(), entry.inode, handle, 0);
        TestSandbox::assert_errno(result, errno.parse().unwrap());
        return;
    }

    for (code, errno) in [("28", "ENOSPC"), ("5", "EIO")] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("flush-error.txt");
        std::fs::write(&path, b"").unwrap();
        let output = std::process::Command::new("strace")
            .args(["-f", "-yy", "-P"])
            .arg(&path)
            .args(["-e", "trace=close", "-e"])
            .arg(format!("inject=close:error={errno}:when=1"))
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ROOT, root.path())
            .env(CHILD_ERRNO, code)
            .output()
            .expect("Linux flush error tests require strace (apt-get install strace)");
        let trace = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{code}: {trace}\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            trace.contains("INJECTED"),
            "fault did not reach the backing close: {trace}"
        );
    }
}
