use super::*;

#[test]
fn test_lookup_file() {
    let sb = TestSandbox::new();
    sb.host_create_file("hello.txt", b"hello");
    let entry = sb.lookup_root("hello.txt").unwrap();
    assert!(entry.inode >= 3);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
}

#[test]
fn test_lookup_dir() {
    let sb = TestSandbox::new();
    sb.host_create_dir("subdir");
    let entry = sb.lookup_root("subdir").unwrap();
    assert!(entry.inode >= 3);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
}

#[test]
fn test_lookup_nonexistent() {
    let sb = TestSandbox::new();
    let result = sb.lookup_root("does_not_exist");
    TestSandbox::assert_errno(result, LINUX_ENOENT);
}

#[test]
fn test_lookup_same_file_same_inode() {
    let sb = TestSandbox::new();
    sb.host_create_file("file.txt", b"data");
    let e1 = sb.lookup_root("file.txt").unwrap();
    let e2 = sb.lookup_root("file.txt").unwrap();
    assert_eq!(e1.inode, e2.inode, "same file should return same inode");
}

#[test]
fn test_lookup_refcount_increment() {
    let sb = TestSandbox::new();
    sb.host_create_file("file.txt", b"data");
    let e1 = sb.lookup_root("file.txt").unwrap();
    let _e2 = sb.lookup_root("file.txt").unwrap();
    // After two lookups, refcount should be 2.
    // Forget once — inode should still be accessible.
    sb.fs.forget(sb.ctx(), e1.inode, 1);
    let result = sb.fs.getattr(sb.ctx(), e1.inode, None);
    assert!(
        result.is_ok(),
        "inode should still exist after partial forget"
    );
}

#[test]
fn test_forget_decrements_to_zero() {
    let sb = TestSandbox::new();
    sb.host_create_file("ephemeral.txt", b"gone");
    let entry = sb.lookup_root("ephemeral.txt").unwrap();
    // Single lookup gives refcount=1. Forget with count=1 removes it.
    sb.fs.forget(sb.ctx(), entry.inode, 1);
    let result = sb.fs.getattr(sb.ctx(), entry.inode, None);
    assert!(result.is_err(), "inode should be removed after forget to 0");
}

#[test]
fn test_forget_partial() {
    let sb = TestSandbox::new();
    sb.host_create_file("file.txt", b"data");
    // Three lookups = refcount 3.
    let e = sb.lookup_root("file.txt").unwrap();
    let _ = sb.lookup_root("file.txt").unwrap();
    let _ = sb.lookup_root("file.txt").unwrap();
    // Forget 2 — refcount should be 1, still accessible.
    sb.fs.forget(sb.ctx(), e.inode, 2);
    assert!(sb.fs.getattr(sb.ctx(), e.inode, None).is_ok());
}

#[test]
fn test_batch_forget_multiple() {
    let sb = TestSandbox::new();
    sb.host_create_file("a.txt", b"a");
    sb.host_create_file("b.txt", b"b");
    let ea = sb.lookup_root("a.txt").unwrap();
    let eb = sb.lookup_root("b.txt").unwrap();
    sb.fs
        .batch_forget(sb.ctx(), vec![(ea.inode, 1), (eb.inode, 1)]);
    assert!(sb.fs.getattr(sb.ctx(), ea.inode, None).is_err());
    assert!(sb.fs.getattr(sb.ctx(), eb.inode, None).is_err());
}

#[test]
fn test_batch_forget_skips_init() {
    let sb = TestSandbox::new();
    sb.fs.batch_forget(sb.ctx(), vec![(INIT_INODE, 100)]);
    // Init should still be accessible.
    assert!(sb.fs.getattr(sb.ctx(), INIT_INODE, None).is_ok());
}

#[test]
fn test_lookup_nested() {
    let sb = TestSandbox::new();
    sb.host_create_dir("dir");
    sb.host_create_file("dir/nested.txt", b"nested");
    let dir_entry = sb.lookup_root("dir").unwrap();
    let file_entry = sb.lookup(dir_entry.inode, "nested.txt").unwrap();
    assert!(file_entry.inode >= 3);
    let mode = file_entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
}

#[test]
fn test_lookup_after_forget() {
    let sb = TestSandbox::new();
    sb.host_create_file("file.txt", b"data");
    let e1 = sb.lookup_root("file.txt").unwrap();
    let old_inode = e1.inode;
    sb.fs.forget(sb.ctx(), old_inode, 1);
    // After forget to zero, the inode is evicted from the table.
    // Re-lookup must allocate a fresh synthetic inode number.
    let e2 = sb.lookup_root("file.txt").unwrap();
    assert_ne!(
        e2.inode, old_inode,
        "re-lookup after full forget should allocate a fresh inode, not reuse the old one"
    );
    assert!(e2.inode >= 3);
}

#[test]
fn test_lookup_two_different_files() {
    let sb = TestSandbox::new();
    sb.host_create_file("one.txt", b"1");
    sb.host_create_file("two.txt", b"2");
    let e1 = sb.lookup_root("one.txt").unwrap();
    let e2 = sb.lookup_root("two.txt").unwrap();
    assert_ne!(e1.inode, e2.inode);
}

#[test]
fn test_getattr_after_lookup() {
    let sb = TestSandbox::new();
    sb.host_create_file("check.txt", b"check");
    let entry = sb.lookup_root("check.txt").unwrap();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), entry.inode, None).unwrap();
    // The stat should be consistent with the entry's attr.
    assert_eq!(
        st.st_mode as u32 & libc::S_IFMT as u32,
        entry.attr.st_mode as u32 & libc::S_IFMT as u32
    );
}
