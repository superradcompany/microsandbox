//! End-to-end quota invariants, driven through the real FUSE handlers
//! (`create` / `write` / `statfs`) against a quota'd `PassthroughFs`.

use super::*;

/// Linux `ENOSPC`, the errno the quota returns when a write is refused.
const ENOSPC: i32 = 28;

/// Build a test sandbox whose mount has a `limit`-byte guest-write budget.
fn quota_fs(limit: u64) -> TestSandbox {
    TestSandbox::with_config(|mut cfg| {
        cfg.quota_bytes = Some(limit);
        cfg
    })
}

#[test]
fn writes_within_quota_succeed() {
    let sb = quota_fs(64 * 1024);
    let (entry, handle) = sb.fuse_create_root("a").unwrap();
    let data = vec![0u8; 64 * 1024];
    let n = sb.fuse_write(entry.inode, handle, &data, 0).unwrap();
    assert_eq!(n, data.len());
}

#[test]
fn writes_past_quota_return_enospc() {
    let sb = quota_fs(64 * 1024);
    let (entry, handle) = sb.fuse_create_root("a").unwrap();
    // Fill the budget exactly.
    sb.fuse_write(entry.inode, handle, &vec![0u8; 64 * 1024], 0)
        .unwrap();
    // One more byte past the cap is refused with ENOSPC.
    let err = sb
        .fuse_write(entry.inode, handle, &[0u8; 1], 64 * 1024)
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(ENOSPC));
}

#[test]
fn overwrites_in_place_do_not_drain_quota() {
    // The heartbeat invariant: rewriting the same region forever stays in
    // budget because only growth is charged, not write volume.
    let sb = quota_fs(64 * 1024);
    let (entry, handle) = sb.fuse_create_root("hb").unwrap();
    let chunk = vec![0u8; 1024];
    for _ in 0..1000 {
        // 1000 * 1 KiB = 1 MiB of writes, but the file never grows past 1 KiB.
        sb.fuse_write(entry.inode, handle, &chunk, 0).unwrap();
    }
}

#[test]
fn baseline_files_are_not_charged() {
    let sb = quota_fs(64 * 1024);
    // A pre-existing host file larger than the quota itself forms the baseline.
    sb.host_create_file("preexisting.bin", &vec![0u8; 1024 * 1024]);
    // The guest can still add a full quota's worth beyond it.
    let (entry, handle) = sb.fuse_create_root("new").unwrap();
    let n = sb
        .fuse_write(entry.inode, handle, &vec![0u8; 64 * 1024], 0)
        .unwrap();
    assert_eq!(n, 64 * 1024);
}

#[test]
fn statfs_reports_guest_budget_without_host_baseline() {
    let limit = 64 * 1024u64;
    let baseline = 32 * 1024u64;
    let used = 16 * 1024u64;
    let sb = quota_fs(limit);
    sb.host_create_file("base.bin", &vec![0u8; baseline as usize]);

    let (entry, handle) = sb.fuse_create_root("g").unwrap();
    sb.fuse_write(entry.inode, handle, &vec![0u8; used as usize], 0)
        .unwrap();

    let st = sb.fs.statfs(sb.ctx(), ROOT_INODE).unwrap();
    let frsize = st.f_frsize as u64;
    let total = st.f_blocks as u64 * frsize;
    let avail = st.f_bavail as u64 * frsize;
    // df reports the guest budget independently of pre-existing host data.
    assert_eq!(total, limit);
    assert_eq!(avail, limit - used);
}

#[test]
fn no_quota_means_unbounded() {
    let sb = TestSandbox::new(); // default config: no quota
    let (entry, handle) = sb.fuse_create_root("big").unwrap();
    let big = vec![0u8; 4 * 1024 * 1024];
    let n = sb.fuse_write(entry.inode, handle, &big, 0).unwrap();
    assert_eq!(n, big.len());
}

#[test]
fn unlinked_open_file_stays_charged_until_guest_releases_it() {
    let sb = quota_fs(4096);
    let (entry, handle) = sb.fuse_create_root("a").unwrap();
    sb.fuse_write(entry.inode, handle, &vec![0; 4096], 0)
        .unwrap();
    sb.fs.unlink(sb.ctx(), ROOT_INODE, c"a").unwrap();
    sb.fs.forget(sb.ctx(), entry.inode, 1);
    let (other, other_handle) = sb.fuse_create_root("b").unwrap();
    assert_eq!(
        sb.fuse_write(other.inode, other_handle, &[0], 0)
            .unwrap_err()
            .raw_os_error(),
        Some(ENOSPC)
    );
    sb.fs
        .release(
            sb.ctx(),
            entry.inode,
            LINUX_O_RDWR,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
    assert_eq!(sb.fs.quota.as_ref().unwrap().used(), 0);
    sb.fuse_write(other.inode, other_handle, &vec![0; 4096], 0)
        .unwrap();
}

#[test]
fn truncate_and_open_trunc_refund_without_waiting_for_quota_pressure() {
    let sb = quota_fs(8192);
    let (entry, handle) = sb.fuse_create_root("a").unwrap();
    sb.fuse_write(entry.inode, handle, &vec![0; 8192], 0)
        .unwrap();
    let mut attr = sb
        .fs
        .getattr(sb.ctx(), entry.inode, Some(handle))
        .unwrap()
        .0;
    attr.st_size = 4096;
    sb.fs
        .setattr(
            sb.ctx(),
            entry.inode,
            attr,
            Some(handle),
            SetattrValid::SIZE,
        )
        .unwrap();
    assert_eq!(sb.fs.quota.as_ref().unwrap().used(), 4096);
    sb.fuse_open(entry.inode, LINUX_O_RDWR | LINUX_O_TRUNC)
        .unwrap();
    assert_eq!(sb.fs.quota.as_ref().unwrap().used(), 0);
}

#[test]
fn charged_inode_survives_forget_and_hardlink_alias() {
    let sb = quota_fs(8192);
    let (entry, handle) = sb.fuse_create_root("a").unwrap();
    sb.fuse_write(entry.inode, handle, &vec![0; 4096], 0)
        .unwrap();
    sb.fs
        .release(
            sb.ctx(),
            entry.inode,
            LINUX_O_RDWR,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
    sb.fs.forget(sb.ctx(), entry.inode, 1);
    std::fs::hard_link(sb.root.join("a"), sb.root.join("alias")).unwrap();
    let alias = sb.fs.lookup(sb.ctx(), ROOT_INODE, c"alias").unwrap();
    assert_eq!(alias.inode, entry.inode);
    let handle = sb.fuse_open(alias.inode, LINUX_O_RDWR).unwrap();
    sb.fuse_write(alias.inode, handle, &vec![0; 4096], 0)
        .unwrap();
    assert_eq!(sb.fs.quota.as_ref().unwrap().used(), 4096);
    sb.fuse_write(alias.inode, handle, &vec![0; 4096], 4096)
        .unwrap();
    assert_eq!(sb.fs.quota.as_ref().unwrap().used(), 8192);
}

#[test]
fn host_unlink_is_reclaimed_after_closed_forgotten_file() {
    let sb = quota_fs(4096);
    let (entry, handle) = sb.fuse_create_root("a").unwrap();
    sb.fuse_write(entry.inode, handle, &vec![0; 4096], 0)
        .unwrap();
    sb.fs
        .release(
            sb.ctx(),
            entry.inode,
            LINUX_O_RDWR,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
    sb.fs.forget(sb.ctx(), entry.inode, 1);
    std::fs::remove_file(sb.root.join("a")).unwrap();
    let (other, other_handle) = sb.fuse_create_root("b").unwrap();
    sb.fuse_write(other.inode, other_handle, &vec![0; 4096], 0)
        .unwrap();
}

#[test]
fn closed_charged_inode_survives_snapshot_and_restored_truncation() {
    let sb = quota_fs(8192);
    let (entry, handle) = sb.fuse_create_root("a").unwrap();
    sb.fuse_write(entry.inode, handle, &vec![0; 4096], 0)
        .unwrap();
    sb.fs
        .release(
            sb.ctx(),
            entry.inode,
            LINUX_O_RDWR,
            handle,
            false,
            false,
            None,
        )
        .unwrap();
    sb.fs.forget(sb.ctx(), entry.inode, 1);
    let state = sb.fs.capture_state().unwrap();
    let restored = PassthroughFs::new(PassthroughConfig {
        root_dir: sb.root.clone(),
        quota_bytes: Some(8192),
        ..Default::default()
    })
    .unwrap();
    restored.restore_state(&state).unwrap();
    assert_eq!(restored.quota.as_ref().unwrap().used(), 4096);
    let lookup = restored.lookup(sb.ctx(), ROOT_INODE, c"a").unwrap();
    assert_eq!(lookup.inode, entry.inode);
    restored
        .open(sb.ctx(), lookup.inode, false, LINUX_O_RDWR | LINUX_O_TRUNC)
        .unwrap();
    assert_eq!(restored.quota.as_ref().unwrap().used(), 0);
}

#[test]
fn deleting_preexisting_host_data_does_not_refund_guest_usage() {
    let sb = quota_fs(4096);
    sb.host_create_file("host", &vec![0; 8192]);
    let (entry, handle) = sb.fuse_create_root("guest").unwrap();
    sb.fuse_write(entry.inode, handle, &vec![0; 4096], 0)
        .unwrap();
    std::fs::remove_file(sb.root.join("host")).unwrap();
    assert_eq!(
        sb.fuse_write(entry.inode, handle, &[0], 4096)
            .unwrap_err()
            .raw_os_error(),
        Some(ENOSPC)
    );
    assert_eq!(sb.fs.quota.as_ref().unwrap().used(), 4096);
}

#[test]
fn create_with_trunc_refunds_and_reports_updated_size() {
    let sb = quota_fs(4096);
    let (entry, handle) = sb.fuse_create_root("a").unwrap();
    sb.fuse_write(entry.inode, handle, &vec![0; 4096], 0)
        .unwrap();
    let (truncated, _) = sb
        .fuse_create_flags(ROOT_INODE, "a", 0o644, false, LINUX_O_RDWR | LINUX_O_TRUNC)
        .unwrap();
    assert_eq!(truncated.attr.st_size, 0);
    assert_eq!(sb.fs.quota.as_ref().unwrap().used(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn short_copy_and_failed_allocation_settle_quota() {
    let sb = quota_fs(4096);
    sb.host_create_file("source", b"abc");
    let source = sb.fs.lookup(sb.ctx(), ROOT_INODE, c"source").unwrap();
    let read_handle = sb.fuse_open(source.inode, 0).unwrap();
    let (dest, write_handle) = sb.fuse_create_root("dest").unwrap();
    let copied = sb
        .fs
        .copyfilerange(
            sb.ctx(),
            source.inode,
            read_handle,
            0,
            dest.inode,
            write_handle,
            0,
            4096,
            0,
        )
        .unwrap();
    assert_eq!(copied, 3);
    assert_eq!(sb.fs.quota.as_ref().unwrap().used(), 3);
    assert!(
        sb.fs
            .fallocate(sb.ctx(), dest.inode, write_handle, 0x8000_0000, 0, 4096)
            .is_err()
    );
    assert_eq!(sb.fs.quota.as_ref().unwrap().used(), 3);
}

#[cfg(target_os = "linux")]
#[test]
fn file_backed_symlink_consumes_guest_budget() {
    let sb = quota_fs(4);
    let entry = sb
        .fs
        .symlink(
            sb.ctx(),
            c"four",
            ROOT_INODE,
            c"link",
            Extensions::default(),
        )
        .unwrap();
    assert_eq!(entry.attr.st_size, 4);
    assert_eq!(sb.fs.quota.as_ref().unwrap().used(), 4);
    assert_eq!(
        sb.fs
            .symlink(
                sb.ctx(),
                c"x",
                ROOT_INODE,
                c"too-much",
                Extensions::default()
            )
            .err()
            .unwrap()
            .raw_os_error(),
        Some(ENOSPC)
    );
    assert!(!sb.root.join("too-much").exists());
}
