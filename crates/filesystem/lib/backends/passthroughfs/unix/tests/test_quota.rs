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
fn statfs_reports_baseline_plus_quota() {
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
    // df total = baseline + quota; available = quota - used.
    assert_eq!(total, baseline + limit);
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
fn deleting_then_rewriting_reclaims_budget() {
    // After filling the quota and removing the file, the recount reclaims the
    // freed space so the guest can write again — no permanent exhaustion.
    let sb = quota_fs(64 * 1024);
    let (entry, handle) = sb.fuse_create_root("a").unwrap();
    sb.fuse_write(entry.inode, handle, &vec![0u8; 64 * 1024], 0)
        .unwrap();
    // Free it on the host (models the guest deleting its file).
    std::fs::remove_file(sb.root.join("a")).unwrap();

    let (entry2, handle2) = sb.fuse_create_root("b").unwrap();
    let n = sb
        .fuse_write(entry2.inode, handle2, &vec![0u8; 64 * 1024], 0)
        .unwrap();
    assert_eq!(n, 64 * 1024);
}
