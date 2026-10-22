//! End-to-end coverage for bind-mount `hide_path` policy durability across restore.
//!
//! This test boots real microVMs and therefore stays ignored during ordinary
//! workspace tests. Run it explicitly on a supported host with:
//!
//! ```sh
//! cargo test -p microsandbox --test hide_path_restore_roundtrip -- --ignored
//! ```

use microsandbox::{Sandbox, Snapshot};
use test_utils::msb_test;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn cleanup(name: &str) {
    if let Ok(handle) = Sandbox::get(name).await {
        let _ = handle.kill().await;
        let _ = handle.remove().await;
    }
}

/// A bind `hide_path` policy must be captured in the snapshot manifest, re-applied on
/// restore, and must refuse a restore that drops it.
#[msb_test]
async fn hide_path_policy_survives_snapshot_restore_and_hides_the_path() {
    let suffix = std::process::id();
    let source_name = format!("hide_path-src-{suffix}");
    let child_name = format!("hide_path-child-{suffix}");
    let snapshot_name = format!("hide_path-snap-{suffix}");

    let host = tempfile::tempdir().unwrap();
    std::fs::write(host.path().join(".env"), b"secret").unwrap();
    std::fs::write(host.path().join("visible.txt"), b"ok").unwrap();

    cleanup(&source_name).await;
    cleanup(&child_name).await;

    let source = Sandbox::builder(&source_name)
        .image("alpine:3.20")
        .cpus(1)
        .memory(512)
        .replace()
        .volume("/data", |mount| mount.bind(host.path()).hide_path([".env"]))
        .create()
        .await
        .expect("create hide-path-bearing source");

    let live = source
        .shell("test ! -e /data/.env && test -f /data/visible.txt")
        .await
        .expect("exercise source hide-path policy");
    assert!(
        live.status().success,
        "source must hide .env: stdout=`{}` stderr=`{}`",
        live.stdout().unwrap_or_default(),
        live.stderr().unwrap_or_default()
    );

    let snapshot = Snapshot::builder(&snapshot_name)
        .from_sandbox(&source_name)
        .create()
        .await
        .expect("snapshot");

    // (a) the hide-path policy round-trips through the snapshot manifest.
    let policies = snapshot
        .manifest()
        .external_mount_policies()
        .expect("read captured hide-path policy");
    let has_policy = policies.as_ref().is_some_and(|policies| {
        policies
            .iter()
            .any(|policy| policy.guest_path == "/data" && policy.hide_path == [".env".to_string()])
    });
    assert!(
        has_policy,
        "captured hide-path policy is missing: {policies:?}"
    );

    let _ = source.stop().await;
    cleanup(&source_name).await;

    // (b) restoring with the hide-path list preserved keeps .env hidden.
    let child = Sandbox::restore(&snapshot_name)
        .name(&child_name)
        .cpus(1)
        .memory(512)
        .volume("/data", |mount| mount.bind(host.path()).hide_path([".env"]))
        .restore()
        .await
        .expect("restore with preserved hide_path");
    let restored = child
        .shell("test ! -e /data/.env && test -f /data/visible.txt")
        .await
        .expect("exercise restored hide-path policy");
    assert!(
        restored.status().success,
        "restored sandbox must hide .env: stdout=`{}` stderr=`{}`",
        restored.stdout().unwrap_or_default(),
        restored.stderr().unwrap_or_default()
    );
    let _ = child.stop().await;
    cleanup(&child_name).await;

    // A restore that drops the captured hide-path list must be refused, never silently weaken it.
    let weakened = Sandbox::restore(&snapshot_name)
        .name(&child_name)
        .volume("/data", |mount| mount.bind(host.path()))
        .restore()
        .await;
    assert!(
        weakened.is_err(),
        "restore that drops the captured hide-path list must be refused"
    );
    if let Ok(child) = weakened {
        let _ = child.stop().await;
    }
    cleanup(&child_name).await;
}

/// A full (execution-state) snapshot must capture and enforce the bind hide-path policy
/// too. The disk path records it directly in the manifest, while the full path
/// resolves external mounts from the checkpoint closure, so a regression there
/// would silently re-expose a hidden path on restore.
#[msb_test]
async fn full_snapshot_captures_bind_hide_path_and_refuses_a_weakened_restore() {
    let suffix = std::process::id();
    let source_name = format!("hide_path-full-src-{suffix}");
    let child_name = format!("hide_path-full-child-{suffix}");
    let snapshot_name = format!("hide_path-full-snap-{suffix}");

    let host = tempfile::tempdir().unwrap();
    std::fs::write(host.path().join(".env"), b"secret").unwrap();
    std::fs::write(host.path().join("visible.txt"), b"ok").unwrap();

    cleanup(&source_name).await;
    cleanup(&child_name).await;

    let source = Sandbox::builder(&source_name)
        .image("alpine:3.20")
        .cpus(1)
        .memory(512)
        .replace()
        .volume("/data", |mount| mount.bind(host.path()).hide_path([".env"]))
        .create()
        .await
        .expect("create hide-path-bearing source");

    // Full capture requires the source to be running, so snapshot before stopping.
    let snapshot = Snapshot::builder(&snapshot_name)
        .from_sandbox(&source_name)
        .full()
        .create()
        .await
        .expect("full snapshot");

    // The full manifest resolves external mounts from the closure, but the hide_path
    // policy must still be recorded for restore to compare.
    let policies = snapshot
        .manifest()
        .external_mount_policies()
        .expect("read captured hide-path policy");
    let has_policy = policies.as_ref().is_some_and(|policies| {
        policies
            .iter()
            .any(|policy| policy.guest_path == "/data" && policy.hide_path == [".env".to_string()])
    });
    assert!(
        has_policy,
        "full snapshot must capture the bind hide-path policy: {policies:?}"
    );

    let _ = source.stop().await;
    cleanup(&source_name).await;

    // A full restore that drops the captured hide-path list must be refused.
    let weakened = Sandbox::restore(&snapshot_name)
        .name(&child_name)
        .volume("/data", |mount| mount.bind(host.path()))
        .restore()
        .await;
    let error = weakened
        .err()
        .expect("full restore that drops the captured hide-path list must be refused")
        .to_string();
    assert!(
        error.contains("weaken bind-mount hide-path policy"),
        "refusal must name the weakened hide-path policy: {error}"
    );
    cleanup(&child_name).await;
}
