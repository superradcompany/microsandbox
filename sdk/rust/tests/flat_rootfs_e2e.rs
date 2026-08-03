//! End-to-end coverage for the public flat-rootfs SDK API.
//!
//! This test boots real microVMs and therefore stays ignored during ordinary
//! workspace tests. Run it explicitly on a supported host with:
//!
//! ```sh
//! cargo test -p microsandbox --test flat_rootfs_e2e -- --ignored
//! ```

use microsandbox::{Sandbox, sandbox::FlatClone};
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

async fn create_flat(name: &str) -> Sandbox {
    Sandbox::builder(name)
        .image("alpine:3.20")
        .root_disk_with(|disk| disk.flat().size(512u32).clone_strategy(FlatClone::Copy))
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create flat-rootfs sandbox through the public SDK")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// A reusable flat artifact must boot as ext4, remain writable, and give each
/// sandbox an independent private disk rather than sharing guest mutations.
#[msb_test]
async fn public_sdk_boots_independent_flat_rootfs_sandboxes() {
    let suffix = std::process::id();
    let first_name = format!("flat-sdk-a-{suffix}");
    let second_name = format!("flat-sdk-b-{suffix}");
    cleanup(&first_name).await;
    cleanup(&second_name).await;

    let first = create_flat(&first_name).await;
    let first_result = first
        .shell(
            "set -eu; test \"$(grep ' / ' /proc/mounts | cut -d ' ' -f 3 | head -n 1)\" = ext4; printf first > /sdk-private-marker; test \"$(cat /sdk-private-marker)\" = first",
        )
        .await
        .expect("exercise first flat rootfs");
    assert!(
        first_result.status().success,
        "first guest check failed: stdout=`{}` stderr=`{}`",
        first_result.stdout().unwrap_or_default(),
        first_result.stderr().unwrap_or_default()
    );
    first.stop().await.expect("stop first sandbox");

    let second = create_flat(&second_name).await;
    let second_result = second
        .shell(
            "set -eu; test \"$(grep ' / ' /proc/mounts | cut -d ' ' -f 3 | head -n 1)\" = ext4; test ! -e /sdk-private-marker; printf second > /sdk-private-marker; test \"$(cat /sdk-private-marker)\" = second",
        )
        .await
        .expect("exercise second flat rootfs");
    let second_stdout = second_result.stdout().unwrap_or_default();
    let second_stderr = second_result.stderr().unwrap_or_default();
    let second_success = second_result.status().success;
    let _ = second.stop().await;
    cleanup(&first_name).await;
    cleanup(&second_name).await;

    assert!(
        second_success,
        "second guest check failed: stdout=`{second_stdout}` stderr=`{second_stderr}`"
    );
}
