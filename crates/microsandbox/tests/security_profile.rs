//! Integration tests for sandbox security profiles.
//!
//! These tests boot real microVMs and verify the default guest-root behavior
//! that Docker-in-Docker and sudo-like workflows depend on. They are
//! `#[ignore]`-gated via `#[msb_test]`; run with:
//!
//!     cargo nextest run -p microsandbox --test security_profile --run-ignored=only

use microsandbox::{Sandbox, sandbox::SecurityProfile};
use test_utils::msb_test;

const IMAGE: &str = "mirror.gcr.io/library/alpine";

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Default sandboxes preserve privilege elevation and guest mount semantics,
/// while restricted sandboxes opt into `no_new_privs` and drop mount capability.
#[msb_test]
async fn default_profile_keeps_guest_privileges_restricted_profile_hardens() {
    let default_name = "security-profile-default";
    let restricted_name = "security-profile-restricted";

    let default = Sandbox::builder(default_name)
        .image(IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .expect("create default sandbox");

    assert_no_new_privs(&default, "0").await;
    assert_mount_tmpfs(&default, true).await;
    default.stop_and_wait().await.expect("stop default");
    let _ = Sandbox::remove(default_name).await;

    let restricted = Sandbox::builder(restricted_name)
        .image(IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .security(SecurityProfile::Restricted)
        .create()
        .await
        .expect("create restricted sandbox");

    assert_no_new_privs(&restricted, "1").await;
    assert_mount_tmpfs(&restricted, false).await;
    restricted.stop_and_wait().await.expect("stop restricted");
    let _ = Sandbox::remove(restricted_name).await;
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn assert_no_new_privs(sandbox: &Sandbox, expected: &str) {
    let out = sandbox
        .shell("awk '/^NoNewPrivs:/{print $2}' /proc/self/status")
        .await
        .expect("read NoNewPrivs");
    assert_eq!(
        out.stdout().expect("utf8").trim(),
        expected,
        "unexpected NoNewPrivs value"
    );
}

async fn assert_mount_tmpfs(sandbox: &Sandbox, should_succeed: bool) {
    let out = sandbox
        .shell("mkdir -p /mnt/msb-security-profile && mount -t tmpfs tmpfs /mnt/msb-security-profile && umount /mnt/msb-security-profile")
        .await
        .expect("run mount probe");
    assert_eq!(
        out.status().success,
        should_succeed,
        "tmpfs mount probe returned stdout=`{}` stderr=`{}`",
        out.stdout().unwrap_or_default(),
        out.stderr().unwrap_or_default()
    );
}
