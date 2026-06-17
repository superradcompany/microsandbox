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
// Functions
//--------------------------------------------------------------------------------------------------

async fn stop_and_remove(name: &str) {
    let handle = Sandbox::get(name).await.expect("get");
    handle.stop().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

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
    assert_cap_sys_admin(&default, true).await;
    assert_mount_tmpfs(&default, true).await;
    stop_and_remove(default_name).await;

    let restricted = Sandbox::builder(restricted_name)
        .image(IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .security(SecurityProfile::Restricted)
        .volume("/mnt/msb-restricted-flags", |m| m.tmpfs().size(16))
        .create()
        .await
        .expect("create restricted sandbox");

    assert_no_new_privs(&restricted, "1").await;
    assert_cap_sys_admin(&restricted, false).await;
    assert_mount_has_flags(
        &restricted,
        "/mnt/msb-restricted-flags",
        &["nosuid", "nodev"],
    )
    .await;
    assert_mount_tmpfs(&restricted, false).await;
    stop_and_remove(restricted_name).await;
}

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

async fn assert_cap_sys_admin(sandbox: &Sandbox, expected: bool) {
    let out = sandbox
        .shell("awk '/^CapEff:/{print $2}' /proc/self/status")
        .await
        .expect("read CapEff");
    let caps =
        u64::from_str_radix(out.stdout().expect("utf8").trim(), 16).expect("parse CapEff hex");
    let has_cap = (caps & (1_u64 << 21)) != 0;
    assert_eq!(has_cap, expected, "unexpected CAP_SYS_ADMIN state");
}

async fn assert_mount_has_flags(sandbox: &Sandbox, path: &str, expected_flags: &[&str]) {
    let script = format!("awk '$5 == \"{path}\" {{print $6}}' /proc/self/mountinfo");
    let out = sandbox.shell(&script).await.expect("read mount options");
    let options = out.stdout().expect("utf8");
    for flag in expected_flags {
        assert!(
            options.trim().split(',').any(|option| option == *flag),
            "expected mount {path} to include {flag}, got `{options}`"
        );
    }
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
