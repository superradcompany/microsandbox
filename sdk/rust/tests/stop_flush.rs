//! Integration test for issue #705: graceful stop must flush guest
//! writes before the VMM exits.
//!
//! Pre-fix, `SandboxHandle::stop` either sent SIGTERM directly to the
//! VMM PID or rode the relay `core.shutdown` path that triggered
//! `exit_handle.trigger()` host-side before agentd had a chance to
//! `sync()` + power off the guest. Either path raced the block-backed
//! upper-ext4 flush and could drop the user's writes.
//!
//! Post-fix, `stop()` sends `core.shutdown` over the agent relay only,
//! the host waits for the VM to exit on its own, and agentd does
//! `libc::sync()` + `reboot(RB_POWER_OFF)` (or signals the handoff
//! init). This test asserts that a marker file written before stop
//! survives the subsequent start, with no explicit `sync` from
//! userland.
//!
//! Requires KVM (or libkrun on macOS); skipped under plain
//! `cargo test`. Run via:
//!
//!     cargo nextest run -p microsandbox --test stop_flush --run-ignored=only

use microsandbox::Sandbox;
use test_utils::msb_test;

const IMAGE: &str = "mirror.gcr.io/library/alpine";
const MARKER_PATH: &str = "/root/test-marker";
const MARKER_VALUE: &str = "hello-705";

async fn cleanup(name: &str) {
    if let Ok(h) = Sandbox::get(name).await {
        let _ = h.kill().await;
        let _ = h.remove().await;
    }
}

/// Mirror of the bash repro in superradcompany/microsandbox#705: write
/// a marker, graceful stop (no explicit `sync` in userland), restart,
/// read the marker back. A regression in the stop/flush ordering
/// surfaces here as an empty or missing marker file.
#[msb_test]
async fn graceful_stop_flushes_writes_to_rootfs() {
    let name = "stop-flush-705";
    cleanup(name).await;

    let sb = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .expect("first create");

    let write = sb
        .exec(
            "sh",
            ["-c", &format!("printf '{MARKER_VALUE}' > {MARKER_PATH}")],
        )
        .await
        .expect("exec: write marker");
    assert!(
        write.status().success,
        "marker write failed: stdout=`{}` stderr=`{}`",
        write.stdout().unwrap_or_default(),
        write.stderr().unwrap_or_default()
    );

    // Detach so the next stop goes through the same SandboxHandle path
    // as `msb stop` rather than the in-process owner drop path.
    sb.detach().await;

    let handle = Sandbox::get(name).await.expect("get handle");
    handle.stop().await.expect("graceful stop");

    let restarted = Sandbox::get(name)
        .await
        .expect("get for restart")
        .start()
        .await
        .expect("start after stop");

    let read = restarted
        .exec("cat", [MARKER_PATH])
        .await
        .expect("exec: read marker");
    let stdout = read.stdout().unwrap_or_default();

    let _ = restarted.stop().await;
    cleanup(name).await;

    assert!(
        read.status().success,
        "cat exited non-zero — marker file likely missing: stdout=`{stdout}` stderr=`{}`",
        read.stderr().unwrap_or_default()
    );
    assert_eq!(
        stdout.trim(),
        MARKER_VALUE,
        "marker content did not survive graceful stop"
    );
}
