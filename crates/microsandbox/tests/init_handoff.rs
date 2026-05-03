//! Integration tests for guest PID 1 handoff (`--init`).
//!
//! These tests boot a real microVM and exercise the handoff path. They
//! require:
//!
//! 1. A static Linux build of `test-init` at the path in
//!    `MSB_TEST_INIT_PATH`. Build it with:
//!
//!    ```sh
//!    cargo build -p test-init --release \
//!        --target x86_64-unknown-linux-musl
//!    export MSB_TEST_INIT_PATH=$PWD/target/x86_64-unknown-linux-musl/release/test-init
//!    ```
//!
//!    On Apple silicon hosts, substitute `aarch64-unknown-linux-musl`
//!    (the same arch the libkrun guest uses).
//!
//! 2. A working microsandbox install (`msb`, `libkrunfw`).
//!
//! Tests are `#[ignore]`-gated like the rest of the integration suite —
//! run with `cargo test -p microsandbox --test init_handoff -- --ignored`.
//!
//! What they verify:
//! - `/proc/1/comm` matches the test init (i.e. handoff happened)
//! - `getppid()` from a host-issued exec returns 1 (the new init)
//! - graceful shutdown via host `Sandbox::stop_and_wait` actually
//!   tears the VM down (signal-based shutdown path works)

use std::path::{Path, PathBuf};

use microsandbox::Sandbox;
use test_utils::msb_test;

const TEST_INIT_PATH_ENV: &str = "MSB_TEST_INIT_PATH";

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

/// Returns the host path to the prebuilt `test-init` binary, or skips
/// the test with a friendly message.
fn require_test_init() -> Option<PathBuf> {
    let raw = std::env::var(TEST_INIT_PATH_ENV).ok()?;
    let path = PathBuf::from(raw);
    if !path.is_file() {
        eprintln!(
            "skipping: {TEST_INIT_PATH_ENV} points at {} which is not a regular file",
            path.display()
        );
        return None;
    }
    Some(path)
}

/// Build a sandbox with the test init patched in at `/sbin/init`.
async fn boot_with_test_init(name: &str, init_bin: &Path) -> Sandbox {
    Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(256)
        .replace()
        .patch(|p| p.copy_file(init_bin, "/sbin/init", Some(0o755), true))
        .init("/sbin/init")
        .create()
        .await
        .expect("create sandbox with handoff")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// PID 1 inside the guest is the test init binary, not agentd.
#[msb_test]
async fn pid_1_is_handed_off_to_test_init() {
    let Some(init_bin) = require_test_init() else {
        return;
    };
    let name = "init-handoff-pid1";
    let sb = boot_with_test_init(name, &init_bin).await;

    let out = sb
        .shell("cat /proc/1/comm")
        .await
        .expect("read /proc/1/comm");
    let comm = out.stdout().expect("utf8").trim().to_owned();

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;

    assert_eq!(
        comm, "test-init",
        "expected /proc/1/comm = 'test-init' (the handoff target), got {comm:?}"
    );
}

/// A host-issued exec lands as a direct child of PID 1 (the new init).
#[msb_test]
async fn exec_session_parent_is_pid_1_post_handoff() {
    let Some(init_bin) = require_test_init() else {
        return;
    };
    let name = "init-handoff-getppid";
    let sb = boot_with_test_init(name, &init_bin).await;

    // The exec process's parent is agentd (its spawner), but agentd's
    // own parent is PID 1 — the new init. Walk up two levels.
    let out = sb
        .shell("awk '/^PPid/{print $2}' /proc/$$/status")
        .await
        .expect("read PPid");
    let agentd_pid: u32 = out
        .stdout()
        .expect("utf8")
        .trim()
        .parse()
        .expect("PPid is u32");

    // Now read agentd's PPid; should be 1.
    let out2 = sb
        .shell(format!(
            "awk '/^PPid/{{print $2}}' /proc/{agentd_pid}/status"
        ))
        .await
        .expect("read agentd PPid");
    let agentd_ppid: u32 = out2
        .stdout()
        .expect("utf8")
        .trim()
        .parse()
        .expect("agentd PPid is u32");

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;

    assert_eq!(
        agentd_ppid, 1,
        "agentd's parent should be the new init (PID 1), got {agentd_ppid}"
    );
}

/// Shutdown via host signal works post-handoff (the new init handles
/// SIGRTMIN+4 / SIGTERM and exits, which panics PID 1 → VMM exits).
#[msb_test]
async fn shutdown_via_signal_path_terminates_guest() {
    let Some(init_bin) = require_test_init() else {
        return;
    };
    let name = "init-handoff-shutdown";
    let sb = boot_with_test_init(name, &init_bin).await;

    // Verify the sandbox is alive first.
    let _ = sb.shell("true").await.expect("alive");

    // stop_and_wait drives request_guest_poweroff inside agentd; the
    // PID-1 branch will fail (we're not PID 1), so the signal-based
    // path runs. Should still complete within the host's normal
    // shutdown timeout.
    let status = sb.stop_and_wait().await.expect("stop_and_wait");
    let _ = Sandbox::remove(name).await;

    assert!(
        status.success(),
        "guest should have exited cleanly via the signal path, got {status:?}"
    );
}
