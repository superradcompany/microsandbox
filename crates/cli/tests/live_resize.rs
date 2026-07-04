//! Integration tests for the live-resize surface (`msb modify --cpus/--memory`).
//!
//! Every test here needs a real VM plus a runtime built with live-resize control ops, so like the other suites in this directory they run under `#[msb_test]`
//! (`#[tokio::test] #[ignore]`) and boot VMs unconditionally when invoked. CI runs them once prebuilt libkrunfw artifacts with the `virtio_msb_cpu` and virtio-mem guest
//! drivers ship; local runs also want `MSB_PATH` pointing at a live-resize-capable `msb`. On macOS that binary must carry the hypervisor entitlement, and `cargo test`
//! relinks `target/debug/msb` (dropping an ad-hoc signature), so point `MSB_PATH` at a signed copy outside the target dir:
//! `cp target/debug/msb /tmp/msb-signed && codesign --entitlements msb-entitlements.plist -s - --force /tmp/msb-signed`.
//!
//! The uncooperative-guest test additionally needs `MSB_TEST_LIVE_RESIZE_OLD_KERNEL` set to a libkrunfw dylib/so WITHOUT the guest drivers (a pre-5.5.0 prebuilt); it is
//! exported as `MSB_LIBKRUNFW_PATH` so the sandbox boots a guest that never converges, which must surface as a `converging` resize state rather than a hang or a lie.

use std::process::Output;
use std::time::{Duration, Instant};

use microsandbox::Sandbox;
use test_utils::msb_test;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const IMAGE: &str = "mirror.gcr.io/library/alpine";

/// Path to a driverless (pre-virtio_msb_cpu) libkrunfw, for the uncooperative-guest test.
const OLD_KERNEL_ENV: &str = "MSB_TEST_LIVE_RESIZE_OLD_KERNEL";

/// Guest convergence allowance. Cooperative guests converge in low single-digit seconds; the slack absorbs slow exec startup on loaded CI hosts.
const CONVERGE_DEADLINE: Duration = Duration::from_secs(60);

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Run the freshly built `msb` binary with a hard timeout, capturing output.
async fn msb(args: &[&str]) -> Output {
    timeout(
        Duration::from_secs(90),
        Command::new(env!("CARGO_BIN_EXE_msb")).args(args).output(),
    )
    .await
    .unwrap_or_else(|_| panic!("msb {args:?} timed out after 90s"))
    .unwrap_or_else(|e| panic!("msb {args:?} failed to spawn: {e}"))
}

/// One `msb exec` attempt; `Some(stdout)` on success. Exec right after boot can be slow, so callers retry via [`poll_exec`].
async fn try_exec(name: &str, cmd: &[&str]) -> Option<String> {
    let mut args = vec!["exec", name, "--"];
    args.extend_from_slice(cmd);
    let out = msb(&args).await;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Retry `cmd` in the guest until `accept` returns true or the deadline passes. Returns the last observed output (None if every attempt failed outright).
async fn poll_exec(
    name: &str,
    cmd: &[&str],
    deadline: Duration,
    accept: impl Fn(&str) -> bool,
) -> Option<String> {
    let started = Instant::now();
    let mut last = None;
    loop {
        if let Some(out) = try_exec(name, cmd).await {
            if accept(&out) {
                return Some(out);
            }
            last = Some(out);
        }
        if started.elapsed() >= deadline {
            return last;
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Parse the first `resize_status` entry out of `msb modify --format json` output.
fn first_resize_status(json: &str) -> serde_json::Value {
    let plan: serde_json::Value = serde_json::from_str(json)
        .unwrap_or_else(|e| panic!("modify emitted invalid JSON: {e}\n{json}"));
    plan["resize_status"]
        .as_array()
        .and_then(|entries| entries.first())
        .unwrap_or_else(|| panic!("modify emitted no resize_status:\n{json}"))
        .clone()
}

async fn cleanup(name: &str) {
    if let Ok(handle) = Sandbox::get(name).await {
        let _ = handle.kill().await;
        let _ = handle.remove().await;
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Live CPU grow then shrink on a cooperative guest: the guest driver onlines and offlines CPUs, observable through `nproc`.
#[msb_test]
async fn live_cpu_grow_and_shrink_converge() {
    let name = "live-resize-cpu";
    cleanup(name).await;

    let sandbox = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(2)
        .max_cpus(6)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let boot = poll_exec(name, &["nproc"], CONVERGE_DEADLINE, |out| out == "2").await;
    assert_eq!(boot.as_deref(), Some("2"), "guest should boot with 2 CPUs");

    // Grow 2 -> 4.
    let out = msb(&["modify", name, "--cpus", "4", "--format", "json"]).await;
    assert!(
        out.status.success(),
        "modify --cpus 4 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let status = first_resize_status(&String::from_utf8_lossy(&out.stdout));
    assert_eq!(status["enforced"], "4", "host must enforce the new target");
    let grown = poll_exec(name, &["nproc"], CONVERGE_DEADLINE, |out| out == "4").await;
    assert_eq!(grown.as_deref(), Some("4"), "guest should online CPUs 2-3");

    // Shrink 4 -> 1.
    let out = msb(&["modify", name, "--cpus", "1", "--format", "json"]).await;
    assert!(
        out.status.success(),
        "modify --cpus 1 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shrunk = poll_exec(name, &["nproc"], CONVERGE_DEADLINE, |out| out == "1").await;
    assert_eq!(
        shrunk.as_deref(),
        Some("1"),
        "guest should offline CPUs 1-3"
    );

    drop(sandbox);
    cleanup(name).await;
}

/// Live memory grow on a cooperative guest: virtio-mem plugs blocks and `MemTotal` rises.
#[msb_test]
async fn live_memory_grow_converges() {
    let name = "live-resize-mem";
    cleanup(name).await;

    let sandbox = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .memory(512)
        .max_memory(1536)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let mem_total_kib = |out: &str| {
        out.split_whitespace()
            .nth(1)
            .and_then(|kb| kb.parse::<u64>().ok())
    };
    let baseline = poll_exec(
        name,
        &["grep", "MemTotal", "/proc/meminfo"],
        CONVERGE_DEADLINE,
        |out| mem_total_kib(out).is_some(),
    )
    .await
    .and_then(|out| mem_total_kib(&out))
    .expect("read boot MemTotal");
    assert!(
        baseline < 600 * 1024,
        "boot MemTotal {baseline} KiB should reflect 512 MiB"
    );

    let out = msb(&["modify", name, "--memory", "1G", "--format", "json"]).await;
    assert!(
        out.status.success(),
        "modify --memory 1G failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 1 GiB minus kernel reservations still lands far above the 512 MiB baseline.
    let grown = poll_exec(
        name,
        &["grep", "MemTotal", "/proc/meminfo"],
        CONVERGE_DEADLINE,
        |out| mem_total_kib(out).is_some_and(|kib| kib > 900 * 1024),
    )
    .await
    .and_then(|out| mem_total_kib(&out));
    assert!(
        grown.is_some_and(|kib| kib > 900 * 1024),
        "MemTotal should grow past 900 MiB, got {grown:?} KiB"
    );

    drop(sandbox);
    cleanup(name).await;
}

/// A target above the boot-time capacity cannot apply live: the CLI must refuse with a non-zero exit and leave the running guest untouched.
#[msb_test]
async fn over_capacity_refusal_exits_nonzero() {
    let name = "live-resize-cap";
    cleanup(name).await;

    let sandbox = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .max_cpus(2)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let boot = poll_exec(name, &["nproc"], CONVERGE_DEADLINE, |out| out == "1").await;
    assert_eq!(boot.as_deref(), Some("1"));

    // 3 vCPUs exceed max_cpus=2, so this needs a restart; without --restart the CLI must refuse.
    let out = msb(&["modify", name, "--cpus", "3"]).await;
    assert!(
        !out.status.success(),
        "over-capacity modify must exit non-zero, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    let after = try_exec(name, &["nproc"]).await;
    assert_eq!(
        after.as_deref(),
        Some("1"),
        "refusal must not change the guest"
    );

    drop(sandbox);
    cleanup(name).await;
}

/// Uncooperative guest: a kernel without `virtio_msb_cpu` never acts on resize requests. The runtime must report `converging` honestly (never `applied`), keep the guest's
/// own view unchanged, and stay reachable.
#[msb_test]
async fn uncooperative_guest_reports_converging() {
    let Some(old_kernel) = std::env::var_os(OLD_KERNEL_ENV) else {
        eprintln!("skipping: {OLD_KERNEL_ENV} not set (needs a driverless libkrunfw)");
        return;
    };
    // SAFETY: each #[msb_test] runs in its own process under cargo-nextest, so this only affects this test and the sandbox it spawns. Must run before the first create.
    unsafe {
        std::env::set_var("MSB_LIBKRUNFW_PATH", &old_kernel);
    }

    let name = "live-resize-oldk";
    cleanup(name).await;

    let sandbox = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(2)
        .max_cpus(4)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let boot = poll_exec(name, &["nproc"], CONVERGE_DEADLINE, |out| out == "2").await;
    assert_eq!(boot.as_deref(), Some("2"));

    // Shrink 2 -> 1: the guest never offlines CPU 1, so the honest answer is a pending state with the guest still reporting 2.
    let out = msb(&["modify", name, "--cpus", "1", "--format", "json"]).await;
    assert!(
        out.status.success(),
        "modify --cpus 1 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let status = first_resize_status(&String::from_utf8_lossy(&out.stdout));
    assert_eq!(status["requested"], "1");
    assert_eq!(
        status["actual"], "2",
        "driverless guest cannot have offlined a CPU"
    );
    assert_eq!(
        status["enforced"], "1",
        "host must still enforce the shrink"
    );
    assert_ne!(
        status["state"], "applied",
        "runtime must not claim an uncooperative guest converged"
    );

    // The guest keeps believing in 2 CPUs, and must remain reachable while the host enforces 1.
    sleep(Duration::from_secs(8)).await;
    let after = poll_exec(name, &["nproc"], CONVERGE_DEADLINE, |out| !out.is_empty()).await;
    assert_eq!(
        after.as_deref(),
        Some("2"),
        "guest view must be unchanged and exec must still work under enforcement"
    );

    // Grow 1 -> 3: the guest never onlines anything either; same honest pending state.
    let out = msb(&["modify", name, "--cpus", "3", "--format", "json"]).await;
    assert!(
        out.status.success(),
        "modify --cpus 3 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let status = first_resize_status(&String::from_utf8_lossy(&out.stdout));
    assert_eq!(status["actual"], "2");
    assert_eq!(status["enforced"], "3");
    assert_ne!(status["state"], "applied");

    drop(sandbox);
    cleanup(name).await;
}
