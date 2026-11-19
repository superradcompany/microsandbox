//! Isolated Linux host-child regressions and opt-in performance measurements.

use std::os::fd::FromRawFd;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::wait::{WaitPidFlag, waitpid};
use tokio::signal::unix::{SignalKind, signal as tokio_signal};

use super::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CASE_ENV: &str = "MSB_REAP_TEST_CASE";
const REAP_TIMEOUT: Duration = Duration::from_secs(5);
const SETTLE_DELAY: Duration = Duration::from_millis(200);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// How the child ends after its handle has been dropped.
#[derive(Clone, Copy)]
enum Ending {
    /// The process exits on its own.
    Exit,
    /// Another handle stops it, e.g. `Sandbox::get(..).stop()`.
    Term,
    /// It is killed outright.
    Kill,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run one scenario in a fresh test process so the SIGCHLD change stays isolated.
fn run_isolated(case: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "runtime::handle::reap_tests::isolated_case",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CASE_ENV, case)
        .env(
            "MSB_TEST_REAP_POLL",
            if case.contains("poll") { "1" } else { "" },
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("reaping subprocess {case} exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    print!("{stdout}");
    assert!(
        output.status.success(),
        "case {case} failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(&format!("reap case {case} passed")),
        "case {case} did not run\nstdout:\n{stdout}"
    );
}

/// Spawn a child that exits only on stdin EOF or a signal, after a host runtime reset
/// SIGCHLD (Node.js does this after every `child_process` call).
fn spawn_child(
    parent_watchdog: Option<OwnedFd>,
) -> (ProcessHandle, tokio::process::ChildStdin, u32) {
    // The SDK installs Tokio's SIGCHLD handler before spawning a sandbox.
    let sigchld = tokio_signal(SignalKind::child()).unwrap();
    std::mem::forget(sigchld);

    let mut child = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("read value")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let pid = child.id().unwrap();
    let handle = ProcessHandle::new(
        pid,
        "reap-test".into(),
        child,
        Vec::new(),
        parent_watchdog,
        None,
    );

    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
    (handle, stdin, pid)
}

async fn assert_reaped(pid: u32) {
    let reaped = tokio::time::timeout(REAP_TIMEOUT, async {
        // A zombie still answers kill(pid, 0); ESRCH means its status was collected.
        while signal::kill(Pid::from_raw(pid as i32), None) != Err(Errno::ESRCH) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();

    assert!(reaped.is_ok(), "child {pid} was not reaped: {state}");
    assert_eq!(
        waitpid(Pid::from_raw(pid as i32), Some(WaitPidFlag::WNOHANG)),
        Err(Errno::ECHILD)
    );
}

/// Release a running child as `detach()` does, or as dropping an unstopped attached
/// owner does (which only closes its parent-watchdog writer), then end it.
async fn released_child_is_reaped(detach: bool, ending: Ending) {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let _watchdog_reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let watchdog_writer = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    let (mut handle, stdin, pid) = spawn_child(Some(watchdog_writer));
    if detach {
        handle.disarm().unwrap();
    }

    // Drop away from the runtime, as a JS finalizer or Python GC may.
    std::thread::spawn(move || drop(handle)).join().unwrap();

    // A real VM keeps running long after release; end the child only once any
    // immediate post-drop reaping attempt has already passed.
    tokio::time::sleep(SETTLE_DELAY).await;
    match ending {
        Ending::Exit => drop(stdin),
        Ending::Term => signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM).unwrap(),
        Ending::Kill => signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL).unwrap(),
    }

    assert_reaped(pid).await;
}

async fn owned_wait_reports_status_once() {
    let (mut handle, stdin, pid) = spawn_child(None);
    signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL).unwrap();

    let status = tokio::time::timeout(REAP_TIMEOUT, handle.wait())
        .await
        .expect("owned wait timed out")
        .unwrap();
    drop(handle);
    drop(stdin);

    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert_reaped(pid).await;
}

async fn retained_child_is_reaped() {
    let (handle, stdin, pid) = spawn_child(None);
    let cleanup = handle.cleanup_control();
    let handle = Arc::new(tokio::sync::Mutex::new(handle));
    cleanup.disarm_retained(Some(&handle)).unwrap();
    cleanup.disarm_retained(Some(&handle)).unwrap();
    tokio::time::sleep(SETTLE_DELAY).await;
    assert!(
        handle.try_lock().is_ok(),
        "observer must not hold the process mutex"
    );
    drop(stdin);
    assert_reaped(pid).await;
    let mut handle = handle.lock().await;
    let first = handle.wait().await.unwrap();
    assert_eq!(first, handle.wait().await.unwrap());
    // Collection must make stale numeric PIDs unusable even while the handle lives.
    assert!(handle.child.id().is_none());
    let mut unrelated = tokio::process::Command::new("/bin/sh")
        .args(["-c", "read value"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    handle.pid = unrelated.id().unwrap();
    handle.kill().unwrap();
    handle.drain().unwrap();
    assert!(unrelated.try_wait().unwrap().is_none());
    unrelated.kill().await.unwrap();
}

async fn cancelled_wait_is_repeatable() {
    let (mut handle, stdin, pid) = spawn_child(None);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), handle.wait())
            .await
            .is_err()
    );
    drop(stdin);
    let status = tokio::time::timeout(REAP_TIMEOUT, handle.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, handle.wait().await.unwrap());
    assert_reaped(pid).await;
}

fn shutdown_case(retained: bool, unpolled: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (handle, stdin, pid) = runtime.block_on(async { spawn_child(None) });
    let cleanup = handle.cleanup_control();
    let handle = Arc::new(tokio::sync::Mutex::new(handle));
    {
        let _entered = runtime.enter();
        cleanup.disarm_retained(Some(&handle)).unwrap();
    }
    let retained_handle = retained.then_some(handle);
    if !unpolled {
        runtime.block_on(async { tokio::time::sleep(Duration::from_millis(50)).await });
    }
    // Shutting down the runtime must not terminate a detached child.
    drop(runtime);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(signal::kill(Pid::from_raw(pid as i32), None), Ok(()));
    drop(stdin);
    let deadline = Instant::now() + REAP_TIMEOUT;
    while signal::kill(Pid::from_raw(pid as i32), None) != Err(Errno::ESRCH) {
        assert!(
            Instant::now() < deadline,
            "shutdown left child {pid} unreaped"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        waitpid(Pid::from_raw(pid as i32), Some(WaitPidFlag::WNOHANG)),
        Err(Errno::ECHILD)
    );
    drop(retained_handle);
}

fn cpu_seconds() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let usage = unsafe { usage.assume_init() };
    (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) as f64
        + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as f64 / 1_000_000.0
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

async fn performance_case() {
    let count: usize = std::env::var("MSB_REAP_PERF_COUNT")
        .unwrap_or_else(|_| "256".into())
        .parse()
        .unwrap();
    let baseline_fds = fd_count();
    let mut children = Vec::new();
    for _ in 0..count {
        let (handle, stdin, pid) = spawn_child(None);
        let cleanup = handle.cleanup_control();
        let handle = Arc::new(tokio::sync::Mutex::new(handle));
        cleanup.disarm_retained(Some(&handle)).unwrap();
        children.push((handle, stdin, pid));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let live_fds = fd_count();
    let cpu_start = cpu_seconds();
    let idle = Instant::now();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let idle_secs = idle.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - cpu_start;
    let exit_start = Instant::now();
    let mut retained = Vec::new();
    let mut pids = Vec::new();
    for (handle, stdin, pid) in children {
        drop(stdin);
        retained.push(handle);
        pids.push(pid);
    }
    let mut latencies = Vec::new();
    while !pids.is_empty() {
        pids.retain(|pid| {
            if signal::kill(Pid::from_raw(*pid as i32), None) == Err(Errno::ESRCH) {
                latencies.push(exit_start.elapsed().as_secs_f64() * 1000.0);
                false
            } else {
                true
            }
        });
        assert!(
            exit_start.elapsed() < REAP_TIMEOUT,
            "performance run left children unreaped"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    drop(retained);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let final_fds = fd_count();
    latencies.sort_by(f64::total_cmp);
    println!(
        "REAP_PERF count={count} poll={} cpu_seconds={cpu:.6} idle_seconds={idle_secs:.3} cpu_percent={:.3} fd_before={baseline_fds} fd_live={live_fds} fd_after={final_fds} latency_p50_ms={:.2} latency_p99_ms={:.2} latency_max_ms={:.2}",
        std::env::var("MSB_TEST_REAP_POLL").unwrap_or_default(),
        cpu / idle_secs * 100.0,
        latencies[count / 2],
        latencies[(count * 99 / 100).min(count - 1)],
        latencies[count - 1]
    );
    assert_eq!(final_fds, baseline_fds, "descriptor leak after collection");
}

/// Measure the one-thread fallback after dropping the runtime with retained children.
fn shutdown_performance_case() {
    let count: usize = std::env::var("MSB_REAP_PERF_COUNT")
        .unwrap_or_else(|_| "256".into())
        .parse()
        .unwrap();
    // Warm process-global Tokio signal descriptors before measuring per-child resources.
    let warmup = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    drop(warmup);
    let baseline_fds = fd_count();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let children = runtime.block_on(async {
        let mut children = Vec::new();
        for _ in 0..count {
            let (handle, stdin, pid) = spawn_child(None);
            let cleanup = handle.cleanup_control();
            let handle = Arc::new(tokio::sync::Mutex::new(handle));
            cleanup.disarm_retained(Some(&handle)).unwrap();
            children.push((handle, stdin, pid));
        }
        children
    });
    drop(runtime);
    std::thread::sleep(Duration::from_millis(500));
    let reapers = std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .ok()
                .and_then(|entry| std::fs::read_to_string(entry.path().join("comm")).ok())
                .is_some_and(|name| name.trim() == "msb-reaper")
        })
        .count();
    assert_eq!(reapers, 1, "fallback must share a single thread");
    let live_fds = fd_count();
    let cpu_start = cpu_seconds();
    let idle = Instant::now();
    std::thread::sleep(Duration::from_secs(3));
    let idle_secs = idle.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - cpu_start;
    let exit_start = Instant::now();
    let mut retained = Vec::new();
    let mut pids = Vec::new();
    for (handle, stdin, pid) in children {
        drop(stdin);
        retained.push(handle);
        pids.push(pid);
    }
    let mut latencies = Vec::new();
    while !pids.is_empty() {
        pids.retain(|pid| {
            if signal::kill(Pid::from_raw(*pid as i32), None) == Err(Errno::ESRCH) {
                latencies.push(exit_start.elapsed().as_secs_f64() * 1000.0);
                false
            } else {
                true
            }
        });
        assert!(
            exit_start.elapsed() < REAP_TIMEOUT,
            "fallback left children unreaped"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(retained);
    std::thread::sleep(Duration::from_millis(300));
    let final_fds = fd_count();
    latencies.sort_by(f64::total_cmp);
    println!(
        "REAP_PERF count={count} mode=shutdown cpu_seconds={cpu:.6} idle_seconds={idle_secs:.3} cpu_percent={:.3} reaper_threads={reapers} fd_before={baseline_fds} fd_live={live_fds} fd_after={final_fds} latency_p50_ms={:.2} latency_p99_ms={:.2} latency_max_ms={:.2}",
        cpu / idle_secs * 100.0,
        latencies[count / 2],
        latencies[(count * 99 / 100).min(count - 1)],
        latencies[count - 1]
    );
    assert_eq!(final_fds, baseline_fds, "fallback descriptor leak");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn isolated_case() {
    let Ok(case) = std::env::var(CASE_ENV) else {
        return;
    };
    if case == "perf-shutdown" {
        shutdown_performance_case();
        println!("reap case {case} passed");
        return;
    }
    if case.starts_with("shutdown") {
        shutdown_case(case.contains("retained"), case.contains("unpolled"));
        println!("reap case {case} passed");
        return;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        match case.as_str() {
            "detached-exit" => released_child_is_reaped(true, Ending::Exit).await,
            "detached-term" => released_child_is_reaped(true, Ending::Term).await,
            "detached-kill" => released_child_is_reaped(true, Ending::Kill).await,
            "attached-drop" => released_child_is_reaped(false, Ending::Exit).await,
            "owned-wait" | "owned-wait-poll" => owned_wait_reports_status_once().await,
            "retained" | "retained-poll" => retained_child_is_reaped().await,
            "cancelled-wait" | "cancelled-wait-poll" => cancelled_wait_is_repeatable().await,
            "detached-exit-poll" => released_child_is_reaped(true, Ending::Exit).await,
            "perf" | "perf-poll" => performance_case().await,
            other => panic!("unknown reap case {other}"),
        }
    });
    println!("reap case {case} passed");
}

#[test]
fn retained_detached_child() {
    run_isolated("retained");
}

#[test]
fn retained_detached_child_without_pidfd() {
    run_isolated("retained-poll");
}

#[test]
fn explicit_wait_without_pidfd() {
    run_isolated("owned-wait-poll");
}

#[test]
fn released_child_without_pidfd() {
    run_isolated("detached-exit-poll");
}

#[test]
fn cancelled_wait() {
    run_isolated("cancelled-wait");
}

#[test]
fn cancelled_wait_without_pidfd() {
    run_isolated("cancelled-wait-poll");
}

#[test]
fn shutdown_released() {
    run_isolated("shutdown-released");
}

#[test]
fn shutdown_retained() {
    run_isolated("shutdown-retained");
}

#[test]
fn shutdown_unpolled_released() {
    run_isolated("shutdown-unpolled-released");
}

#[test]
fn shutdown_unpolled_retained() {
    run_isolated("shutdown-unpolled-retained");
}

#[test]
#[ignore = "explicit Linux process performance measurement"]
fn reaping_performance() {
    run_isolated("perf");
    run_isolated("perf-poll");
    run_isolated("perf-shutdown");
}

#[test]
fn detached_child_is_reaped_after_it_exits() {
    run_isolated("detached-exit");
}

#[test]
fn detached_child_is_reaped_after_another_handle_stops_it() {
    run_isolated("detached-term");
}

#[test]
fn detached_child_is_reaped_after_sigkill() {
    run_isolated("detached-kill");
}

#[test]
fn dropped_attached_child_is_reaped() {
    run_isolated("attached-drop");
}

#[test]
fn owned_wait_still_reports_exit_status() {
    run_isolated("owned-wait");
}
