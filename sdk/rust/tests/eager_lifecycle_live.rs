//! Portable lifecycle qualification plus Linux-only injected eager preparation checks.
//! Use a fresh full snapshot containing /work/hash and one isolated MSB_HOME.
//! MSB_TEST_EAGER_MODE is delay, error, or cancel; delay is 15000/45000 ms respectively.

#![cfg(feature = "local")]

#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use microsandbox::{CreationProgress, MicrosandboxError, Sandbox, StartupPhase};
use microsandbox_db::entity::sandbox as sandbox_row;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
#[cfg(target_os = "linux")]
use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct EmergencyCleanup {
    name: String,
    armed: bool,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for EmergencyCleanup {
    fn drop(&mut self) {
        if self.armed {
            // This fallback runs only after a failed assertion. Each successful test
            // explicitly performs the cleanup appropriate to the behavior it qualifies.
            let _ = std::process::Command::new(std::env::var("MSB_PATH").unwrap())
                .args(["stop", "--force", &self.name])
                .status();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn trace() -> Vec<Value> {
    let path = std::env::var("MSB_TEST_EAGER_TRACE").expect("shim trace path");
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

#[cfg(target_os = "linux")]
async fn wait_for_injection(event: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(record) = trace().into_iter().find(|record| record["event"] == event) {
                return record;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("scoped shim never reached the real VMM's checkpoint-object read")
}

#[cfg(target_os = "linux")]
async fn prove_runtime_cleanup(name: &str, pid: u64) {
    let backend = microsandbox::backend::default_backend();
    let local = backend.as_local().unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            // Observe/reconcile before taking the test's lease. Holding that lease during
            // get() could make the test itself appear to be a still-live runtime owner.
            let handle = Sandbox::get(name).await;
            let ownership = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
                &local.config().run_dir(),
                name,
            )
            .unwrap();
            if ownership.is_some() && !PathBuf::from(format!("/proc/{pid}")).exists() {
                match handle {
                    Ok(handle)
                        if matches!(
                            handle.status_snapshot(),
                            microsandbox::sandbox::SandboxStatus::Stopped
                                | microsandbox::sandbox::SandboxStatus::Crashed
                        ) =>
                    {
                        drop(ownership);
                        handle.remove().await.unwrap();
                        break;
                    }
                    Err(MicrosandboxError::SandboxNotFound(_)) => break,
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("test cleanup retained a process, lifecycle owner, or active catalog row");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[cfg(target_os = "linux")]
#[ignore = "requires matching real VMM/agent, fresh snapshot, and scoped Linux preload shim"]
async fn eager_preparation_boundary_live() {
    let mode = std::env::var("MSB_TEST_EAGER_MODE").expect("delay/error/cancel mode");
    assert!(["delay", "error", "cancel"].contains(&mode.as_str()));
    let snapshot = std::env::var("MSB_PROGRESS_SNAPSHOT").expect("fresh checksum snapshot");
    let name = format!("eager-{}-{mode}", std::process::id());
    assert!(matches!(
        Sandbox::get(&name).await,
        Err(MicrosandboxError::SandboxNotFound(_))
    ));
    let mut cleanup = EmergencyCleanup {
        name: name.clone(),
        armed: true,
    };
    let started = Instant::now();
    // Deliberately no .forked(): the stall must occur inside eager VMM reconstruction.
    let (mut progress, mut task) = Sandbox::restore(&snapshot)
        .name(&name)
        .restore_with_progress()
        .unwrap();
    let phases = Arc::new(Mutex::new(Vec::new()));
    let observed = phases.clone();
    let observer = tokio::spawn(async move {
        while let Some(event) = progress.recv().await {
            println!(
                "{} {}",
                started.elapsed().as_millis(),
                serde_json::to_string(&event).unwrap()
            );
            if let CreationProgress::Startup(event) = event {
                assert!(
                    event
                        .total_bytes
                        .is_none_or(|total| event.completed_bytes <= total)
                );
                observed.lock().unwrap().push(event.phase);
            }
        }
    });

    if mode == "cancel" {
        let injected = wait_for_injection("delay_begin").await;
        let cancelled = Instant::now();
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        prove_runtime_cleanup(&name, injected["pid"].as_u64().unwrap()).await;
        assert!(cancelled.elapsed() < Duration::from_secs(15));
        assert!(!trace().iter().any(|record| record["event"] == "delay_end"));
        assert!(!trace().iter().any(|record| {
            record["pid"] == injected["pid"]
                && record["event"] == "startup"
                && record["progress"]["phase"] == "activating"
        }));
    } else {
        let result = tokio::time::timeout(Duration::from_secs(60), &mut task)
            .await
            .expect("bounded test safety deadline")
            .unwrap();
        if mode == "error" {
            let error = match result {
                Err(error) => error.to_string(),
                Ok(_) => panic!("injected object EIO unexpectedly created a sandbox"),
            };
            println!("original_error={error}");
            assert!(error.contains("Input/output error") || error.contains("os error 5"));
            assert!(!error.contains("startup channel closed"));
            let injected = wait_for_injection("read_error").await;
            prove_runtime_cleanup(&name, injected["pid"].as_u64().unwrap()).await;
            assert!(!trace().iter().any(|record| {
                record["pid"] == injected["pid"]
                    && record["event"] == "startup"
                    && record["progress"]["phase"] == "activating"
            }));
        } else {
            let sandbox = result.unwrap();
            let create_ms = started.elapsed().as_millis();
            let records = trace();
            let begin = records
                .iter()
                .find(|record| record["event"] == "delay_begin")
                .unwrap();
            let end = records
                .iter()
                .find(|record| record["event"] == "delay_end")
                .unwrap();
            assert!(
                end["monotonic_ns"].as_u64().unwrap() - begin["monotonic_ns"].as_u64().unwrap()
                    >= 12_000_000_000
            );
            let activating = records
                .iter()
                .find(|record| {
                    record["event"] == "startup"
                        && record["pid"] == begin["pid"]
                        && record["progress"]["phase"] == "activating"
                })
                .expect("actual Activating frame for the delayed runtime");
            assert!(activating["monotonic_ns"].as_u64() >= end["monotonic_ns"].as_u64());
            let checksum = sandbox
                .exec("sha256sum", ["-c", "/work/hash"])
                .await
                .unwrap();
            assert!(checksum.status().success);
            println!("activation_assertions_passed create_ms={create_ms} checksum=ok");
            // This test qualifies activation, not graceful Stop. Explicit Kill is only
            // disposal after the assertions above; the portable and delayed-PID1 tests
            // independently require real Stop completion without this cleanup shortcut.
            sandbox.kill().await.unwrap();
            prove_runtime_cleanup(&name, begin["pid"].as_u64().unwrap()).await;
            println!("cleanup=explicit_kill runtime_reaped=true ownership_released=true");
        }
    }
    tokio::time::timeout(Duration::from_secs(15), observer)
        .await
        .unwrap()
        .unwrap();
    let activating = phases.lock().unwrap().contains(&StartupPhase::Activating);
    assert_eq!(activating, mode == "delay");
    cleanup.armed = false;
    println!(
        "PASS mode={mode} elapsed_ms={}",
        started.elapsed().as_millis()
    );
}

#[tokio::test]
#[ignore = "requires matching runtime/agent and a fresh full snapshot containing /work/hash"]
async fn portable_eager_forked_progress_and_stop_completion() {
    let snapshot = std::env::var("MSB_PROGRESS_SNAPSHOT").expect("fresh checksum snapshot");
    for forked in [false, true] {
        let name = format!("portable-life-{}-{forked}", std::process::id());
        assert!(matches!(
            Sandbox::get(&name).await,
            Err(MicrosandboxError::SandboxNotFound(_))
        ));
        let mut cleanup = EmergencyCleanup {
            name: name.clone(),
            armed: true,
        };
        let started = Instant::now();
        let builder = Sandbox::restore(&snapshot).name(&name);
        let builder = if forked { builder.forked() } else { builder };
        let (mut progress, task) = builder.restore_with_progress().unwrap();
        let mut activating = false;
        while let Some(event) = progress.recv().await {
            println!(
                "{} {}",
                started.elapsed().as_millis(),
                serde_json::to_string(&event).unwrap()
            );
            if let CreationProgress::Startup(event) = event {
                assert!(
                    event
                        .total_bytes
                        .is_none_or(|total| event.completed_bytes <= total)
                );
                activating |= event.phase == StartupPhase::Activating;
            }
        }
        let sandbox = task.await.unwrap().unwrap();
        let create_ms = started.elapsed().as_millis();
        println!("created portable forked={forked} create_ms={create_ms}");
        assert!(activating, "creation EOF must not replace Activating");
        let zero = sandbox.stop_with_timeout(Duration::ZERO).await;
        assert!(matches!(zero, Err(MicrosandboxError::StopTimeout { .. })));
        let checksum = sandbox
            .exec("sha256sum", ["-c", "/work/hash"])
            .await
            .unwrap();
        assert!(
            checksum.status().success,
            "zero-budget Stop must not dispatch or kill"
        );
        sandbox.pause().await.unwrap();
        let paused_stop = tokio::time::timeout(Duration::from_secs(5), sandbox.stop())
            .await
            .unwrap()
            .expect_err("paused Stop must explicitly refuse");
        assert!(paused_stop.to_string().contains("paused"));
        assert!(sandbox.pause_state().await.unwrap().paused);
        sandbox.resume().await.unwrap();
        let checksum = sandbox
            .exec("sha256sum", ["-c", "/work/hash"])
            .await
            .unwrap();
        assert!(checksum.status().success);
        let backend = microsandbox::backend::default_backend();
        let local = backend.as_local().unwrap();
        // Open the existing catalog before timing Stop, without a reconciling handle lookup.
        let pools = local.db().await.unwrap();
        let stop_started = Instant::now();
        tokio::time::timeout(Duration::from_secs(30), sandbox.stop())
            .await
            .unwrap()
            .unwrap();
        let stop_ms = stop_started.elapsed().as_millis();
        // Remove can wait for ownership (and has legacy Windows cleanup), so test Stop's
        // boundary first: one nonblocking acquisition, with no await, retry, or sleep.
        let ownership = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
            &local.config().run_dir(),
            &name,
        )
        .unwrap()
        .expect("successful Stop must already have released runtime ownership");
        // Read the raw row while holding our test lease. Sandbox::get/status would
        // reconcile state and could conceal a failure to publish completion before Stop.
        let terminal = sandbox_row::Entity::find()
            .filter(sandbox_row::Column::Name.eq(&name))
            .one(pools.read())
            .await
            .unwrap()
            .expect("persistent Stop must retain the sandbox row");
        assert!(matches!(
            terminal.status,
            sandbox_row::SandboxStatus::Stopped | sandbox_row::SandboxStatus::Crashed
        ));
        println!(
            "ownership_released=true terminal_status={:?}",
            terminal.status
        );
        drop(ownership);
        // No force, status polling, or sleep may be required between successful Stop and Remove.
        let remove_started = Instant::now();
        sandbox.remove_persisted().await.unwrap();
        let remove_ms = remove_started.elapsed().as_millis();
        cleanup.armed = false;
        println!(
            "PASS portable forked={forked} create_ms={create_ms} stop_ms={stop_ms} remove_ms={remove_ms} total_lifecycle_ms={}",
            started.elapsed().as_millis()
        );
    }
}
