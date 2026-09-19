//! Opt-in SDK qualification against an installed full checkpoint containing /work/hash.
//! Set MSB_PROGRESS_SNAPSHOT plus MSB_HOME/MSB_PATH/MSB_AGENTD_PATH/MSB_LIBKRUNFW_PATH.

#![cfg(feature = "local")]

use microsandbox::{CreationProgress, Sandbox, StartupPhase};

#[tokio::test]
#[ignore = "requires a matching runtime and prepared full snapshot fixture"]
async fn restored_creation_progress_and_ignored_observer() {
    let snapshot = std::env::var("MSB_PROGRESS_SNAPSHOT").expect("snapshot fixture");
    for observed in [true, false] {
        let name = format!("progress-live-{}-{observed}", std::process::id());
        let started = std::time::Instant::now();
        let (mut progress, task) = Sandbox::restore(&snapshot)
            .name(&name)
            .forked()
            .restore_with_progress()
            .unwrap();
        if observed {
            let mut activating = false;
            while let Some(event) = progress.recv().await {
                println!(
                    "{} {}",
                    started.elapsed().as_millis(),
                    serde_json::to_string(&event).unwrap()
                );
                if let CreationProgress::Startup(event) = event {
                    activating |= event.phase == StartupPhase::Activating;
                    assert!(
                        event
                            .total_bytes
                            .is_none_or(|total| event.completed_bytes <= total)
                    );
                }
            }
            assert!(activating, "EOF cannot replace the activation signal");
        } else {
            drop(progress);
        }
        let sandbox = task.await.unwrap().unwrap();
        println!(
            "created observed={observed} elapsed_ms={}",
            started.elapsed().as_millis()
        );
        let result = sandbox.exec("sha256sum", ["-c", "/work/hash"]).await;
        // Always stop our child before asserting workload results.
        sandbox.kill().await.unwrap();
        let result = result.unwrap();
        assert!(result.status().success);
    }
}

/// Cancellation must clean up an unfinished VM even while another process holds its backing lock.
#[cfg(unix)]
#[tokio::test]
#[ignore = "requires a disposable cbh-* fixture with one unpinned RAM cache entry"]
async fn cancelled_backing_preparation_reaps_and_reconciles() {
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::path::PathBuf;
    use std::time::Duration;

    let home = PathBuf::from(std::env::var("MSB_HOME").expect("disposable fixture"));
    assert!(
        home.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("cbh-")
    );
    let snapshot = std::env::var("MSB_PROGRESS_SNAPSHOT").expect("snapshot fixture");
    let locks: Vec<_> = std::fs::read_dir(home.join("cache/memory/snapshots"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "build-lock")
        })
        .collect();
    assert_eq!(
        locks.len(),
        1,
        "fixture must have one prepared snapshot backing"
    );
    let lock = File::open(&locks[0]).unwrap();
    // The fixture is stopped. Refuse to move a backing pinned by any live VM.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let cache = locks[0].with_extension("ram");
    if cache.exists() {
        let pin = File::open(&cache).unwrap();
        assert_eq!(
            unsafe { libc::flock(pin.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        std::fs::rename(
            &cache,
            cache.with_extension(format!("cancel-test-{}", std::process::id())),
        )
        .unwrap();
    }
    let name = format!("cancel-progress-{}", std::process::id());
    let (mut progress, task) = Sandbox::restore(&snapshot)
        .name(&name)
        .forked()
        .restore_with_progress()
        .unwrap();
    let waiting = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(event) = progress.recv().await {
            if matches!(event, CreationProgress::Startup(event) if event.phase == StartupPhase::WaitingForMemoryBacking) {
                return true;
            }
        }
        false
    }).await;
    // Always cancel before assertions so a failed observation cannot leave our test VM behind.
    let cancelled = std::time::Instant::now();
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert!(
        waiting.unwrap(),
        "runtime never reported waiting for the deliberately held lock"
    );
    let backend = microsandbox::backend::default_backend();
    let local = backend.as_local().unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let handle = Sandbox::get(&name).await.unwrap();
            let terminal = matches!(
                handle.status_snapshot(),
                microsandbox::sandbox::SandboxStatus::Stopped
                    | microsandbox::sandbox::SandboxStatus::Crashed
            );
            let ownership = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
                &local.config().run_dir(),
                &name,
            )
            .unwrap();
            if terminal && ownership.is_some() {
                drop(ownership);
                // Remove immediately: no flush-window sleep or force removal may be necessary.
                handle.remove().await.unwrap();
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled create left process ownership or nonterminal catalog state");
    println!(
        "cancelled preparation: ownership released and removed in {} ms",
        cancelled.elapsed().as_millis()
    );
    // Keep the backing lock held until cleanup is proven; releasing it must not be what lets
    // the VM finish preparation and escape cancellation.
    drop(lock);
}
