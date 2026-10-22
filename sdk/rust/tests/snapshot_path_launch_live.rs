//! Path-set launch qualification against a real local VM runtime.

#![cfg(feature = "local")]

use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::FutureExt;
use microsandbox::backend::{Backend, LocalBackend};
use microsandbox::sandbox::SandboxBuilder;
use microsandbox::{Sandbox, Snapshot};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn check(sandbox: &Sandbox, command: &str) -> String {
    let output = sandbox.shell(command).await.expect("guest command");
    assert!(
        output.status().success,
        "guest command failed: {:?}",
        output.stderr()
    );
    output.stdout().unwrap()
}

async fn remove(name: &str) {
    if let Ok(sandbox) = Sandbox::get(name).await {
        let _ = sandbox.kill().await;
        let _ = sandbox.remove().await;
    }
}

async fn verify_resumed_process(sandbox: &Sandbox) {
    check(sandbox, r#"pid=$(cat /root/counter.pid); kill -0 "$pid"; before=$(cat /root/counter); for i in $(seq 1 50); do after=$(cat /root/counter); test "$after" -gt "$before" && exit 0; sleep 0.1; done; exit 1"#).await;
}

async fn scenario(home: &Path, full: bool) {
    eprintln!("launch qualification: creating source");
    let source = Sandbox::builder("path-source")
        .image("alpine:3.20")
        .cpus(1)
        .memory(256)
        .create()
        .boxed()
        .await
        .unwrap();
    check(&source, r#"mkdir -p /root/tree && for i in $(seq 1 500); do printf 'marker-%s\n' "$i" > /root/tree/file-$i; done && dd if=/dev/urandom of=/root/data.bin bs=1048576 count=16 2>/dev/null && sha256sum /root/data.bin > /root/data.sha && printf base > /root/phase && sync"#).await;
    if full {
        // Keep state in a surviving shell, not merely files. Resuming must
        // preserve its PID and continue the in-memory counter.
        check(&source, r#"nohup sh -c 'echo $$ > /root/counter.pid; n=0; while :; do n=$((n+1)); echo "$n" > /root/counter; sleep 1; done' </dev/null >/root/counter.log 2>&1 &"#).await;
        check(
            &source,
            "for i in $(seq 1 50); do test -s /root/counter && exit 0; sleep 0.1; done; exit 1",
        )
        .await;
    }
    eprintln!("launch qualification: capturing base (full={full})");
    let captured = source
        .snapshot_with("history", |capture| {
            let capture = capture.initial_checkpoint("base").record_integrity();
            if full { capture.full() } else { capture }
        })
        .await
        .unwrap();
    let base = captured.checkpoint;
    let group = captured.snapshot;
    check(&source, "printf tip > /root/phase && sync").await;
    eprintln!("launch qualification: capturing tip");
    let tip = group
        .checkpoint_with(|capture| {
            let capture = capture.name("tip").record_integrity();
            if full { capture.full() } else { capture }
        })
        .await
        .unwrap()
        .checkpoint;
    let base_archive = home.join("base.msb");
    let tip_archive = home.join("tip.unusual-extension");
    base.save(&base_archive).await.unwrap();
    tip.save_with(&tip_archive, |save| {
        save.since(base.reference().value().to_owned())
    })
    .await
    .unwrap();
    remove("path-source").await;
    drop(source);
    group.remove().await.unwrap();
    assert!(Snapshot::list().await.unwrap().is_empty());

    if full {
        for option in ["command", "init", "hostname", "thp", "security"] {
            let builder = Sandbox::builder("path-child")
                .override_snapshot_paths(vec![tip_archive.clone(), base_archive.clone()], None)
                .snapshot_launch_options(false, false);
            let builder = match option {
                "command" => builder.foreground_command(["echo", "must-not-run"]),
                "init" => builder.init("auto"),
                "hostname" => builder.hostname("replacement"),
                "thp" => builder.thp(microsandbox::sandbox::TransparentHugePagePolicy::Never),
                "security" => builder.security(microsandbox::sandbox::SecurityProfile::Default),
                _ => unreachable!(),
            };
            let error = builder
                .create()
                .boxed()
                .await
                .err()
                .expect("full resume must refuse boot overrides");
            assert!(error.to_string().contains("disk-only"), "{option}: {error}");
            assert!(Sandbox::list().await.unwrap().sandboxes.is_empty());
        }
    }
    eprintln!("launch qualification: source removed, launching archive sets");
    for paths in [
        vec![tip_archive.clone(), base_archive.clone()],
        vec![base_archive.clone(), tip_archive.clone()],
    ] {
        let child = Sandbox::builder("path-child")
            .memory(256)
            .override_snapshot_paths(paths, None)
            .snapshot_launch_options(false, false)
            .create()
            .boxed()
            .await
            .unwrap();
        assert_eq!(child.config().resumed_from_full_snapshot(), full);
        if full {
            verify_resumed_process(&child).await;
        }
        let result = check(&child, r#"test "$(find /root/tree -type f | wc -l)" -eq 500 && sha256sum -c /root/data.sha && printf 'PHASE=' && cat /root/phase"#).await;
        assert!(result.ends_with("PHASE=tip"), "{result}");
        remove("path-child").await;
        drop(child);
        assert!(Snapshot::list().await.unwrap().is_empty());
    }
    eprintln!("launch qualification: preparing exact base");
    let config = Sandbox::builder("path-child")
        .memory(256)
        .override_snapshot_paths(
            vec![tip_archive.clone(), base_archive.clone()],
            Some(base.id().clone()),
        )
        .build()
        .boxed()
        .await
        .unwrap();
    // Prepared sources own their bytes; no later path lookup can resurrect the
    // deleted source, select the tip instead, or depend on either archive file.
    std::fs::remove_file(base_archive).unwrap();
    std::fs::remove_file(tip_archive).unwrap();
    let child = SandboxBuilder::from(config).create().boxed().await.unwrap();
    assert_eq!(child.config().resumed_from_full_snapshot(), full);
    if full {
        verify_resumed_process(&child).await;
    }
    let result = check(&child, r#"test "$(find /root/tree -type f | wc -l)" -eq 500 && sha256sum -c /root/data.sha && printf 'PHASE=' && cat /root/phase"#).await;
    assert!(result.ends_with("PHASE=base"), "{result}");
    remove("path-child").await;
    drop(child);
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires an installed VM runtime; MSB_LAUNCH_TEST_HOME optionally selects an empty home"]
async fn archive_sets_launch_after_source_and_group_deletion() {
    // CI runs ignored VM tests without a caller-provisioned home. Keep that
    // case isolated too, without changing the process-wide SDK configuration.
    // The guard outlives guest cleanup; explicit qualification homes stay owned
    // by their caller and retain the existing empty-directory requirement.
    let explicit_home = std::env::var_os("MSB_LAUNCH_TEST_HOME").map(PathBuf::from);
    let owned_home = if explicit_home.is_none() {
        let root = if cfg!(unix) {
            // Match the other VM fixtures' short Unix roots for socket paths.
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        Some(
            tempfile::Builder::new()
                .prefix("msb-launch-")
                .tempdir_in(root)
                .expect("isolated launch test home"),
        )
    } else {
        None
    };
    let home = explicit_home.unwrap_or_else(|| owned_home.as_ref().unwrap().path().to_path_buf());
    eprintln!("launch qualification: isolated home {}", home.display());
    assert!(
        std::fs::read_dir(&home).unwrap().next().is_none(),
        "test home must be empty"
    );
    let full =
        std::env::var_os("MSB_LAUNCH_TEST_FULL").as_deref() == Some(std::ffi::OsStr::new("1"));
    let backend: Arc<dyn Backend> =
        Arc::new(LocalBackend::builder().home(&home).build().await.unwrap());
    microsandbox::with_backend(backend, async {
        let outcome = AssertUnwindSafe(scenario(&home, full).boxed())
            .catch_unwind()
            .await;
        remove("path-child").await;
        remove("path-source").await;
        if let Ok(group) = Snapshot::get("history").await {
            let _ = group.remove().await;
        }
        assert!(
            Sandbox::list().await.unwrap().sandboxes.is_empty(),
            "test left a sandbox behind"
        );
        assert!(
            Snapshot::list().await.unwrap().is_empty(),
            "test left a group behind"
        );
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    })
    .await;
}
