//! Path-set launch qualification against a real local VM runtime.

#![cfg(feature = "local")]

use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

use futures::FutureExt;
use microsandbox::{Context, LocalContext};

use microsandbox::Sandbox;

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

async fn remove(backend: &dyn Context, name: &str) {
    if let Ok(sandbox) = backend.sandboxes().get(name).await {
        let _ = sandbox.kill().await;
        let _ = sandbox.destroy().await;
    }
}

async fn verify_resumed_process(sandbox: &Sandbox) {
    check(sandbox, r#"pid=$(cat /root/counter.pid); kill -0 "$pid"; before=$(cat /root/counter); for i in $(seq 1 50); do after=$(cat /root/counter); test "$after" -gt "$before" && exit 0; sleep 0.1; done; exit 1"#).await;
}

async fn scenario(backend: &dyn Context, home: &Path, full: bool) {
    eprintln!("launch qualification: creating source");
    let source = backend
        .sandboxes()
        .builder("path-source")
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
    remove(backend, "path-source").await;
    drop(source);
    group.remove().await.unwrap();
    assert!(backend.snapshots().list().await.unwrap().is_empty());

    if full {
        for option in ["command", "init", "hostname", "thp", "security"] {
            let builder = backend
                .sandboxes()
                .builder("path-child")
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
            assert!(
                backend
                    .sandboxes()
                    .list()
                    .await
                    .unwrap()
                    .sandboxes
                    .is_empty()
            );
        }
    }
    eprintln!("launch qualification: source removed, launching archive sets");
    for paths in [
        vec![tip_archive.clone(), base_archive.clone()],
        vec![base_archive.clone(), tip_archive.clone()],
    ] {
        let child = backend
            .sandboxes()
            .builder("path-child")
            .memory(256)
            .override_snapshot_paths(paths, None)
            .snapshot_launch_options(false, false)
            .create()
            .boxed()
            .await
            .unwrap();
        assert_eq!(
            child
                .launch_info()
                .expect("created sandbox retains its launch outcome")
                .resumed_from_full_snapshot,
            full
        );
        if full {
            verify_resumed_process(&child).await;
        }
        let result = check(&child, r#"test "$(find /root/tree -type f | wc -l)" -eq 500 && sha256sum -c /root/data.sha && printf 'PHASE=' && cat /root/phase"#).await;
        assert!(result.ends_with("PHASE=tip"), "{result}");
        remove(backend, "path-child").await;
        drop(child);
        assert!(backend.snapshots().list().await.unwrap().is_empty());
    }
    eprintln!("launch qualification: preparing exact base");
    let config = backend
        .sandboxes()
        .builder("path-child")
        .memory(256)
        .override_snapshot_paths(
            vec![tip_archive.clone(), base_archive.clone()],
            Some(microsandbox::snapshot::SnapshotId::new(base.id()).unwrap()),
        )
        .build()
        .boxed()
        .await
        .unwrap();
    // Prepared sources own their bytes; no later path lookup can resurrect the
    // deleted source, select the tip instead, or depend on either archive file.
    std::fs::remove_file(base_archive).unwrap();
    std::fs::remove_file(tip_archive).unwrap();
    let child = backend.sandboxes().create(config).boxed().await.unwrap();
    assert_eq!(
        child
            .launch_info()
            .expect("created sandbox retains its launch outcome")
            .resumed_from_full_snapshot,
        full
    );
    if full {
        verify_resumed_process(&child).await;
    }
    let result = check(&child, r#"test "$(find /root/tree -type f | wc -l)" -eq 500 && sha256sum -c /root/data.sha && printf 'PHASE=' && cat /root/phase"#).await;
    assert!(result.ends_with("PHASE=base"), "{result}");
    remove(backend, "path-child").await;
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
    let provider = LocalContext::builder().home(&home).build().unwrap();
    let backend: &dyn Context = &provider;
    async {
        let outcome = AssertUnwindSafe(scenario(backend, &home, full).boxed())
            .catch_unwind()
            .await;
        remove(backend, "path-child").await;
        remove(backend, "path-source").await;
        if let Ok(group) = backend.snapshots().get("history").await {
            let _ = group.remove().await;
        }
        assert!(
            backend
                .sandboxes()
                .list()
                .await
                .unwrap()
                .sandboxes
                .is_empty(),
            "test left a sandbox behind"
        );
        assert!(
            backend.snapshots().list().await.unwrap().is_empty(),
            "test left a group behind"
        );
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }
    .await;
}

#[tokio::test]
#[ignore = "requires an installed VM runtime with local fork support"]
async fn isolated_image_can_fork_and_restore_from_imported_bundle_offline() {
    use microsandbox::sandbox::PullPolicy;

    let root = tempfile::Builder::new()
        .prefix("msb-image-")
        .tempdir_in(if cfg!(unix) {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        })
        .unwrap();
    let home = root.path().join("home");
    let cache = root.path().join("private");
    let provider = LocalContext::builder()
        .home(&home)
        .config_path(home.join("config.json"))
        .build()
        .unwrap();
    let backend: &dyn Context = &provider;

    let outcome = AssertUnwindSafe(async {
        let source = backend
            .sandboxes()
            .builder("source")
            .image("alpine:3.20")
            .image_cache_dir(&cache)
            .cpus(1)
            .memory(256)
            .create_detached()
            .boxed()
            .await
            .unwrap();
        check(&source, "printf private > /root/cache-marker && sync").await;
        let child = source.fork("fork").fork().boxed().await.unwrap();
        assert_eq!(check(&child, "cat /root/cache-marker").await, "private");
        let private = microsandbox_image::GlobalCache::new(&cache).unwrap();
        let shared = microsandbox_image::GlobalCache::new(&provider.cache_dir()).unwrap();
        let reference = "alpine:3.20".parse().unwrap();
        let digest = private
            .read_image_metadata(&reference)
            .unwrap()
            .unwrap()
            .manifest_digest
            .parse()
            .unwrap();
        assert!(!shared.vmdk_path(&digest).exists());
        drop(child);

        let captured = source
            .snapshot_with("cache-history", |capture| {
                capture.initial_checkpoint("base")
            })
            .await
            .unwrap();
        let archive = root.path().join("offline.msb");
        captured
            .checkpoint
            .save_with(&archive, |save| save.with_image())
            .await
            .unwrap();
        captured.snapshot.remove().await.unwrap();
        let imported = backend.checkpoints().load(&archive, None).await.unwrap();
        let restored = backend
            .sandboxes()
            .restore_ref(imported.reference())
            .name("restored")
            .pull_policy(PullPolicy::Never)
            .restore()
            .boxed()
            .await
            .unwrap();
        assert_eq!(check(&restored, "cat /root/cache-marker").await, "private");
    })
    .catch_unwind()
    .await;

    for name in ["restored", "fork", "source"] {
        remove(backend, name).await;
    }
    if let Err(error) = outcome {
        std::panic::resume_unwind(error);
    }
}
