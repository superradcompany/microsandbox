use chrono::Utc;
use microsandbox_metrics::{
    ActivateSlot, MetricsSlotWriter, ReleaseMode, ReserveSlot, SampleWrite,
};
use sea_orm::Set;

use super::*;
use crate::SandboxConfig;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn catalog_run(local: &LocalContext, name: &str) -> (i32, i32) {
    let pools = local.db().await.unwrap();
    let mut config = SandboxConfig::default();
    config.spec.name = name.into();
    let id = LocalContext::insert_sandbox_record(pools.write(), &config)
        .await
        .unwrap();
    let run = run::Entity::insert(run::ActiveModel {
        sandbox_id: Set(id),
        pid: Set(Some(std::process::id() as i32)),
        status: Set(run::RunStatus::Running),
        started_at: Set(Some(Utc::now().naive_utc())),
        ..Default::default()
    })
    .exec(pools.write())
    .await
    .unwrap()
    .last_insert_id;
    (id, run)
}

fn write(
    registry: &MetricsRegistry,
    name: &str,
    sandbox: i32,
    run: i32,
    memory: u64,
) -> MetricsSlotWriter {
    let slot = registry
        .reserve(ReserveSlot {
            sandbox_id: sandbox,
            name,
            memory_limit_bytes: 1024,
        })
        .unwrap();
    let writer = registry
        .activate_writer(ActivateSlot {
            slot: slot.slot,
            generation: slot.generation,
            run_id: run,
            pid: std::process::id() as i32,
            started_at: Utc::now(),
        })
        .unwrap();
    writer
        .write_sample(SampleWrite {
            sampled_at: Utc::now(),
            cpu_percent: None,
            vcpu_time_ns: None,
            memory_bytes: Some(memory),
            memory_available_bytes: None,
            memory_host_resident_bytes: None,
            memory_limit_bytes: None,
            disk_read_bytes: 0,
            disk_write_bytes: 0,
            net_rx_bytes: 0,
            net_tx_bytes: 0,
            net_inbound_tcp_rejected: None,
            net_outbound_tcp_rejected: None,
            net_outbound_udp_evicted: None,
            upper_used_bytes: None,
            upper_free_bytes: None,
            upper_host_allocated_bytes: None,
        })
        .unwrap();
    writer
}

fn cleanup(names: &[String]) {
    #[cfg(unix)]
    for name in names {
        let name = std::ffi::CString::new(name.as_bytes()).unwrap();
        unsafe {
            libc::shm_unlink(name.as_ptr());
        }
    }
    #[cfg(windows)]
    let _ = names; // Named mappings close when the test drops its final handles.
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn metrics_retain_the_shared_database_identity_after_control_is_dropped() {
    let home = tempfile::tempdir().unwrap();
    let mut local = crate::test_support::local_backend(crate::config::GlobalConfig {
        home: Some(home.path().to_path_buf()),
        ..Default::default()
    });
    local.db().await.unwrap();
    let identity = local
        .inner
        .metrics_lookup
        .state
        .lock()
        .unwrap()
        .database
        .clone()
        .unwrap();
    assert_eq!(Arc::strong_count(&identity), 3);
    drop(std::mem::take(
        &mut Arc::get_mut(&mut local.inner).unwrap().control_sessions,
    ));
    assert_eq!(Arc::strong_count(&identity), 2);
    assert!(
        local
            .verified_metrics(None, false)
            .await
            .unwrap()
            .is_empty()
    );
    // Windows SQLite connections prevent renaming the open catalog. Retain only
    // the shared identity and use binding verification after closing the pools.
    let pools = local.db().await.unwrap();
    pools.read().inner().close_by_ref().await.unwrap();
    pools.write().inner().close_by_ref().await.unwrap();
    local
        .inner
        .metrics_lookup
        .bind_database(identity.clone())
        .unwrap();
    let path = home.path().join("db/msb.db");
    std::fs::rename(&path, home.path().join("db/old.db")).unwrap();
    assert!(
        local
            .inner
            .metrics_lookup
            .bind_database(identity.clone())
            .unwrap_err()
            .to_string()
            .contains("metrics lookup: runtime session changed")
    );
    std::fs::write(path, b"replacement").unwrap();
    assert!(
        local
            .inner
            .metrics_lookup
            .bind_database(identity)
            .unwrap_err()
            .to_string()
            .contains("metrics lookup: runtime session changed")
    );
}

#[tokio::test]
async fn dual_names_validate_runs_merge_and_invalidate_reused_slots() {
    let home = tempfile::tempdir().unwrap();
    let mut local = LocalContext::builder().home(home.path()).build().unwrap();
    let tag = Utc::now().timestamp_nanos_opt().unwrap() as u64;
    Arc::get_mut(&mut local.inner)
        .unwrap()
        .metrics_registry_names = vec![format!("/msb-n-{tag:x}"), format!("/msb-o-{tag:x}")];
    let new = MetricsRegistry::open_or_create(&local.inner.metrics_registry_names[0], 8).unwrap();
    let old = MetricsRegistry::open_or_create(&local.inner.metrics_registry_names[1], 8).unwrap();
    let (a, ar) = catalog_run(&local, "old").await;
    let (b, br) = catalog_run(&local, "new").await;
    // A registry can exist yet have no matching run. A miss must not become permanent.
    assert!(
        local
            .verified_metrics(Some(ar), false)
            .await
            .unwrap()
            .is_empty()
    );
    let old_writer = write(&old, "old", a, ar, 11);
    let _new_writer = write(&new, "new", b, br, 22);
    assert_eq!(
        local.verified_metrics(Some(ar), false).await.unwrap()[0].memory_bytes,
        11
    );
    assert_eq!(local.verified_metrics(None, false).await.unwrap().len(), 2);
    // A matching run ID with the wrong sandbox must not hide the legacy match.
    let wrong = write(&new, "wrong", b, ar, 99);
    assert_eq!(
        local.verified_metrics(Some(ar), false).await.unwrap()[0].memory_bytes,
        11
    );
    drop(wrong);
    // Full API surfaces use the same verified matches.
    let all = crate::sandbox::all_sandbox_metrics_local(&local)
        .await
        .unwrap();
    assert_eq!(all["old"].memory_bytes, 11);
    assert_eq!(all["new"].memory_bytes, 22);
    let reports = crate::sandbox::all_sandbox_metrics_reports_local(&local, true)
        .await
        .unwrap();
    assert_eq!(reports.len(), 2);
    let report = crate::sandbox::sandbox_metrics_report_local(&local, "old")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.name, "old");
    // A new-name duplicate wins and listings remain deduplicated by verified run.
    let duplicate = write(&new, "old", a, ar, 33);
    assert_eq!(
        local.verified_metrics(Some(ar), false).await.unwrap()[0].memory_bytes,
        33
    );
    assert_eq!(local.verified_metrics(None, false).await.unwrap().len(), 2);
    duplicate.release(ReleaseMode::Stale).unwrap();
    assert_eq!(
        local.verified_metrics(Some(ar), true).await.unwrap()[0].memory_bytes,
        11
    );
    let reports = crate::sandbox::all_sandbox_metrics_reports_local(&local, true)
        .await
        .unwrap();
    assert!(
        reports
            .iter()
            .filter(|report| report.name == "old")
            .all(|report| report.state == crate::sandbox::SandboxMetricsState::Running)
    );
    let stale = new
        .identified_snapshot(true)
        .into_iter()
        .find(|sample| sample.metric.run_id == ar && sample.metric.memory_bytes == 33)
        .unwrap();
    new.release(stale.slot, stale.generation, ReleaseMode::Free)
        .unwrap();
    let reused = write(&new, "wrong-reused-slot", a, ar, 99);
    assert_eq!(
        local.verified_metrics(Some(ar), false).await.unwrap()[0].memory_bytes,
        11
    );
    reused.release(ReleaseMode::Free).unwrap();
    old_writer.release(ReleaseMode::Stale).unwrap();
    assert_eq!(local.verified_metrics(None, false).await.unwrap().len(), 1);
    let exited = crate::sandbox::sandbox_metrics_report_local(&local, "old")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exited.state, crate::sandbox::SandboxMetricsState::Exited);
    assert_eq!(local.verified_metrics(None, true).await.unwrap().len(), 2);
    let pools = local.db().await.unwrap();
    let next = run::Entity::insert(run::ActiveModel {
        sandbox_id: Set(a),
        pid: Set(Some(std::process::id() as i32)),
        status: Set(run::RunStatus::Running),
        started_at: Set(Some(Utc::now().naive_utc())),
        ..Default::default()
    })
    .exec(pools.write())
    .await
    .unwrap()
    .last_insert_id;
    let _restarted = write(&new, "old", a, next, 44);
    let mut config = SandboxConfig::default();
    config.spec.name = "old".into();
    let point = crate::sandbox::metrics::local_metrics(&local, "old", &config)
        .await
        .unwrap();
    assert_eq!(point.memory_bytes, 44);
    use futures::StreamExt;
    let names = local.inner.metrics_registry_names.clone();
    let mut stream = crate::sandbox::metrics::local_metrics_stream(
        Arc::new(local),
        "old".into(),
        config,
        std::time::Duration::from_millis(1),
    );
    assert_eq!(stream.next().await.unwrap().unwrap().memory_bytes, 44);
    cleanup(&names);
}

#[tokio::test]
async fn replacing_registry_never_returns_a_cached_mapping() {
    let home = tempfile::tempdir().unwrap();
    let mut local = LocalContext::builder().home(home.path()).build().unwrap();
    let tag = Utc::now().timestamp_nanos_opt().unwrap() as u64;
    Arc::get_mut(&mut local.inner)
        .unwrap()
        .metrics_registry_names = vec![format!("/msb-r-{tag:x}")];
    let (id, run) = catalog_run(&local, "replaced").await;
    let registry =
        MetricsRegistry::open_or_create(&local.inner.metrics_registry_names[0], 1).unwrap();
    let writer = write(&registry, "replaced", id, run, 1);
    assert_eq!(
        local.verified_metrics(Some(run), false).await.unwrap()[0].memory_bytes,
        1
    );
    drop(writer);
    drop(registry);
    cleanup(&local.inner.metrics_registry_names);
    assert!(
        local
            .verified_metrics(Some(run), false)
            .await
            .unwrap()
            .is_empty()
    );
    let replacement =
        MetricsRegistry::open_or_create(&local.inner.metrics_registry_names[0], 1).unwrap();
    let _writer = write(&replacement, "replaced", id, run, 2);
    assert_eq!(
        local.verified_metrics(Some(run), false).await.unwrap()[0].memory_bytes,
        2
    );
    cleanup(&local.inner.metrics_registry_names);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn private_metrics_reads_private_files_and_shared_registries_during_transition() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().unwrap();
    let mut local = LocalContext::builder()
        .home(home.path())
        .private_metrics(true)
        .build()
        .unwrap();
    let tag = Utc::now().timestamp_nanos_opt().unwrap() as u64;
    Arc::get_mut(&mut local.inner)
        .unwrap()
        .metrics_registry_names = vec![format!("/msb-tr-{tag:x}")];

    // Existing sandbox started before private_metrics was enabled writes to shared /dev/shm.
    let shared =
        MetricsRegistry::open_or_create(&local.inner.metrics_registry_names[0], 4).unwrap();
    let (shared_id, shared_run) = catalog_run(&local, "legacy-shared").await;
    let _shared_writer = write(&shared, "legacy-shared", shared_id, shared_run, 111);

    // New sandbox installs a private single-slot file and updates it via open_file.
    let (priv_id, priv_run) = catalog_run(&local, "new-private").await;
    let run_dir = local.config().run_dir();
    let (shm_name, slot, generation) =
        crate::runtime::private_metrics::install(&run_dir, priv_id, "new-private", 4096).unwrap();
    assert_eq!(
        shm_name,
        crate::runtime::private_metrics::shm_name("new-private")
    );
    assert_eq!(slot, 0);

    let file_path = crate::runtime::private_metrics::metrics_path(&run_dir, "new-private");
    assert_eq!(
        std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(file_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    let priv_reg = MetricsRegistry::open_file(&file_path).unwrap();
    let priv_writer = priv_reg
        .activate_writer(ActivateSlot {
            slot,
            generation,
            run_id: priv_run,
            pid: std::process::id() as i32,
            started_at: Utc::now(),
        })
        .unwrap();
    priv_writer
        .write_sample(SampleWrite {
            sampled_at: Utc::now(),
            cpu_percent: None,
            vcpu_time_ns: None,
            memory_bytes: Some(222),
            memory_available_bytes: None,
            memory_host_resident_bytes: None,
            memory_limit_bytes: None,
            disk_read_bytes: 0,
            disk_write_bytes: 0,
            net_rx_bytes: 0,
            net_tx_bytes: 0,
            net_inbound_tcp_rejected: None,
            net_outbound_tcp_rejected: None,
            net_outbound_udp_evicted: None,
            upper_used_bytes: None,
            upper_free_bytes: None,
            upper_host_allocated_bytes: None,
        })
        .unwrap();

    // Both sandboxes are observable together and individually.
    let all = local.verified_metrics(None, false).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(
        local
            .verified_metrics(Some(shared_run), false)
            .await
            .unwrap()[0]
            .memory_bytes,
        111
    );
    assert_eq!(
        local.verified_metrics(Some(priv_run), false).await.unwrap()[0].memory_bytes,
        222
    );

    // Replacing the private file with a symlink must fail closed.
    drop(priv_writer);
    drop(priv_reg);
    let outside = home.path().join("outside-metrics");
    std::fs::rename(&file_path, &outside).unwrap();
    std::os::unix::fs::symlink(&outside, &file_path).unwrap();
    assert!(local.verified_metrics(Some(priv_run), false).await.is_err());

    // Cleanup removes the entry and ignores subsequent calls.
    crate::runtime::private_metrics::remove(&run_dir, "new-private").unwrap();
    crate::runtime::private_metrics::remove(&run_dir, "new-private").unwrap();
    assert!(!file_path.exists());
    cleanup(&local.inner.metrics_registry_names);
}
