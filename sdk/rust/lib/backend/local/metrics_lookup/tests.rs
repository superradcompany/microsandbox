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

async fn catalog_run(local: &LocalBackend, name: &str) -> (i32, i32) {
    let pools = local.db().await.unwrap();
    let mut config = SandboxConfig::default();
    config.spec.name = name.into();
    let id = LocalBackend::insert_sandbox_record(pools.write(), &config)
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
async fn dual_names_validate_runs_merge_and_invalidate_reused_slots() {
    let home = tempfile::tempdir().unwrap();
    let mut local = LocalBackend::builder()
        .home(home.path())
        .build()
        .await
        .unwrap();
    let tag = Utc::now().timestamp_nanos_opt().unwrap() as u64;
    local.metrics_registry_names = vec![format!("/msb-n-{tag:x}"), format!("/msb-o-{tag:x}")];
    let new = MetricsRegistry::open_or_create(&local.metrics_registry_names[0], 8).unwrap();
    let old = MetricsRegistry::open_or_create(&local.metrics_registry_names[1], 8).unwrap();
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
    let names = local.metrics_registry_names.clone();
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
    let mut local = LocalBackend::builder()
        .home(home.path())
        .build()
        .await
        .unwrap();
    let tag = Utc::now().timestamp_nanos_opt().unwrap() as u64;
    local.metrics_registry_names = vec![format!("/msb-r-{tag:x}")];
    let (id, run) = catalog_run(&local, "replaced").await;
    let registry = MetricsRegistry::open_or_create(&local.metrics_registry_names[0], 1).unwrap();
    let writer = write(&registry, "replaced", id, run, 1);
    assert_eq!(
        local.verified_metrics(Some(run), false).await.unwrap()[0].memory_bytes,
        1
    );
    drop(writer);
    drop(registry);
    cleanup(&local.metrics_registry_names);
    assert!(
        local
            .verified_metrics(Some(run), false)
            .await
            .unwrap()
            .is_empty()
    );
    let replacement = MetricsRegistry::open_or_create(&local.metrics_registry_names[0], 1).unwrap();
    let _writer = write(&replacement, "replaced", id, run, 2);
    assert_eq!(
        local.verified_metrics(Some(run), false).await.unwrap()[0].memory_bytes,
        2
    );
    cleanup(&local.metrics_registry_names);
}
