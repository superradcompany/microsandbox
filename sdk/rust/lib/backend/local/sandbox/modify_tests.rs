//! Local modification engine: planning, persistence, and live-batch tests.

use sea_orm::ActiveModelTrait;
use tempfile::tempdir;

use super::*;
use crate::backend::LocalBackend;

fn config(cpus: u8, memory_mib: u32) -> SandboxConfig {
    let mut config = SandboxConfig::default();
    config.spec.name = "api".to_string();
    config.spec.resources.cpus = cpus;
    config.spec.resources.memory_mib = memory_mib;
    config.spec.resources.max_cpus = cpus;
    config.spec.resources.max_memory_mib = memory_mib;
    config
}

#[tokio::test]
async fn persist_config_replaces_label_projection() {
    let temp = tempdir().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(
        LocalBackend::builder()
            .config_path(temp.path().join("config.json"))
            .managed_config_path(temp.path().join("managed.json"))
            .home(temp.path())
            .build()
            .await
            .unwrap(),
    );
    let pools = backend.as_local().unwrap().db().await.unwrap();
    let mut current = config(2, 1024);
    current.spec.labels.insert("team".into(), "stale".into());
    current.spec.labels.insert("removed".into(), "ghost".into());
    let model = sandbox_entity::ActiveModel {
        name: Set(current.spec.name.clone()),
        config: Set(serde_json::to_string(&current).unwrap()),
        active_config: Set(None),
        status: Set(SandboxStatus::Stopped),
        ephemeral: Set(false),
        created_at: Set(None),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(pools.write())
    .await
    .unwrap();
    let sandbox_id = model.id;
    for (key, value) in [("team", "stale"), ("removed", "ghost")] {
        sandbox_label_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            key: Set(key.into()),
            value: Set(value.into()),
        }
        .insert(pools.write())
        .await
        .unwrap();
    }

    let mut updated = current;
    updated.spec.labels.remove("removed");
    updated.spec.labels.insert("team".into(), "metrics".into());
    updated.spec.labels.insert("tier".into(), "gold".into());
    let handle = backend
        .sandboxes()
        .get(backend.clone(), &updated.spec.name)
        .await
        .unwrap();

    persist_config(&backend, &handle, &updated).await.unwrap();

    let mut rows = sandbox_label_entity::Entity::find()
        .filter(sandbox_label_entity::Column::SandboxId.eq(sandbox_id))
        .all(pools.read())
        .await
        .unwrap();
    rows.sort_by(|left, right| left.key.cmp(&right.key));
    assert_eq!(
        rows.into_iter()
            .map(|row| (row.key, row.value))
            .collect::<Vec<_>>(),
        vec![
            ("team".into(), "metrics".into()),
            ("tier".into(), "gold".into()),
        ]
    );
    let stored = sandbox_entity::Entity::find_by_id(sandbox_id)
        .one(pools.read())
        .await
        .unwrap()
        .unwrap();
    let stored: SandboxConfig = serde_json::from_str(&stored.config).unwrap();
    assert_eq!(stored.spec.labels, updated.spec.labels);

    let mut without_labels = updated;
    without_labels.spec.labels.clear();
    persist_config(&backend, &handle, &without_labels)
        .await
        .unwrap();

    let rows = sandbox_label_entity::Entity::find()
        .filter(sandbox_label_entity::Column::SandboxId.eq(sandbox_id))
        .all(pools.read())
        .await
        .unwrap();
    assert!(rows.is_empty());
    let stored = sandbox_entity::Entity::find_by_id(sandbox_id)
        .one(pools.read())
        .await
        .unwrap()
        .unwrap();
    let stored: SandboxConfig = serde_json::from_str(&stored.config).unwrap();
    assert!(stored.spec.labels.is_empty());
}

async fn identity_test_backend(home: &std::path::Path) -> Arc<dyn Backend> {
    Arc::new(
        crate::test_support::local_backend_builder(home)
            .build()
            .await
            .unwrap(),
    )
}

/// Insert a stopped row and its labels for `config`.
async fn insert_stopped_row(backend: &Arc<dyn Backend>, config: &SandboxConfig) -> i32 {
    let pools = backend.as_local().unwrap().db().await.unwrap();
    let id = sandbox_entity::ActiveModel {
        name: Set(config.spec.name.clone()),
        config: Set(serde_json::to_string(config).unwrap()),
        active_config: Set(None),
        status: Set(SandboxStatus::Stopped),
        ephemeral: Set(false),
        created_at: Set(None),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(pools.write())
    .await
    .unwrap()
    .id;
    for (key, value) in &config.spec.labels {
        sandbox_label_entity::ActiveModel {
            sandbox_id: Set(id),
            key: Set(key.clone()),
            value: Set(value.clone()),
        }
        .insert(pools.write())
        .await
        .unwrap();
    }
    id
}

/// Remove the row `id` and create a replacement under the same name.
async fn recreate_row(backend: &Arc<dyn Backend>, id: i32, config: &SandboxConfig) -> i32 {
    let pools = backend.as_local().unwrap().db().await.unwrap();
    sandbox_entity::Entity::delete_by_id(id)
        .exec(pools.write())
        .await
        .unwrap();
    let replacement = insert_stopped_row(backend, config).await;
    assert_ne!(replacement, id);
    replacement
}

/// Stored config JSON, update time, and sorted labels of row `id`.
async fn row_snapshot(
    backend: &Arc<dyn Backend>,
    id: i32,
) -> (String, Option<chrono::NaiveDateTime>, Vec<(String, String)>) {
    let pools = backend.as_local().unwrap().db().await.unwrap();
    let row = sandbox_entity::Entity::find_by_id(id)
        .one(pools.read())
        .await
        .unwrap()
        .unwrap();
    let mut labels = sandbox_label_entity::Entity::find()
        .filter(sandbox_label_entity::Column::SandboxId.eq(id))
        .all(pools.read())
        .await
        .unwrap()
        .into_iter()
        .map(|label| (label.key, label.value))
        .collect::<Vec<_>>();
    labels.sort();
    (row.config, row.updated_at, labels)
}

fn assert_replaced(error: crate::MicrosandboxError, name: &str, expected: i32, actual: i32) {
    assert!(
        matches!(
            &error,
            crate::MicrosandboxError::SandboxReplaced {
                name: replaced,
                expected: stale,
                actual: current,
            } if replaced == name
                && *stale == format!("local:{expected}")
                && *current == format!("local:{actual}")
        ),
        "expected SandboxReplaced, got {error:?}"
    );
}

#[tokio::test]
async fn local_modifications_are_not_resumable_operations() {
    let temp = tempdir().unwrap();
    let backend = identity_test_backend(temp.path()).await;
    insert_stopped_row(&backend, &config(2, 1024)).await;
    let handle = backend
        .sandboxes()
        .get(backend.clone(), "api")
        .await
        .unwrap();

    let error = handle.resume_modification("op-1").await.unwrap_err();

    assert!(
        matches!(
            error,
            crate::MicrosandboxError::Unsupported {
                op: crate::Operation::SandboxModify,
                reason: crate::UnsupportedReason::NotAvailable(_),
            }
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn modify_builder_refuses_a_recreated_name() {
    let temp = tempdir().unwrap();
    let backend = identity_test_backend(temp.path()).await;
    let mut original = config(2, 1024);
    original
        .spec
        .labels
        .insert("generation".into(), "old".into());
    let original_id = insert_stopped_row(&backend, &original).await;
    let builder = backend
        .sandboxes()
        .get(backend.clone(), "api")
        .await
        .unwrap()
        .modify()
        .env("MODIFIED", "yes")
        .label("generation", "modified")
        .cpus(4);

    let mut replacement = config(1, 512);
    replacement
        .spec
        .labels
        .insert("generation".into(), "new".into());
    let replacement_id = recreate_row(&backend, original_id, &replacement).await;
    let before = row_snapshot(&backend, replacement_id).await;

    let planned = builder.clone().dry_run().await.unwrap_err();
    assert_replaced(planned, "api", original_id, replacement_id);
    let applied = builder.apply().await.unwrap_err();
    assert_replaced(applied, "api", original_id, replacement_id);

    assert_eq!(row_snapshot(&backend, replacement_id).await, before);
}

#[tokio::test]
async fn persist_config_refuses_a_replaced_row() {
    let temp = tempdir().unwrap();
    let backend = identity_test_backend(temp.path()).await;
    let original = config(2, 1024);
    let original_id = insert_stopped_row(&backend, &original).await;
    let handle = backend
        .sandboxes()
        .get(backend.clone(), "api")
        .await
        .unwrap();

    let mut replacement = config(1, 512);
    replacement.spec.labels.insert("owner".into(), "new".into());
    let replacement_id = recreate_row(&backend, original_id, &replacement).await;
    let before = row_snapshot(&backend, replacement_id).await;
    let mut updated = original;
    updated.spec.labels.insert("owner".into(), "stale".into());

    let error = persist_config(&backend, &handle, &updated)
        .await
        .unwrap_err();
    assert_replaced(error, "api", original_id, replacement_id);
    assert_eq!(row_snapshot(&backend, replacement_id).await, before);

    let pools = backend.as_local().unwrap().db().await.unwrap();
    sandbox_entity::Entity::delete_by_id(replacement_id)
        .exec(pools.write())
        .await
        .unwrap();
    let error = persist_config(&backend, &handle, &updated)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, crate::MicrosandboxError::SandboxNotFound(name) if name == "api"),
        "expected SandboxNotFound, got {error:?}"
    );
}

/// Insert a running row whose live run is owned by this test process.
#[cfg(unix)]
async fn insert_running_row(backend: &Arc<dyn Backend>, config: &SandboxConfig) -> i32 {
    let pools = backend.as_local().unwrap().db().await.unwrap();
    sandbox_entity::ActiveModel {
        name: Set(config.spec.name.clone()),
        config: Set(serde_json::to_string(config).unwrap()),
        active_config: Set(None),
        status: Set(SandboxStatus::Running),
        ephemeral: Set(false),
        created_at: Set(None),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(pools.write())
    .await
    .unwrap()
    .id
}

/// Start a new live run for row `sandbox_id`, ending any earlier one.
#[cfg(unix)]
async fn start_test_run(backend: &Arc<dyn Backend>, sandbox_id: i32) -> SandboxRunIdentity {
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

    let pools = backend.as_local().unwrap().db().await.unwrap();
    let pid = std::process::id() as i32;
    for (sql, values) in [
        (
            "UPDATE run SET status = 'Terminated' WHERE sandbox_id = ?",
            vec![sandbox_id.into()],
        ),
        (
            "INSERT INTO run (sandbox_id, pid, status) VALUES (?, ?, 'Running')",
            vec![sandbox_id.into(), pid.into()],
        ),
    ] {
        pools
            .write()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                sql,
                values,
            ))
            .await
            .unwrap();
    }
    let run = LocalBackend::load_active_run(pools.read(), sandbox_id)
        .await
        .unwrap()
        .unwrap();
    SandboxRunIdentity {
        sandbox_id,
        run_id: run.id,
        pid,
    }
}

#[cfg(unix)]
#[tokio::test]
async fn live_root_grow_reaches_only_the_captured_run() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let home = tempfile::tempdir_in("/tmp").unwrap();
    let backend = identity_test_backend(home.path()).await;
    let local = backend.as_local().unwrap();
    let agent = crate::runtime::sandbox_agent_socket_path_candidates_for(local, "api").remove(0);
    let path = microsandbox_runtime::control::control_socket_path_for(&agent);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let listener = tokio::net::UnixListener::bind(path).unwrap();

    let original_id = insert_running_row(&backend, &config(2, 1024)).await;
    let planned = start_test_run(&backend, original_id).await;
    let restarted = start_test_run(&backend, original_id).await;
    let error = grow_root_disk_live(local, "api", planned, 64)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("changed runtime"),
        "expected a runtime change refusal, got {error:?}"
    );

    let pools = local.db().await.unwrap();
    sandbox_entity::Entity::delete_by_id(original_id)
        .exec(pools.write())
        .await
        .unwrap();
    let replacement_id = insert_running_row(&backend, &config(1, 512)).await;
    let replacement = start_test_run(&backend, replacement_id).await;
    let error = grow_root_disk_live(local, "api", restarted, 64)
        .await
        .unwrap_err();
    assert_replaced(error, "api", original_id, replacement_id);

    // Refused requests never connect, so nothing is queued on the endpoint.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );

    let size_bytes = 64 * 1024 * 1024u64;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        assert_eq!(line, "{\"op\":\"capabilities\"}\n");
        stream
            .get_mut()
            .write_all(b"{\"ok\":true,\"capabilities\":{\"root_disk_grow\":true,\"cpu_resize\":false,\"memory_resize\":false,\"secrets_update\":false}}\n")
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["op"], "root_disk_grow");
        assert_eq!(request["size_bytes"], size_bytes);
        let response = serde_json::json!({"ok": true, "root_disk": {
            "filesystem_bytes": size_bytes, "device_bytes": size_bytes,
            "total_us": 0, "pause_us": 0, "guest_us": 0
        }});
        stream
            .get_mut()
            .write_all(format!("{response}\n").as_bytes())
            .await
            .unwrap();
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        grow_root_disk_live(local, "api", replacement, 64),
    )
    .await
    .unwrap()
    .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn offline_root_grow_refuses_a_replaced_row() {
    let temp = tempdir().unwrap();
    let backend = identity_test_backend(temp.path()).await;
    let original = oci_config_with_upper(64);
    let original_id = insert_stopped_row(&backend, &original).await;
    let replacement_id = recreate_row(&backend, original_id, &oci_config_with_upper(32)).await;
    let upper = backend
        .as_local()
        .unwrap()
        .sandboxes_dir()
        .join("api")
        .join("upper.ext4");
    std::fs::create_dir_all(upper.parent().unwrap()).unwrap();
    std::fs::write(&upper, vec![0; 4096]).unwrap();

    let error = grow_root_disk_now(&backend, "api", original_id, &original, 128)
        .await
        .unwrap_err();

    assert_replaced(error, "api", original_id, replacement_id);
    assert_eq!(std::fs::metadata(&upper).unwrap().len(), 4096);
}

#[test]
fn running_resource_changes_require_restart_until_live_resize_lands() {
    let patch = SandboxModificationPatch {
        cpus: Some(4),
        memory_mib: Some(4096),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config(2, 1024),
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert_eq!(plan.changes.len(), 4);
    for change in plan.changes {
        let PlannedChange::Config(change) = change else {
            panic!("expected config change");
        };
        assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
        match change.field.as_str() {
            "cpus" | "memory" => {
                assert_eq!(change.reason.as_deref(), Some(LIVE_RESIZE_UNAVAILABLE));
            }
            "max_cpus" | "max_memory" => {
                assert!(
                    change
                        .reason
                        .as_deref()
                        .is_some_and(|reason| { reason.contains("boot-time capacity") })
                );
            }
            field => panic!("unexpected field {field}"),
        }
    }
}

#[test]
fn running_cpus_within_active_capacity_classify_live() {
    // The sandbox booted with reserved capacity: desired and active agree
    // on max_cpus 8 while only 2 CPUs are online.
    let mut desired = config(2, 1024);
    desired.spec.resources.max_cpus = 8;
    let active = desired.clone();
    let patch = SandboxModificationPatch {
        cpus: Some(4),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &desired,
        Some(&active),
        LiveControl {
            root_disk_grow: false,
            cpu_resize: true,
            memory_resize: true,
            secrets: false,
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );

    let PlannedChange::Config(change) = &plan.changes[0] else {
        panic!("expected config change");
    };
    assert_eq!(change.field, "cpus");
    assert_eq!(change.disposition, ModificationDisposition::Live);
    assert!(change.reason.is_none());
    assert!(validate_apply_supported(&plan).is_ok());
    assert_eq!(live_cpu_target(&plan, &patch), Some(4));
}

#[test]
fn running_memory_within_capacity_classifies_live_only_with_control_socket() {
    let mut desired = config(2, 512);
    desired.spec.resources.max_memory_mib = 2048;
    let active = desired.clone();
    let patch = SandboxModificationPatch {
        memory_mib: Some(1024),
        ..SandboxModificationPatch::default()
    };

    for (live_memory_supported, expected) in [
        (true, ModificationDisposition::Live),
        (false, ModificationDisposition::RequiresRestart),
    ] {
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &desired,
            Some(&active),
            LiveControl {
                root_disk_grow: false,
                cpu_resize: live_memory_supported,
                memory_resize: live_memory_supported,
                secrets: false,
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        let PlannedChange::Config(change) = &plan.changes[0] else {
            panic!("expected config change");
        };
        assert_eq!(change.field, "memory");
        assert_eq!(change.disposition, expected);
        if live_memory_supported {
            assert_eq!(live_memory_target(&plan, &patch), Some(1024));
        } else {
            assert_eq!(live_memory_target(&plan, &patch), None);
        }
    }
}

#[test]
fn cpu_and_memory_capabilities_are_independent() {
    let mut active = config(1, 256);
    active.spec.resources.max_cpus = 2;
    active.spec.resources.max_memory_mib = 512;
    for (cpu_resize, memory_resize) in [(true, false), (false, true)] {
        let plan = build_plan(
            "api".into(),
            SandboxStatus::Running,
            &active,
            Some(&active),
            LiveControl {
                root_disk_grow: false,
                cpu_resize,
                memory_resize,
                secrets: false,
            },
            SandboxModificationPatch {
                cpus: Some(2),
                memory_mib: Some(512),
                ..Default::default()
            },
            ModificationPolicy::NoRestart,
        );
        for (field, supported) in [("cpus", cpu_resize), ("memory", memory_resize)] {
            let change = plan
                .changes
                .iter()
                .find_map(|change| match change {
                    PlannedChange::Config(change) if change.field == field => Some(change),
                    _ => None,
                })
                .unwrap();
            assert_eq!(
                change.disposition,
                if supported {
                    ModificationDisposition::Live
                } else {
                    ModificationDisposition::RequiresRestart
                }
            );
        }
    }
}

#[test]
fn running_cpus_above_active_capacity_require_restart() {
    let mut active = config(2, 1024);
    active.spec.resources.max_cpus = 8;
    let patch = SandboxModificationPatch {
        cpus: Some(12),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config(2, 1024),
        Some(&active),
        LiveControl {
            root_disk_grow: false,
            cpu_resize: true,
            memory_resize: true,
            secrets: false,
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );

    let PlannedChange::Config(change) = &plan.changes[0] else {
        panic!("expected config change");
    };
    assert_eq!(change.field, "cpus");
    assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
    assert!(
        change
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("exceeds the active max capacity 8"))
    );
    assert_eq!(live_cpu_target(&plan, &patch), None);
}

#[test]
fn restart_policy_allows_restart_required_resource_apply() {
    let patch = SandboxModificationPatch {
        cpus: Some(4),
        memory_mib: Some(4096),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config(2, 1024),
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::Restart,
    );

    assert!(validate_apply_supported(&plan).is_ok());
}

#[test]
fn no_restart_policy_rejects_restart_required_resource_apply() {
    let patch = SandboxModificationPatch {
        cpus: Some(4),
        memory_mib: Some(4096),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config(2, 1024),
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert!(validate_apply_supported(&plan).is_err());
}

#[test]
fn stopped_resource_changes_are_next_start() {
    let patch = SandboxModificationPatch {
        cpus: Some(4),
        memory_mib: Some(4096),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config(2, 1024),
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert_eq!(plan.changes.len(), 4);
    for change in plan.changes {
        let PlannedChange::Config(change) = change else {
            panic!("expected config change");
        };
        assert_eq!(change.disposition, ModificationDisposition::NextStart);
        assert!(change.reason.is_none());
    }
}

#[test]
fn max_capacity_conflicts_with_requested_effective_value() {
    let patch = SandboxModificationPatch {
        cpus: Some(8),
        max_cpus: Some(4),
        memory_mib: Some(8192),
        max_memory_mib: Some(4096),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config(2, 1024),
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert_eq!(plan.conflicts.len(), 2);
    assert_eq!(plan.conflicts[0].field, "max_cpus");
    assert_eq!(plan.conflicts[1].field, "max_memory");
}

#[test]
fn zero_resource_values_are_conflicts() {
    let patch = SandboxModificationPatch {
        cpus: Some(0),
        max_cpus: Some(0),
        memory_mib: Some(0),
        max_memory_mib: Some(0),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config(2, 1024),
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert!(
        plan.conflicts
            .iter()
            .any(|conflict| conflict.field == "cpus")
    );
    assert!(
        plan.conflicts
            .iter()
            .any(|conflict| conflict.field == "memory")
    );
    assert!(
        plan.conflicts
            .iter()
            .any(|conflict| conflict.field == "max_cpus")
    );
    assert!(
        plan.conflicts
            .iter()
            .any(|conflict| conflict.field == "max_memory")
    );
}

#[test]
fn applying_effective_resource_change_raises_capacity_when_needed() {
    let mut config = config(2, 1024);
    let patch = SandboxModificationPatch {
        cpus: Some(4),
        memory_mib: Some(4096),
        ..SandboxModificationPatch::default()
    };

    apply_patch_to_config(&mut config, &patch);

    assert_eq!(config.spec.resources.cpus, 4);
    assert_eq!(config.spec.resources.max_cpus, 4);
    assert_eq!(config.spec.resources.memory_mib, 4096);
    assert_eq!(config.spec.resources.max_memory_mib, 4096);
}

fn oci_config_with_upper(upper_mib: u32) -> SandboxConfig {
    let mut config = config(2, 1024);
    config.spec.image = RootfsSource::Oci(microsandbox_types::OciRootfsSource {
        reference: "python".to_string(),
        root_disk: Some(RootDisk::managed(upper_mib)),
    });
    config
}

fn oci_config_with_root_disk(root_disk: RootDisk) -> SandboxConfig {
    let mut config = config(2, 1024);
    config.spec.image = RootfsSource::Oci(microsandbox_types::OciRootfsSource {
        reference: "python".to_string(),
        root_disk: Some(root_disk),
    });
    config
}

#[test]
fn stopped_upper_grow_classifies_next_start() {
    let patch = SandboxModificationPatch {
        root_disk_size_mib: Some(8192),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &oci_config_with_upper(4096),
        None,
        LiveControl::default(),
        patch.clone(),
        ModificationPolicy::NoRestart,
    );

    assert!(plan.conflicts.is_empty());
    assert_eq!(plan.changes.len(), 1);
    let PlannedChange::Config(change) = &plan.changes[0] else {
        panic!("expected config change");
    };
    assert_eq!(change.field, "root_disk_size");
    assert_eq!(change.change, ChangeKind::Updated);
    assert_eq!(change.before.as_deref(), Some("4 GiB"));
    assert_eq!(change.after.as_deref(), Some("8 GiB"));
    assert_eq!(change.disposition, ModificationDisposition::NextStart);
    assert!(change.reason.is_none());
    assert!(validate_apply_supported(&plan).is_ok());
    assert_eq!(
        root_disk_grow_target(&plan, &patch, &oci_config_with_upper(4096)),
        Some(8192)
    );
}

#[test]
fn invalid_checkpoint_backed_root_grow_does_not_mutate_the_sealed_base() {
    let sandbox = tempdir().unwrap();
    let runtime = sandbox.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    let base = sandbox.path().join("rootfs.raw");
    let head = sandbox.path().join("root-active.qcow2");
    std::fs::write(&base, vec![0; 4096]).unwrap();
    // Checkpoint chains can grow here; malformed heads must still fail before any write.
    std::fs::write(&head, b"qcow").unwrap();
    let head_before = std::fs::read(&head).unwrap();
    let state = serde_json::json!({
        "schema": "microsandbox.runtime-root-disk/1",
        "volume_id": "vol_00000000000000000000000000000000",
        "device_id": "vda",
        "layout": "flat-root",
        "published_generation": 1,
        "layers": [
            {
                "layer_id": "layer_00000000000000000000000000000001",
                "path": base,
                "format": "raw",
                "integrity_root": microsandbox_image::checkpoint::sparse_file_integrity(&base).unwrap().root
            },
            {
                "layer_id": "layer_00000000000000000000000000000002",
                "path": head,
                "format": "qcow2",
                "integrity_root": null
            }
        ]
    });
    std::fs::write(
        runtime.join("root-disk.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();

    let error = microsandbox_runtime::checkpoint::grow_stopped_root(&runtime, 8192).unwrap_err();
    let expected = microsandbox_image::checkpoint::layer_capacities(vec![
        microsandbox_image::checkpoint::CompactLayer {
            path: head.clone(),
            qcow2: true,
        },
    ])
    .unwrap_err();
    assert_eq!(error, expected.to_string());
    assert_eq!(std::fs::read(&base).unwrap(), vec![0; 4096]);
    assert_eq!(std::fs::read(&head).unwrap(), head_before);
    assert_eq!(
        std::fs::read(runtime.join("root-disk.json")).unwrap(),
        serde_json::to_vec(&state).unwrap()
    );
}

#[test]
fn old_runtime_upper_grow_requires_explicit_restart() {
    let patch = SandboxModificationPatch {
        root_disk_size_mib: Some(8192),
        ..SandboxModificationPatch::default()
    };

    // CPU/memory resize capability alone does not advertise root growth.
    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &oci_config_with_upper(4096),
        None,
        LiveControl {
            root_disk_grow: false,
            cpu_resize: true,
            memory_resize: true,
            secrets: true,
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );

    let PlannedChange::Config(change) = &plan.changes[0] else {
        panic!("expected config change");
    };
    assert_eq!(change.field, "root_disk_size");
    assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
    assert_eq!(
        change.reason.as_deref(),
        Some(UPPER_LIVE_RESIZE_UNAVAILABLE)
    );
    assert!(validate_apply_supported(&plan).is_err());

    // The restart policy makes the same change applicable.
    let restart_plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &oci_config_with_upper(4096),
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::Restart,
    );
    assert!(validate_apply_supported(&restart_plan).is_ok());
    assert!(plan_requires_restart(&restart_plan));
}

#[test]
fn owned_root_growth_uses_live_capability_but_respects_explicit_policies() {
    for root in [RootDisk::managed(512), RootDisk::flat(512)] {
        let config = oci_config_with_root_disk(root);
        for (policy, expected) in [
            (ModificationPolicy::NoRestart, ModificationDisposition::Live),
            (
                ModificationPolicy::NextStart,
                ModificationDisposition::NextStart,
            ),
            (
                ModificationPolicy::Restart,
                ModificationDisposition::RequiresRestart,
            ),
        ] {
            let plan = build_plan(
                "grow".into(),
                SandboxStatus::Running,
                &config,
                None,
                LiveControl {
                    root_disk_grow: true,
                    cpu_resize: false,
                    memory_resize: false,
                    secrets: false,
                },
                SandboxModificationPatch {
                    root_disk_size_mib: Some(1024),
                    ..Default::default()
                },
                policy,
            );
            assert!(plan.conflicts.is_empty());
            let PlannedChange::Config(change) = &plan.changes[0] else {
                panic!("expected disk change")
            };
            assert_eq!(change.disposition, expected);
            assert!(validate_apply_supported(&plan).is_ok());
        }
    }
}

#[test]
fn running_upper_grow_under_next_start_persists_desired_only() {
    let patch = SandboxModificationPatch {
        root_disk_size_mib: Some(8192),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &oci_config_with_upper(4096),
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NextStart,
    );

    let PlannedChange::Config(change) = &plan.changes[0] else {
        panic!("expected config change");
    };
    assert_eq!(change.disposition, ModificationDisposition::NextStart);
    assert_eq!(change.reason.as_deref(), Some(UPPER_GROWS_ON_NEXT_START));
    assert!(validate_apply_supported(&plan).is_ok());
}

#[test]
fn upper_shrink_and_same_size_requests_conflict() {
    for (target_mib, expected) in [
        (2048, "shrink is not supported"),
        (4096, "only grow is supported"),
    ] {
        let patch = SandboxModificationPatch {
            root_disk_size_mib: Some(target_mib),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &oci_config_with_upper(4096),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert!(plan.changes.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].field, "root_disk_size");
        assert!(
            plan.conflicts[0].message.contains(expected),
            "unexpected conflict for {target_mib}: {}",
            plan.conflicts[0].message
        );
        assert!(validate_apply_supported(&plan).is_err());
    }
}

#[test]
fn non_oci_rootfs_upper_change_conflicts() {
    let mut current = config(2, 1024);
    current.spec.image = RootfsSource::Bind {
        path: "/srv/rootfs".into(),
        follow_root_symlinks: false,
    };
    let patch = SandboxModificationPatch {
        root_disk_size_mib: Some(8192),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &current,
        None,
        LiveControl::default(),
        patch.clone(),
        ModificationPolicy::NoRestart,
    );

    assert!(plan.changes.is_empty());
    assert_eq!(plan.conflicts.len(), 1);
    assert_eq!(plan.conflicts[0].field, "root_disk_size");
    assert!(plan.conflicts[0].message.contains("requires an OCI rootfs"));
    assert_eq!(root_disk_grow_target(&plan, &patch, &current), None);
}

#[test]
fn unmaterialized_upper_default_compares_against_create_default() {
    // Configs that predate materialized defaults store no upper size; the
    // effective current size is the create-time default (4 GiB).
    let patch = SandboxModificationPatch {
        root_disk_size_mib: Some(2048),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config(2, 1024),
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert_eq!(plan.conflicts.len(), 1);
    assert!(
        plan.conflicts[0]
            .message
            .contains("shrink is not supported")
    );
}

#[test]
fn applying_upper_patch_updates_oci_config() {
    let mut config = oci_config_with_upper(4096);
    let patch = SandboxModificationPatch {
        root_disk_size_mib: Some(8192),
        ..SandboxModificationPatch::default()
    };

    apply_patch_to_config(&mut config, &patch);

    assert_eq!(
        config.spec.image.oci_root_disk(),
        Some(&RootDisk::managed(8192))
    );
}

#[test]
fn tmpfs_root_disk_resizes_any_direction_without_host_grow() {
    let current = oci_config_with_root_disk(RootDisk::tmpfs(1024));
    // Shrink is fine for tmpfs: the content is ephemeral.
    let patch = SandboxModificationPatch {
        root_disk_size_mib: Some(512),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &current,
        None,
        LiveControl::default(),
        patch.clone(),
        ModificationPolicy::NoRestart,
    );

    assert!(plan.conflicts.is_empty());
    assert_eq!(plan.changes.len(), 1);
    let PlannedChange::Config(change) = &plan.changes[0] else {
        panic!("expected config change");
    };
    assert_eq!(change.field, "root_disk_size");
    // No host file to grow for a tmpfs root disk.
    assert_eq!(root_disk_grow_target(&plan, &patch, &current), None);
}

#[test]
fn tmpfs_root_disk_resize_over_memory_conflicts() {
    // config() allocates 1024 MiB of guest memory.
    let current = oci_config_with_root_disk(RootDisk::tmpfs(512));
    let patch = SandboxModificationPatch {
        root_disk_size_mib: Some(2048),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &current,
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert!(plan.changes.is_empty());
    assert_eq!(plan.conflicts.len(), 1);
    assert!(
        plan.conflicts[0]
            .message
            .contains("must not exceed sandbox memory")
    );
}

#[test]
fn disk_image_root_disk_resize_conflicts() {
    let current = oci_config_with_root_disk(RootDisk::DiskImage {
        path: "./scratch.img".into(),
        format: microsandbox_types::DiskImageFormat::Raw,
        fstype: None,
    });
    let patch = SandboxModificationPatch {
        root_disk_size_mib: Some(8192),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &current,
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert!(plan.changes.is_empty());
    assert_eq!(plan.conflicts.len(), 1);
    assert!(
        plan.conflicts[0]
            .message
            .contains("user-supplied disk image")
    );
}

#[test]
fn running_env_label_workdir_changes_require_restart() {
    let patch = SandboxModificationPatch {
        env: vec![EnvVar::new("MODE", "prod")],
        labels: vec![("team".to_string(), "infra".to_string())],
        workdir: Some("/srv".to_string()),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config(2, 1024),
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert_eq!(plan.changes.len(), 3);
    for change in plan.changes {
        let PlannedChange::Config(change) = change else {
            panic!("expected config change");
        };
        assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
        assert_eq!(change.change, ChangeKind::Added);
        match change.field.as_str() {
            "env" | "workdir" => {
                assert_eq!(
                    change.reason.as_deref(),
                    Some(LIVE_EXEC_DEFAULT_UPDATE_UNAVAILABLE)
                );
            }
            "label" => {
                assert_eq!(
                    change.reason.as_deref(),
                    Some(LIVE_LABEL_UPDATE_UNAVAILABLE)
                );
            }
            field => panic!("unexpected field {field}"),
        }
    }
}

#[test]
fn stopped_env_label_workdir_changes_are_next_start() {
    let patch = SandboxModificationPatch {
        env: vec![EnvVar::new("MODE", "prod")],
        env_remove: vec!["EXTRA".to_string()],
        labels: vec![("team".to_string(), "infra".to_string())],
        labels_remove: vec!["old".to_string()],
        workdir: Some("/srv".to_string()),
        ..SandboxModificationPatch::default()
    };

    let mut current = config(2, 1024);
    current.spec.env.push(EnvVar::new("EXTRA", "1"));
    current
        .spec
        .labels
        .insert("old".to_string(), "x".to_string());

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &current,
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert_eq!(plan.changes.len(), 5);
    assert!(plan.conflicts.is_empty());
    for change in plan.changes {
        let PlannedChange::Config(change) = change else {
            panic!("expected config change");
        };
        assert_eq!(change.disposition, ModificationDisposition::NextStart);
        assert!(change.reason.is_none());
    }
}

#[test]
fn spec_change_kinds_follow_current_config() {
    let mut current = config(2, 1024);
    current.spec.env = vec![EnvVar::new("MODE", "dev"), EnvVar::new("EXTRA", "1")];
    current
        .spec
        .labels
        .insert("team".to_string(), "infra".to_string());
    current.spec.runtime.workdir = Some("/app".to_string());

    let patch = SandboxModificationPatch {
        env: vec![EnvVar::new("MODE", "prod"), EnvVar::new("NEW", "1")],
        env_remove: vec!["EXTRA".to_string(), "MISSING".to_string()],
        labels: vec![("tier".to_string(), "gold".to_string())],
        labels_remove: vec!["team".to_string()],
        workdir: Some("/srv".to_string()),
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &current,
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    let rows: Vec<(&str, ChangeKind, Option<&str>, Option<&str>)> = plan
        .changes
        .iter()
        .map(|change| {
            let PlannedChange::Config(change) = change else {
                panic!("expected config change");
            };
            (
                change.field.as_str(),
                change.change,
                change.before.as_deref(),
                change.after.as_deref(),
            )
        })
        .collect();

    assert_eq!(
        rows,
        vec![
            (
                "env",
                ChangeKind::Updated,
                Some("MODE=dev"),
                Some("MODE=prod")
            ),
            ("env", ChangeKind::Added, None, Some("NEW=1")),
            ("env", ChangeKind::Removed, Some("EXTRA=1"), None),
            ("label", ChangeKind::Added, None, Some("tier=gold")),
            ("label", ChangeKind::Removed, Some("team=infra"), None),
            ("workdir", ChangeKind::Updated, Some("/app"), Some("/srv")),
        ]
    );
}

#[test]
fn running_spec_changes_warn_future_execs_only_under_restart_and_next_start() {
    let current = config(2, 1024);
    let patch = SandboxModificationPatch {
        env: vec![EnvVar::new("MODE", "prod"), EnvVar::new("NEW", "1")],
        workdir: Some("/srv".to_string()),
        labels: vec![("tier".to_string(), "gold".to_string())],
        ..SandboxModificationPatch::default()
    };

    for policy in [ModificationPolicy::Restart, ModificationPolicy::NextStart] {
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &current,
            None,
            LiveControl::default(),
            patch.clone(),
            policy,
        );

        let future_exec_fields: Vec<&str> = plan
            .warnings
            .iter()
            .filter(|warning| warning.message == FUTURE_EXECS_ONLY)
            .map(|warning| warning.field.as_str())
            .collect();
        // One warning per field: env is deduplicated, labels are excluded.
        assert_eq!(future_exec_fields, vec![ENV_FIELD, WORKDIR_FIELD]);
    }
}

#[test]
fn future_exec_warning_skips_stopped_sandboxes_and_default_policy() {
    let current = config(2, 1024);
    let patch = SandboxModificationPatch {
        env: vec![EnvVar::new("MODE", "prod")],
        workdir: Some("/srv".to_string()),
        ..SandboxModificationPatch::default()
    };

    let cases = [
        (SandboxStatus::Stopped, ModificationPolicy::NextStart),
        (SandboxStatus::Stopped, ModificationPolicy::Restart),
        (SandboxStatus::Running, ModificationPolicy::NoRestart),
    ];
    for (status, policy) in cases {
        let plan = build_plan(
            "api".to_string(),
            status,
            &current,
            None,
            LiveControl::default(),
            patch.clone(),
            policy,
        );

        assert!(
            plan.warnings
                .iter()
                .all(|warning| warning.message != FUTURE_EXECS_ONLY),
            "unexpected future-exec warning for {status:?} under {policy:?}"
        );
    }
}

#[test]
fn applying_env_label_workdir_patch_mutates_config() {
    let mut current = config(2, 1024);
    current.spec.env = vec![EnvVar::new("MODE", "dev"), EnvVar::new("EXTRA", "1")];
    current
        .spec
        .labels
        .insert("team".to_string(), "infra".to_string());
    let patch = SandboxModificationPatch {
        env: vec![EnvVar::new("MODE", "prod"), EnvVar::new("NEW", "1")],
        env_remove: vec!["EXTRA".to_string()],
        labels: vec![("tier".to_string(), "gold".to_string())],
        labels_remove: vec!["team".to_string()],
        workdir: Some("/srv".to_string()),
        ..SandboxModificationPatch::default()
    };

    apply_patch_to_config(&mut current, &patch);

    assert_eq!(
        current.spec.env,
        vec![EnvVar::new("MODE", "prod"), EnvVar::new("NEW", "1")]
    );
    assert_eq!(
        current.spec.labels.get("tier").map(String::as_str),
        Some("gold")
    );
    assert!(!current.spec.labels.contains_key("team"));
    assert_eq!(current.spec.runtime.workdir.as_deref(), Some("/srv"));
}

#[test]
fn setting_and_removing_the_same_key_is_a_conflict() {
    let patch = SandboxModificationPatch {
        env: vec![EnvVar::new("MODE", "prod")],
        env_remove: vec!["MODE".to_string()],
        labels: vec![("team".to_string(), "infra".to_string())],
        labels_remove: vec!["team".to_string()],
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config(2, 1024),
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert_eq!(plan.conflicts.len(), 2);
    assert_eq!(plan.conflicts[0].field, "env");
    assert!(plan.conflicts[0].message.contains("MODE"));
    assert_eq!(plan.conflicts[1].field, "label");
    assert!(plan.conflicts[1].message.contains("team"));
    assert!(validate_apply_supported(&plan).is_err());
}

#[test]
fn secret_plan_never_contains_secret_values() {
    const VALUE_SENTINEL: &str = "modify-plan-secret-sentinel";

    // Put real material into the input: an empty value would make the
    // absence assertion pass even if planning accidentally copied it.
    let patch = SandboxModificationPatch {
        secrets: vec![SecretModificationPatch {
            name: "API_KEY".to_string(),
            source: None,
            value: zeroize::Zeroizing::new(VALUE_SENTINEL.to_string()),
            placeholder: None,
            allowed_hosts: vec!["api.example.com".to_string()],
            ..SecretModificationPatch::default()
        }],
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config(2, 1024),
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );
    let json = serde_json::to_string(&plan).unwrap();

    assert!(json.contains("$MSB_API_KEY"));
    assert!(json.contains("api.example.com"));
    assert!(!json.contains(VALUE_SENTINEL));
    assert!(!format!("{plan:?}").contains(VALUE_SENTINEL));
    assert_eq!(plan.sandbox, "api");

    let PlannedChange::Secret(change) = &plan.changes[0] else {
        panic!("expected secret change");
    };
    assert_eq!(change.field, SECRET_FIELD);
    assert_eq!(change.change, SecretChangeKind::Added);
    assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
}

//----------------------------------------------------------------------------------------------
// Tests: Secrets
//----------------------------------------------------------------------------------------------

#[cfg(feature = "net")]
const SECRET_SENTINEL: &str = "sentinel-secret-value";

#[cfg(feature = "net")]
fn config_with_secret(name: &str, value: &str) -> SandboxConfig {
    use microsandbox_network::secrets::config::{HostPattern, SecretEntry, SecretSubstitution};

    let mut config = config(2, 1024);
    let mut network = config.local_network_config().unwrap();
    network.secrets.secrets.push(SecretEntry {
        env_var: name.to_string(),
        value: zeroize::Zeroizing::new(value.to_string()),
        source: None,
        placeholder: format!("$MSB_{name}"),
        allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
        substitution: SecretSubstitution::default(),
        passthrough_hosts: Vec::new(),
        violation_action: None,
        require_tls_identity: true,
    });
    // Mirror the top-level sandbox builder's create-time policy.
    crate::sandbox::config::ensure_tls_for_secrets(&mut network);
    config.set_local_network_config(network).unwrap();
    config
}

/// The pre-fix shape this bug used to persist: a secret with TLS off.
#[cfg(feature = "net")]
fn config_with_secret_and_tls_disabled(name: &str, value: &str) -> SandboxConfig {
    let mut config = config_with_secret(name, value);
    let mut network = config.local_network_config().unwrap();
    network.tls.enabled = false;
    config.set_local_network_config(network).unwrap();
    config
}

/// A deliberate plain-HTTP secret configuration: substitution is allowed
/// without TLS identity, so interception stays off.
#[cfg(feature = "net")]
fn config_with_plain_http_secret_and_tls_disabled(name: &str, value: &str) -> SandboxConfig {
    let mut config = config_with_secret_and_tls_disabled(name, value);
    let mut network = config.local_network_config().unwrap();
    network.secrets.secrets[0].require_tls_identity = false;
    config.set_local_network_config(network).unwrap();
    config
}

/// A source-based spec for `name`, resolving from the same-named host
/// environment variable.
#[cfg(feature = "net")]
fn source_spec(name: &str, hosts: &[&str]) -> SecretModificationPatch {
    SecretModificationPatch {
        name: name.to_string(),
        source: Some(SecretSource::Env {
            var: name.to_string(),
        }),
        allowed_hosts: hosts.iter().map(ToString::to_string).collect(),
        ..SecretModificationPatch::default()
    }
}

/// A material-free spec for `name` (hosts and/or placeholder only).
#[cfg(feature = "net")]
fn bare_spec(name: &str, hosts: &[&str]) -> SecretModificationPatch {
    SecretModificationPatch {
        name: name.to_string(),
        allowed_hosts: hosts.iter().map(ToString::to_string).collect(),
        ..SecretModificationPatch::default()
    }
}

#[cfg(feature = "net")]
fn patch_with_specs(specs: Vec<SecretModificationPatch>) -> SandboxModificationPatch {
    SandboxModificationPatch {
        secrets: specs,
        ..SandboxModificationPatch::default()
    }
}

#[cfg(feature = "net")]
fn secret_policy_specs() -> Vec<SecretModificationPatch> {
    vec![
        SecretModificationPatch {
            substitution: Some(SecretSubstitution {
                headers: false,
                header_fields: Vec::new(),
                query: true,
                body: true,
            }),
            ..bare_spec("API_KEY", &[])
        },
        SecretModificationPatch {
            violation_action: Some(SecretViolationAction::BlockAndTerminate),
            ..bare_spec("API_KEY", &[])
        },
        SecretModificationPatch {
            require_tls_identity: Some(false),
            ..bare_spec("API_KEY", &[])
        },
        SecretModificationPatch {
            passthrough_hosts: vec!["logs.example.com".into()],
            ..bare_spec("API_KEY", &[])
        },
        SecretModificationPatch {
            substitution: Some(SecretSubstitution {
                header_fields: vec!["authorization".into(), "x-api-key".into()],
                ..SecretSubstitution::default()
            }),
            ..bare_spec("API_KEY", &[])
        },
    ]
}

#[cfg(feature = "net")]
#[test]
fn secret_policy_edits_are_planned_and_never_sent_live() {
    let config = config_with_secret("API_KEY", SECRET_SENTINEL);
    for spec in secret_policy_specs() {
        for (status, policy, expected, apply_allowed) in [
            (
                SandboxStatus::Running,
                ModificationPolicy::NoRestart,
                ModificationDisposition::RequiresRestart,
                false,
            ),
            (
                SandboxStatus::Running,
                ModificationPolicy::Restart,
                ModificationDisposition::RequiresRestart,
                true,
            ),
            (
                SandboxStatus::Running,
                ModificationPolicy::NextStart,
                ModificationDisposition::NextStart,
                true,
            ),
            (
                SandboxStatus::Stopped,
                ModificationPolicy::NoRestart,
                ModificationDisposition::NextStart,
                true,
            ),
            (
                SandboxStatus::Stopped,
                ModificationPolicy::Restart,
                ModificationDisposition::NextStart,
                true,
            ),
            (
                SandboxStatus::Stopped,
                ModificationPolicy::NextStart,
                ModificationDisposition::NextStart,
                true,
            ),
            (
                SandboxStatus::Paused,
                ModificationPolicy::NoRestart,
                ModificationDisposition::Unsupported,
                false,
            ),
            (
                SandboxStatus::Paused,
                ModificationPolicy::Restart,
                ModificationDisposition::Unsupported,
                false,
            ),
            (
                SandboxStatus::Paused,
                ModificationPolicy::NextStart,
                ModificationDisposition::NextStart,
                true,
            ),
        ] {
            for supported in [false, true] {
                for combined_change in 0..3 {
                    let mut spec = spec.clone();
                    match combined_change {
                        1 => spec.allowed_hosts = vec!["other.example.com".into()],
                        2 => spec.value = SECRET_SENTINEL.to_string().into(),
                        _ => {}
                    }
                    let patch = patch_with_specs(vec![spec]);
                    let plan = build_plan(
                        "api".into(),
                        status,
                        &config,
                        Some(&config),
                        LiveControl {
                            secrets: supported,
                            ..Default::default()
                        },
                        patch.clone(),
                        policy,
                    );
                    assert_eq!(plan.changes.len(), 1);
                    match &plan.changes[0] {
                        PlannedChange::Config(change) => {
                            assert_eq!(change.field, "secret.API_KEY.policy");
                            assert_eq!(change.change, ChangeKind::Updated);
                            assert_eq!(change.disposition, expected);
                        }
                        PlannedChange::Secret(change) => {
                            assert_ne!(combined_change, 0);
                            assert_eq!(change.disposition, expected);
                        }
                    }
                    assert!(live_secret_updates(&plan, &patch).unwrap().is_empty());
                    assert_eq!(validate_apply_supported(&plan).is_ok(), apply_allowed,);
                    assert_eq!(
                        plan_requires_restart(&plan),
                        expected == ModificationDisposition::RequiresRestart
                    );
                    assert!(
                        !serde_json::to_string(&plan)
                            .unwrap()
                            .contains(SECRET_SENTINEL)
                    );
                    assert!(plan.warnings.is_empty());
                }
            }
        }
    }
}

#[cfg(feature = "net")]
#[test]
fn secret_policy_comparison_preserves_noops_and_checks_active_rules() {
    let original = config_with_secret("API_KEY", SECRET_SENTINEL);
    for spec in secret_policy_specs() {
        let patch = patch_with_specs(vec![spec]);
        let mut desired = original.clone();
        apply_secret_patch_to_config(&mut desired, &patch).unwrap();
        let plan = build_plan(
            "api".into(),
            SandboxStatus::Running,
            &desired,
            Some(&desired),
            LiveControl {
                secrets: true,
                ..Default::default()
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        assert!(
            plan.changes.is_empty(),
            "identical explicit policies are no-ops"
        );

        let pending = build_plan(
            "api".into(),
            SandboxStatus::Running,
            &desired,
            Some(&original),
            LiveControl {
                secrets: true,
                ..Default::default()
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        assert!(plan_requires_restart(&pending));
        assert!(validate_apply_supported(&pending).is_err());
        assert!(live_secret_updates(&pending, &patch).unwrap().is_empty());

        let omitted = patch_with_specs(vec![bare_spec("API_KEY", &[])]);
        let unchanged = build_plan(
            "api".into(),
            SandboxStatus::Running,
            &desired,
            Some(&desired),
            LiveControl {
                secrets: true,
                ..Default::default()
            },
            omitted,
            ModificationPolicy::NoRestart,
        );
        assert!(
            unchanged.changes.is_empty(),
            "omitted fields preserve existing policies"
        );
    }
}

#[cfg(feature = "net")]
#[tokio::test]
async fn applying_stopped_secret_policy_edits_persists_each_option() {
    let temp = tempdir().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(
        LocalBackend::builder()
            .config_path(temp.path().join("config.json"))
            .managed_config_path(temp.path().join("managed.json"))
            .home(temp.path())
            .build()
            .await
            .unwrap(),
    );
    let pools = backend.as_local().unwrap().db().await.unwrap();
    for (index, spec) in secret_policy_specs().into_iter().enumerate() {
        let mut current = config_with_secret("API_KEY", SECRET_SENTINEL);
        current.spec.name = format!("policy-{index}");
        let model = sandbox_entity::ActiveModel {
            name: Set(current.spec.name.clone()),
            config: Set(serde_json::to_string(&current).unwrap()),
            active_config: Set(None),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let patch = patch_with_specs(vec![spec]);
        let plan = backend
            .sandboxes()
            .get(backend.clone(), &current.spec.name)
            .await
            .unwrap()
            .modify()
            .with_patch(patch.clone())
            .apply()
            .await
            .unwrap();
        assert!(plan.applied);
        assert_eq!(plan.changes.len(), 1);
        let row = sandbox_entity::Entity::find_by_id(model.id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        assert!(row.active_config.is_none());
        let saved: SandboxConfig = serde_json::from_str(&row.config).unwrap();
        let network = saved.local_network_config().unwrap();
        let entry = &network.secrets.secrets[0];
        match index {
            0 => {
                assert!(!entry.substitution.headers);
                assert!(entry.substitution.query);
                assert!(entry.substitution.body);
            }
            1 => assert_eq!(
                entry.violation_action,
                Some(SecretViolationAction::BlockAndTerminate)
            ),
            2 => assert!(!entry.require_tls_identity),
            3 => assert_eq!(
                entry
                    .passthrough_hosts
                    .iter()
                    .cloned()
                    .map(format_host_pattern)
                    .collect::<Vec<_>>(),
                vec!["logs.example.com"]
            ),
            4 => assert_eq!(
                entry.substitution.header_fields,
                vec!["authorization", "x-api-key"]
            ),
            _ => unreachable!(),
        }
        assert!(!secret_policy_changes(
            &patch.secrets[0],
            existing_secret(&saved, "API_KEY").as_ref()
        ));
        assert_eq!(
            &*saved.local_network_config().unwrap().secrets.secrets[0].value,
            SECRET_SENTINEL
        );
        let repeat = backend
            .sandboxes()
            .get(backend.clone(), &current.spec.name)
            .await
            .unwrap()
            .modify()
            .with_patch(patch)
            .apply()
            .await
            .unwrap();
        assert!(repeat.changes.is_empty());
    }
}

/// The `tls` change a secret patch emits when it must turn interception on.
#[cfg(feature = "net")]
fn tls_plan_change(plan: &SandboxModificationPlan) -> Option<&ConfigPlannedChange> {
    plan.changes.iter().find_map(|change| match change {
        PlannedChange::Config(change) if change.field == TLS_FIELD => Some(change),
        _ => None,
    })
}

#[cfg(feature = "net")]
fn secret_plan_dispositions(plan: &SandboxModificationPlan) -> Vec<ModificationDisposition> {
    plan.changes
        .iter()
        .map(|change| match change {
            PlannedChange::Secret(change) => change.disposition.clone(),
            PlannedChange::Config(_) => panic!("expected secret change"),
        })
        .collect()
}

#[cfg(feature = "net")]
fn secret_plan_kinds(plan: &SandboxModificationPlan) -> Vec<SecretChangeKind> {
    plan.changes
        .iter()
        .map(|change| match change {
            PlannedChange::Secret(change) => change.change,
            PlannedChange::Config(_) => panic!("expected secret change"),
        })
        .collect()
}

#[cfg(feature = "net")]
#[test]
fn running_secret_rotate_remove_hosts_classify_live_with_runtime_support() {
    let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let mut network = config.local_network_config().unwrap();
    let mut other = network.secrets.secrets[0].clone();
    other.env_var = "OTHER_KEY".to_string();
    other.placeholder = "$MSB_OTHER_KEY".to_string();
    network.secrets.secrets.push(other);
    config.set_local_network_config(network).unwrap();

    let patch = patch_with_specs(vec![
        source_spec("API_KEY", &[]),
        bare_spec("OTHER_KEY", &["*.example.org"]),
    ]);
    let removal_patch = SandboxModificationPatch {
        secrets_remove: vec!["API_KEY".to_string()],
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            root_disk_grow: false,
            cpu_resize: false,
            memory_resize: false,
            secrets: true,
        },
        patch,
        ModificationPolicy::NoRestart,
    );

    assert_eq!(
        secret_plan_kinds(&plan),
        vec![SecretChangeKind::Rotated, SecretChangeKind::HostsUpdated]
    );
    assert_eq!(
        secret_plan_dispositions(&plan),
        vec![ModificationDisposition::Live; 2]
    );
    assert!(plan.conflicts.is_empty());
    assert!(plan.warnings.is_empty());
    assert!(validate_apply_supported(&plan).is_ok());

    let removal_plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            root_disk_grow: false,
            cpu_resize: false,
            memory_resize: false,
            secrets: true,
        },
        removal_patch,
        ModificationPolicy::NoRestart,
    );
    assert_eq!(
        secret_plan_kinds(&removal_plan),
        vec![SecretChangeKind::Removed]
    );
    assert_eq!(
        secret_plan_dispositions(&removal_plan),
        vec![ModificationDisposition::Live]
    );
}

#[cfg(feature = "net")]
#[test]
fn running_secret_add_and_placeholder_change_require_restart_even_with_live_support() {
    let config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let mut patch = patch_with_specs(vec![source_spec("NEW_KEY", &["api.new.test"])]);
    let mut placeholder_spec = bare_spec("API_KEY", &[]);
    placeholder_spec.placeholder = Some("$ROTATED_REF".to_string());
    patch.secrets.push(placeholder_spec);

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            root_disk_grow: false,
            cpu_resize: false,
            memory_resize: false,
            secrets: true,
        },
        patch,
        ModificationPolicy::NoRestart,
    );

    assert_eq!(
        secret_plan_kinds(&plan),
        vec![
            SecretChangeKind::Added,
            SecretChangeKind::PlaceholderUpdated
        ]
    );
    assert_eq!(
        secret_plan_dispositions(&plan),
        vec![ModificationDisposition::RequiresRestart; 2]
    );
    assert!(validate_apply_supported(&plan).is_err());
}

#[cfg(feature = "net")]
#[test]
fn running_rotate_with_placeholder_change_requires_restart_even_with_live_support() {
    let config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let mut spec = source_spec("API_KEY", &[]);
    spec.placeholder = Some("$NEW_REF".to_string());
    let patch = patch_with_specs(vec![spec]);

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            root_disk_grow: false,
            cpu_resize: false,
            memory_resize: false,
            secrets: true,
        },
        patch,
        ModificationPolicy::NoRestart,
    );

    let PlannedChange::Secret(change) = &plan.changes[0] else {
        panic!("expected secret change");
    };
    assert_eq!(change.change, SecretChangeKind::Rotated);
    assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
    assert!(
        change
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("placeholder"))
    );
    // No live-support warning: the restart is forced by the placeholder,
    // not by a runtime gap.
    assert!(plan.warnings.is_empty());
}

#[cfg(feature = "net")]
#[test]
fn running_secret_rotate_requires_restart_without_runtime_support() {
    let config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    let PlannedChange::Secret(change) = &plan.changes[0] else {
        panic!("expected secret change");
    };
    assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
    assert_eq!(
        change.reason.as_deref(),
        Some(LIVE_SECRET_RECONFIGURE_UNAVAILABLE)
    );
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.field == SECRET_FIELD)
    );
    assert!(validate_apply_supported(&plan).is_err());
    // The restart policy unblocks the same plan shape.
    let restart_plan = SandboxModificationPlan {
        policy: ModificationPolicy::Restart,
        ..plan
    };
    assert!(validate_apply_supported(&restart_plan).is_ok());
}

#[cfg(feature = "net")]
#[test]
fn stopped_secret_changes_are_next_start_and_apply_supported() {
    let config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config,
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert_eq!(
        secret_plan_dispositions(&plan),
        vec![ModificationDisposition::NextStart]
    );
    assert!(validate_apply_supported(&plan).is_ok());
}

/// A plan must neither vary with nor contain the secret value (cloud dry runs never send it).
#[cfg(feature = "net")]
#[tokio::test]
async fn value_only_rotation_plans_the_same_for_any_value() {
    let temp = tempdir().unwrap();
    let backend = identity_test_backend(temp.path()).await;
    insert_stopped_row(&backend, &config_with_secret("API_KEY", SECRET_SENTINEL)).await;
    let handle = backend
        .sandboxes()
        .get(backend.clone(), "api")
        .await
        .unwrap();

    let mut plans = Vec::new();
    for value in ["first-rotated-material", "second, longer rotated material"] {
        let plan = handle
            .modify()
            .secret(|secret| secret.env("API_KEY").value(value))
            .dry_run()
            .await
            .unwrap();
        assert_eq!(secret_plan_kinds(&plan), vec![SecretChangeKind::Rotated]);
        assert_eq!(
            secret_plan_dispositions(&plan),
            vec![ModificationDisposition::NextStart]
        );
        let plan = serde_json::to_string(&plan).unwrap();
        assert!(!plan.contains(value));
        assert!(!plan.contains(SECRET_SENTINEL));
        plans.push(plan);
    }
    assert_eq!(plans[0], plans[1]);
}

#[cfg(feature = "net")]
#[test]
fn planner_infers_change_kinds_from_spec_diffs() {
    let config = config_with_secret("API_KEY", SECRET_SENTINEL);

    // Material on an existing secret: rotated (source or value alike).
    let mut value_spec = bare_spec("API_KEY", &[]);
    value_spec.value = zeroize::Zeroizing::new("new-material".to_string());
    for spec in [source_spec("API_KEY", &[]), value_spec] {
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch_with_specs(vec![spec]),
            ModificationPolicy::NoRestart,
        );
        assert_eq!(secret_plan_kinds(&plan), vec![SecretChangeKind::Rotated]);
        assert!(plan.conflicts.is_empty());
    }

    // Material for an unknown name: added.
    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config,
        None,
        LiveControl::default(),
        patch_with_specs(vec![source_spec("NEW_KEY", &["api.new.test"])]),
        ModificationPolicy::NoRestart,
    );
    assert_eq!(secret_plan_kinds(&plan), vec![SecretChangeKind::Added]);
    assert!(plan.conflicts.is_empty());

    // Hosts-only diff: hosts updated.
    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config,
        None,
        LiveControl::default(),
        patch_with_specs(vec![bare_spec("API_KEY", &["*.example.org"])]),
        ModificationPolicy::NoRestart,
    );
    assert_eq!(
        secret_plan_kinds(&plan),
        vec![SecretChangeKind::HostsUpdated]
    );

    // Placeholder-only diff: placeholder updated.
    let mut spec = bare_spec("API_KEY", &[]);
    spec.placeholder = Some("$NEW_REF".to_string());
    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config,
        None,
        LiveControl::default(),
        patch_with_specs(vec![spec]),
        ModificationPolicy::NoRestart,
    );
    assert_eq!(
        secret_plan_kinds(&plan),
        vec![SecretChangeKind::PlaceholderUpdated]
    );
}

#[cfg(feature = "net")]
#[test]
fn spec_matching_current_state_is_a_declarative_noop() {
    let config = config_with_secret("API_KEY", SECRET_SENTINEL);

    // Same hosts, same placeholder, no material: nothing to change.
    let mut spec = bare_spec("API_KEY", &["api.example.com"]);
    spec.placeholder = Some("$MSB_API_KEY".to_string());
    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config,
        None,
        LiveControl::default(),
        patch_with_specs(vec![spec]),
        ModificationPolicy::NoRestart,
    );
    assert!(plan.changes.is_empty());
    assert!(plan.conflicts.is_empty());

    // Removing a secret that does not exist is also a no-op.
    let patch = SandboxModificationPatch {
        secrets_remove: vec!["MISSING".to_string()],
        ..SandboxModificationPatch::default()
    };
    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config,
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );
    assert!(plan.changes.is_empty());
}

#[cfg(feature = "net")]
#[test]
fn secret_conflicts_reject_impossible_patches() {
    let config = config_with_secret("API_KEY", SECRET_SENTINEL);

    // Adding a new secret without any allowed host.
    let patch = patch_with_specs(vec![source_spec("NEW_KEY", &[])]);
    let mut conflicts = Vec::new();
    push_secret_conflicts(&config, &patch, &mut conflicts);
    assert!(conflicts[0].message.contains("allowed host"));

    // A new secret needs material (source or value).
    let patch = patch_with_specs(vec![bare_spec("MISSING", &["api.example.com"])]);
    let mut conflicts = Vec::new();
    push_secret_conflicts(&config, &patch, &mut conflicts);
    assert!(conflicts[0].message.contains("source or value"));

    // Value and source together are ambiguous.
    let mut spec = source_spec("API_KEY", &[]);
    spec.value = zeroize::Zeroizing::new("inline-material".to_string());
    let patch = patch_with_specs(vec![spec]);
    let mut conflicts = Vec::new();
    push_secret_conflicts(&config, &patch, &mut conflicts);
    assert!(conflicts[0].message.contains("mutually exclusive"));

    // Store-backed sources are not implemented yet.
    let mut spec = source_spec("API_KEY", &[]);
    spec.source = Some(SecretSource::Store {
        reference: "vault://team/api-key".to_string(),
    });
    let patch = patch_with_specs(vec![spec]);
    let mut conflicts = Vec::new();
    push_secret_conflicts(&config, &patch, &mut conflicts);
    assert!(conflicts[0].message.contains("store-backed"));

    // Configuring and removing the same secret in one patch.
    let mut patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);
    patch.secrets_remove.push("API_KEY".to_string());
    let mut conflicts = Vec::new();
    push_secret_conflicts(&config, &patch, &mut conflicts);
    assert!(conflicts[0].message.contains("both configured and removed"));

    // A spec without a name cannot target anything.
    let patch = patch_with_specs(vec![SecretModificationPatch::default()]);
    let mut conflicts = Vec::new();
    push_secret_conflicts(&config, &patch, &mut conflicts);
    assert!(conflicts[0].message.contains("needs a name"));
}

/// Regression for #1422: the first secret left `tls.enabled` false, so the
/// placeholder reached the upstream unsubstituted.
#[cfg(feature = "net")]
#[test]
fn adding_first_secret_enables_tls_in_durable_config() {
    let mut config = config(2, 1024);
    assert!(!config.local_network_config().unwrap().tls.enabled);

    let patch = patch_with_specs(vec![source_spec("API_KEY", &["api.example.com"])]);
    apply_secret_patch_to_config(&mut config, &patch).unwrap();

    let network = config.local_network_config().unwrap();
    assert_eq!(network.secrets.secrets.len(), 1);
    assert!(network.tls.enabled);
}

/// Interception is restart-backed, so the first secret must show up in the
/// plan and drive the restart rather than flip silently under a running VM.
#[cfg(feature = "net")]
#[test]
fn first_secret_plans_tls_change_and_forces_restart() {
    let config = config(2, 1024);
    let patch = patch_with_specs(vec![source_spec("API_KEY", &["api.example.com"])]);

    // Stopped: lands on the next start.
    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config,
        None,
        LiveControl::default(),
        patch.clone(),
        ModificationPolicy::NoRestart,
    );
    let tls = tls_plan_change(&plan).expect("expected a tls change");
    assert_eq!(tls.change, ChangeKind::Updated);
    assert_eq!(tls.disposition, ModificationDisposition::NextStart);
    assert!(validate_apply_supported(&plan).is_ok());

    // Running under the default policy: an explicit error.
    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            secrets: true,
            ..LiveControl::default()
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );
    assert_eq!(
        tls_plan_change(&plan).unwrap().disposition,
        ModificationDisposition::RequiresRestart
    );
    assert!(validate_apply_supported(&plan).is_err());

    // Restart opted in: the restart rebuilds active from the durable config.
    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            secrets: true,
            ..LiveControl::default()
        },
        patch,
        ModificationPolicy::Restart,
    );
    assert!(validate_apply_supported(&plan).is_ok());
    assert!(plan_requires_restart(&plan));
}

/// Rotating a secret on a legacy TLS-off config classifies as live, and
/// mirroring it would claim TLS the running proxy does not have.
#[cfg(feature = "net")]
#[test]
fn live_secret_change_on_tls_disabled_config_requires_restart() {
    let config = config_with_secret_and_tls_disabled("API_KEY", SECRET_SENTINEL);
    let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            secrets: true,
            ..LiveControl::default()
        },
        patch,
        ModificationPolicy::NoRestart,
    );

    // The rotate itself is live-applicable, so tls is the only blocker.
    let secret_dispositions: Vec<_> = plan
        .changes
        .iter()
        .filter_map(|change| match change {
            PlannedChange::Secret(change) => Some(change.disposition.clone()),
            PlannedChange::Config(_) => None,
        })
        .collect();
    assert_eq!(secret_dispositions, vec![ModificationDisposition::Live]);
    assert_eq!(
        tls_plan_change(&plan).unwrap().disposition,
        ModificationDisposition::RequiresRestart
    );
    let err = validate_apply_supported(&plan).unwrap_err().to_string();
    assert_eq!(err, "cannot apply modification: tls requires restart");
}

/// Plain-HTTP substitution is an intentional TLS-off configuration, so a
/// live rotation must not enable interception or force a restart.
#[cfg(feature = "net")]
#[test]
fn live_plain_http_secret_rotation_does_not_enable_tls() {
    let mut config = config_with_plain_http_secret_and_tls_disabled("API_KEY", SECRET_SENTINEL);
    let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            secrets: true,
            ..LiveControl::default()
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );

    assert!(tls_plan_change(&plan).is_none());
    assert_eq!(
        secret_plan_dispositions(&plan),
        vec![ModificationDisposition::Live]
    );
    assert!(validate_apply_supported(&plan).is_ok());

    apply_secret_patch_to_config(&mut config, &patch).unwrap();
    let network = config.local_network_config().unwrap();
    assert!(!network.tls.enabled);
    assert!(!network.secrets.secrets[0].require_tls_identity);
}

/// Enabling TLS identity on an existing plain-HTTP secret must plan the
/// interception restart that persistence will require.
#[cfg(feature = "net")]
#[test]
fn enabling_tls_identity_on_existing_secret_plans_tls_restart() {
    let mut config = config_with_plain_http_secret_and_tls_disabled("API_KEY", SECRET_SENTINEL);
    let mut spec = source_spec("API_KEY", &[]);
    spec.require_tls_identity = Some(true);
    let patch = patch_with_specs(vec![spec]);

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            secrets: true,
            ..LiveControl::default()
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );

    assert_eq!(
        tls_plan_change(&plan).unwrap().disposition,
        ModificationDisposition::RequiresRestart
    );
    assert!(validate_apply_supported(&plan).is_err());

    apply_secret_patch_to_config(&mut config, &patch).unwrap();
    let network = config.local_network_config().unwrap();
    assert!(network.tls.enabled);
    assert!(network.secrets.secrets[0].require_tls_identity);
}

/// A new secret can explicitly opt out of TLS identity, so persistence
/// and planning must both leave interception disabled.
#[cfg(feature = "net")]
#[test]
fn adding_plain_http_secret_does_not_plan_tls_enable() {
    let mut config = config(2, 1024);
    let mut spec = source_spec("API_KEY", &["api.example.com"]);
    spec.require_tls_identity = Some(false);
    let patch = patch_with_specs(vec![spec]);

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            secrets: true,
            ..LiveControl::default()
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );

    assert!(tls_plan_change(&plan).is_none());

    apply_secret_patch_to_config(&mut config, &patch).unwrap();
    let network = config.local_network_config().unwrap();
    assert!(!network.tls.enabled);
    assert!(!network.secrets.secrets[0].require_tls_identity);
}

/// A removal-only patch can leave another TLS-dependent secret behind.
/// Planning and persistence must both surface the implied TLS enable.
#[cfg(feature = "net")]
#[test]
fn removing_one_legacy_secret_plans_tls_for_the_remaining_secret() {
    let mut config = config_with_secret_and_tls_disabled("KEEP", SECRET_SENTINEL);
    let mut network = config.local_network_config().unwrap();
    let mut removed = network.secrets.secrets[0].clone();
    removed.env_var = "REMOVE".to_string();
    removed.placeholder = "$MSB_REMOVE".to_string();
    network.secrets.secrets.push(removed);
    config.set_local_network_config(network).unwrap();
    let patch = SandboxModificationPatch {
        secrets_remove: vec!["REMOVE".to_string()],
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            secrets: true,
            ..LiveControl::default()
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );

    assert_eq!(
        tls_plan_change(&plan).unwrap().disposition,
        ModificationDisposition::RequiresRestart
    );
    assert!(validate_apply_supported(&plan).is_err());

    apply_secret_patch_to_config(&mut config, &patch).unwrap();
    let network = config.local_network_config().unwrap();
    assert_eq!(network.secrets.secrets.len(), 1);
    assert_eq!(network.secrets.secrets[0].env_var, "KEEP");
    assert!(network.tls.enabled);
}

/// Removal-only patches that leave only plain-HTTP secrets remain live and
/// keep interception disabled.
#[cfg(feature = "net")]
#[test]
fn removing_one_plain_http_secret_keeps_tls_disabled() {
    let mut config = config_with_plain_http_secret_and_tls_disabled("KEEP", SECRET_SENTINEL);
    let mut network = config.local_network_config().unwrap();
    let mut removed = network.secrets.secrets[0].clone();
    removed.env_var = "REMOVE".to_string();
    removed.placeholder = "$MSB_REMOVE".to_string();
    network.secrets.secrets.push(removed);
    config.set_local_network_config(network).unwrap();
    let patch = SandboxModificationPatch {
        secrets_remove: vec!["REMOVE".to_string()],
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            secrets: true,
            ..LiveControl::default()
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );

    assert!(tls_plan_change(&plan).is_none());
    assert!(validate_apply_supported(&plan).is_ok());

    apply_secret_patch_to_config(&mut config, &patch).unwrap();
    let network = config.local_network_config().unwrap();
    assert_eq!(network.secrets.secrets.len(), 1);
    assert_eq!(network.secrets.secrets[0].env_var, "KEEP");
    assert!(!network.tls.enabled);
}

/// One-way: emptying the secret set must not turn interception off.
#[cfg(feature = "net")]
#[test]
fn removing_last_secret_keeps_tls_enabled() {
    let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let patch = SandboxModificationPatch {
        secrets_remove: vec!["API_KEY".to_string()],
        ..SandboxModificationPatch::default()
    };

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config,
        None,
        LiveControl::default(),
        patch.clone(),
        ModificationPolicy::NoRestart,
    );
    assert!(tls_plan_change(&plan).is_none());

    apply_secret_patch_to_config(&mut config, &patch).unwrap();

    let network = config.local_network_config().unwrap();
    assert!(network.secrets.secrets.is_empty());
    assert!(network.tls.enabled);
}

/// Interception already on: nothing to enable, so no extra plan noise.
#[cfg(feature = "net")]
#[test]
fn secret_change_with_tls_already_enabled_plans_no_tls_change() {
    let config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config,
        None,
        LiveControl::default(),
        patch,
        ModificationPolicy::NoRestart,
    );

    assert!(tls_plan_change(&plan).is_none());
}
#[cfg(feature = "net")]
#[test]
fn applying_new_source_spec_uses_create_placeholder_default() {
    use microsandbox_network::secrets::config::HostPattern;

    let mut config = config(2, 1024);
    let patch = patch_with_specs(vec![source_spec("API_KEY", &["api.example.com"])]);

    apply_secret_patch_to_config(&mut config, &patch).unwrap();

    let network = config.local_network_config().unwrap();
    let entry = &network.secrets.secrets[0];
    assert_eq!(entry.env_var, "API_KEY");
    assert!(entry.value.is_empty());
    assert_eq!(
        entry.source,
        Some(SecretSource::Env {
            var: "API_KEY".into()
        })
    );
    assert_eq!(entry.placeholder, "$MSB_API_KEY");
    assert_eq!(
        entry.allowed_hosts,
        vec![HostPattern::Exact("api.example.com".into())]
    );
    assert!(entry.require_tls_identity);
}

#[cfg(feature = "net")]
#[test]
fn applying_source_rotate_drops_inlined_value_and_keeps_placeholder() {
    let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

    apply_secret_patch_to_config(&mut config, &patch).unwrap();

    let network = config.local_network_config().unwrap();
    let entry = &network.secrets.secrets[0];
    assert!(entry.value.is_empty());
    assert_eq!(
        entry.source,
        Some(SecretSource::Env {
            var: "API_KEY".into()
        })
    );
    // Rotation keeps the guest-visible placeholder and host allow-list.
    assert_eq!(entry.placeholder, "$MSB_API_KEY");
    assert_eq!(entry.allowed_hosts.len(), 1);
}

#[cfg(feature = "net")]
#[test]
fn applying_value_spec_persists_value_and_clears_reference() {
    let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
    // Give the entry a stale source reference to prove the value clears it.
    let mut network = config.local_network_config().unwrap();
    network.secrets.secrets[0].source = Some(SecretSource::Env {
        var: "API_KEY".into(),
    });
    config.set_local_network_config(network).unwrap();

    let mut spec = bare_spec("API_KEY", &[]);
    spec.value = zeroize::Zeroizing::new("caller-held-value".to_string());
    let patch = patch_with_specs(vec![spec]);

    apply_secret_patch_to_config(&mut config, &patch).unwrap();

    // The value persists at rest (documented secret_env-style property)
    // and the entry is no longer reference-backed.
    let network = config.local_network_config().unwrap();
    let entry = &network.secrets.secrets[0];
    assert_eq!(entry.value.as_str(), "caller-held-value");
    assert_eq!(entry.source, None);
    assert_eq!(entry.placeholder, "$MSB_API_KEY");
}

#[cfg(feature = "net")]
#[test]
fn applying_secret_remove_deletes_entry() {
    let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let patch = SandboxModificationPatch {
        secrets_remove: vec!["API_KEY".to_string()],
        ..SandboxModificationPatch::default()
    };

    apply_secret_patch_to_config(&mut config, &patch).unwrap();

    let network = config.local_network_config().unwrap();
    assert!(network.secrets.secrets.is_empty());
}

#[cfg(feature = "net")]
#[test]
fn applying_hosts_only_spec_replaces_allow_list() {
    use microsandbox_network::secrets::config::HostPattern;

    let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let patch = patch_with_specs(vec![bare_spec("API_KEY", &["*.example.org", "*"])]);

    apply_secret_patch_to_config(&mut config, &patch).unwrap();

    let network = config.local_network_config().unwrap();
    assert_eq!(
        network.secrets.secrets[0].allowed_hosts,
        vec![
            HostPattern::Wildcard("*.example.org".into()),
            HostPattern::Any,
        ]
    );
}

#[cfg(feature = "net")]
#[test]
fn applying_placeholder_only_spec_renames_guest_reference() {
    let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let mut spec = bare_spec("API_KEY", &[]);
    spec.placeholder = Some("$NEW_REF".to_string());
    let patch = patch_with_specs(vec![spec]);

    apply_secret_patch_to_config(&mut config, &patch).unwrap();

    let network = config.local_network_config().unwrap();
    assert_eq!(network.secrets.secrets[0].placeholder, "$NEW_REF");
}

#[cfg(feature = "net")]
#[test]
fn rotate_flow_never_leaks_the_value_into_plans_configs_or_errors() {
    let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

    // The plan for a live rotate is value-free even though the current
    // config carries an inlined value.
    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            root_disk_grow: false,
            cpu_resize: false,
            memory_resize: false,
            secrets: true,
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );
    let plan_json = serde_json::to_string(&plan).unwrap();
    assert!(!plan_json.contains(SECRET_SENTINEL));

    // The persisted config drops the inlined value in favor of the
    // source reference.
    apply_secret_patch_to_config(&mut config, &patch).unwrap();
    let config_json = serde_json::to_string(&config).unwrap();
    assert!(!config_json.contains(SECRET_SENTINEL));
    assert!(config_json.contains("\"var\":\"API_KEY\""));

    // The live control batch carries the value only for socket transport;
    // any Debug-logged form of the request shows [redacted] instead.
    let rotated_value = format!("{SECRET_SENTINEL}-rotated");
    let _env_guard = crate::test_support::lock_env();
    // SAFETY: every environment-mutating SDK unit test holds the shared lock.
    unsafe { std::env::set_var("API_KEY_MODIFY_LEAK_TEST", &rotated_value) };
    let mut live_patch = patch.clone();
    live_patch.secrets[0].source = Some(SecretSource::Env {
        var: "API_KEY_MODIFY_LEAK_TEST".to_string(),
    });
    let updates = live_secret_updates(&plan, &live_patch).unwrap();
    assert!(!updates.is_empty());
    let request = microsandbox_runtime::control::ControlRequest::SecretsUpdate { changes: updates };
    assert!(!format!("{request:?}").contains(SECRET_SENTINEL));
    unsafe { std::env::remove_var("API_KEY_MODIFY_LEAK_TEST") };

    // Resolution failures name the variable, never a value.
    let error = resolve_secret_source_value(
        "API_KEY",
        Some(&SecretSource::Env {
            var: "API_KEY_MODIFY_LEAK_TEST_MISSING".to_string(),
        }),
    )
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("API_KEY_MODIFY_LEAK_TEST_MISSING"));
    assert!(!message.contains(SECRET_SENTINEL));
}

#[cfg(feature = "net")]
#[test]
fn value_bearing_patch_never_leaks_into_plans_debug_or_live_request_debug() {
    const VALUE_SENTINEL: &str = "value-sentinel-material";

    let config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let mut spec = bare_spec("API_KEY", &[]);
    spec.value = zeroize::Zeroizing::new(VALUE_SENTINEL.to_string());
    let patch = patch_with_specs(vec![spec]);

    // Debug output of the patch redacts the value.
    let debug = format!("{patch:?}");
    assert!(!debug.contains(VALUE_SENTINEL));
    assert!(debug.contains("[REDACTED]"));

    // The plan is value-free.
    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            root_disk_grow: false,
            cpu_resize: false,
            memory_resize: false,
            secrets: true,
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );
    assert_eq!(secret_plan_kinds(&plan), vec![SecretChangeKind::Rotated]);
    assert_eq!(
        secret_plan_dispositions(&plan),
        vec![ModificationDisposition::Live]
    );
    let plan_json = serde_json::to_string(&plan).unwrap();
    assert!(!plan_json.contains(VALUE_SENTINEL));

    // The live rotate uses the caller value without touching the host
    // environment, and the request's Debug form stays redacted.
    let updates = live_secret_updates(&plan, &patch).unwrap();
    assert_eq!(updates.len(), 1);
    let request = microsandbox_runtime::control::ControlRequest::SecretsUpdate { changes: updates };
    assert!(!format!("{request:?}").contains(VALUE_SENTINEL));

    // Material-free rotate errors name the secret only.
    let error = resolve_secret_value(&bare_spec("API_KEY", &[])).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("API_KEY"));
    assert!(!message.contains(VALUE_SENTINEL));
}

/// A rotation with new allowed hosts must be one `SecretsUpdate`; split, the value
/// could land under a stale allow-list.
#[cfg(feature = "net")]
#[test]
fn a_rotation_with_new_hosts_travels_as_one_batch() {
    let config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let patch = patch_with_specs(vec![SecretModificationPatch {
        name: "API_KEY".to_string(),
        value: zeroize::Zeroizing::new("rotated".to_string()),
        allowed_hosts: vec!["api.example.com".to_string()],
        ..SecretModificationPatch::default()
    }]);

    let plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            root_disk_grow: false,
            cpu_resize: false,
            memory_resize: false,
            secrets: true,
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );

    let updates = live_secret_updates(&plan, &patch).unwrap();

    assert_eq!(
        updates.len(),
        2,
        "both changes belong in one batch, got {updates:?}"
    );
    assert!(matches!(
        &updates[0],
        microsandbox_runtime::control::SecretLiveChange::Rotate { name, .. }
            if name == "API_KEY"
    ));
    assert!(matches!(
        &updates[1],
        microsandbox_runtime::control::SecretLiveChange::SetAllowedHosts { name, hosts }
            if name == "API_KEY" && *hosts == ["api.example.com"]
    ));
}

#[cfg(feature = "net")]
#[test]
fn live_secret_updates_cover_only_live_dispositions() {
    use microsandbox_runtime::control::SecretLiveChange;

    let config = config_with_secret("API_KEY", SECRET_SENTINEL);
    let patch = SandboxModificationPatch {
        secrets: vec![bare_spec("API_KEY", &["api.example.com", "*.example.org"])],
        ..SandboxModificationPatch::default()
    };
    let removal_patch = SandboxModificationPatch {
        secrets_remove: vec!["API_KEY".to_string()],
        ..SandboxModificationPatch::default()
    };

    let live_plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            root_disk_grow: false,
            cpu_resize: false,
            memory_resize: false,
            secrets: true,
        },
        patch.clone(),
        ModificationPolicy::NoRestart,
    );
    let updates = live_secret_updates(&live_plan, &patch).unwrap();
    assert_eq!(updates.len(), 1);
    assert!(matches!(
        &updates[0],
        SecretLiveChange::SetAllowedHosts { name, hosts }
            if name == "API_KEY" && hosts.len() == 2
    ));

    let removal_plan = build_plan(
        "api".to_string(),
        SandboxStatus::Running,
        &config,
        None,
        LiveControl {
            root_disk_grow: false,
            cpu_resize: false,
            memory_resize: false,
            secrets: true,
        },
        removal_patch.clone(),
        ModificationPolicy::NoRestart,
    );
    let updates = live_secret_updates(&removal_plan, &removal_patch).unwrap();
    assert_eq!(updates.len(), 1);
    assert!(matches!(&updates[0], SecretLiveChange::Remove { name } if name == "API_KEY"));

    // Next-start plans produce no live updates.
    let stopped_plan = build_plan(
        "api".to_string(),
        SandboxStatus::Stopped,
        &config,
        None,
        LiveControl::default(),
        patch.clone(),
        ModificationPolicy::NoRestart,
    );
    assert!(
        live_secret_updates(&stopped_plan, &patch)
            .unwrap()
            .is_empty()
    );
}
