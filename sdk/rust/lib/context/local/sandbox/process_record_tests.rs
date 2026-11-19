//! Exact identity survives catalog reads; ambiguity never authorizes destructive recovery.

use sea_orm::{EntityTrait, Set};

use super::super::{LocalContext, runtime_identity::RecordedRuntime};
use super::*;
use crate::sandbox::{SandboxConfig, SandboxStatus};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(in crate::context::local::sandbox) async fn model_reused_pid(
    context: &LocalContext,
    run: &run_entity::Model,
) {
    let identity = ProcessIdentity::capture(run.pid.unwrap()).unwrap();
    ProcessRecord::publish(context.db().await.unwrap().write(), run, &identity)
        .await
        .unwrap();
    let LoadedProcessRecord::Known(mut record) =
        ProcessRecord::load(context.db().await.unwrap().read(), run)
            .await
            .unwrap()
    else {
        panic!("missing fixture identity")
    };
    // Deterministically model a prior kernel birth value, without exhausting the host PID space.
    record.birth[0] = record.birth[0].wrapping_add(1);
    context
        .db()
        .await
        .unwrap()
        .write()
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE run SET process_identity = ? WHERE id = ?",
            [
                serde_json::to_string(&record).unwrap().into(),
                run.id.into(),
            ],
        ))
        .await
        .unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn exact_database_identity_and_reuse_are_distinct_from_heuristics() {
    let home = tempfile::tempdir().unwrap();
    let context = crate::test_support::local_backend_builder(home.path())
        .build()
        .unwrap();
    let pools = context.db().await.unwrap();
    let config = SandboxConfig {
        spec: microsandbox_types::SandboxSpec {
            name: "identity".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let id = LocalContext::insert_sandbox_record(pools.write(), &config)
        .await
        .unwrap();
    let pid = std::process::id() as i32;
    let run_id = run_entity::Entity::insert(run_entity::ActiveModel {
        sandbox_id: Set(id),
        pid: Set(Some(pid)),
        status: Set(run_entity::RunStatus::Running),
        ..Default::default()
    })
    .exec(pools.write())
    .await
    .unwrap()
    .last_insert_id;
    let run = run_entity::Entity::find_by_id(run_id)
        .one(pools.read())
        .await
        .unwrap()
        .unwrap();
    let lock =
        microsandbox_runtime::ipc::lifecycle_lock_path(&context.config().run_dir(), "identity");
    assert!(matches!(
        LocalContext::recorded_runtime(pools.read(), Some(&run), &lock)
            .await
            .unwrap(),
        RecordedRuntime::Unverified { .. }
    ));
    let identity = ProcessIdentity::capture(pid).unwrap();
    ProcessRecord::publish(pools.write(), &run, &identity)
        .await
        .unwrap();
    assert!(matches!(
        LocalContext::recorded_runtime(pools.read(), Some(&run), &lock)
            .await
            .unwrap(),
        RecordedRuntime::Live(_)
    ));
    assert!(
        ProcessRecord::publish(pools.write(), &run, &identity)
            .await
            .is_err(),
        "identity cannot be overwritten"
    );
    let LoadedProcessRecord::Known(mut record) =
        ProcessRecord::load(pools.read(), &run).await.unwrap()
    else {
        panic!("missing fixture identity")
    };
    record.birth[0] = record.birth[0].wrapping_add(1);
    for boot in [record.boot.clone(), "previous-boot".into()] {
        record.boot = boot;
        pools
            .write()
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE run SET process_identity = ? WHERE id = ?",
                [
                    serde_json::to_string(&record).unwrap().into(),
                    run_id.into(),
                ],
            ))
            .await
            .unwrap();
        assert!(matches!(
            LocalContext::recorded_runtime(pools.read(), Some(&run), &lock)
                .await
                .unwrap(),
            RecordedRuntime::Recycled
        ));
    }
    for invalid in ["{}".to_owned(), "not-json".to_owned(), {
        record.run_id += 1;
        serde_json::to_string(&record).unwrap()
    }] {
        pools
            .write()
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE run SET process_identity = ? WHERE id = ?",
                [invalid.into(), run_id.into()],
            ))
            .await
            .unwrap();
        assert!(
            LocalContext::recorded_runtime(pools.read(), Some(&run), &lock)
                .await
                .is_err()
        );
    }
}

async fn stopped_fixture(
    name: &str,
) -> (
    tempfile::TempDir,
    std::sync::Arc<LocalContext>,
    i32,
    run_entity::Model,
) {
    let home = tempfile::tempdir().unwrap();
    let context = std::sync::Arc::new(
        crate::test_support::local_backend_builder(home.path())
            .build()
            .unwrap(),
    );
    let pools = context.db().await.unwrap();
    let config = SandboxConfig {
        spec: microsandbox_types::SandboxSpec {
            name: name.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let id = LocalContext::insert_sandbox_record(pools.write(), &config)
        .await
        .unwrap();
    LocalContext::update_sandbox_status(pools.write(), id, SandboxStatus::Stopped)
        .await
        .unwrap();
    let run_id = run_entity::Entity::insert(run_entity::ActiveModel {
        sandbox_id: Set(id),
        pid: Set(Some(std::process::id() as i32)),
        status: Set(run_entity::RunStatus::Terminated),
        ..Default::default()
    })
    .exec(pools.write())
    .await
    .unwrap()
    .last_insert_id;
    let run = run_entity::Entity::find_by_id(run_id)
        .one(pools.read())
        .await
        .unwrap()
        .unwrap();
    (home, context, id, run)
}

#[tokio::test]
async fn future_identity_remains_inspectable_but_never_authorizes_recovery() {
    use crate::Context;
    let (_home, context, id, run) = stopped_fixture("future").await;
    let pools = context.db().await.unwrap();
    // A future representation need not have any of version 1's fields.
    pools
        .write()
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE run SET process_identity = ? WHERE id = ?",
            [
                r#"{"version":2,"new_identity":{"opaque":true}}"#.into(),
                run.id.into(),
            ],
        ))
        .await
        .unwrap();
    for status in [SandboxStatus::Running, SandboxStatus::Stopped] {
        LocalContext::update_sandbox_status(pools.write(), id, status)
            .await
            .unwrap();
        let page = context.sandboxes().list().await.unwrap();
        assert_eq!(page.sandboxes.len(), 1);
        let sandbox = context.sandboxes().get("future").await.unwrap();
        assert_eq!(sandbox.status().await.unwrap(), status);
        if status == SandboxStatus::Running {
            assert!(context.kill_sandbox("future", Some(id)).await.is_err());
            assert!(context.drain_sandbox("future", Some(id)).await.is_err());
        } else {
            // These APIs already no-op on terminal rows; they still must leave
            // unknown evidence intact and cannot authorize storage destruction.
            context.kill_sandbox("future", Some(id)).await.unwrap();
            context.drain_sandbox("future", Some(id)).await.unwrap();
            let error = sandbox.ensure_running().await.unwrap_err();
            assert!(
                error.to_string().contains("ownership cannot be verified"),
                "{error}"
            );
        }
        assert!(sandbox.stop().await.is_err());
        assert!(sandbox.destroy().await.is_err());
        assert_eq!(sandbox.status().await.unwrap(), status);
        assert!(matches!(
            ProcessRecord::load(pools.read(), &run).await.unwrap(),
            LoadedProcessRecord::Unsupported
        ));
    }
}

#[tokio::test]
async fn retirement_requires_proof_and_free_fences_then_allows_downgrade() {
    use chrono::{TimeDelta, Utc};
    use microsandbox_migration::{Migrator, MigratorTrait};
    let (_home, context, id, mut run) = stopped_fixture("retire").await;
    let pools = context.db().await.unwrap();
    let identity = ProcessIdentity::capture(run.pid.unwrap()).unwrap();
    ProcessRecord::publish(pools.write(), &run, &identity)
        .await
        .unwrap();
    let lock =
        microsandbox_runtime::ipc::lifecycle_lock_path(&context.config().run_dir(), "retire");
    // Persist actual skewed timestamps. The kernel identity, not wall-clock
    // proximity or a terminal status, must remain authoritative on every read.
    for offset in [-3600, 0, 3600] {
        run.started_at = Some((Utc::now() + TimeDelta::seconds(offset)).naive_utc());
        pools
            .write()
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE run SET started_at = ? WHERE id = ?",
                [run.started_at.into(), run.id.into()],
            ))
            .await
            .unwrap();
        let observed = LocalContext::load_latest_run(pools.read(), id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            LocalContext::recorded_runtime(pools.read(), Some(&observed), &lock)
                .await
                .unwrap(),
            RecordedRuntime::Live(_)
        ));
    }
    context
        .sandbox_handle_state("retire", Some(id))
        .await
        .unwrap();
    assert!(matches!(
        ProcessRecord::load(pools.read(), &run).await.unwrap(),
        LoadedProcessRecord::Known(_)
    ));
    assert!(
        Migrator::down(pools.write().inner(), Some(1))
            .await
            .is_err()
    );

    let LoadedProcessRecord::Known(mut record) =
        ProcessRecord::load(pools.read(), &run).await.unwrap()
    else {
        unreachable!()
    };
    record.birth[0] = record.birth[0].wrapping_add(1);
    pools
        .write()
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE run SET process_identity = ? WHERE id = ?",
            [
                serde_json::to_string(&record).unwrap().into(),
                run.id.into(),
            ],
        ))
        .await
        .unwrap();
    let transition = microsandbox_runtime::ipc::try_acquire_transition_guard(
        &context.config().run_dir(),
        "retire",
    )
    .unwrap()
    .unwrap();
    context
        .sandbox_handle_state("retire", Some(id))
        .await
        .unwrap();
    assert!(matches!(
        ProcessRecord::load(pools.read(), &run).await.unwrap(),
        LoadedProcessRecord::Known(_)
    ));
    drop(transition);
    let owner =
        microsandbox_runtime::ipc::acquire_lifecycle_guard(&context.config().run_dir(), "retire")
            .unwrap();
    context
        .sandbox_handle_state("retire", Some(id))
        .await
        .unwrap();
    assert!(matches!(
        ProcessRecord::load(pools.read(), &run).await.unwrap(),
        LoadedProcessRecord::Known(_)
    ));
    drop(owner);

    context
        .sandbox_handle_state("retire", Some(id))
        .await
        .unwrap();
    let retired = LocalContext::load_latest_run(pools.read(), id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.pid, None);
    assert_eq!(retired.started_at, run.started_at);
    assert_eq!(retired.status, run.status);
    assert!(matches!(
        ProcessRecord::load(pools.read(), &retired).await.unwrap(),
        LoadedProcessRecord::Missing
    ));
    // Roll back with the sandbox and history intact, exercise the older named-column
    // contract, then upgrade again. Neither path invents process ownership.
    Migrator::down(pools.write().inner(), Some(1))
        .await
        .unwrap();
    pools.write().execute_unprepared("UPDATE run SET exit_code = 0 WHERE sandbox_id IN (SELECT id FROM sandbox WHERE name = 'retire')").await.unwrap();
    let older = LocalContext::load_latest_run(pools.read(), id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(older.exit_code, Some(0));
    assert_eq!(older.pid, None);
    Migrator::up(pools.write().inner(), None).await.unwrap();
    assert!(matches!(
        ProcessRecord::load(pools.read(), &older).await.unwrap(),
        LoadedProcessRecord::Missing
    ));
    assert_eq!(
        context
            .sandbox_handle_state("retire", Some(id))
            .await
            .unwrap()
            .0
            .id,
        id
    );
}

#[tokio::test]
async fn historical_retirement_preserves_other_live_and_future_records() {
    use microsandbox_migration::{Migrator, MigratorTrait};

    let (_home, context, id, old) = stopped_fixture("history").await;
    let pools = context.db().await.unwrap();
    model_reused_pid(&context, &old).await;
    let identity = ProcessIdentity::capture(std::process::id() as i32).unwrap();
    let mut retained = Vec::new();
    for future in [false, true] {
        let run_id = run_entity::Entity::insert(run_entity::ActiveModel {
            sandbox_id: Set(id),
            pid: Set(Some(identity.pid)),
            status: Set(run_entity::RunStatus::Terminated),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap()
        .last_insert_id;
        let run = run_entity::Entity::find_by_id(run_id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        ProcessRecord::publish(pools.write(), &run, &identity)
            .await
            .unwrap();
        if future {
            pools
                .write()
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "UPDATE run SET process_identity = ? WHERE id = ?",
                    [r#"{"version":2}"#.into(), run_id.into()],
                ))
                .await
                .unwrap();
        }
        retained.push(run);
    }

    // One safely finished historical run does not authorize clearing the rest,
    // even when every row claims Terminated and all resource fences are free.
    context
        .sandbox_handle_state("history", Some(id))
        .await
        .unwrap();
    let old = run_entity::Entity::find_by_id(old.id)
        .one(pools.read())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old.pid, None);
    assert!(matches!(
        ProcessRecord::load(pools.read(), &old).await.unwrap(),
        LoadedProcessRecord::Missing
    ));
    assert!(matches!(
        ProcessRecord::load(pools.read(), &retained[0])
            .await
            .unwrap(),
        LoadedProcessRecord::Known(_)
    ));
    assert!(matches!(
        ProcessRecord::load(pools.read(), &retained[1])
            .await
            .unwrap(),
        LoadedProcessRecord::Unsupported
    ));
    assert!(
        Migrator::down(pools.write().inner(), Some(1))
            .await
            .is_err()
    );
}
