//! Exact identity survives catalog reads; ambiguity never authorizes destructive recovery.

use sea_orm::{EntityTrait, Set};

use super::super::{LocalContext, runtime_identity::RecordedRuntime};
use super::*;
use crate::sandbox::SandboxConfig;

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
    let mut record = ProcessRecord::load(context.db().await.unwrap().read(), run)
        .await
        .unwrap()
        .unwrap();
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
    let mut record = ProcessRecord::load(pools.read(), &run)
        .await
        .unwrap()
        .unwrap();
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
