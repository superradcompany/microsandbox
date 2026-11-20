//! Process-kill driver for real released artifacts. Invoked only by the qualification harness.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use microsandbox_db::pool::DbPools;
use microsandbox_image::snapshot::migration::inspect_v066_source;
use microsandbox_migration::{Migrator, MigratorTrait};
use microsandbox_types::snapshot::Manifest;
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use serde_json::json;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Pause only the explicitly selected artifact/action/phase. The hook does not exist in
/// shipped libraries. The parent kills this process after the durable marker, rather than
/// inferring a crash location from timing or manufacturing journal rows after the fact.
pub(super) fn boundary(artifact: &Path, action: &str, phase: &str) {
    let Some(root) = std::env::var_os("MSB_TEST_HISTORICAL_ROOT").map(PathBuf::from) else {
        return;
    };
    if artifact != root.join("snapshots/artifact")
        || std::env::var("MSB_TEST_HISTORICAL_ACTION").as_deref() != Ok(action)
        || std::env::var("MSB_TEST_HISTORICAL_BOUNDARY").as_deref() != Ok(phase)
    {
        return;
    }
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("boundary.json"))
        .unwrap();
    marker
        .write_all(
            serde_json::to_string(
                &json!({"pid":std::process::id(), "action":action, "phase":phase}),
            )
            .unwrap()
            .as_bytes(),
        )
        .unwrap();
    marker.sync_all().unwrap();
    File::open(&root).unwrap().sync_all().unwrap();
    // The parent must not kill us merely because an incompletely written marker exists.
    // Seeing this acknowledgement means both the marker and its directory were flushed.
    File::create(root.join("boundary-ready")).unwrap();
    loop {
        std::thread::park();
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "subprocess driver requiring private real historical artifacts; scripts/smoke/cli/historical-recovery.py"]
async fn historical_recovery_worker() {
    let root = PathBuf::from(
        std::env::var_os("MSB_TEST_HISTORICAL_ROOT").expect("private qualification directory"),
    );
    assert!(root.is_absolute() && root.join("snapshots").is_dir());
    let db = root.join("migration.db");
    let pools = DbPools::open(&db, 2, Duration::from_secs(5), Duration::from_secs(5))
        .await
        .unwrap();
    Migrator::up(pools.write().inner(), None).await.unwrap();
    let action = std::env::var("MSB_TEST_HISTORICAL_ACTION").unwrap();
    let report = match action.as_str() {
        "upgrade" => {
            let result = super::migration::reconcile_managed(&pools, &root.join("snapshots"))
                .await
                .unwrap();
            assert_eq!(result.blocked, 0, "historical migration was blocked");
            json!({"migrated":result.migrated, "canonical":result.canonical})
        }
        "downgrade" => {
            let result = super::downgrade::reverse_managed_v066(
                pools.write().inner(),
                &root.join("snapshots"),
                &root.join("recovery"),
            )
            .await
            .unwrap();
            json!({"artifacts":result.artifacts})
        }
        _ => panic!("unsupported historical qualification action"),
    };
    let rows = pools
        .write()
        .inner()
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT digest, migration_state FROM snapshot_index ORDER BY artifact_path",
        ))
        .await
        .unwrap();
    let index: Vec<_> = rows
        .iter()
        .map(|row| {
            json!({
                "digest":row.try_get_by_index::<String>(0).unwrap(),
                "migration_state":row.try_get_by_index::<String>(1).unwrap(),
            })
        })
        .collect();
    assert_eq!(
        index.len(),
        1,
        "qualification expects exactly one indexed artifact"
    );
    let artifact = root.join("snapshots/artifact");
    let (expected_digest, expected_state) = if action == "upgrade" {
        (
            Manifest::from_bytes(&std::fs::read(artifact.join("snapshot.json")).unwrap())
                .unwrap()
                .digest()
                .unwrap(),
            "complete",
        )
    } else {
        (
            inspect_v066_source(&std::fs::read(artifact.join("manifest.json")).unwrap())
                .unwrap()
                .source_digest,
            "reverse_complete",
        )
    };
    assert_eq!(index[0]["digest"], expected_digest);
    assert_eq!(index[0]["migration_state"], expected_state);
    let journal = pools
        .write()
        .inner()
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT kind, phase, error_code FROM snapshot_artifact_migration ORDER BY kind, artifact_path",
        ))
        .await
        .unwrap();
    let journal: Vec<_> = journal
        .iter()
        .map(|row| {
            json!({
                "kind":row.try_get_by_index::<String>(0).unwrap(),
                "phase":row.try_get_by_index::<String>(1).unwrap(),
                "error_code":row.try_get_by_index::<Option<String>>(2).unwrap(),
            })
        })
        .collect();
    std::fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(
            &json!({"action":action,"report":report,"index":index,"journal":journal}),
        )
        .unwrap(),
    )
    .unwrap();
}
