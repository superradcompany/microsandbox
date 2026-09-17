//! Catalog upgrades explicitly requested by the owning CLI, never by SDK launch children.

use microsandbox_migration::{Migrator, MigratorTrait};
use microsandbox_runtime::maintenance;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryFilter, TransactionTrait,
};

use super::{LocalBackend, connect_catalog};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    /// Prepare this installation's catalog for a user-facing CLI operation.
    ///
    /// Internal CLI integration only. SDK backends preserve existing catalogs;
    /// the CLI calls this before opening its backend, after selecting a local home.
    /// A process launched through `msb machine` must not call this method.
    #[doc(hidden)]
    pub async fn prepare_cli_catalog(&self) -> MicrosandboxResult<()> {
        let pools = self
            .db
            .get_or_try_init(|| async {
                let db_dir = self.config.home().join(microsandbox_utils::DB_SUBDIR);
                let pools = connect_catalog(
                    &db_dir,
                    &self.config.database,
                    &self.config.snapshots_dir(),
                    true,
                    None,
                )
                .await?;
                self.control_sessions
                    .bind_database(&db_dir.join(microsandbox_utils::DB_FILENAME))
                    .map_err(MicrosandboxError::ControlClient)?;
                Ok::<_, MicrosandboxError>(pools)
            })
            .await?;
        // Authority is selected before exposing a backend to SDK operations.
        // Never silently report success if a caller already opened an older
        // catalog with SDK-preserving semantics on this same backend.
        if !crate::db::admission::is_current(pools.read()).await? {
            return Err(MicrosandboxError::Runtime(
                "prepare the CLI catalog before opening the local backend".into(),
            ));
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn upgrade(pools: &microsandbox_db::pool::DbPools) -> MicrosandboxResult<()> {
    // The caller holds the migration file lock. Existing runtimes do not hold
    // that lock throughout their lifetimes, so also exclude installation work
    // and refuse live runtimes before changing the schema they may still write.
    let lease = maintenance::acquire_install_exclusive_lease(pools.write())
        .await
        .map_err(|error| MicrosandboxError::Runtime(error.to_string()))?;
    let result: MicrosandboxResult<()> = async {
        let transaction = begin_quiescent_upgrade(pools).await?;
        // All pending SQL migrations and their history commit together. A failed
        // migration must not leave an unrecognized, partially upgraded catalog.
        Migrator::up(&transaction, None).await?;
        transaction.commit().await?;
        Ok(())
    }
    .await;
    let cleared = maintenance::clear_install_exclusive_lease(pools.write(), &lease)
        .await
        .map_err(|error| MicrosandboxError::Runtime(error.to_string()));
    result?;
    cleared
}

/// Return the same write transaction that proved the catalog quiescent. The
/// caller must retain it through migration commit, while holding the install
/// lease and migration file lock.
async fn begin_quiescent_upgrade(
    pools: &microsandbox_db::pool::DbPools,
) -> MicrosandboxResult<DatabaseTransaction> {
    let transaction = pools.write().inner().begin().await?;
    // Reserve SQLite's writer before observing lifecycle state. Historical
    // SDKs can retain an open pool and ignore the install lease, but must
    // write Starting before launching a VM. A real write (even a no-op)
    // fences those callers through the migration commit without requiring
    // a new protocol or cooperation from old binaries.
    transaction
        .execute_unprepared(
            "UPDATE maintenance_lease SET holder_pid = holder_pid WHERE name = 'install_exclusive'",
        )
        .await?;
    let active = maintenance::active_sandboxes_for_schema_rollback(&transaction)
        .await
        .map_err(|error| MicrosandboxError::Runtime(error.to_string()))?;
    if !active.is_empty() {
        return Err(MicrosandboxError::Runtime(
            "catalog upgrade requires stopped sandboxes; use `msb ps` to list them and `msb stop <name>...` to stop them, then retry"
                .into(),
        ));
    }
    Ok(transaction)
}

/// Recover only an abandoned catalog-operation lease. The caller must hold
/// the migration lock and reject incomplete downgrade journals first: a
/// Windows handoff intentionally outlives the parent PID recorded in its lease.
pub(super) async fn recover_abandoned_lease(
    pools: &microsandbox_db::pool::DbPools,
) -> MicrosandboxResult<()> {
    use microsandbox_db::entity::maintenance_lease as lease;
    use sea_orm::sea_query::Expr;

    if !microsandbox_db::catalog::has_table(pools.read(), "maintenance_lease").await? {
        return Ok(());
    }
    let Some(row) = lease::Entity::find_by_id(lease::INSTALL_EXCLUSIVE)
        .one(pools.read())
        .await?
    else {
        return Ok(());
    };
    let Some(pid) = row.holder_pid else {
        return Ok(());
    };
    // Windows retains an exited process object while another process holds a
    // handle: opening that PID does not prove the lease owner can still run.
    // Keep Unix's conservative existence check because a zombie leader can
    // still have threads tearing down shared resources. A reused live PID must
    // remain protected on either platform.
    #[cfg(windows)]
    let owner_may_be_live = microsandbox_utils::process::pid_is_alive(pid);
    #[cfg(not(windows))]
    let owner_may_be_live = microsandbox_utils::process::pid_exists(pid);
    if pid <= 0 || owner_may_be_live {
        return Ok(());
    }
    lease::Entity::update_many()
        .col_expr(lease::Column::HolderPid, Expr::value(None::<i32>))
        .col_expr(
            lease::Column::LeaseExpiresAt,
            Expr::value(chrono::Utc::now().naive_utc()),
        )
        .filter(lease::Column::Name.eq(lease::INSTALL_EXCLUSIVE))
        .filter(lease::Column::HolderPid.eq(pid))
        .filter(lease::Column::LeaseExpiresAt.eq(row.lease_expires_at))
        .exec(pools.write())
        .await?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use microsandbox_db::pool::DbPools;
    use sea_orm::ConnectionTrait;

    use super::*;

    #[tokio::test]
    async fn abandoned_lease_recovery_preserves_live_owner() {
        let home = tempfile::tempdir().unwrap();
        let pools = historical(home.path()).await;
        let live = maintenance::acquire_install_exclusive_lease(pools.write())
            .await
            .unwrap();
        recover_abandoned_lease(&pools).await.unwrap();
        assert!(
            maintenance::refuse_if_install_exclusive_held(pools.write())
                .await
                .is_err()
        );
        maintenance::clear_install_exclusive_lease(pools.write(), &live)
            .await
            .unwrap();
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn abandoned_lease_recovers_but_never_bypasses_downgrade_journal() {
        let home = tempfile::tempdir().unwrap();
        let pools = historical(home.path()).await;
        #[cfg(unix)]
        let mut child = std::process::Command::new("true").spawn().unwrap();
        #[cfg(windows)]
        let mut child = std::process::Command::new("cmd")
            .args(["/D", "/C", "exit", "0"])
            .spawn()
            .unwrap();
        let dead = child.id();
        child.wait().unwrap();
        #[cfg(unix)]
        assert!(!microsandbox_utils::process::pid_exists(dead as i32));
        // Keep Child (and its Windows process handle) alive throughout recovery.
        // This reproduces the exited-but-openable PID from the crash harness.
        #[cfg(windows)]
        {
            assert!(microsandbox_utils::process::pid_exists(dead as i32));
            assert!(!microsandbox_utils::process::pid_is_alive(dead as i32));
        }
        let lease = maintenance::acquire_install_exclusive_lease(pools.write())
            .await
            .unwrap();
        pools
            .write()
            .inner()
            .execute_unprepared(&format!(
                "UPDATE maintenance_lease SET holder_pid = {dead} WHERE name = 'install_exclusive'"
            ))
            .await
            .unwrap();
        let dir = home.path().join("db/self-downgrade/pending");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("journal.json"),
            r#"{"phase":"artifacts_reverting"}"#,
        )
        .unwrap();
        let error = LocalBackend::builder()
            .home(home.path())
            .build()
            .await
            .err()
            .expect("pending handoff must remain blocked");
        assert!(
            error
                .to_string()
                .contains("self_downgrade_recovery_required")
        );
        assert!(
            maintenance::refuse_if_install_exclusive_held(pools.write())
                .await
                .is_err()
        );
        // A cancelled preflight is hidden, whereas a mutating operation above
        // must not be treated as abandoned merely because its parent exited.
        std::fs::rename(&dir, dir.with_file_name(".cancelled-pending")).unwrap();
        let local = LocalBackend::builder()
            .home(home.path())
            .build()
            .await
            .unwrap();
        local.db().await.unwrap();
        maintenance::refuse_if_install_exclusive_held(pools.write())
            .await
            .unwrap();
        assert!(
            !crate::db::admission::is_current(pools.read())
                .await
                .unwrap()
        );
        assert!(
            maintenance::clear_install_exclusive_lease(pools.write(), &lease)
                .await
                .is_err()
        );
        drop(child);
    }

    #[tokio::test]
    #[ignore = "requires isolated MSB_CATALOG_TEST_HOME plus actual historical MSB_PATH/MSB_LIBKRUNFW_PATH and host virtualization"]
    async fn live_sdk_preserves_historical_catalog_and_old_cli_reads_new_records() {
        use futures::FutureExt;
        use std::sync::Arc;

        let home = std::env::var("MSB_CATALOG_TEST_HOME").expect("explicit disposable test home");
        let local = Arc::new(LocalBackend::builder().home(&home).build().await.unwrap());
        let expected = crate::runtime::launch_contract::catalog_patch(local.config())
            .await
            .unwrap()
            .expect("historical runtime");
        let before = Migrator::get_applied_migrations(local.db().await.unwrap().write().inner())
            .await
            .unwrap();
        assert_eq!(
            before.len(),
            crate::db::admission::historical_migration_count(expected).unwrap() as usize
        );
        let backend: Arc<dyn crate::backend::Backend> = local.clone();
        crate::backend::with_backend(backend, async {
            #[cfg(feature = "net")]
            {
                // A newer SDK must not silently omit a security/resource
                // request that the selected historical runtime cannot honor.
                let rejected = crate::Sandbox::builder("catalog-unsupported")
                    .image("alpine:3.21").cpus(1).memory(256u32).max_duration(120)
                    .network(|network| network.max_udp_connections(0))
                    .create().await;
                let error = match rejected {
                    Ok(unexpected) => {
                        unexpected.stop().await.unwrap();
                        crate::Sandbox::remove("catalog-unsupported").await.unwrap();
                        panic!("historical runtime accepted an unsupported UDP limit");
                    }
                    Err(error) => error.to_string(),
                };
                assert!(error.contains("max_udp_connections") || error.contains("UDP connection limits"), "{error}");
                assert!(matches!(crate::Sandbox::get("catalog-unsupported").await,
                    Err(MicrosandboxError::SandboxNotFound(_))));
                assert!(!local.config().sandboxes_dir().join("catalog-unsupported").exists());
                let after = Migrator::get_applied_migrations(local.db().await.unwrap().write().inner()).await.unwrap();
                assert_eq!(after.iter().map(|migration| migration.name()).collect::<Vec<_>>(), before.iter().map(|migration| migration.name()).collect::<Vec<_>>());
                println!("historical runtime 0.6.{expected}: unsupported UDP request refused without a sandbox or schema change");
            }
            for count in [0, 1, 3] {
                let name = format!("catalog-mounts-{count}");
                let started = std::time::Instant::now();
                let mut builder = crate::Sandbox::builder(&name).image("alpine:3.21").cpus(1).memory(256u32).max_duration(120);
                for index in 0..count {
                    builder = builder.volume(format!("/catalog-{index}"), |mount| mount.tmpfs().size(16u32));
                }
                let sandbox = builder.create().await.expect("create through historical writer/runtime");
                let result = std::panic::AssertUnwindSafe(async {
                    let output = sandbox.exec("sh", ["-c", "printf catalog-sdk-ok"]).await.unwrap();
                    assert!(output.status().success);
                    assert_eq!(output.stdout().unwrap(), "catalog-sdk-ok");
                    for index in 0..count {
                        let script = format!("echo mount-ok > /catalog-{index}/marker; cat /catalog-{index}/marker");
                        let output = sandbox.exec("sh", ["-c", &script]).await.unwrap();
                        assert!(output.status().success);
                        assert_eq!(output.stdout().unwrap().trim(), "mount-ok");
                    }
                    let output = tokio::process::Command::new(std::env::var_os("MSB_PATH").unwrap())
                        .env("MSB_HOME", &home).args(["inspect", &name]).output().await.unwrap();
                    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
                    let after = Migrator::get_applied_migrations(local.db().await.unwrap().write().inner()).await.unwrap();
                    assert_eq!(after.iter().map(|migration| migration.name()).collect::<Vec<_>>(), before.iter().map(|migration| migration.name()).collect::<Vec<_>>());
                    sandbox.stop().await.unwrap();
                    let handle = crate::Sandbox::get(&name).await.unwrap();
                    handle.modify().memory(384u32).max_memory(384u32)
                        .env("CATALOG_TEST_A", "one").env("CATALOG_TEST_B", "two")
                        .label("catalog-test", "modified").apply().await.unwrap();
                    let restarted = handle.start().await.unwrap();
                    let output = restarted.exec("sh", ["-c", "printf '%s:%s' \"$CATALOG_TEST_A\" \"$CATALOG_TEST_B\""]).await.unwrap();
                    assert!(output.status().success);
                    assert_eq!(output.stdout().unwrap(), "one:two");
                    assert_eq!(restarted.config().spec.resources.memory_mib, 384);
                    restarted.stop().await.unwrap();
                    let after = Migrator::get_applied_migrations(local.db().await.unwrap().write().inner()).await.unwrap();
                    assert_eq!(after.iter().map(|migration| migration.name()).collect::<Vec<_>>(), before.iter().map(|migration| migration.name()).collect::<Vec<_>>());
                }).catch_unwind().await;
                sandbox.stop().await.expect("cleanup historical VM");
                crate::Sandbox::remove(&name).await.expect("cleanup historical sandbox");
                result.unwrap();
                println!("historical runtime 0.6.{expected}: {count} mounts, exec, old CLI inspect, modify/restart, unchanged schema, cleanup: {:?}", started.elapsed());
            }
        }).await;
    }

    async fn historical(home: &std::path::Path) -> DbPools {
        std::fs::create_dir_all(home.join("db")).unwrap();
        let pools = DbPools::open(
            &home.join("db/msb.db"),
            1,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        Migrator::up(pools.write().inner(), Some(25)).await.unwrap();
        pools
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn unsupported_replacement_preserves_the_existing_sandbox() {
        use std::sync::Arc;

        // macOS's default temporary root can exceed historical socket limits.
        #[cfg(unix)]
        let home = tempfile::tempdir_in("/tmp").unwrap();
        #[cfg(not(unix))]
        let home = tempfile::tempdir().unwrap();
        let pools = historical(home.path()).await;
        let original = include_str!("../../db/fixtures/config-0.6.18.json")
            .replace("catalog-fixture", "preserved");
        pools.write().execute_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Sqlite,
            "INSERT INTO sandbox (id, name, config, status, ephemeral) VALUES (1, 'preserved', ?, 'Stopped', 0)",
            [original.clone().into()],
        )).await.unwrap();
        let sandbox_dir = home.path().join("sandboxes/preserved");
        std::fs::create_dir_all(&sandbox_dir).unwrap();
        std::fs::write(sandbox_dir.join("sentinel"), "existing data").unwrap();
        let local = Arc::new(
            LocalBackend::builder()
                .home(home.path())
                .build()
                .await
                .unwrap(),
        );
        let backend: Arc<dyn crate::backend::Backend> = local;
        let result = crate::backend::with_backend(backend, async {
            crate::Sandbox::builder("preserved")
                .image("alpine:3.21")
                .network(|network| network.max_udp_connections(0))
                .replace()
                .create()
                .await
        })
        .await;
        let error = result
            .err()
            .expect("unsupported replacement must fail")
            .to_string();
        assert!(error.contains("max_udp_connections"), "{error}");
        assert_eq!(
            std::fs::read_to_string(sandbox_dir.join("sentinel")).unwrap(),
            "existing data"
        );
        let row = pools.read().query_one_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Sqlite, "SELECT config FROM sandbox WHERE id = 1 AND name = 'preserved' AND status = 'Stopped'"
        )).await.unwrap().unwrap();
        assert_eq!(row.try_get_by_index::<String>(0).unwrap(), original);
        assert!(
            !crate::db::admission::is_current(pools.read())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn sdk_preserves_old_catalog_but_cli_upgrades_it() {
        let home = tempfile::tempdir().unwrap();
        drop(historical(home.path()).await);
        let sdk = LocalBackend::builder()
            .home(home.path())
            .build()
            .await
            .unwrap();
        assert!(
            !crate::db::admission::is_current(sdk.db().await.unwrap().read())
                .await
                .unwrap()
        );
        assert!(sdk.prepare_cli_catalog().await.is_err());
        drop(sdk);
        let cli = LocalBackend::builder().home(home.path()).build_lazy();
        cli.prepare_cli_catalog().await.unwrap();
        assert!(
            crate::db::admission::is_current(cli.db().await.unwrap().read())
                .await
                .unwrap()
        );
        cli.prepare_cli_catalog().await.unwrap();
    }

    #[tokio::test]
    async fn active_catalog_refusal_releases_lease_and_preserves_schema() {
        let home = tempfile::tempdir().unwrap();
        let pools = historical(home.path()).await;
        pools.write().inner().execute_unprepared(
            "INSERT INTO sandbox (name, config, status, ephemeral) VALUES ('active', '{}', 'Starting', 0)",
        ).await.unwrap();
        let error = upgrade(&pools).await.unwrap_err();
        assert!(error.to_string().contains("msb stop <name>..."));
        assert!(
            !crate::db::admission::is_current(pools.read())
                .await
                .unwrap()
        );
        maintenance::refuse_if_install_exclusive_held(pools.write())
            .await
            .unwrap();
        pools
            .write()
            .inner()
            .execute_unprepared("UPDATE sandbox SET status = 'Stopped'")
            .await
            .unwrap();
        upgrade(&pools).await.unwrap();
        assert!(
            crate::db::admission::is_current(pools.read())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn catalog_upgrade_fences_preopened_lifecycle_writers_until_commit_or_rollback() {
        for commit in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let pools = historical(home.path()).await;
            pools.write().inner().execute_unprepared(
                "INSERT INTO sandbox (name, config, status, ephemeral) VALUES ('stopped', '{}', 'Stopped', 0)",
            ).await.unwrap();
            // A separate, already-open pool models an old SDK that does not
            // cooperate with either the install lease or migration file lock.
            // Zero busy timeout makes contention deterministic, without sleeps.
            let old_sdk = DbPools::open(
                &home.path().join("db/msb.db"),
                1,
                Duration::from_secs(5),
                Duration::ZERO,
            )
            .await
            .unwrap();
            let lease = maintenance::acquire_install_exclusive_lease(pools.write())
                .await
                .unwrap();
            let transaction = begin_quiescent_upgrade(&pools).await.unwrap();
            let lifecycle_writes = [
                "INSERT INTO sandbox (name, config, status, ephemeral) VALUES ('new', '{}', 'Starting', 0)",
                "UPDATE sandbox SET status = 'Starting' WHERE name = 'stopped'",
            ];
            for sql in lifecycle_writes {
                let error = old_sdk
                    .write()
                    .inner()
                    .execute_unprepared(sql)
                    .await
                    .unwrap_err();
                assert!(error.to_string().contains("database is locked"), "{error}");
            }
            assert!(
                maintenance::active_sandboxes_for_schema_rollback(&transaction)
                    .await
                    .unwrap()
                    .is_empty()
            );
            Migrator::up(&transaction, None).await.unwrap();
            if commit {
                transaction.commit().await.unwrap();
            } else {
                transaction.rollback().await.unwrap();
            }
            maintenance::clear_install_exclusive_lease(pools.write(), &lease)
                .await
                .unwrap();
            assert_eq!(
                crate::db::admission::is_current(old_sdk.read())
                    .await
                    .unwrap(),
                commit
            );
            // Both outcomes release the writer. This checks ordering, not
            // whether a historical runtime supports the newly committed schema.
            for sql in lifecycle_writes {
                old_sdk
                    .write()
                    .inner()
                    .execute_unprepared(sql)
                    .await
                    .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn failed_sql_migration_rolls_back_all_pending_steps() {
        let home = tempfile::tempdir().unwrap();
        let pools = historical(home.path()).await;
        // Force a deterministic SQL failure after the first pending migration
        // has added columns. Those columns and its history must roll back.
        pools
            .write()
            .inner()
            .execute_unprepared(
                "CREATE INDEX idx_snapshot_index_snapshot_id ON snapshot_index (name)",
            )
            .await
            .unwrap();
        assert!(upgrade(&pools).await.is_err());
        assert!(
            !microsandbox_db::catalog::has_column(pools.read(), "snapshot_index", "snapshot_id")
                .await
                .unwrap()
        );
        maintenance::refuse_if_install_exclusive_held(pools.write())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn historical_config_survives_catalog_upgrade() {
        for (patch, raw) in [
            (0, include_str!("../../db/fixtures/config-0.6.0.json")),
            (5, include_str!("../../db/fixtures/config-0.6.5.json")),
            (9, include_str!("../../db/fixtures/config-0.6.9.json")),
            (18, include_str!("../../db/fixtures/config-0.6.18.json")),
        ] {
            let home = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(home.path().join("db")).unwrap();
            let pools = DbPools::open(
                &home.path().join("db/msb.db"),
                1,
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            Migrator::up(
                pools.write().inner(),
                Some(crate::db::admission::historical_migration_count(patch).unwrap()),
            )
            .await
            .unwrap();
            pools.write().execute_raw(sea_orm::Statement::from_sql_and_values(
                sea_orm::DbBackend::Sqlite,
                "INSERT INTO sandbox (name, config, status, ephemeral) VALUES ('catalog-fixture', ?, 'Stopped', 0)",
                [raw.into()],
            )).await.unwrap();
            let expected = serde_json::to_value(crate::db::config::decode(raw).unwrap()).unwrap();
            upgrade(&pools).await.unwrap();
            let updated = pools
                .read()
                .query_one_raw(sea_orm::Statement::from_string(
                    sea_orm::DbBackend::Sqlite,
                    "SELECT config FROM sandbox WHERE name = 'catalog-fixture'",
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get_by_index::<String>(0)
                .unwrap();
            assert_eq!(
                serde_json::to_value(crate::db::config::decode(&updated).unwrap()).unwrap(),
                expected,
                "patch {patch}"
            );
            assert!(
                crate::db::admission::is_current(pools.read())
                    .await
                    .unwrap()
            );
        }
    }
}
