//! Catalog upgrades explicitly requested by the owning CLI, never by SDK launch children.

use microsandbox_migration::{Migrator, MigratorTrait};
use microsandbox_runtime::maintenance;
use sea_orm::TransactionTrait;

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
    let result = async {
        let active = maintenance::active_sandboxes_for_schema_rollback(pools.write())
            .await
            .map_err(|error| MicrosandboxError::Runtime(error.to_string()))?;
        if !active.is_empty() {
            return Err(MicrosandboxError::Runtime(
                "catalog upgrade requires stopped sandboxes; use `msb ps` to list them and `msb stop <name>...` to stop them, then retry"
                    .into(),
            ));
        }
        // All pending SQL migrations and their history commit together. A failed
        // migration must not leave an unrecognized, partially upgraded catalog.
        let transaction = pools.write().inner().begin().await?;
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
