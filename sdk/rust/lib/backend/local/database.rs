//! Transactional SDK/CLI catalog upgrades that preserve already-running VMs.

use std::collections::BTreeSet;

use microsandbox_db::catalog::has_table;
use microsandbox_migration::{Migrator, MigratorTrait, schema_metadata};
use microsandbox_runtime::maintenance;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, EntityTrait, QueryFilter,
    Statement, TransactionTrait,
};

use super::LocalBackend;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    /// Prepare this installation's catalog for a user-facing CLI operation.
    ///
    /// SDK and CLI opens use the same upgrade policy. The CLI calls this
    /// after selecting a local home, before its user-facing operation.
    /// A process launched through `msb machine` must not call this method.
    #[doc(hidden)]
    pub async fn prepare_cli_catalog(&self) -> MicrosandboxResult<()> {
        self.db().await?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Compare identities, not counts: an unknown migration must never admit a current writer.
pub(super) async fn is_current<C: ConnectionTrait>(db: &C) -> MicrosandboxResult<bool> {
    let rows = db
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT version FROM seaql_migrations",
        ))
        .await?;
    let applied = rows
        .into_iter()
        .map(|row| row.try_get_by_index::<String>(0))
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(applied
        == schema_metadata::migration_ids()
            .map(str::to_owned)
            .collect())
}

/// Returns true only for a new catalog or interrupted pre-floor initialization.
/// Known complete prefixes use the normal upgrade path. Unknown or gapped
/// histories are refused rather than guessed from their migration count.
pub(super) async fn requires_initialization<C: ConnectionTrait>(
    db: &C,
) -> MicrosandboxResult<bool> {
    if !has_table(db, "seaql_migrations").await? {
        let tables = db.query_one_raw(Statement::from_string(DbBackend::Sqlite,
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"))
            .await?.expect("COUNT returns one row").try_get_by_index::<i64>(0)?;
        if tables == 0 {
            return Ok(true);
        }
        return Err(MicrosandboxError::Runtime("database has tables but no migration history; refusing to initialize an unrecognized catalog".into()));
    }
    let rows = db
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT version FROM seaql_migrations",
        ))
        .await?;
    let applied = rows
        .into_iter()
        .map(|row| row.try_get_by_index::<String>(0))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if let Some(prefix) =
        schema_metadata::canonical_applied_prefix(applied.iter().map(String::as_str))
    {
        return Ok(prefix.len() < schema_metadata::BASELINE_0_6_0_MIGRATIONS.len());
    }
    Err(MicrosandboxError::Runtime(
        "database schema is newer than this msb binary or has an unknown migration prefix; refusing to change an unrecognized catalog".into(),
    ))
}

pub(super) async fn upgrade(pools: &microsandbox_db::pool::DbPools) -> MicrosandboxResult<()> {
    // The caller holds the migration file lock. Existing runtimes do not hold
    // that lock throughout their lifetimes, so also exclude installation work
    // while preserving their lifecycle SQL contract. Running VMs are not a
    // reason to preserve an older SDK/CLI's catalog representation.
    let lease = maintenance::acquire_install_exclusive_lease(pools.write())
        .await
        .map_err(|error| MicrosandboxError::Runtime(error.to_string()))?;
    let result: MicrosandboxResult<()> = async {
        let transaction = begin_upgrade(pools).await?;
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

/// Reserve SQLite's writer through migration commit, while the caller holds
/// the install lease and migration file lock. Older runtime writes may wait
/// briefly, but must remain valid against the resulting schema.
async fn begin_upgrade(
    pools: &microsandbox_db::pool::DbPools,
) -> MicrosandboxResult<DatabaseTransaction> {
    let transaction = pools.write().inner().begin().await?;
    // Old processes do not all cooperate with the install lease. A real write
    // (even a no-op) fences concurrent writes before migration reads begin,
    // without requiring a new protocol or cooperation from old binaries.
    transaction
        .execute_unprepared(
            "UPDATE maintenance_lease SET holder_pid = holder_pid WHERE name = 'install_exclusive'",
        )
        .await?;
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
    use std::{sync::LazyLock, time::Duration};

    use microsandbox_db::pool::DbPools;
    use sea_orm::{ConnectionTrait, Database};
    use serde::Deserialize;

    use super::*;
    use crate::runtime::launch_contract;
    use crate::{SandboxConfig, test_support};

    //--------------------------------------------------------------------------------------------------
    // Constants
    //--------------------------------------------------------------------------------------------------

    static RELEASED: LazyLock<Vec<ReleasedCatalog>> = LazyLock::new(|| {
        serde_json::from_str(include_str!("../../db/fixtures/catalog-profiles.json"))
            .expect("checked-in released catalog profiles must parse")
    });

    //--------------------------------------------------------------------------------------------------
    // Types
    //--------------------------------------------------------------------------------------------------

    #[derive(Deserialize)]
    struct ReleasedCatalog {
        versions: Vec<String>,
        migrations: BTreeSet<String>,
    }

    //--------------------------------------------------------------------------------------------------
    // Functions
    //--------------------------------------------------------------------------------------------------

    fn v0_6_migration_count(patch: u64) -> MicrosandboxResult<u32> {
        let version = format!("v0.6.{patch}");
        RELEASED
            .iter()
            .find(|profile| profile.versions.contains(&version))
            .map(|profile| profile.migrations.len() as u32)
            .ok_or_else(|| {
                MicrosandboxError::Runtime(format!("unrecognized catalog release {version}"))
            })
    }

    #[tokio::test]
    async fn every_released_profile_is_preserved_and_unknown_history_is_refused() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        assert!(requires_initialization(&db).await.unwrap());
        db.execute_unprepared(
            "CREATE TABLE seaql_migrations (version TEXT PRIMARY KEY, applied_at BIGINT NOT NULL)",
        )
        .await
        .unwrap();
        for profile in RELEASED.iter() {
            db.execute_unprepared("DELETE FROM seaql_migrations")
                .await
                .unwrap();
            for version in &profile.migrations {
                db.execute_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "INSERT INTO seaql_migrations VALUES (?, 1)",
                    [version.clone().into()],
                ))
                .await
                .unwrap();
            }
            assert!(!requires_initialization(&db).await.unwrap());
            let count = db
                .query_one_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "SELECT COUNT(*) FROM seaql_migrations",
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get_by_index::<i64>(0)
                .unwrap();
            assert_eq!(count as usize, profile.migrations.len());
        }
        db.execute_unprepared(
            "INSERT INTO seaql_migrations VALUES ('unknown_future_migration', 1)",
        )
        .await
        .unwrap();
        assert!(requires_initialization(&db).await.is_err());
    }

    #[tokio::test]
    async fn every_known_post_floor_prefix_can_upgrade() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            "CREATE TABLE seaql_migrations (version TEXT PRIMARY KEY, applied_at BIGINT NOT NULL)",
        )
        .await
        .unwrap();
        let floor = schema_metadata::BASELINE_0_6_0_MIGRATIONS.len();
        for (index, version) in schema_metadata::migration_ids().enumerate() {
            db.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO seaql_migrations VALUES (?, 1)",
                [version.into()],
            ))
            .await
            .unwrap();
            assert_eq!(
                requires_initialization(&db).await.unwrap(),
                index + 1 < floor
            );
        }
        db.execute_unprepared("DELETE FROM seaql_migrations WHERE version = (SELECT version FROM seaql_migrations ORDER BY version LIMIT 1)").await.unwrap();
        assert!(requires_initialization(&db).await.is_err());
    }

    #[tokio::test]
    async fn equal_migration_counts_do_not_admit_an_unknown_writer() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            "CREATE TABLE seaql_migrations (version TEXT PRIMARY KEY, applied_at BIGINT NOT NULL)",
        )
        .await
        .unwrap();
        for version in schema_metadata::migration_ids() {
            db.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO seaql_migrations VALUES (?, 1)",
                [version.into()],
            ))
            .await
            .unwrap();
        }
        assert!(is_current(&db).await.unwrap());
        db.execute_unprepared("UPDATE seaql_migrations SET version = 'unknown_replacement' WHERE version = (SELECT version FROM seaql_migrations ORDER BY version LIMIT 1)").await.unwrap();
        assert!(!is_current(&db).await.unwrap());
        assert!(requires_initialization(&db).await.is_err());
    }

    #[tokio::test]
    async fn abandoned_lease_recovery_preserves_live_owner() {
        let home = tempfile::tempdir().unwrap();
        let pools = previous_version_database(home.path()).await;
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
        let pools = previous_version_database(home.path()).await;
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
            .config_path(home.path().join("config.json"))
            .managed_config_path(home.path().join("managed.json"))
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
            .config_path(home.path().join("config.json"))
            .managed_config_path(home.path().join("managed.json"))
            .home(home.path())
            .build()
            .await
            .unwrap();
        local.db().await.unwrap();
        maintenance::refuse_if_install_exclusive_held(pools.write())
            .await
            .unwrap();
        assert!(is_current(pools.read()).await.unwrap());
        assert!(
            maintenance::clear_install_exclusive_lease(pools.write(), &lease)
                .await
                .is_err()
        );
        drop(child);
    }

    #[tokio::test]
    #[ignore = "requires isolated MSB_CATALOG_TEST_HOME plus actual previous MSB_PATH/MSB_LIBKRUNFW_PATH and host virtualization"]
    async fn live_sdk_upgrades_catalog_with_previous_version_runtime() {
        use futures::FutureExt;
        use std::sync::Arc;

        let home = std::env::var("MSB_CATALOG_TEST_HOME").expect("explicit disposable test home");
        let local = Arc::new(crate::test_support::local_backend(
            crate::config::GlobalConfig {
                home: Some(std::path::PathBuf::from(&home)),
                // This isolated backend does not read environment paths. Supply the
                // released runtime pair selected by the previous fixture explicitly.
                paths: crate::config::PathsConfig {
                    msb: Some(std::env::var_os("MSB_PATH").expect("previous msb").into()),
                    libkrunfw: Some(
                        std::env::var_os("MSB_LIBKRUNFW_PATH")
                            .expect("previous firmware")
                            .into(),
                    ),
                    ..Default::default()
                },
                ..Default::default()
            },
        ));

        let expected = launch_contract::resolve(
            &crate::setup::resolve_runtime(local.config())
                .unwrap()
                .msb_path,
        )
        .await
        .unwrap()
        .patch;

        // Start with the released CLI, before the candidate SDK ever opens
        // the catalog. This catches a blanket active-runtime upgrade refusal.
        let old = std::env::var_os("MSB_PATH").unwrap();
        for args in [
            vec![
                "create",
                "alpine:3.21",
                "--name",
                "catalog-running",
                "--cpus",
                "1",
                "--memory",
                "256M",
                "--max-duration",
                "120s",
            ],
            vec![
                "exec",
                "catalog-running",
                "--",
                "sh",
                "-c",
                "echo retained > /dev/shm/catalog-marker",
            ],
        ] {
            let output = tokio::process::Command::new(&old)
                .env("MSB_HOME", &home)
                .args(args)
                .output()
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let released = DbPools::open(
            &std::path::Path::new(&home).join("db/msb.db"),
            1,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let before = Migrator::get_applied_migrations(released.write().inner())
            .await
            .unwrap();
        assert_eq!(
            before.len(),
            v0_6_migration_count(expected).unwrap() as usize
        );
        let pid = released
            .read()
            .query_one_raw(sea_orm::Statement::from_string(
                sea_orm::DbBackend::Sqlite,
                "SELECT pid FROM run WHERE status = 'Running'",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<i32>(0)
            .unwrap();
        let backend: Arc<dyn crate::backend::Backend> = local.clone();
        crate::backend::with_backend(backend, async {
            let pools = local.db().await.unwrap();
            assert!(is_current(pools.read()).await.unwrap());
            let before = Migrator::get_applied_migrations(pools.write().inner()).await.unwrap();
            let active = crate::Sandbox::get("catalog-running").await.unwrap().connect().await.unwrap();
            let output = active.exec("cat", ["/dev/shm/catalog-marker"]).await.unwrap();
            assert!(output.status().success);
            assert_eq!(output.stdout().unwrap().trim(), "retained");
            let current_pid = pools.read().query_one_raw(sea_orm::Statement::from_string(
                sea_orm::DbBackend::Sqlite, "SELECT pid FROM run WHERE status = 'Running'",
            )).await.unwrap().unwrap().try_get_by_index::<i32>(0).unwrap();
            assert_eq!(current_pid, pid, "upgrade must not restart the old VM");
            active.stop().await.unwrap();
            crate::Sandbox::remove("catalog-running").await.unwrap();
            #[cfg(feature = "net")]
            {
                // A newer SDK must not silently omit a security/resource
                // request that the selected previous runtime cannot honor.
                let rejected = crate::Sandbox::builder("catalog-unsupported")
                    .image("alpine:3.21").cpus(1).memory(256u32).max_duration(120)
                    .network(|network| network.max_udp_connections(0))
                    .create().await;
                let error = match rejected {
                    Ok(unexpected) => {
                        unexpected.stop().await.unwrap();
                        crate::Sandbox::remove("catalog-unsupported").await.unwrap();
                        panic!("previous runtime accepted an unsupported UDP limit");
                    }
                    Err(error) => error.to_string(),
                };
                assert!(error.contains("max_udp_connections") || error.contains("UDP connection limits"), "{error}");
                assert!(matches!(crate::Sandbox::get("catalog-unsupported").await,
                    Err(MicrosandboxError::SandboxNotFound(_))));
                assert!(!local.config().sandboxes_dir().join("catalog-unsupported").exists());
                let after = Migrator::get_applied_migrations(local.db().await.unwrap().write().inner()).await.unwrap();
                assert_eq!(after.iter().map(|migration| migration.name()).collect::<Vec<_>>(), before.iter().map(|migration| migration.name()).collect::<Vec<_>>());
                println!("previous runtime 0.6.{expected}: unsupported UDP request refused without a sandbox or schema change");
            }
            for count in [0, 1, 3] {
                let name = format!("catalog-mounts-{count}");
                let started = std::time::Instant::now();
                let mut builder = crate::Sandbox::builder(&name).image("alpine:3.21").cpus(1).memory(256u32).max_duration(120);
                for index in 0..count {
                    builder = builder.volume(format!("/catalog-{index}"), |mount| mount.tmpfs().size(16u32));
                }
                let sandbox = builder.create().await.expect("create through previous writer/runtime");
                let result = std::panic::AssertUnwindSafe(async {
                    #[cfg(feature = "net")]
                    {
                        let error = crate::Sandbox::builder(&name).image("alpine:3.21")
                            .network(|network| network.max_udp_connections(0)).replace()
                            .create().await.err().expect("unsupported replacement must fail");
                        assert!(error.to_string().contains("UDP connection limits"), "{error}");
                    }
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
                    // Old SDK/CLI catalog readers are not promised access after
                    // upgrade. The VM executable itself still works below.
                    assert!(!output.status.success());
                    let error = String::from_utf8_lossy(&output.stderr);
                    assert!(error.contains("database schema is newer") || error.contains("Migration file"), "{error}");
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
                sandbox.stop().await.expect("cleanup previous VM");
                crate::Sandbox::remove(&name).await.expect("cleanup previous sandbox");
                result.unwrap();
                println!("previous runtime 0.6.{expected}: {count} mounts, exec, old CLI refusal, modify/restart on current schema, cleanup: {:?}", started.elapsed());
            }
            let host_file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(host_file.path(), b"file-mount-compatible").unwrap();
            let result = crate::Sandbox::builder("catalog-file-mount")
                .image("alpine:3.21").cpus(1).memory(256u32).max_duration(120)
                .volume("/compat-file", |mount| mount.bind(host_file.path()).readonly())
                .create().await;
            if expected < 16 {
                let error = result.err().expect("old runtime must reject isolated file mounts");
                assert!(error.to_string().contains("file mounts"), "{error}");
            } else {
                let sandbox = result.expect("runtime supports isolated file mounts");
                let output = sandbox.exec("cat", ["/compat-file"]).await;
                sandbox.stop().await.unwrap();
                crate::Sandbox::remove("catalog-file-mount").await.unwrap();
                let output = output.unwrap();
                assert!(output.status().success);
                assert_eq!(output.stdout().unwrap(), "file-mount-compatible");
            }
            println!("previous runtime 0.6.{expected}: isolated file-mount support checked");
        }).await;
    }

    async fn previous_version_database(home: &std::path::Path) -> DbPools {
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
    async fn invalid_replacement_preserves_the_existing_sandbox_after_upgrade() {
        use std::sync::Arc;

        // macOS's default temporary root can exceed previous socket limits.
        #[cfg(unix)]
        let home = tempfile::tempdir_in("/tmp").unwrap();
        #[cfg(not(unix))]
        let home = tempfile::tempdir().unwrap();
        let pools = previous_version_database(home.path()).await;
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
                .config_path(home.path().join("config.json"))
                .managed_config_path(home.path().join("managed.json"))
                .home(home.path())
                .build()
                .await
                .unwrap(),
        );
        local.db().await.unwrap();
        let migrated = pools
            .read()
            .query_one_raw(sea_orm::Statement::from_string(
                sea_orm::DbBackend::Sqlite,
                "SELECT config FROM sandbox WHERE id = 1",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<String>(0)
            .unwrap();
        assert_eq!(
            serde_json::to_value(serde_json::from_str::<crate::SandboxConfig>(&migrated).unwrap())
                .unwrap(),
            serde_json::to_value(test_support::fixtures::decode(&original).unwrap()).unwrap()
        );
        let backend: Arc<dyn crate::backend::Backend> = local;
        let result = crate::backend::with_backend(backend, async {
            crate::Sandbox::builder("preserved")
                .image("alpine:3.21")
                .hostname("x".repeat(65))
                .replace()
                .create()
                .await
        })
        .await;
        let error = result
            .err()
            .expect("invalid replacement must fail")
            .to_string();
        assert!(error.contains("hostname"), "{error}");
        assert_eq!(
            std::fs::read_to_string(sandbox_dir.join("sentinel")).unwrap(),
            "existing data"
        );
        let row = pools.read().query_one_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Sqlite, "SELECT config FROM sandbox WHERE id = 1 AND name = 'preserved' AND status = 'Stopped'"
        )).await.unwrap().unwrap();
        assert_eq!(row.try_get_by_index::<String>(0).unwrap(), migrated);
        assert!(is_current(pools.read()).await.unwrap());
    }

    #[tokio::test]
    async fn sdk_and_cli_both_upgrade_old_catalogs() {
        let home = tempfile::tempdir().unwrap();
        drop(previous_version_database(home.path()).await);
        let sdk = LocalBackend::builder()
            .config_path(home.path().join("config.json"))
            .managed_config_path(home.path().join("managed.json"))
            .home(home.path())
            .build()
            .await
            .unwrap();
        assert!(is_current(sdk.db().await.unwrap().read()).await.unwrap());
        sdk.prepare_cli_catalog().await.unwrap();
        drop(sdk);
        let cli = crate::test_support::local_backend(crate::config::GlobalConfig {
            home: Some(home.path().to_path_buf()),
            ..Default::default()
        });
        cli.prepare_cli_catalog().await.unwrap();
        assert!(is_current(cli.db().await.unwrap().read()).await.unwrap());
        cli.prepare_cli_catalog().await.unwrap();
    }

    #[tokio::test]
    async fn active_catalog_upgrade_releases_lease_and_preserves_lifecycle_state() {
        let home = tempfile::tempdir().unwrap();
        let pools = previous_version_database(home.path()).await;
        pools.write().inner().execute_unprepared(
            "INSERT INTO sandbox (name, config, status, ephemeral) VALUES ('active', '{}', 'Starting', 0)",
        ).await.unwrap();
        upgrade(&pools).await.unwrap();
        assert!(is_current(pools.read()).await.unwrap());
        maintenance::refuse_if_install_exclusive_held(pools.write())
            .await
            .unwrap();
        let row = pools
            .read()
            .query_one_raw(sea_orm::Statement::from_string(
                sea_orm::DbBackend::Sqlite,
                "SELECT status FROM sandbox WHERE name = 'active'",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get_by_index::<String>(0).unwrap(), "Starting");
        pools
            .write()
            .inner()
            .execute_unprepared("UPDATE sandbox SET status = 'Stopped'")
            .await
            .unwrap();
        upgrade(&pools).await.unwrap();
        assert!(is_current(pools.read()).await.unwrap());
    }

    #[tokio::test]
    async fn catalog_upgrade_fences_preopened_lifecycle_writers_until_commit_or_rollback() {
        for commit in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let pools = previous_version_database(home.path()).await;
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
            let transaction = begin_upgrade(&pools).await.unwrap();
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
            assert_eq!(is_current(old_sdk.read()).await.unwrap(), commit);
            // Both outcomes release the writer. This checks ordering, not
            // whether a previous runtime supports the newly committed schema.
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
        let pools = previous_version_database(home.path()).await;
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
    async fn preopened_runtime_writer_waits_for_upgrade_then_records_exit() {
        let home = tempfile::tempdir().unwrap();
        let pools = previous_version_database(home.path()).await;
        pools.write().inner().execute_unprepared(
            "INSERT INTO sandbox (name, config, status, ephemeral) VALUES ('active', '{}', 'Running', 0)",
        ).await.unwrap();
        let runtime = DbPools::open(
            &home.path().join("db/msb.db"),
            1,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let lease = maintenance::acquire_install_exclusive_lease(pools.write())
            .await
            .unwrap();
        let transaction = begin_upgrade(&pools).await.unwrap();
        let writer = tokio::spawn(async move {
            runtime.write().inner().execute_unprepared(
                "UPDATE sandbox SET status = 'Stopped', active_config = NULL, network_slot = NULL WHERE name = 'active'",
            ).await
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !writer.is_finished(),
            "writer must not see intermediate schema"
        );
        Migrator::up(&transaction, None).await.unwrap();
        transaction.commit().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        maintenance::clear_install_exclusive_lease(pools.write(), &lease)
            .await
            .unwrap();
        let row = pools
            .read()
            .query_one_raw(sea_orm::Statement::from_string(
                sea_orm::DbBackend::Sqlite,
                "SELECT status FROM sandbox WHERE name = 'active'",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get_by_index::<String>(0).unwrap(), "Stopped");
    }

    #[tokio::test]
    async fn catalog_upgrade_migrates_saved_and_active_secret_policies() {
        let home = tempfile::tempdir().unwrap();
        let pools = previous_version_database(home.path()).await;
        let raw =
            include_str!("../../db/fixtures/config-0.6.18-global-passthrough-with-entries.json");

        pools.write().execute_raw(sea_orm::Statement::from_sql_and_values(sea_orm::DbBackend::Sqlite,
            "INSERT INTO sandbox (name, config, active_config, status, ephemeral) VALUES ('secret-migration', ?, ?, 'Running', 0)",
            [raw.into(), raw.into()],
        )).await.unwrap();

        let expected = serde_json::to_value(test_support::fixtures::decode(raw).unwrap()).unwrap();
        upgrade(&pools).await.unwrap();

        for column in ["config", "active_config"] {
            let row = pools
                .read()
                .query_one_raw(sea_orm::Statement::from_string(
                    sea_orm::DbBackend::Sqlite,
                    format!("SELECT {column} FROM sandbox WHERE name = 'secret-migration'"),
                ))
                .await
                .unwrap()
                .unwrap();
            let stored: String = row.try_get_by_index(0).unwrap();
            assert!(!stored.contains("\"injection\""));
            assert!(stored.contains("\"substitution\""));
            assert_eq!(
                serde_json::to_value(
                    serde_json::from_str::<crate::SandboxConfig>(&stored).unwrap()
                )
                .unwrap(),
                expected
            );
        }
        upgrade(&pools).await.unwrap();
    }

    #[tokio::test]
    async fn previous_version_active_config_survives_catalog_upgrade() {
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
                Some(v0_6_migration_count(patch).unwrap()),
            )
            .await
            .unwrap();
            pools.write().execute_raw(sea_orm::Statement::from_sql_and_values(
                sea_orm::DbBackend::Sqlite,
                "INSERT INTO sandbox (name, config, status, ephemeral) VALUES ('catalog-fixture', ?, 'Running', 0)",
                [raw.into()],
            )).await.unwrap();
            if patch >= 4 {
                pools
                    .write()
                    .inner()
                    .execute_unprepared("UPDATE sandbox SET active_config = config")
                    .await
                    .unwrap();
            }
            let expected =
                serde_json::to_value(test_support::fixtures::decode(raw).unwrap()).unwrap();
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
                serde_json::to_value(serde_json::from_str::<SandboxConfig>(&updated).unwrap())
                    .unwrap(),
                expected,
                "patch {patch}"
            );
            if patch >= 4 {
                let active = pools
                    .read()
                    .query_one_raw(sea_orm::Statement::from_string(
                        sea_orm::DbBackend::Sqlite,
                        "SELECT active_config FROM sandbox WHERE name = 'catalog-fixture'",
                    ))
                    .await
                    .unwrap()
                    .unwrap()
                    .try_get_by_index::<String>(0)
                    .unwrap();
                assert_eq!(
                    serde_json::to_value(serde_json::from_str::<SandboxConfig>(&active).unwrap())
                        .unwrap(),
                    expected
                );
            }
            assert!(is_current(pools.read()).await.unwrap());
        }
    }
}
