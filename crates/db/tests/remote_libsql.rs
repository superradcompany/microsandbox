//! Integration tests against a live libSQL server.
//!
//! Gated on `MSB_TEST_LIBSQL_URL` pointing at a running `sqld` with a fresh
//! database, e.g.:
//!
//! ```text
//! sqld --db-path /tmp/msb-libsql-test --http-listen-addr 127.0.0.1:8890
//! MSB_TEST_LIBSQL_URL=http://127.0.0.1:8890 cargo test -p microsandbox-db --test remote_libsql -- --ignored
//! ```

mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    };

    use microsandbox_db::entity::sandbox;
    use microsandbox_db::{DbReadConnection, DbWriteConnection};

    //--------------------------------------------------------------------------------------------------
    // Constants
    //--------------------------------------------------------------------------------------------------

    const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
    const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
    const READ_CONNECTIONS: u32 = 4;

    static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

    //--------------------------------------------------------------------------------------------------
    // Functions
    //--------------------------------------------------------------------------------------------------

    fn server_url() -> String {
        std::env::var("MSB_TEST_LIBSQL_URL")
            .expect("MSB_TEST_LIBSQL_URL must point at a running sqld instance")
    }

    fn unique_name(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        format!("{prefix}-{nanos}")
    }

    fn new_sandbox(name: &str) -> sandbox::ActiveModel {
        // Truncate to milliseconds: the text format stores what chrono formats,
        // and equality below asserts an exact round trip.
        let now = chrono::Utc::now().naive_utc();
        let now = now
            - chrono::Duration::nanoseconds(i64::from(
                now.and_utc().timestamp_subsec_nanos() % 1_000_000,
            ));

        sandbox::ActiveModel {
            name: Set(name.to_owned()),
            config: Set("{}".to_owned()),
            active_config: Set(None),
            status: Set(sandbox::SandboxStatus::Created),
            ephemeral: Set(false),
            created_at: Set(Some(now)),
            updated_at: Set(None),
            ..Default::default()
        }
    }

    async fn setup() -> (DbReadConnection, DbWriteConnection) {
        let url = server_url();

        let write = DbWriteConnection::open_url(&url, ACQUIRE_TIMEOUT, BUSY_TIMEOUT)
            .await
            .expect("open write proxy");

        MIGRATED
            .get_or_init(|| async {
                use microsandbox_migration::MigratorTrait;
                microsandbox_migration::Migrator::up(write.inner(), None)
                    .await
                    .expect("apply migrations against sqld");
            })
            .await;

        let read =
            DbReadConnection::open_url(&url, READ_CONNECTIONS, ACQUIRE_TIMEOUT, BUSY_TIMEOUT)
                .await
                .expect("open read proxy");

        (read, write)
    }

    //--------------------------------------------------------------------------------------------------
    // Tests
    //--------------------------------------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running sqld (MSB_TEST_LIBSQL_URL)"]
    async fn migrations_apply_and_are_idempotent() {
        use microsandbox_migration::MigratorTrait;

        let (_read, write) = setup().await;

        // A second run must be a no-op, not an error.
        microsandbox_migration::Migrator::up(write.inner(), None)
            .await
            .expect("re-running migrations is idempotent");

        let applied = microsandbox_migration::Migrator::get_applied_migrations(write.inner())
            .await
            .expect("list applied migrations");
        assert!(!applied.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires a running sqld (MSB_TEST_LIBSQL_URL)"]
    async fn entity_crud_round_trips() {
        let (read, write) = setup().await;
        let name = unique_name("crud");

        let inserted = new_sandbox(&name).insert(&write).await.expect("insert");
        assert!(inserted.id > 0, "insert reports the assigned rowid");

        let found = sandbox::Entity::find_by_id(inserted.id)
            .one(&read)
            .await
            .expect("select")
            .expect("row exists via the read proxy");
        assert_eq!(found, inserted, "typed round trip through the server");
        assert!(found.created_at.is_some(), "timestamp survives conversion");

        let mut update: sandbox::ActiveModel = found.into();
        update.status = Set(sandbox::SandboxStatus::Running);
        let updated = update.update(&write).await.expect("update");
        assert_eq!(updated.status, sandbox::SandboxStatus::Running);

        sandbox::Entity::delete_by_id(inserted.id)
            .exec(&write)
            .await
            .expect("delete");
        let gone = sandbox::Entity::find_by_id(inserted.id)
            .one(&read)
            .await
            .expect("select after delete");
        assert!(gone.is_none());
    }

    #[tokio::test]
    #[ignore = "requires a running sqld (MSB_TEST_LIBSQL_URL)"]
    async fn transaction_commit_is_durable() {
        let (read, write) = setup().await;
        let name_a = unique_name("txn-a");
        let name_b = unique_name("txn-b");

        write
            .transaction(|txn| {
                let (name_a, name_b) = (name_a.clone(), name_b.clone());
                async move {
                    new_sandbox(&name_a).insert(&txn).await?;
                    new_sandbox(&name_b).insert(&txn).await?;
                    Ok::<_, sea_orm::DbErr>((txn, ()))
                }
            })
            .await
            .expect("transaction commits");

        let committed = sandbox::Entity::find()
            .filter(sandbox::Column::Name.is_in([name_a, name_b]))
            .count(&read)
            .await
            .expect("count");
        assert_eq!(committed, 2, "both writes visible after commit");
    }

    #[tokio::test]
    #[ignore = "requires a running sqld (MSB_TEST_LIBSQL_URL)"]
    async fn transaction_error_rolls_back() {
        let (read, write) = setup().await;
        let name = unique_name("rollback");

        let result: Result<(), sea_orm::DbErr> = write
            .transaction(|txn| {
                let name = name.clone();
                async move {
                    new_sandbox(&name).insert(&txn).await?;
                    Err(sea_orm::DbErr::Custom("abort on purpose".into()))
                }
            })
            .await;
        assert!(result.is_err());

        let rows = sandbox::Entity::find()
            .filter(sandbox::Column::Name.eq(name))
            .count(&read)
            .await
            .expect("count");
        assert_eq!(rows, 0, "aborted transaction leaves no rows");
    }

    #[tokio::test]
    #[ignore = "requires a running sqld (MSB_TEST_LIBSQL_URL)"]
    async fn concurrent_reads_respect_admission() {
        let (read, write) = setup().await;
        let name = unique_name("concurrent");
        new_sandbox(&name).insert(&write).await.expect("insert");

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..(READ_CONNECTIONS * 8) {
            let read = read.clone();
            let name = name.clone();
            tasks.spawn(async move {
                sandbox::Entity::find()
                    .filter(sandbox::Column::Name.eq(name))
                    .one(&read)
                    .await
            });
        }

        while let Some(result) = tasks.join_next().await {
            let row = result.expect("task").expect("query under admission");
            assert!(row.is_some());
        }
    }

    #[tokio::test]
    #[ignore = "requires a running sqld (MSB_TEST_LIBSQL_URL)"]
    async fn count_decodes_the_paginator_alias() {
        let (read, _write) = setup().await;
        // Regression guard: sea-orm decodes its COUNT alias as i32 on SQLite.
        sandbox::Entity::find()
            .count(&read)
            .await
            .expect("count all");
    }

    //--------------------------------------------------------------------------------------------------
    // Tests: Server Restart
    //--------------------------------------------------------------------------------------------------

    /// A sqld instance owned by the test, so it can be killed and restarted.
    struct TestServer {
        bin: String,
        db_dir: std::path::PathBuf,
        port: u16,
        child: std::process::Child,
    }

    impl TestServer {
        /// Spawn sqld from `MSB_TEST_SQLD_BIN` and wait until it answers queries.
        async fn spawn(db_dir: std::path::PathBuf, port: u16) -> Self {
            let bin = std::env::var("MSB_TEST_SQLD_BIN")
                .expect("MSB_TEST_SQLD_BIN must point at a sqld binary");
            let child = Self::launch(&bin, &db_dir, port);

            let server = Self {
                bin,
                db_dir,
                port,
                child,
            };
            server.wait_ready().await;
            server
        }

        fn launch(bin: &str, db_dir: &std::path::Path, port: u16) -> std::process::Child {
            std::process::Command::new(bin)
                .arg("--db-path")
                .arg(db_dir)
                .arg("--http-listen-addr")
                .arg(format!("127.0.0.1:{port}"))
                .arg("--no-welcome")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn sqld")
        }

        fn url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }

        /// SIGKILL the server, then bring it back on the same database.
        async fn kill_and_restart(&mut self) {
            self.child.kill().expect("kill sqld");
            self.child.wait().expect("reap sqld");

            self.child = Self::launch(&self.bin, &self.db_dir, self.port);
            self.wait_ready().await;
        }

        /// Poll with fresh throwaway connections until a real query answers.
        async fn wait_ready(&self) {
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                let probe = DbWriteConnection::open_url(
                    &self.url(),
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                )
                .await;
                if probe.is_ok() {
                    return;
                }

                assert!(
                    std::time::Instant::now() < deadline,
                    "sqld not ready within 30s"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[tokio::test]
    #[ignore = "requires a sqld binary (MSB_TEST_SQLD_BIN)"]
    async fn connections_reconnect_after_server_restart() {
        use sea_orm::ConnectionTrait;

        let dir = tempfile::tempdir().expect("tempdir");
        let mut server = TestServer::spawn(dir.path().to_owned(), 18901).await;

        let write = DbWriteConnection::open_url(&server.url(), ACQUIRE_TIMEOUT, BUSY_TIMEOUT)
            .await
            .expect("open write proxy");
        write
            .inner()
            .execute_unprepared("CREATE TABLE t (name TEXT NOT NULL)")
            .await
            .expect("create table");
        write
            .inner()
            .execute_unprepared("INSERT INTO t (name) VALUES ('before')")
            .await
            .expect("insert before restart");

        let read = DbReadConnection::open_url(&server.url(), 2, ACQUIRE_TIMEOUT, BUSY_TIMEOUT)
            .await
            .expect("open read proxy");

        server.kill_and_restart().await;

        // Both held connections lost their stream; the next request must
        // transparently reconnect and succeed.
        write
            .inner()
            .execute_unprepared("INSERT INTO t (name) VALUES ('after')")
            .await
            .expect("insert after restart reconnects");

        let stmt = sea_orm::Statement::from_string(
            sea_orm::DbBackend::Sqlite,
            "SELECT count(*) AS n FROM t".to_owned(),
        );
        let row = read
            .inner()
            .query_one(stmt)
            .await
            .expect("query after restart reconnects")
            .expect("count row");
        let n: i64 = row.try_get("", "n").expect("decode count");
        assert_eq!(n, 2, "both writes durable across the restart");
    }

    #[tokio::test]
    #[ignore = "requires a sqld binary (MSB_TEST_SQLD_BIN)"]
    async fn transaction_interrupted_by_restart_retries_whole() {
        use sea_orm::ConnectionTrait;
        use std::sync::atomic::{AtomicU32, Ordering};

        let dir = tempfile::tempdir().expect("tempdir");
        let server = TestServer::spawn(dir.path().to_owned(), 18902).await;

        let write = DbWriteConnection::open_url(&server.url(), ACQUIRE_TIMEOUT, BUSY_TIMEOUT)
            .await
            .expect("open write proxy");
        write
            .inner()
            .execute_unprepared("CREATE TABLE t (name TEXT NOT NULL)")
            .await
            .expect("create table");

        let server = std::sync::Arc::new(tokio::sync::Mutex::new(server));
        let attempts = std::sync::Arc::new(AtomicU32::new(0));

        write
            .transaction(|txn| {
                let server = server.clone();
                let attempts = attempts.clone();
                async move {
                    let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;

                    txn.execute_unprepared("INSERT INTO t (name) VALUES ('one')")
                        .await?;

                    // First attempt: the server dies (and comes back) under the
                    // open transaction. Its next statement hits the dead stream,
                    // poisons the transaction, and the whole closure re-runs.
                    if attempt == 1 {
                        server.lock().await.kill_and_restart().await;
                    }

                    txn.execute_unprepared("INSERT INTO t (name) VALUES ('two')")
                        .await?;
                    Ok::<_, sea_orm::DbErr>((txn, ()))
                }
            })
            .await
            .expect("transaction succeeds on the retried attempt");

        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "first attempt lost its stream and was retried"
        );

        // Exactly one committed transaction: no rows leaked from the aborted
        // attempt, both rows from the successful one.
        let stmt = sea_orm::Statement::from_string(
            sea_orm::DbBackend::Sqlite,
            "SELECT count(*) AS n FROM t".to_owned(),
        );
        let row = write
            .inner()
            .query_one(stmt)
            .await
            .expect("count")
            .expect("count row");
        let n: i64 = row.try_get("", "n").expect("decode count");
        assert_eq!(n, 2, "only the committed attempt's rows are present");
    }

    #[tokio::test]
    #[ignore = "requires a sqld binary (MSB_TEST_SQLD_BIN)"]
    async fn cancelled_transaction_releases_write_permit() {
        // Regression test: if a write transaction future is cancelled before
        // COMMIT/ROLLBACK, `WriteProxy::start_rollback` must release the permit
        // synchronously so the next transaction can acquire it.
        use sea_orm::ConnectionTrait;
        use std::sync::Arc;

        let dir = tempfile::tempdir().expect("tempdir");
        let server = TestServer::spawn(dir.path().to_owned(), 18903).await;

        let write = DbWriteConnection::open_url(&server.url(), ACQUIRE_TIMEOUT, BUSY_TIMEOUT)
            .await
            .expect("open write proxy");
        write
            .inner()
            .execute_unprepared("CREATE TABLE t (name TEXT NOT NULL)")
            .await
            .expect("create table");

        let write = Arc::new(write);
        let write2 = write.clone();

        // Spawn a task that opens a transaction and then sleeps long inside it.
        // Aborting the task cancels the future, which drops the DatabaseTransaction
        // without COMMIT/ROLLBACK — exactly the bug scenario.
        let handle = tokio::spawn(async move {
            write2
                .transaction(|txn| async move {
                    txn.execute_unprepared("INSERT INTO t (name) VALUES ('cancelled')")
                        .await?;
                    // Long sleep so the abort hits mid-transaction.
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok::<_, sea_orm::DbErr>((txn, ()))
                })
                .await
        });

        // Give the spawned task a moment to open its transaction and reach the sleep.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Abort the task — this cancels the transaction future mid-flight.
        handle.abort();
        let _ = handle.await; // reap (will be Err(Cancelled))

        // The permit must now be free. A subsequent write transaction must succeed
        // within ACQUIRE_TIMEOUT, not block forever.
        let result = tokio::time::timeout(
            ACQUIRE_TIMEOUT,
            write.transaction(|txn| async move {
                txn.execute_unprepared("INSERT INTO t (name) VALUES ('after-cancel')")
                    .await?;
                Ok::<_, sea_orm::DbErr>((txn, ()))
            }),
        )
        .await;

        assert!(
            result.is_ok(),
            "write after cancelled transaction timed out — permit was not released"
        );
        assert!(
            result.unwrap().is_ok(),
            "write transaction after cancel must succeed"
        );
    }
}
