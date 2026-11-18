//! Durable catalog admission for a filesystem storage migration.

use std::path::Path;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteSynchronous};
use sqlx::{ConnectOptions, Connection};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Fence an already validated storage plan against downgrade before publishing its disks.
///
/// The caller owns lifecycle and storage exclusion and has persisted the recoverable filesystem
/// intent. A dedicated FULL-synchronous connection makes this commit durable without changing the
/// normal pool's durability policy. No disk copying may run inside this short transaction.
pub async fn admit(
    database: &Path,
    sandbox_id: i32,
    name: &str,
    expected_config: &str,
) -> Result<(), sqlx::Error> {
    let mut connection = SqliteConnectOptions::new()
        .filename(database)
        .create_if_missing(false)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
        .synchronous(SqliteSynchronous::Full)
        .connect()
        .await?;
    // Reserving SQLite's writer before the comparison closes the configuration/recreation race.
    // Dropping the connection on cancellation rolls back; no pool receives a partially configured
    // connection or an unfinished transaction.
    let mut transaction = connection.begin_with("BEGIN IMMEDIATE").await?;
    let matches: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sandbox WHERE id = ? AND name = ? AND config = ?")
            .bind(sandbox_id)
            .bind(name)
            .bind(expected_config)
            .fetch_one(&mut *transaction)
            .await?;
    if matches != 1 {
        return Err(sqlx::Error::Protocol(
            "sandbox identity or configuration changed during storage migration; inspect and retry"
                .into(),
        ));
    }
    // UPDATE on a pre-existing row also places this admission behind the FULL commit boundary.
    // This covers homes registered by an earlier failed 0.7.12 admission.
    sqlx::query(
        "INSERT INTO protected_sandbox_state (sandbox_id, layout_version) VALUES (?, 1) \
         ON CONFLICT(sandbox_id) DO UPDATE SET layout_version = excluded.layout_version",
    )
    .bind(sandbox_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    connection.close().await
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sqlx::Executor;

    use super::*;

    #[tokio::test]
    async fn admission_requires_the_same_incarnation_and_configuration() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("catalog.db");
        let mut observer = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .connect()
            .await
            .unwrap();
        observer.execute("PRAGMA journal_mode=WAL; CREATE TABLE sandbox(id INTEGER PRIMARY KEY, name TEXT, config TEXT); CREATE TABLE protected_sandbox_state(sandbox_id INTEGER PRIMARY KEY REFERENCES sandbox(id), layout_version INTEGER); INSERT INTO sandbox VALUES (1,'app','saved')").await.unwrap();

        for (id, name, config) in [
            (2, "app", "saved"),
            (1, "other", "saved"),
            (1, "app", "changed"),
        ] {
            assert!(admit(&path, id, name, config).await.is_err());
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM protected_sandbox_state")
                .fetch_one(&mut observer)
                .await
                .unwrap();
            assert_eq!(count, 0);
        }
        admit(&path, 1, "app", "saved").await.unwrap();
        admit(&path, 1, "app", "saved").await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM protected_sandbox_state")
            .fetch_one(&mut observer)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }
}
