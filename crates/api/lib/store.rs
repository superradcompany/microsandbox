//! Persistent API-owned execution store.

use std::path::Path;

use chrono::{DateTime, Utc};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const RESTART_ERROR: &str = "API server restarted before execution completion; Microsandbox does \
    not persist live exec sessions.";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Persistent execution store.
#[derive(Debug, Clone)]
pub struct ExecutionStore {
    pool: SqlitePool,
}

/// New execution insert data.
#[derive(Debug, Clone)]
pub struct ExecutionInsert {
    /// Devbox ID.
    pub devbox_id: String,

    /// Execution ID.
    pub execution_id: String,

    /// Command.
    pub command: String,

    /// Whether stdin is attached.
    pub stdin_attached: bool,
}

/// Stored execution row.
#[derive(Debug, Clone)]
pub struct StoredExecution {
    /// Devbox ID.
    pub devbox_id: String,

    /// Execution ID.
    pub execution_id: String,

    /// Command.
    pub command: String,

    /// Status.
    pub status: ExecutionStatus,

    /// Whether stdin is attached.
    pub stdin_attached: bool,

    /// Exit code.
    pub exit_code: Option<i32>,

    /// Captured stdout.
    pub stdout: String,

    /// Captured stderr.
    pub stderr: String,

    /// Whether stdout was truncated.
    pub stdout_truncated: bool,

    /// Whether stderr was truncated.
    pub stderr_truncated: bool,

    /// Error message.
    pub error: Option<String>,

    /// Created timestamp.
    pub created_at: DateTime<Utc>,

    /// Updated timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Execution is queued.
    Queued,

    /// Execution is running.
    Running,

    /// Execution completed successfully or with an exit code.
    Completed,

    /// Execution failed before completion.
    Failed,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecutionStore {
    /// Open and migrate the store at `path`.
    pub async fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            tokio::fs::create_dir_all(parent).await?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    /// Insert a queued execution.
    pub async fn insert(&self, insert: ExecutionInsert) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            r#"
            INSERT INTO api_executions (
                devbox_id,
                execution_id,
                command,
                status,
                stdin_attached,
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, 'queued', ?, '', '', 0, 0, ?, ?)
            "#,
        )
        .bind(insert.devbox_id)
        .bind(insert.execution_id)
        .bind(insert.command)
        .bind(insert.stdin_attached)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Mark an execution running.
    pub async fn mark_running(&self, devbox_id: &str, execution_id: &str) -> anyhow::Result<()> {
        self.update_status(
            devbox_id,
            execution_id,
            ExecutionStatus::Running,
            None,
            None,
        )
        .await
    }

    /// Mark an execution completed with an exit code.
    pub async fn mark_completed(
        &self,
        devbox_id: &str,
        execution_id: &str,
        exit_code: i32,
    ) -> anyhow::Result<()> {
        self.update_status(
            devbox_id,
            execution_id,
            ExecutionStatus::Completed,
            Some(exit_code),
            None,
        )
        .await
    }

    /// Mark an execution failed with an error message.
    pub async fn mark_failed(
        &self,
        devbox_id: &str,
        execution_id: &str,
        error: &str,
    ) -> anyhow::Result<()> {
        self.update_status(
            devbox_id,
            execution_id,
            ExecutionStatus::Failed,
            None,
            Some(error),
        )
        .await
    }

    /// Append captured stdout and stderr, retaining the newest 1 MiB per stream.
    pub async fn append_output(
        &self,
        devbox_id: &str,
        execution_id: &str,
        stdout: &[u8],
        stderr: &[u8],
    ) -> anyhow::Result<()> {
        let Some(row) = self.get(devbox_id, execution_id).await? else {
            anyhow::bail!("execution {execution_id} for devbox {devbox_id} not found");
        };
        let (stdout, stdout_truncated) = append_capped(&row.stdout, stdout);
        let (stderr, stderr_truncated) = append_capped(&row.stderr, stderr);
        let result = sqlx::query(
            r#"
            UPDATE api_executions
            SET stdout = ?,
                stderr = ?,
                stdout_truncated = ?,
                stderr_truncated = ?,
                updated_at = ?
            WHERE devbox_id = ? AND execution_id = ?
            "#,
        )
        .bind(stdout)
        .bind(stderr)
        .bind(row.stdout_truncated || stdout_truncated)
        .bind(row.stderr_truncated || stderr_truncated)
        .bind(Utc::now().to_rfc3339())
        .bind(devbox_id)
        .bind(execution_id)
        .execute(&self.pool)
        .await?;

        ensure_updated(result.rows_affected(), devbox_id, execution_id)
    }

    /// Get a stored execution.
    pub async fn get(
        &self,
        devbox_id: &str,
        execution_id: &str,
    ) -> anyhow::Result<Option<StoredExecution>> {
        let row = sqlx::query(
            r#"
            SELECT
                devbox_id,
                execution_id,
                command,
                status,
                stdin_attached,
                exit_code,
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
                error,
                created_at,
                updated_at
            FROM api_executions
            WHERE devbox_id = ? AND execution_id = ?
            "#,
        )
        .bind(devbox_id)
        .bind(execution_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_execution).transpose()
    }

    /// Mark queued or running executions as failed after an API restart.
    pub async fn reconcile_incomplete_on_startup(&self) -> anyhow::Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE api_executions
            SET status = 'failed',
                exit_code = NULL,
                error = ?,
                updated_at = ?
            WHERE status IN ('queued', 'running')
            "#,
        )
        .bind(RESTART_ERROR)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS api_executions (
                devbox_id TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                command TEXT NOT NULL,
                status TEXT NOT NULL,
                stdin_attached INTEGER NOT NULL,
                exit_code INTEGER,
                stdout TEXT NOT NULL,
                stderr TEXT NOT NULL,
                stdout_truncated INTEGER NOT NULL,
                stderr_truncated INTEGER NOT NULL,
                error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (devbox_id, execution_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn update_status(
        &self,
        devbox_id: &str,
        execution_id: &str,
        status: ExecutionStatus,
        exit_code: Option<i32>,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        let result = sqlx::query(
            r#"
            UPDATE api_executions
            SET status = ?,
                exit_code = ?,
                error = ?,
                updated_at = ?
            WHERE devbox_id = ? AND execution_id = ?
            "#,
        )
        .bind(status.as_str())
        .bind(exit_code)
        .bind(error)
        .bind(Utc::now().to_rfc3339())
        .bind(devbox_id)
        .bind(execution_id)
        .execute(&self.pool)
        .await?;

        ensure_updated(result.rows_affected(), devbox_id, execution_id)
    }
}

impl ExecutionStatus {
    /// Return the lowercase SQLite/API representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn append_capped(existing: &str, addition: &[u8]) -> (String, bool) {
    if addition.is_empty() {
        return (existing.to_owned(), false);
    }

    let addition = String::from_utf8_lossy(addition);
    let mut output = String::with_capacity(existing.len() + addition.len());
    output.push_str(existing);
    output.push_str(&addition);

    cap_newest_utf8(output)
}

fn cap_newest_utf8(output: String) -> (String, bool) {
    if output.len() <= MAX_OUTPUT_BYTES {
        return (output, false);
    }

    let mut start = output.len() - MAX_OUTPUT_BYTES;
    while !output.is_char_boundary(start) {
        start += 1;
    }

    (output[start..].to_owned(), true)
}

fn ensure_updated(rows_affected: u64, devbox_id: &str, execution_id: &str) -> anyhow::Result<()> {
    if rows_affected == 0 {
        anyhow::bail!("execution {execution_id} for devbox {devbox_id} not found");
    }

    Ok(())
}

fn row_to_execution(row: sqlx::sqlite::SqliteRow) -> anyhow::Result<StoredExecution> {
    let status: String = row.try_get("status")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;

    Ok(StoredExecution {
        devbox_id: row.try_get("devbox_id")?,
        execution_id: row.try_get("execution_id")?,
        command: row.try_get("command")?,
        status: parse_status(&status)?,
        stdin_attached: row.try_get("stdin_attached")?,
        exit_code: row.try_get("exit_code")?,
        stdout: row.try_get("stdout")?,
        stderr: row.try_get("stderr")?,
        stdout_truncated: row.try_get("stdout_truncated")?,
        stderr_truncated: row.try_get("stderr_truncated")?,
        error: row.try_get("error")?,
        created_at: DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
        updated_at: DateTime::parse_from_rfc3339(&updated_at)?.with_timezone(&Utc),
    })
}

fn parse_status(status: &str) -> anyhow::Result<ExecutionStatus> {
    match status {
        "queued" => Ok(ExecutionStatus::Queued),
        "running" => Ok(ExecutionStatus::Running),
        "completed" => Ok(ExecutionStatus::Completed),
        "failed" => Ok(ExecutionStatus::Failed),
        other => anyhow::bail!("unknown execution status {other}"),
    }
}
