//! Record a live effect only in the run and snapshot that produced the request.

use microsandbox_db::DbWriteConnection;
use sea_orm::{ConnectionTrait, DbBackend, Statement};

use super::session::ControlSession;
use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ControlSession {
    pub(crate) async fn persist_active_config(
        &self,
        db: &DbWriteConnection,
        expected: Option<&str>,
        active: &SandboxConfig,
    ) -> MicrosandboxResult<String> {
        let conflict = || MicrosandboxError::ControlStateChanged;
        if self.entry.invalidated.is_cancelled() {
            return Err(conflict());
        }
        self.entry
            .connector
            .verify_session(tokio::time::Instant::now() + std::time::Duration::from_secs(10))
            .await
            .map_err(|_| conflict())?;
        let key = self.entry.key;
        let json = serde_json::to_string(active)?;
        // Verification alone would leave a restart race before the write. This
        // single statement compares the latest run and the exact snapshot in
        // the same SQLite write. A concurrent modifier is also detected rather
        // than overwriting its accepted changes with our earlier snapshot.
        let result = db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE sandbox SET active_config = ?, updated_at = ?
                 WHERE id = ? AND status IN ('Running', 'Draining')
                   AND active_config IS ?
                   AND ? = (SELECT id FROM run WHERE sandbox_id = ?
                            AND status = 'Running' ORDER BY id DESC LIMIT 1)
                   AND EXISTS (SELECT 1 FROM run WHERE id = ? AND pid = ?
                               AND status = 'Running')",
                [
                    json.clone().into(),
                    chrono::Utc::now().naive_utc().into(),
                    key.sandbox_id.into(),
                    expected.map(str::to_owned).into(),
                    key.run_id.into(),
                    key.sandbox_id.into(),
                    key.run_id.into(),
                    key.pid.into(),
                ],
            ))
            .await?;
        if result.rows_affected() != 1 {
            return Err(conflict());
        }
        Ok(json)
    }
}
