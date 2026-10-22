//! Runtime-owned, borrowed evidence for the configuration selected during live capture.

use std::{io, path::PathBuf};

use microsandbox_db::DbWriteConnection;
use sea_orm::{ConnectionTrait, DbBackend, QueryResult, Statement};
use serde_json::Value;

use super::{RetainedConfiguration, RetentionJournal, catalog_file_identity, invalid};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Local configuration evidence borrowed from the owning runtime's mutation authority.
///
/// Keep the executor's mutation guard and this borrow through capture/publication. The borrow
/// prevents journal transitions while the checkpoint coordinator captures the corresponding VM.
/// Catalog metadata can also be written by older SDKs, so revalidate before using the result.
/// This is neither portable metadata nor proof of guest-applied CPU/memory capacity.
/// It does not lock out direct catalog writers or detect a change that was later undone; capture
/// must still establish its metadata boundary and enforce publication provenance.
pub struct LiveConfigurationSelection<'a> {
    journal: &'a RetentionJournal,
    db: &'a DbWriteConnection,
    confirmed: &'a RetainedConfiguration,
    catalog_path: PathBuf,
    pending: Option<Value>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RetentionJournal {
    /// Select confirmed evidence only inside the process owning the current live run.
    /// Missing legacy evidence stays unknown and does not prevent ordinary runtime operations.
    pub async fn select_live_configuration<'a>(
        &'a self,
        db: &'a DbWriteConnection,
    ) -> io::Result<Option<LiveConfigurationSelection<'a>>> {
        let Some(confirmed) = self.record.current(&self.record.owner) else {
            return Ok(None);
        };
        let row = db
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT file FROM pragma_database_list WHERE name = 'main'",
            ))
            .await
            .map_err(|_| invalid("could not identify capture catalog"))?
            .ok_or_else(|| invalid("capture catalog is missing"))?;
        let path: String = row
            .try_get("", "file")
            .map_err(|_| invalid("invalid capture catalog path"))?;
        if path.is_empty() {
            return Ok(None);
        }
        let mut capture = LiveConfigurationSelection {
            journal: self,
            db,
            confirmed,
            catalog_path: path.into(),
            pending: None,
        };
        let Some(row) = capture.read_validated_metadata().await? else {
            return Ok(None);
        };
        let pending: Option<String> = row
            .try_get("", "config")
            .map_err(|_| invalid("invalid pending capture configuration"))?;
        capture.pending = pending
            .map(|pending| {
                serde_json::from_str(&pending)
                    .map_err(|_| invalid("invalid pending capture configuration document"))
            })
            .transpose()?;
        Ok(Some(capture))
    }
}

impl LiveConfigurationSelection<'_> {
    /// Host-private source selected under runtime mutation authority. Never serialize this raw
    /// value into an archive; portable projection must apply exclusions and destination bindings.
    pub fn configuration(&self) -> &RetainedConfiguration {
        self.confirmed
    }

    /// Next-start intent read in the same SQLite statement as validated active provenance.
    /// Later desired-only edits do not alter this selection or certify any active settings.
    pub fn pending_configuration(&self) -> Option<&Value> {
        self.pending.as_ref()
    }

    /// Check lifecycle/catalog provenance again while the original runtime guard remains held.
    /// A false result means unknown, not empty defaults or permission to borrow desired config.
    pub async fn revalidate(&self) -> io::Result<bool> {
        Ok(self.read_validated_metadata().await?.is_some())
    }

    async fn read_validated_metadata(&self) -> io::Result<Option<QueryResult>> {
        let db = self.db;
        let owner = &self.confirmed.owner;
        if catalog_file_identity(&self.catalog_path)? != owner.catalog_file {
            return Ok(None);
        }
        if !microsandbox_db::catalog::has_column(db, "sandbox", "active_config")
            .await
            .map_err(|_| invalid("could not inspect capture configuration support"))?
        {
            return Ok(None);
        }
        // One SQLite statement binds the source value to the latest run and both row identities.
        // Filtering terminal runs first, or checking an arbitrary live PID, could resurrect stale
        // evidence after a restart. Only this executor's actual process can attest to its journal.
        let row = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT s.created_at AS sandbox_created_at, s.status AS sandbox_status, \
                 s.active_config, s.config, r.id AS run_id, r.started_at AS run_started_at, \
                 r.status AS run_status, r.pid, r.terminated_at \
                 FROM sandbox s JOIN run r ON r.sandbox_id = s.id \
                 WHERE s.id = ? ORDER BY r.id DESC LIMIT 1",
                [owner.sandbox_id.into()],
            ))
            .await
            .map_err(|_| invalid("could not read live capture provenance"))?;
        let Some(row) = row else { return Ok(None) };
        let sandbox_created_at: Option<String> = row
            .try_get("", "sandbox_created_at")
            .map_err(|_| invalid("invalid capture sandbox identity"))?;
        let run_started_at: Option<String> = row
            .try_get("", "run_started_at")
            .map_err(|_| invalid("invalid capture run identity"))?;
        let run_id: i32 = row
            .try_get("", "run_id")
            .map_err(|_| invalid("invalid capture run"))?;
        let run_status: String = row
            .try_get("", "run_status")
            .map_err(|_| invalid("invalid capture run status"))?;
        let sandbox_status: String = row
            .try_get("", "sandbox_status")
            .map_err(|_| invalid("invalid capture sandbox status"))?;
        let pid: Option<i32> = row
            .try_get("", "pid")
            .map_err(|_| invalid("invalid capture process identity"))?;
        let terminated_at: Option<String> = row
            .try_get("", "terminated_at")
            .map_err(|_| invalid("invalid capture termination evidence"))?;
        if sandbox_created_at != owner.sandbox_created_at
            || run_started_at.as_deref() != Some(owner.run_started_at.as_str())
            || run_id != owner.run_id
            || run_status != "Running"
            || !matches!(sandbox_status.as_str(), "Running" | "Paused")
            || terminated_at.is_some()
            || pid.and_then(|pid| u32::try_from(pid).ok()) != Some(std::process::id())
        {
            return Ok(None);
        }
        let active: Option<String> = row
            .try_get("", "active_config")
            .map_err(|_| invalid("invalid live capture configuration"))?;
        let active = active
            .map(|active| {
                serde_json::from_str::<Value>(&active)
                    .map_err(|_| invalid("invalid live capture configuration document"))
            })
            .transpose()?;
        if active.as_ref() != self.confirmed.source.as_ref() {
            return Ok(None);
        }
        // Another process must not be able to replace a durable journal while this runtime keeps
        // an apparently valid in-memory generation. Never reopen the catalog just to read identity:
        // closing an extra Unix database descriptor would release SQLite's POSIX record locks.
        let Some(record) = RetentionJournal::read(
            self.journal
                .directory
                .parent()
                .ok_or_else(|| invalid("missing capture owner directory"))?,
        )?
        else {
            return Ok(None);
        };
        Ok(record
            .current(owner)
            .is_some_and(|confirmed| {
                confirmed.generation == self.confirmed.generation
                    && confirmed.source == self.confirmed.source
            })
            .then_some(row))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::retention::RetentionOwner;

    struct Fixture {
        directory: tempfile::TempDir,
        db: DbWriteConnection,
        journal: RetentionJournal,
    }

    impl Fixture {
        async fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("catalog.db");
            let db = DbWriteConnection::open(&path, Duration::from_secs(1), Duration::from_secs(1))
                .await
                .unwrap();
            db.execute_unprepared(&format!(
                "CREATE TABLE sandbox (id INTEGER PRIMARY KEY, created_at TEXT, status TEXT, config TEXT, active_config TEXT); \
                 CREATE TABLE run (id INTEGER PRIMARY KEY, sandbox_id INTEGER, started_at TEXT, status TEXT, terminated_at TEXT, pid INTEGER); \
                 INSERT INTO sandbox VALUES (1, 'created', 'Running', '{{\"memory\":999}}', '{{\"memory\":256}}'); \
                 INSERT INTO run VALUES (1, 1, 'started', 'Running', NULL, {});", std::process::id()
            )).await.unwrap();
            let owner = RetentionOwner::for_run(&db, &path, 1, 1, "boot".into())
                .await
                .unwrap();
            let mut journal = RetentionJournal::begin_start(directory.path(), owner).unwrap();
            journal
                .confirm(Some(serde_json::json!({"memory":256})))
                .unwrap();
            Self {
                directory,
                db,
                journal,
            }
        }
    }

    #[tokio::test]
    async fn live_capture_borrows_confirmed_source_and_detects_direct_metadata_changes() {
        let fixture = Fixture::new().await;
        let capture = fixture
            .journal
            .select_live_configuration(&fixture.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            capture.configuration().source.as_ref().unwrap()["memory"],
            256
        );
        // Desired-only edits must never replace last-active evidence.
        fixture
            .db
            .execute_unprepared(
                "UPDATE sandbox SET config = '{\"memory\":1024}', status = 'Paused'",
            )
            .await
            .unwrap();
        assert!(capture.revalidate().await.unwrap());
        assert_eq!(capture.pending_configuration().unwrap()["memory"], 999);
        let later = fixture
            .journal
            .select_live_configuration(&fixture.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(later.pending_configuration().unwrap()["memory"], 1024);
        assert_eq!(
            later.configuration().source.as_ref().unwrap()["memory"],
            256
        );
        fixture
            .db
            .execute_unprepared("UPDATE sandbox SET active_config = '{\"memory\":512}'")
            .await
            .unwrap();
        assert!(!capture.revalidate().await.unwrap());
        assert!(
            fixture
                .journal
                .select_live_configuration(&fixture.db)
                .await
                .unwrap()
                .is_none()
        );
        // A selected source stays immutable even when catalog metadata changes.
        assert_eq!(
            capture.configuration().source.as_ref().unwrap()["memory"],
            256
        );
    }

    #[tokio::test]
    async fn pending_selection_preserves_absence_and_redacts_invalid_documents() {
        let fixture = Fixture::new().await;
        fixture
            .db
            .execute_unprepared("UPDATE sandbox SET config = NULL")
            .await
            .unwrap();
        let selected = fixture
            .journal
            .select_live_configuration(&fixture.db)
            .await
            .unwrap()
            .unwrap();
        assert!(selected.pending_configuration().is_none());
        fixture
            .db
            .execute_unprepared("UPDATE sandbox SET config = 'PRIVATE_INVALID_INTENT'")
            .await
            .unwrap();
        // Later desired edits do not change active provenance or an already selected cut.
        assert!(selected.revalidate().await.unwrap());
        assert!(selected.pending_configuration().is_none());
        let error = fixture
            .journal
            .select_live_configuration(&fixture.db)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("pending capture configuration document"));
        assert!(!error.contains("PRIVATE_INVALID_INTENT"));
    }

    #[tokio::test]
    async fn live_capture_requires_current_process_latest_run_and_original_catalog() {
        let fixture = Fixture::new().await;
        let capture = fixture
            .journal
            .select_live_configuration(&fixture.db)
            .await
            .unwrap()
            .unwrap();
        let cases = [
            (
                "UPDATE run SET pid = NULL".to_owned(),
                format!("UPDATE run SET pid = {}", std::process::id()),
            ),
            (
                "UPDATE run SET pid = -1".into(),
                format!("UPDATE run SET pid = {}", std::process::id()),
            ),
            (
                "UPDATE run SET status = 'Terminated'".into(),
                "UPDATE run SET status = 'Running'".into(),
            ),
            (
                "UPDATE run SET terminated_at = 'ended'".into(),
                "UPDATE run SET terminated_at = NULL".into(),
            ),
            (
                "UPDATE run SET started_at = 'reused'".into(),
                "UPDATE run SET started_at = 'started'".into(),
            ),
            (
                "UPDATE sandbox SET created_at = 'reused'".into(),
                "UPDATE sandbox SET created_at = 'created'".into(),
            ),
            (
                "UPDATE sandbox SET status = 'Starting'".into(),
                "UPDATE sandbox SET status = 'Running'".into(),
            ),
            (
                "UPDATE sandbox SET active_config = NULL".into(),
                "UPDATE sandbox SET active_config = '{\"memory\":256}'".into(),
            ),
        ];
        for (change, undo) in cases {
            fixture.db.execute_unprepared(&change).await.unwrap();
            assert!(!capture.revalidate().await.unwrap(), "{change}");
            fixture.db.execute_unprepared(&undo).await.unwrap();
            assert!(capture.revalidate().await.unwrap());
        }
        fixture
            .db
            .execute_unprepared(
                "INSERT INTO run VALUES (2, 1, 'later', 'Terminated', 'ended', NULL)",
            )
            .await
            .unwrap();
        assert!(!capture.revalidate().await.unwrap());
        fixture
            .db
            .execute_unprepared("DELETE FROM run WHERE id = 2")
            .await
            .unwrap();
        let other = Fixture::new().await;
        // Matching row values in a different database do not establish the selected catalog.
        assert!(
            other
                .journal
                .select_live_configuration(&fixture.db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn live_capture_never_repairs_missing_legacy_or_uncertain_evidence() {
        let mut fixture = Fixture::new().await;
        fixture.journal.begin_modify().unwrap();
        assert!(
            fixture
                .journal
                .select_live_configuration(&fixture.db)
                .await
                .unwrap()
                .is_none()
        );
        fixture.journal.confirm(None).unwrap();
        assert!(
            fixture
                .journal
                .select_live_configuration(&fixture.db)
                .await
                .unwrap()
                .is_none()
        );
        fixture.journal.begin_modify().unwrap();
        fixture
            .journal
            .confirm(Some(serde_json::json!({"memory":256})))
            .unwrap();
        let capture = fixture
            .journal
            .select_live_configuration(&fixture.db)
            .await
            .unwrap()
            .unwrap();
        let journal_path = fixture.directory.path().join("last-active/state.json");
        std::fs::remove_file(&journal_path).unwrap();
        assert!(!capture.revalidate().await.unwrap());
        assert!(!journal_path.exists());
        fixture
            .db
            .execute_unprepared("ALTER TABLE sandbox DROP COLUMN active_config")
            .await
            .unwrap();
        assert!(
            fixture
                .journal
                .select_live_configuration(&fixture.db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !microsandbox_db::catalog::has_column(&fixture.db, "sandbox", "active_config")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn live_capture_redacts_malformed_source_and_checks_durable_generation() {
        let fixture = Fixture::new().await;
        let capture = fixture
            .journal
            .select_live_configuration(&fixture.db)
            .await
            .unwrap()
            .unwrap();
        fixture
            .db
            .execute_unprepared("UPDATE sandbox SET active_config = 'PRIVATE_CONFIG_VALUE'")
            .await
            .unwrap();
        let error = capture.revalidate().await.unwrap_err().to_string();
        assert!(!error.contains("PRIVATE_CONFIG_VALUE"));
        fixture
            .db
            .execute_unprepared("UPDATE sandbox SET active_config = '{\"memory\":256}'")
            .await
            .unwrap();
        let journal_path = fixture.directory.path().join("last-active/state.json");
        let bytes = std::fs::read(&journal_path).unwrap();
        let original: Value = serde_json::from_slice(&bytes).unwrap();
        for (field, value) in [
            ("generation", serde_json::json!(2)),
            ("pending", serde_json::json!("modify")),
            ("uncertain_since", serde_json::json!(1)),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            std::fs::write(&journal_path, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(!capture.revalidate().await.unwrap(), "{field}");
        }
    }
}
