//! Select local stopped-source evidence independently of the journal's claimed owner.

use std::{io, path::Path};

use microsandbox_db::DbWriteConnection;
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde_json::Value;

use super::{RetainedConfiguration, RetentionJournal, RetentionOwner, invalid};
use crate::ipc::SandboxLifecycleGuard;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Select confirmed configuration for the latest, terminated run while retaining lifecycle
/// ownership. `None` means unknown; it never means an empty/default configuration.
///
/// The caller must hold the supplied guard for this sandbox through disk capture. This proves
/// configuration provenance, not that disk ownership has drained or backing is capture-ready.
/// The returned local source can contain sensitive values and must never enter an archive
/// without the portable saved-config projection and exclusion checks.
pub async fn select_stopped_configuration(
    db: &DbWriteConnection,
    sandbox_directory: &Path,
    sandbox_id: i32,
    _lifecycle_guard: &SandboxLifecycleGuard,
) -> io::Result<Option<RetainedConfiguration>> {
    let Some(record) = RetentionJournal::read(sandbox_directory)? else {
        return Ok(None);
    };
    let Some(terminal) = RetentionJournal::read_terminal(sandbox_directory)? else {
        return Ok(None);
    };
    // Select the latest run before checking its terminal state. Filtering to terminal runs
    // first would resurrect an older receipt while a later start is pending or has failed.
    let Some(row) = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT r.id AS run_id, r.pid, r.status AS run_status, r.terminated_at, \
             s.status AS sandbox_status FROM sandbox s JOIN run r ON r.sandbox_id = s.id \
             WHERE s.id = ? ORDER BY r.id DESC LIMIT 1",
            [sandbox_id.into()],
        ))
        .await
        .map_err(|_| invalid("could not read latest retention run"))?
    else {
        return Ok(None);
    };
    let run_id: i32 = row
        .try_get("", "run_id")
        .map_err(|_| invalid("invalid latest retention run"))?;
    let run_status: String = row
        .try_get("", "run_status")
        .map_err(|_| invalid("invalid retention run status"))?;
    let sandbox_status: String = row
        .try_get("", "sandbox_status")
        .map_err(|_| invalid("invalid retention sandbox status"))?;
    let terminated_at: Option<String> = row
        .try_get("", "terminated_at")
        .map_err(|_| invalid("invalid retention termination evidence"))?;
    let pid: Option<i32> = row
        .try_get("", "pid")
        .map_err(|_| invalid("invalid retention process identity"))?;
    if record.owner.sandbox_id != sandbox_id
        || record.owner.run_id != run_id
        || run_status != "Terminated"
        || !matches!(sandbox_status.as_str(), "Stopped" | "Crashed")
        || terminated_at.is_none()
        || pid.is_some_and(|pid| pid <= 0 || microsandbox_utils::process::pid_is_alive(pid))
    {
        return Ok(None);
    }

    let catalog = db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
        ))
        .await
        .map_err(|_| invalid("could not identify retention catalog"))?
        .ok_or_else(|| invalid("retention catalog is missing"))?;
    let path: String = catalog
        .try_get("", "file")
        .map_err(|_| invalid("invalid retention catalog path"))?;
    if path.is_empty() {
        return Ok(None);
    }
    let owner = RetentionOwner::for_run(
        db,
        Path::new(&path),
        sandbox_id,
        run_id,
        record.owner.runtime_boot_id.clone(),
    )
    .await?;
    let Some(confirmed) = terminal.current(&owner, &record) else {
        return Ok(None);
    };

    // A legacy SDK may still write active_config directly. A surviving contradictory value
    // must invalidate the receipt; desired config is deliberately never read here.
    if microsandbox_db::catalog::has_column(db, "sandbox", "active_config")
        .await
        .map_err(|_| invalid("could not inspect active configuration support"))?
    {
        let row = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT active_config FROM sandbox WHERE id = ?",
                [sandbox_id.into()],
            ))
            .await
            .map_err(|_| invalid("could not read retained configuration provenance"))?
            .ok_or_else(|| invalid("retention sandbox is missing"))?;
        let active: Option<String> = row
            .try_get("", "active_config")
            .map_err(|_| invalid("invalid retained configuration provenance"))?;
        if let Some(active) = active {
            let active: Value = serde_json::from_str(&active)
                .map_err(|_| invalid("invalid retained configuration document"))?;
            if confirmed.source.as_ref() != Some(&active) {
                return Ok(None);
            }
        }
    }
    Ok(Some(confirmed.clone()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention::{RetentionTerminalOrigin, seal_terminal};

    struct Fixture {
        directory: tempfile::TempDir,
        db: DbWriteConnection,
        guard: SandboxLifecycleGuard,
    }

    impl Fixture {
        async fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let db = DbWriteConnection::open(
                &directory.path().join("catalog.db"),
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
            db.execute_unprepared(
                "CREATE TABLE sandbox (id INTEGER PRIMARY KEY, created_at TEXT, status TEXT, \
                 config TEXT, active_config TEXT);
                 CREATE TABLE run (id INTEGER PRIMARY KEY, sandbox_id INTEGER, started_at TEXT, \
                 status TEXT, terminated_at TEXT, pid INTEGER);
                 INSERT INTO sandbox VALUES (1, 'created', 'Stopped', \
                 '{\"resources\":{\"memory_mib\":999}}', '{\"resources\":{\"memory_mib\":256}}');
                 INSERT INTO run VALUES (1, 1, 'started', 'Terminated', 'ended', NULL);",
            )
            .await
            .unwrap();
            let guard = crate::ipc::try_acquire_lifecycle_guard(directory.path(), "source")
                .unwrap()
                .unwrap();
            let owner = RetentionOwner::for_run(
                &db,
                &directory.path().join("catalog.db"),
                1,
                1,
                "boot".into(),
            )
            .await
            .unwrap();
            let mut journal = RetentionJournal::begin_start(directory.path(), owner).unwrap();
            journal
                .confirm(Some(serde_json::json!({"resources": {"memory_mib": 256}})))
                .unwrap();
            seal_terminal(
                &db,
                directory.path(),
                1,
                1,
                Some("boot"),
                RetentionTerminalOrigin::RuntimeExit,
            )
            .await
            .unwrap();
            db.execute_unprepared("UPDATE sandbox SET active_config = NULL")
                .await
                .unwrap();
            Self {
                directory,
                db,
                guard,
            }
        }

        async fn select(&self) -> io::Result<Option<RetainedConfiguration>> {
            select_stopped_configuration(&self.db, self.directory.path(), 1, &self.guard).await
        }
    }

    /// An external lifecycle harness owns the disposable VM and invokes this exact test
    /// after shutdown. No production diagnostics expose raw retained configuration.
    #[tokio::test]
    #[ignore = "requires an isolated stopped sandbox from the live retention harness"]
    async fn live_stopped_selection() {
        let home = std::path::PathBuf::from(
            std::env::var_os("MSB_TEST_STOPPED_SELECTION_HOME").expect("live test home"),
        );
        let expected = std::env::var("MSB_TEST_STOPPED_SELECTION_EXPECT").unwrap();
        assert!(matches!(expected.as_str(), "known" | "unknown"));
        let db = DbWriteConnection::open(
            &home.join("db/msb.db"),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        let row = db
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT id FROM sandbox WHERE name = 'rt'",
            ))
            .await
            .unwrap()
            .unwrap();
        let id: i32 = row.try_get("", "id").unwrap();
        let guard = crate::ipc::try_acquire_lifecycle_guard(
            &home.join(microsandbox_utils::RUN_SUBDIR),
            "rt",
        )
        .unwrap()
        .expect("source must have released lifecycle ownership");
        let selected = select_stopped_configuration(
            &db,
            &home.join(microsandbox_utils::SANDBOXES_SUBDIR).join("rt"),
            id,
            &guard,
        )
        .await
        .unwrap();
        assert_eq!(selected.is_some(), expected == "known");
        if let Ok(expected_init) = std::env::var("MSB_TEST_STOPPED_INIT_EXPECT") {
            let init = selected
                .as_ref()
                .map(|source| {
                    super::super::read_retained_init(
                        &home.join(microsandbox_utils::SANDBOXES_SUBDIR).join("rt"),
                        source,
                    )
                })
                .transpose()
                .unwrap()
                .flatten();
            let expected_init: Option<microsandbox_protocol::init_observation::InitObservation> =
                serde_json::from_str(&expected_init).expect("expected init observation JSON");
            assert_eq!(init, expected_init);
        }

        if let Ok(memory) = std::env::var("MSB_TEST_STOPPED_SELECTION_MEMORY") {
            let expected_memory: u64 = memory.parse().unwrap();
            let selected = selected.expect("expected confirmed source");
            assert_eq!(
                selected.source.unwrap()["resources"]["memory_mib"].as_u64(),
                Some(expected_memory)
            );
        }
    }

    #[tokio::test]
    async fn stopped_selection_uses_latest_terminal_owner_not_desired_settings_or_history() {
        let fixture = Fixture::new().await;
        let selected = fixture.select().await.unwrap().unwrap();
        assert_eq!(selected.generation, 1);
        assert_eq!(
            selected.source.unwrap()["resources"]["memory_mib"],
            serde_json::json!(256)
        );

        for status in ["Created", "Starting", "Running", "Draining", "Paused"] {
            fixture
                .db
                .execute_unprepared(&format!("UPDATE sandbox SET status = '{status}'"))
                .await
                .unwrap();
            assert!(fixture.select().await.unwrap().is_none(), "{status}");
        }
        fixture
            .db
            .execute_unprepared("UPDATE sandbox SET status = 'Crashed'")
            .await
            .unwrap();
        assert!(fixture.select().await.unwrap().is_some());
        // A later failed/unsupported start still supersedes the earlier record. Do not
        // pre-filter to successful or terminal runs when selecting the latest owner.
        fixture
            .db
            .execute_unprepared("INSERT INTO run VALUES (2, 1, 'later', 'Running', NULL, NULL)")
            .await
            .unwrap();
        assert!(fixture.select().await.unwrap().is_none());
        fixture
            .db
            .execute_unprepared(
                "UPDATE run SET status = 'Terminated', terminated_at = 'later-ended' WHERE id = 2",
            )
            .await
            .unwrap();
        assert!(fixture.select().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn stopped_selection_rejects_live_pid_unconfirmed_exit_and_reused_rows() {
        let fixture = Fixture::new().await;
        let cases = [
            (
                format!("UPDATE run SET pid = {}", std::process::id()),
                "UPDATE run SET pid = NULL",
            ),
            (
                "UPDATE run SET pid = -1".into(),
                "UPDATE run SET pid = NULL",
            ),
            (
                "UPDATE run SET terminated_at = NULL".into(),
                "UPDATE run SET terminated_at = 'ended'",
            ),
            (
                "UPDATE run SET status = 'Running'".into(),
                "UPDATE run SET status = 'Terminated'",
            ),
            (
                "UPDATE run SET started_at = 'reused'".into(),
                "UPDATE run SET started_at = 'started'",
            ),
            (
                "UPDATE sandbox SET created_at = 'reused'".into(),
                "UPDATE sandbox SET created_at = 'created'",
            ),
            (
                "UPDATE sandbox SET active_config = '{\"resources\":{\"memory_mib\":512}}'".into(),
                "UPDATE sandbox SET active_config = NULL",
            ),
        ];
        for (change, restore) in cases {
            fixture.db.execute_unprepared(&change).await.unwrap();
            assert!(fixture.select().await.unwrap().is_none());
            fixture.db.execute_unprepared(restore).await.unwrap();
            assert!(fixture.select().await.unwrap().is_some());
        }
        // Replacing the catalog with identical rows must not borrow the original file's
        // receipt. VACUUM INTO creates a distinct database identity without changing rows.
        let copy = fixture.directory.path().join("copy.db");
        fixture
            .db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "VACUUM INTO ?",
                [copy.to_string_lossy().into_owned().into()],
            ))
            .await
            .unwrap();
        let copied_db = DbWriteConnection::open(
            &copy,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(
            select_stopped_configuration(&copied_db, fixture.directory.path(), 1, &fixture.guard,)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn stopped_selection_requires_complete_receipt_and_never_repairs_legacy_state() {
        let fixture = Fixture::new().await;
        fixture
            .db
            .execute_unprepared("ALTER TABLE sandbox DROP COLUMN active_config")
            .await
            .unwrap();
        assert!(fixture.select().await.unwrap().is_some());
        assert!(
            !microsandbox_db::catalog::has_column(&fixture.db, "sandbox", "active_config")
                .await
                .unwrap()
        );
        let journal_path = fixture.directory.path().join("last-active/state.json");
        let original = std::fs::read(&journal_path).unwrap();
        let mut record: super::super::RetentionRecord = serde_json::from_slice(&original).unwrap();
        record.pending = Some(super::super::RetentionTransition::Modify);
        std::fs::write(&journal_path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(fixture.select().await.unwrap().is_none());
        std::fs::write(&journal_path, original).unwrap();
        std::fs::remove_file(fixture.directory.path().join("last-active/terminal.json")).unwrap();
        assert!(fixture.select().await.unwrap().is_none());
        assert!(
            !fixture
                .directory
                .path()
                .join("last-active/terminal.json")
                .exists()
        );
        std::fs::write(&journal_path, b"PRIVATE_BAD_DOCUMENT").unwrap();
        let error = fixture.select().await.err().unwrap().to_string();
        assert!(!error.contains("PRIVATE_BAD_DOCUMENT"));
        std::fs::remove_file(journal_path).unwrap();
        assert!(fixture.select().await.unwrap().is_none());
    }
}
