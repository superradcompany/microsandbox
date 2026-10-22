//! Persistence and failure boundaries exercised without a VM.

use std::time::Duration;

use microsandbox_protocol::control::ErrorEffect;

use super::*;
use crate::retention::RetentionOwner;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct Fixture {
    directory: tempfile::TempDir,
    db: DbWriteConnection,
    journal: RetentionJournal,
    before: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.db");
        let db = DbWriteConnection::open(&path, Duration::from_secs(1), Duration::from_secs(1))
            .await
            .unwrap();
        let before = r#"{"labels":{"remove":"old"},"private":"PRIVATE_SOURCE"}"#.to_owned();
        db.execute_unprepared(&format!(
            "CREATE TABLE sandbox (id INTEGER PRIMARY KEY, created_at TEXT, status TEXT, config TEXT, active_config TEXT, updated_at TEXT); \
             CREATE TABLE sandbox_labels (sandbox_id INTEGER, key TEXT, value TEXT, PRIMARY KEY(sandbox_id,key)); \
             CREATE TABLE run (id INTEGER PRIMARY KEY, sandbox_id INTEGER, started_at TEXT, status TEXT, terminated_at TEXT, pid INTEGER); \
             INSERT INTO sandbox VALUES (1, 'created', 'Running', '{{}}', '{before}', NULL); \
             INSERT INTO run VALUES (1, 1, 'started', 'Running', NULL, {});", std::process::id()
        )).await.unwrap();
        let owner = RetentionOwner::for_run(&db, &path, 1, 1, "boot".into())
            .await
            .unwrap();
        let mut journal = RetentionJournal::begin_start(directory.path(), owner).unwrap();
        journal
            .confirm(Some(serde_json::from_str(&before).unwrap()))
            .unwrap();
        Self {
            directory,
            db,
            journal,
            before,
        }
    }
    fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.before.as_bytes()))
    }
    async fn active(&self) -> String {
        self.db
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT active_config FROM sandbox WHERE id = 1",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "active_config")
            .unwrap()
    }
    async fn apply(&mut self) -> Result<(), ControlError> {
        let digest = self.digest();
        update_labels(
            &mut self.journal,
            &self.db,
            &digest,
            r#"{"labels":{"added":"PRIVATE_LABEL"},"pending":"PRIVATE_PENDING"}"#,
            &BTreeMap::from([("added".into(), "PRIVATE_LABEL".into())]),
            &["remove".into()],
        )
        .await
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn label_update_commits_desired_active_and_index_with_confirmation() {
    let mut f = Fixture::new().await;
    let generation = f.journal.record().generation;
    f.apply().await.unwrap();
    let after: Value = serde_json::from_str(&f.active().await).unwrap();
    assert_eq!(
        after["labels"],
        serde_json::json!({"added":"PRIVATE_LABEL"})
    );
    assert_eq!(after["private"], "PRIVATE_SOURCE");
    let record = RetentionJournal::read(f.directory.path()).unwrap().unwrap();
    assert_eq!(record.generation, generation + 1);
    assert_eq!(record.current(&record.owner).unwrap().source, Some(after));
    assert!(
        f.journal
            .select_live_configuration(&f.db)
            .await
            .unwrap()
            .is_some()
    );
    let desired: String =
        f.db.query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT config FROM sandbox",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "config")
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&desired).unwrap(),
        serde_json::json!({"labels":{"added":"PRIVATE_LABEL"},"pending":"PRIVATE_PENDING"})
    );
    let labels =
        f.db.query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT key,value FROM sandbox_labels",
        ))
        .await
        .unwrap();
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0].try_get::<String>("", "key").unwrap(), "added");
    assert_eq!(
        labels[0].try_get::<String>("", "value").unwrap(),
        "PRIVATE_LABEL"
    );
}

#[tokio::test]
async fn label_update_does_not_certify_an_older_writers_other_changes() {
    let mut f = Fixture::new().await;
    f.before = r#"{"labels":{},"private":"OTHER_WRITER"}"#.into();
    f.db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "UPDATE sandbox SET active_config = ?",
        [f.before.clone().into()],
    ))
    .await
    .unwrap();
    f.apply().await.unwrap();
    assert!(
        f.journal
            .record()
            .confirmed
            .as_ref()
            .unwrap()
            .source
            .is_none()
    );
    assert!(
        f.journal
            .select_live_configuration(&f.db)
            .await
            .unwrap()
            .is_none()
    );
    f.before = f.active().await;
    f.apply().await.unwrap();
    assert!(
        f.journal
            .record()
            .confirmed
            .as_ref()
            .unwrap()
            .source
            .is_none()
    );
}

#[tokio::test]
async fn label_update_refuses_stale_active_record_or_run_before_transition() {
    for sql in [
        "UPDATE sandbox SET active_config = '{}'",
        "UPDATE sandbox SET created_at = 'replaced'",
        "UPDATE run SET pid = -1",
        "UPDATE run SET status = 'Terminated'",
        "INSERT INTO run VALUES (2,1,'later','Terminated','ended',NULL)",
    ] {
        let mut f = Fixture::new().await;
        f.db.execute_unprepared(sql).await.unwrap();
        let before = f.active().await;
        let generation = f.journal.record().generation;
        let error = f.apply().await.unwrap_err();
        assert_eq!(error.effect, ErrorEffect::None);
        assert_eq!(f.active().await, before);
        assert_eq!(f.journal.record().generation, generation);
    }
}

#[tokio::test]
async fn label_confirmation_failure_reports_unknown_without_repeating_the_write() {
    let mut f = Fixture::new().await;
    let digest = f.digest();
    let error = update_labels_with(
        &mut f.journal,
        &f.db,
        &digest,
        r#"{"labels":{"added":"PRIVATE_LABEL"},"pending":"PRIVATE_PENDING"}"#,
        &BTreeMap::from([("added".into(), "PRIVATE_LABEL".into())]),
        &[],
        |_, _| Err(std::io::Error::other("PRIVATE_FAILURE")),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "configuration_outcome_unknown");
    assert_eq!(error.effect, ErrorEffect::Unknown);
    assert!(!format!("{error:?}").contains("PRIVATE"));
    assert!(f.active().await.contains("PRIVATE_LABEL"));
    assert!(f.journal.record().pending.is_some());
    assert!(
        f.journal
            .record()
            .current(&f.journal.record().owner)
            .is_none()
    );
    assert!(
        RetentionJournal::read(f.directory.path())
            .unwrap()
            .unwrap()
            .pending
            .is_some()
    );
}

#[tokio::test]
async fn label_database_failure_retains_the_uncertainty_fence_and_redacts_diagnostics() {
    let mut f = Fixture::new().await;
    f.db.execute_unprepared("CREATE TRIGGER refuse_labels BEFORE UPDATE ON sandbox BEGIN SELECT RAISE(ABORT, 'PRIVATE_SQL'); END;").await.unwrap();
    let error = f.apply().await.unwrap_err();
    assert_eq!(error.effect, ErrorEffect::Unknown);
    assert!(!format!("{error:?}").contains("PRIVATE"));
    assert_eq!(f.active().await, f.before);
    assert!(f.journal.record().pending.is_some());
}

#[cfg(unix)]
#[tokio::test]
async fn label_update_requires_a_durable_transition_before_the_catalog_effect() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = Fixture::new().await;
    let directory = f.directory.path().join("last-active");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = f.apply().await;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.code, "configuration_not_applied");
    assert_eq!(error.effect, ErrorEffect::None);
    assert_eq!(f.active().await, f.before);
    assert!(f.journal.record().pending.is_none());
}

#[tokio::test]
async fn label_index_failure_rolls_back_desired_and_active_together() {
    let mut f = Fixture::new().await;
    f.db.execute_unprepared("CREATE TRIGGER refuse_index BEFORE INSERT ON sandbox_labels BEGIN SELECT RAISE(ABORT, 'PRIVATE_INDEX'); END;").await.unwrap();
    let error = f.apply().await.unwrap_err();
    assert_eq!(error.effect, ErrorEffect::Unknown);
    assert!(!format!("{error:?}").contains("PRIVATE"));
    assert_eq!(f.active().await, f.before);
    let desired: String =
        f.db.query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT config FROM sandbox",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "config")
        .unwrap();
    assert_eq!(desired, "{}");
    assert!(f.journal.record().pending.is_some());
}

#[tokio::test]
async fn compact_label_update_preserves_large_scripts_and_commits_mixed_desired_changes() {
    let mut f = Fixture::new().await;
    let before = serde_json::json!({"runtime":{"scripts":{"large":"x".repeat(5 * 1024 * 1024)}},"labels":{"remove":"old"},"pending":false}).to_string();
    f.db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "UPDATE sandbox SET config = ?",
        [before.clone().into()],
    ))
    .await
    .unwrap();
    let mut after: Value = serde_json::from_str(&before).unwrap();
    after["labels"] = serde_json::json!({"added":"PRIVATE_LABEL"});
    after["pending"] = Value::Null;
    let delta = microsandbox_protocol::labels_delta::between(&before, &after.to_string()).unwrap();
    assert!(delta.len() < 1024);
    let expected_desired = hex::encode(Sha256::digest(before.as_bytes()));
    let digest = f.digest();
    update_labels_plan(
        &mut f.journal,
        &f.db,
        &digest,
        DesiredConfig::Delta {
            expected: &expected_desired,
            encoded: &delta,
        },
        &BTreeMap::from([("added".into(), "PRIVATE_LABEL".into())]),
        &["remove".into()],
        |journal, source| journal.confirm(source),
    )
    .await
    .unwrap();
    let actual: String =
        f.db.query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT config FROM sandbox",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "config")
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&actual).unwrap(), after);
    assert_eq!(
        serde_json::from_str::<Value>(&f.active().await).unwrap()["labels"],
        after["labels"]
    );
}

#[tokio::test]
async fn compact_label_update_refuses_changed_desired_state_before_journaling() {
    let mut f = Fixture::new().await;
    let generation = f.journal.record().generation;
    let delta = microsandbox_protocol::labels_delta::between(
        "{}",
        r#"{"labels":{"added":"PRIVATE_LABEL"}}"#,
    )
    .unwrap();
    f.db.execute_unprepared(r#"UPDATE sandbox SET config = '{"other":true}'"#)
        .await
        .unwrap();
    let digest = f.digest();
    let expected = hex::encode(Sha256::digest(b"{}"));
    let error = update_labels_plan(
        &mut f.journal,
        &f.db,
        &digest,
        DesiredConfig::Delta {
            expected: &expected,
            encoded: &delta,
        },
        &BTreeMap::from([("added".into(), "PRIVATE_LABEL".into())]),
        &[],
        |journal, source| journal.confirm(source),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "configuration_not_applied");
    assert_eq!(f.journal.record().generation, generation);
    assert_eq!(f.active().await, f.before);
}
