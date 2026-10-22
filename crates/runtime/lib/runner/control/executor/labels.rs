//! Runtime-owned active-label changes under the existing mutation authority.

use std::collections::BTreeMap;
use std::path::Path;

use microsandbox_db::DbWriteConnection;
use microsandbox_protocol::control::ControlError;
use microsandbox_protocol::labels::{LabelsRequest, LabelsResponse};
use sea_orm::{ActiveValue::Set, ConnectionTrait, DbBackend, DbErr, EntityTrait, Statement};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::RuntimeControlExecutor;
use crate::control::RuntimeLifecycle;
use crate::retention::{RetentionJournal, RetentionTransition, catalog_file_identity};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

enum DesiredConfig<'a> {
    Complete(&'a str),
    Delta { expected: &'a str, encoded: &'a str },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeControlExecutor {
    pub(crate) fn labels_request(
        &self,
        request: LabelsRequest,
    ) -> Result<LabelsResponse, ControlError> {
        let mut state = self.state.lock().unwrap();
        let runtime_boot_id = state.runtime_boot_id.clone();
        let (expected_boot, expected_active_sha256, desired, set, remove) = match &request {
            LabelsRequest::Hello => {
                return Ok(LabelsResponse::Supported {
                    runtime_boot_id,
                    config_delta: true,
                });
            }
            LabelsRequest::Update {
                runtime_boot_id,
                expected_active_sha256,
                desired_config_json,
                set,
                remove,
            } => (
                runtime_boot_id,
                expected_active_sha256,
                DesiredConfig::Complete(desired_config_json),
                set,
                remove,
            ),
            LabelsRequest::UpdateDelta {
                runtime_boot_id,
                expected_active_sha256,
                expected_desired_sha256,
                desired_delta_json,
                set,
                remove,
            } => (
                runtime_boot_id,
                expected_active_sha256,
                DesiredConfig::Delta {
                    expected: expected_desired_sha256,
                    encoded: desired_delta_json,
                },
                set,
                remove,
            ),
            _ => {
                return Err(error(
                    "unsupported_operation",
                    "unsupported label operation",
                ));
            }
        };
        if expected_boot != &runtime_boot_id {
            return Err(error(
                "runtime_changed",
                "label update belongs to another runtime",
            ));
        }
        if state.lifecycle != RuntimeLifecycle::Running
            || state.retention.record().pending == Some(RetentionTransition::Start)
        {
            return Err(error(
                "runtime_busy",
                "runtime cannot currently accept label updates",
            ));
        }
        let revision = state.revision.checked_add(1).ok_or_else(|| {
            error(
                "revision_exhausted",
                "runtime mutation revision is exhausted",
            )
        })?;
        let result = self.signal_runtime.block_on(update_labels_plan(
            &mut state.retention,
            &self.retention_db,
            expected_active_sha256,
            desired,
            set,
            remove,
            |journal, source| journal.confirm(source),
        ));
        // Confirmation can fail after the catalog effect; fence subsequent mutations
        // with the advanced revision even when the caller receives an uncertain result.
        if result.is_ok()
            || result
                .as_ref()
                .is_err_and(|e| e.code == "configuration_outcome_unknown")
        {
            state.revision = revision;
        }
        result?;
        Ok(LabelsResponse::Updated {
            runtime_boot_id,
            generation: state.retention.record().generation,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
async fn update_labels(
    journal: &mut RetentionJournal,
    db: &DbWriteConnection,
    expected: &str,
    desired_config_json: &str,
    set: &BTreeMap<String, String>,
    remove: &[String],
) -> Result<(), ControlError> {
    update_labels_with(
        journal,
        db,
        expected,
        desired_config_json,
        set,
        remove,
        |journal, source| journal.confirm(source),
    )
    .await
}

#[cfg(test)]
async fn update_labels_with(
    journal: &mut RetentionJournal,
    db: &DbWriteConnection,
    expected: &str,
    desired_config_json: &str,
    set: &BTreeMap<String, String>,
    remove: &[String],
    confirm: impl FnOnce(&mut RetentionJournal, Option<Value>) -> std::io::Result<()>,
) -> Result<(), ControlError> {
    update_labels_plan(
        journal,
        db,
        expected,
        DesiredConfig::Complete(desired_config_json),
        set,
        remove,
        confirm,
    )
    .await
}

async fn update_labels_plan(
    journal: &mut RetentionJournal,
    db: &DbWriteConnection,
    expected: &str,
    desired_plan: DesiredConfig<'_>,
    set: &BTreeMap<String, String>,
    remove: &[String],
    confirm: impl FnOnce(&mut RetentionJournal, Option<Value>) -> std::io::Result<()>,
) -> Result<(), ControlError> {
    // Match existing SDK rules: reserved keys may be removed to repair an old record.
    if set.keys().any(|key| {
        key.is_empty()
            || ["sandbox.", "microsandbox.", "service."]
                .iter()
                .any(|prefix| key.starts_with(prefix))
            || remove.contains(key)
    }) || expected.len() != 64
        || !expected.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(error("invalid_request", "invalid label update"));
    }
    let owner = journal.record().owner.clone();
    let file = db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
        ))
        .await
        .map_err(|_| error("configuration_not_applied", "cannot identify label catalog"))?
        .ok_or_else(|| error("runtime_changed", "label catalog is unavailable"))?;
    let path: String = file
        .try_get("", "file")
        .map_err(|_| error("runtime_changed", "label catalog is unavailable"))?;
    if catalog_file_identity(Path::new(&path)).ok() != Some(owner.catalog_file) {
        return Err(error("runtime_changed", "label catalog identity changed"));
    }
    // One atomic compare-and-set below repeats these predicates. Old catalog writers,
    // new run rows and same-name replacements cannot redirect this runtime's mutation.
    let predicate = "s.id = ? AND s.created_at IS ? AND s.status IN ('Running', 'Draining') \
        AND EXISTS (SELECT 1 FROM run r WHERE r.sandbox_id = s.id AND r.id = ? \
        AND r.started_at = ? AND r.status = 'Running' AND r.terminated_at IS NULL \
        AND r.pid = ? AND r.id = (SELECT MAX(id) FROM run WHERE sandbox_id = s.id))";
    let identity: Vec<sea_orm::Value> = vec![
        owner.sandbox_id.into(),
        owner.sandbox_created_at.clone().into(),
        owner.run_id.into(),
        owner.run_started_at.clone().into(),
        (std::process::id() as i64).into(),
    ];
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            format!("SELECT s.active_config, s.config FROM sandbox s WHERE {predicate}"),
            identity.clone(),
        ))
        .await
        .map_err(|_| {
            error(
                "configuration_not_applied",
                "cannot read active label configuration",
            )
        })?
        .ok_or_else(|| {
            error(
                "runtime_changed",
                "label update no longer owns the active run",
            )
        })?;
    let before: Option<String> = row.try_get("", "active_config").map_err(|_| {
        error(
            "configuration_not_applied",
            "cannot read active label configuration",
        )
    })?;
    let before = before.ok_or_else(|| {
        error(
            "configuration_not_applied",
            "active label configuration is unavailable",
        )
    })?;
    if hex::encode(Sha256::digest(before.as_bytes())) != expected {
        return Err(error(
            "configuration_not_applied",
            "active configuration changed before label update",
        ));
    }
    // Resolve against the exact desired document selected by the SDK, not a typed
    // reconstruction. The transaction repeats this guard so old writers cannot be lost.
    let (desired_config_json, desired_before) = match desired_plan {
        DesiredConfig::Complete(json) => (json.to_owned(), None),
        DesiredConfig::Delta { expected, encoded } => {
            let before: String = row.try_get("", "config").map_err(|_| {
                error(
                    "configuration_not_applied",
                    "cannot read desired configuration",
                )
            })?;
            if hex::encode(Sha256::digest(before.as_bytes())) != expected {
                return Err(error(
                    "configuration_not_applied",
                    "desired configuration changed before label update",
                ));
            }
            let json = microsandbox_protocol::labels_delta::apply(&before, encoded)
                .map_err(|_| error("invalid_request", "invalid desired configuration delta"))?;
            (json, Some(before))
        }
    };
    // Keep the existing SDK transaction boundary: the full validated desired plan,
    // active label delta and index are committed together, even for mixed modifications.
    let desired: Value = serde_json::from_str(&desired_config_json)
        .map_err(|_| error("invalid_request", "invalid desired label configuration"))?;
    let object = desired
        .as_object()
        .ok_or_else(|| error("invalid_request", "invalid desired label configuration"))?;
    let indexed_labels: BTreeMap<String, String> = match object.get("labels") {
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|_| error("invalid_request", "invalid desired labels"))?,
        None => BTreeMap::new(),
    };
    if set
        .iter()
        .any(|(key, value)| indexed_labels.get(key) != Some(value))
        || remove.iter().any(|key| indexed_labels.contains_key(key))
    {
        return Err(error(
            "invalid_request",
            "desired labels do not match label update",
        ));
    }
    let mut after: Value = serde_json::from_str(&before).map_err(|_| {
        error(
            "configuration_not_applied",
            "invalid active label configuration",
        )
    })?;
    let object = after.as_object_mut().ok_or_else(|| {
        error(
            "configuration_not_applied",
            "invalid active label configuration",
        )
    })?;
    let labels = object
        .entry("labels")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| error("configuration_not_applied", "invalid active labels"))?;
    for (key, value) in set {
        labels.insert(key.clone(), value.clone().into());
    }
    for key in remove {
        labels.remove(key);
    }
    let after_json = serde_json::to_string(&after)
        .map_err(|_| error("configuration_not_applied", "cannot encode updated labels"))?;
    // A valid catalog value is not evidence that an old writer's other settings were
    // applied. Preserve unknown source unless the journal/catalog provenance agrees.
    let known = journal
        .select_live_configuration(db)
        .await
        .map_err(|_| {
            error(
                "configuration_not_applied",
                "cannot validate retained label source",
            )
        })?
        .is_some();
    journal.begin_modify().map_err(|_| {
        error(
            "configuration_not_applied",
            "label change refused before application: cannot record configuration transition",
        )
    })?;
    let mut values = vec![after_json.into(), desired_config_json.to_owned().into()];
    values.extend(identity);
    values.push(before.into());
    let desired_predicate = if let Some(before) = desired_before {
        values.push(before.into());
        " AND s.config = ?"
    } else {
        ""
    };
    let changed: Result<bool, DbErr> = db.transaction(|txn| {
        let values = values.clone();
        let indexed_labels = indexed_labels.clone();
        let predicate = predicate.to_owned();
        async move {
            let changed = txn.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
                format!("UPDATE sandbox AS s SET active_config = ?, config = ?, updated_at = CURRENT_TIMESTAMP WHERE {predicate} AND s.active_config = ?{desired_predicate}"), values)).await?;
            if changed.rows_affected() != 1 {
                return Ok((txn, false));
            }
            txn.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
                "DELETE FROM sandbox_labels WHERE sandbox_id = ?", [owner.sandbox_id.into()])).await?;
            if !indexed_labels.is_empty() {
                use microsandbox_db::entity::sandbox_label;
                sandbox_label::Entity::insert_many(indexed_labels.into_iter().map(|(key, value)| sandbox_label::ActiveModel {
                    sandbox_id: Set(owner.sandbox_id), key: Set(key), value: Set(value),
                })).exec(&txn).await?;
            }
            Ok((txn, true))
        }
    }).await;
    let changed = changed.map_err(|_| {
        error(
            "configuration_outcome_unknown",
            "label catalog transaction failed; outcome uncertain; runtime remains running",
        )
    })?;
    if !changed {
        return Err(error(
            "configuration_not_applied",
            "active run changed before label publication",
        ));
    }
    confirm(journal, known.then_some(after)).map_err(|_| {
        error(
            "configuration_outcome_unknown",
            "labels applied but durable confirmation failed; runtime remains running",
        )
    })?;
    Ok(())
}

fn error(code: &str, message: &str) -> ControlError {
    let mut error = ControlError::rejected(code, message);
    if code == "configuration_outcome_unknown" {
        error.effect = microsandbox_protocol::control::ErrorEffect::Unknown;
    }
    error
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
#[path = "labels_tests.rs"]
mod tests;
