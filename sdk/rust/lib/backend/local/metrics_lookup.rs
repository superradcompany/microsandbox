//! Backend-scoped dual-name metrics lookup. Writers and persisted state are untouched.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use microsandbox_db::entity::{run, sandbox};
use microsandbox_metrics::{IdentifiedMetric, LiveMetric, LiveMetricState, MetricsRegistry};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use super::LocalBackend;
use super::control::identity::{DatabaseIdentity, ProcessIdentity};
use crate::{MicrosandboxError, MicrosandboxResult};

#[cfg(test)]
mod tests;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
pub(super) struct MetricsLookup {
    state: Mutex<LookupState>,
}

#[derive(Default)]
struct LookupState {
    database: Option<DatabaseIdentity>,
    matches: HashMap<i32, CachedMatch>,
}

struct CachedMatch {
    registry: String,
    slot: u32,
    generation: u64,
    created_at_ms: i64,
    started_at_ms: i64,
    sandbox_id: i32,
    catalog_started_at: Option<chrono::NaiveDateTime>,
    process: Option<Arc<ProcessIdentity>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MetricsLookup {
    pub(super) fn bind_database(&self, path: &Path) -> MicrosandboxResult<()> {
        let identity = DatabaseIdentity::capture(path).map_err(metrics_error)?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = &state.database {
            existing.verify().map_err(metrics_error)?;
        } else {
            state.database = Some(identity);
        }
        Ok(())
    }
}

impl LocalBackend {
    /// Every metrics API passes through this catalog- and process-verified lookup.
    pub(crate) async fn verified_metrics(
        &self,
        requested_run: Option<i32>,
        include_exited: bool,
    ) -> MicrosandboxResult<Vec<LiveMetric>> {
        let pools = self.db().await?;
        let models = microsandbox_db::catalog::sandbox_query(pools.read())
            .await?
            .all(pools.read())
            .await?;
        let mut query = run::Entity::find();
        if let Some(id) = requested_run {
            query = query.filter(run::Column::Id.eq(id));
        }
        let runs: HashMap<_, _> = query
            .all(pools.read())
            .await?
            .into_iter()
            .map(|run| (run.id, run))
            .collect();
        let models: HashMap<_, _> = models.into_iter().map(|model| (model.id, model)).collect();
        let mut state = self
            .metrics_lookup
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let database = state
            .database
            .as_ref()
            .ok_or_else(|| metrics_error("unbound metrics catalog"))?;
        if let Err(error) = database.verify() {
            state.matches.clear();
            return Err(metrics_error(error));
        }
        let mut found = HashMap::new();
        let mut output: Vec<LiveMetric> = Vec::new();
        for name in &self.metrics_registry_names {
            // Reopen by name even for a cached match: retaining a mapping alone
            // would keep reading an unlinked/replaced registry indefinitely.
            let registry = match MetricsRegistry::open(name) {
                Ok(registry) => registry,
                Err(microsandbox_metrics::MetricsError::Io(error))
                    if crate::sandbox::metrics::is_missing_registry_io_error(&error) =>
                {
                    continue;
                }
                Err(error) => return Err(metrics_error(error)),
            };
            let cached = requested_run
                .and_then(|id| state.matches.get(&id))
                .filter(|entry| entry.registry == *name)
                .and_then(|entry| registry.identified_at(entry.slot, include_exited))
                .filter(|sample| Some(sample.metric.run_id) == requested_run);
            // A cache hit is a slot hint, never an authority. A changed slot still
            // falls back to searching the registry and is validated below.
            let mut samples = registry.identified_snapshot(include_exited);
            if let Some(cached) = cached
                && let Some(index) = samples.iter().position(|sample| sample.slot == cached.slot)
            {
                // Prefer the successful slot, but keep searching if its process
                // identity no longer verifies. A hint cannot suppress fallback.
                samples.swap(0, index);
            }
            for sample in samples {
                let live = &sample.metric;
                if requested_run.is_some_and(|id| live.run_id != id)
                    || found
                        .get(&live.run_id)
                        .is_some_and(|active| *active || live.state != LiveMetricState::Active)
                    || !sample_matches(&sample, &runs, &models)
                {
                    continue;
                }
                let run = &runs[&live.run_id];
                let process = if live.state == LiveMetricState::Active {
                    if run.status != run::RunStatus::Running {
                        continue;
                    }
                    let cached = state
                        .matches
                        .get(&live.run_id)
                        .filter(|entry| {
                            entry.registry == *name
                                && entry.slot == sample.slot
                                && entry.generation == sample.generation
                                && entry.created_at_ms == sample.registry_created_at_ms
                                && entry.started_at_ms == sample.started_at_ms
                                && entry.sandbox_id == live.sandbox_id
                                && entry.catalog_started_at == run.started_at
                        })
                        .and_then(|entry| entry.process.clone());
                    let process = match cached {
                        Some(process) => process,
                        None => match ProcessIdentity::capture(live.pid) {
                            Ok(process) => Arc::new(process),
                            Err(_) => continue,
                        },
                    };
                    if process.verify_peer(live.pid).is_err()
                        || run
                            .started_at
                            .is_some_and(|started| !process.started_by(started))
                    {
                        state.matches.remove(&live.run_id);
                        continue;
                    }
                    Some(process)
                } else {
                    // Terminal samples have no live OS process to inspect. Their
                    // catalog identity and activation time must still match.
                    None
                };
                state.matches.insert(
                    live.run_id,
                    CachedMatch {
                        registry: name.clone(),
                        slot: sample.slot,
                        generation: sample.generation,
                        created_at_ms: sample.registry_created_at_ms,
                        started_at_ms: sample.started_at_ms,
                        sandbox_id: live.sandbox_id,
                        catalog_started_at: run.started_at,
                        process,
                    },
                );
                // Active samples beat stale duplicates across either name. When
                // states tie, the normalized registry encountered first wins.
                found.insert(live.run_id, live.state == LiveMetricState::Active);
                if let Some(existing) = output.iter_mut().find(|item| item.run_id == live.run_id) {
                    *existing = sample.metric;
                } else {
                    output.push(sample.metric);
                }
            }
        }
        if let Some(id) = requested_run {
            if !found.contains_key(&id) {
                state.matches.remove(&id);
            }
        } else {
            state.matches.retain(|id, _| found.contains_key(id));
        }
        // Bound reader memory independently of historical catalog size. Eviction
        // changes only lookup cost; it does not release slots or cache misses.
        if state.matches.len() > 4096 {
            state.matches.clear();
        }
        state
            .database
            .as_ref()
            .unwrap()
            .verify()
            .map_err(metrics_error)?;
        Ok(output)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn sample_matches(
    sample: &IdentifiedMetric,
    runs: &HashMap<i32, run::Model>,
    models: &HashMap<i32, sandbox::Model>,
) -> bool {
    let live = &sample.metric;
    let Some(run) = runs.get(&live.run_id) else {
        return false;
    };
    let Some(model) = models.get(&live.sandbox_id) else {
        return false;
    };
    run.sandbox_id == live.sandbox_id
        && run.pid == Some(live.pid)
        && live.pid > 0
        && model.name == live.name
        && run
            .started_at
            .is_none_or(|start| sample.started_at_ms >= start.and_utc().timestamp_millis())
        && run
            .terminated_at
            .is_none_or(|end| sample.started_at_ms <= end.and_utc().timestamp_millis())
}

fn metrics_error(error: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::Custom(format!("metrics lookup: {error}"))
}
