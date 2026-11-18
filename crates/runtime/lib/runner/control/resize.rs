//! Runtime-incarnation-bound resize ownership, independent for CPU and memory.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use microsandbox_protocol::resize::{
    MAX_RETAINED_RESIZES, ResizeObservation, ResizeOperation, ResizeOutcome, ResizeTarget,
    ResizeTracking,
};
use microsandbox_types::modify::ResourceResizeStatus;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct ResizeTracker {
    runtime_boot_id: String,
    observation_fence: Arc<()>,
    generations: [u64; 2],
    latest: [Option<String>; 2],
    records: BTreeMap<String, ResizeOperation>,
    order: VecDeque<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ResizeTracker {
    pub fn new(runtime_boot_id: String) -> Self {
        Self {
            runtime_boot_id,
            observation_fence: Arc::new(()),
            generations: [0, 0],
            latest: [None, None],
            records: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }

    /// An owned token cannot be reused while a query still retains it, avoiding counter ABA.
    pub fn observation_fence(&self) -> Arc<()> {
        Arc::clone(&self.observation_fence)
    }

    pub fn invalidate_observation(&mut self) {
        self.observation_fence = Arc::new(());
    }

    pub fn matches_observation(&self, fence: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.observation_fence, fence)
    }

    pub fn tracking(&self) -> ResizeTracking {
        ResizeTracking {
            runtime_boot_id: self.runtime_boot_id.clone(),
            max_retained: MAX_RETAINED_RESIZES,
        }
    }

    pub fn get(&self, id: &str) -> Option<&ResizeOperation> {
        self.records.get(id)
    }

    pub fn current(&self) -> Vec<ResizeOperation> {
        self.latest
            .iter()
            .flatten()
            .filter_map(|id| self.get(id).cloned())
            .collect()
    }

    /// A retained completion is historical evidence; only unfinished operations lose
    /// their live observation while execution is paused or otherwise unavailable.
    pub fn mark_pending_paused(&mut self) {
        for record in self.records.values_mut() {
            if record.outcome == ResizeOutcome::Pending {
                record.observation = ResizeObservation::Paused;
            }
        }
    }

    /// Must be checked before dispatch. Exhaustion cannot follow an applied mutation.
    pub fn admits(&self, target: &ResizeTarget) -> bool {
        self.generations[index(target)] < u64::MAX
    }

    /// Called under the executor's mutation lock only after the host accepted a setter.
    /// Legacy setters use this same path, including identical numeric targets.
    pub fn accepted(
        &mut self,
        id: String,
        requested_target: ResizeTarget,
        accepted_target: ResizeTarget,
        status: ResourceResizeStatus,
    ) -> ResizeOperation {
        let resource = index(&requested_target);
        self.generations[resource] = self.generations[resource]
            .checked_add(1)
            .expect("resize generation admission must precede dispatch");
        if let Some(previous) = self.latest[resource]
            .as_ref()
            .and_then(|id| self.records.get_mut(id))
            && previous.outcome == ResizeOutcome::Pending
        {
            previous.outcome = ResizeOutcome::Superseded;
        }
        let record = ResizeOperation {
            id: id.clone(),
            runtime_boot_id: self.runtime_boot_id.clone(),
            generation: self.generations[resource],
            requested_target,
            accepted_target,
            status,
            outcome: ResizeOutcome::Pending,
            observation: ResizeObservation::Unavailable,
        };
        self.latest[resource] = Some(id.clone());
        self.records.insert(id.clone(), record.clone());
        self.order.push_back(id);
        // At most two records are current. Never evict either current operation;
        // older records already have an explicit superseded/applied outcome.
        while self.records.len() > MAX_RETAINED_RESIZES {
            let oldest = self.order.pop_front().expect("record order is nonempty");
            if self.latest.iter().flatten().any(|id| id == &oldest) {
                self.order.push_back(oldest);
            } else {
                self.records.remove(&oldest);
            }
        }
        record
    }

    /// Publish only evidence for the still-current operation. A later request,
    /// even one returning to identical quantities, must not receive this result.
    pub fn observed(
        &mut self,
        id: &str,
        generation: u64,
        mut status: ResourceResizeStatus,
        observation: ResizeObservation,
    ) {
        let Some(record) = self.records.get_mut(id) else {
            return;
        };
        let resource = index(&record.requested_target);
        if record.generation != generation
            || self.latest[resource].as_deref() != Some(id)
            || record.outcome != ResizeOutcome::Pending
        {
            return;
        }
        if observation != ResizeObservation::Available
            && status.state == microsandbox_types::modify::ResourceConvergenceState::Applied
        {
            // Missing evidence cannot leak an Applied state through callers
            // that project only the existing per-resource status fields.
            status = record.status.clone();
        }
        record.status = status;
        record.observation = observation;
        if observation == ResizeObservation::Available
            && record.status.state == microsandbox_types::modify::ResourceConvergenceState::Applied
        {
            record.outcome = ResizeOutcome::Applied;
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn index(target: &ResizeTarget) -> usize {
    match target {
        ResizeTarget::Cpus { .. } => 0,
        ResizeTarget::Memory { .. } => 1,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_types::modify::{ResourceConvergenceState, ResourceKind};

    fn status(target: &ResizeTarget, state: ResourceConvergenceState) -> ResourceResizeStatus {
        let (resource, value) = match target {
            ResizeTarget::Cpus { online } => (ResourceKind::Cpus, online.to_string()),
            ResizeTarget::Memory { total_mib } => {
                (ResourceKind::Memory, format!("{total_mib} MiB"))
            }
        };
        ResourceResizeStatus {
            resource,
            requested: value.clone(),
            actual: value.clone(),
            enforced: value,
            state,
        }
    }
    fn accept(tracker: &mut ResizeTracker, id: &str, target: ResizeTarget) -> ResizeOperation {
        assert!(tracker.admits(&target));
        tracker.accepted(
            id.into(),
            target.clone(),
            target.clone(),
            status(&target, ResourceConvergenceState::Accepted),
        )
    }
    #[test]
    fn pause_invalidates_only_pending_observations_and_preserves_history() {
        let mut tracker = ResizeTracker::new("boot".into());
        let completed = accept(&mut tracker, "completed", ResizeTarget::Cpus { online: 2 });
        tracker.observed(
            &completed.id,
            completed.generation,
            status(
                &completed.accepted_target,
                ResourceConvergenceState::Applied,
            ),
            ResizeObservation::Available,
        );
        let completed = tracker.get("completed").unwrap().clone();
        accept(
            &mut tracker,
            "old-memory",
            ResizeTarget::Memory { total_mib: 512 },
        );
        let pending = accept(
            &mut tracker,
            "new-memory",
            ResizeTarget::Memory { total_mib: 768 },
        );
        let superseded = tracker.get("old-memory").unwrap().clone();
        tracker.mark_pending_paused();
        assert_eq!(tracker.get("completed"), Some(&completed));
        assert_eq!(tracker.get("old-memory"), Some(&superseded));
        let paused = tracker.get("new-memory").unwrap();
        assert_eq!(paused.outcome, ResizeOutcome::Pending);
        assert_eq!(paused.status, pending.status);
        assert_eq!(paused.observation, ResizeObservation::Paused);
    }

    #[test]
    fn failed_or_intervening_mutations_invalidate_query_evidence_without_changing_operations() {
        let mut tracker = ResizeTracker::new("boot".into());
        let operation = accept(&mut tracker, "cpu", ResizeTarget::Cpus { online: 2 });
        let original = tracker.observation_fence();
        assert!(tracker.matches_observation(&original));
        // A failed capture can return to the same state without a successful mutation revision.
        tracker.invalidate_observation();
        let after_failure = tracker.observation_fence();
        assert!(!tracker.matches_observation(&original));
        assert!(tracker.matches_observation(&after_failure));
        assert_eq!(tracker.get("cpu"), Some(&operation));
        tracker.invalidate_observation();
        assert!(!tracker.matches_observation(&original));
        assert!(!tracker.matches_observation(&after_failure));
    }

    #[test]
    fn resource_ownership_survives_other_resource_mutations_but_rejects_aba() {
        let mut tracker = ResizeTracker::new("boot".into());
        let a = accept(&mut tracker, "a", ResizeTarget::Cpus { online: 8 });
        accept(
            &mut tracker,
            "memory",
            ResizeTarget::Memory { total_mib: 1024 },
        );
        assert_eq!(tracker.get("a").unwrap().outcome, ResizeOutcome::Pending);
        accept(&mut tracker, "b", ResizeTarget::Cpus { online: 4 });
        let c = accept(&mut tracker, "c", ResizeTarget::Cpus { online: 8 });
        assert_ne!(a.generation, c.generation);
        tracker.observed(
            "a",
            a.generation,
            status(&a.accepted_target, ResourceConvergenceState::Applied),
            ResizeObservation::Available,
        );
        assert_eq!(tracker.get("a").unwrap().outcome, ResizeOutcome::Superseded);
        assert_eq!(tracker.get("c").unwrap().outcome, ResizeOutcome::Pending);
        tracker.observed(
            "c",
            c.generation,
            status(&c.accepted_target, ResourceConvergenceState::Applied),
            ResizeObservation::Unsupported,
        );
        assert_eq!(tracker.get("c").unwrap().outcome, ResizeOutcome::Pending);
        tracker.observed(
            "c",
            c.generation,
            status(&c.accepted_target, ResourceConvergenceState::Applied),
            ResizeObservation::Available,
        );
        assert_eq!(tracker.get("c").unwrap().outcome, ResizeOutcome::Applied);
        accept(&mut tracker, "d", ResizeTarget::Cpus { online: 1 });
        assert_eq!(tracker.get("c").unwrap().outcome, ResizeOutcome::Applied);
    }
    #[test]
    fn bounded_retention_keeps_both_latest_resources_and_never_invents_history() {
        let mut tracker = ResizeTracker::new("boot".into());
        accept(
            &mut tracker,
            "memory",
            ResizeTarget::Memory { total_mib: 1024 },
        );
        for i in 0..600 {
            accept(
                &mut tracker,
                &format!("cpu-{i}"),
                ResizeTarget::Cpus { online: 2 },
            );
        }
        assert_eq!(tracker.records.len(), MAX_RETAINED_RESIZES);
        assert!(tracker.get("memory").is_some());
        assert!(tracker.get("cpu-0").is_none());
        assert_eq!(tracker.current().len(), 2);
        let next = ResizeTracker::new("new-boot".into());
        assert!(next.get("memory").is_none());
        assert_ne!(
            next.tracking().runtime_boot_id,
            tracker.tracking().runtime_boot_id
        );
    }
}
