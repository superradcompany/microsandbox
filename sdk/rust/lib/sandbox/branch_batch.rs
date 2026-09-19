//! Explicit capture-once branching. Shared state exists only for the duration of this call.

#[cfg(any(feature = "local", test))]
use std::collections::HashSet;
#[cfg(any(feature = "local", test))]
use std::future::Future;
use std::sync::Arc;
#[cfg(any(feature = "local", test))]
use std::sync::OnceLock;

#[cfg(any(feature = "local", test))]
use futures::{StreamExt, future::Either, stream};
#[cfg(any(feature = "local", test))]
use tokio::sync::Notify;

use crate::backend::Backend;
use crate::backend::sandbox::SandboxIdentity;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::SandboxConfig;
use super::branch::BranchOutcome;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Bound transient startup work, not the eventual population of detached children.
#[cfg(feature = "local")]
const BATCH_STARTUP_CONCURRENCY: usize = 4;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Independent links and RAM ownership survive first-child failure or source deletion.
#[cfg(feature = "local")]
#[derive(Debug)]
pub(crate) struct BatchCapture {
    pub staging: tempfile::TempDir,
    pub pin: Arc<microsandbox_runtime::checkpoint::LocalMemoryPin>,
    pub state: Arc<microsandbox_runtime::checkpoint::LocalBranchState>,
    pub snapshot_parent: Option<String>,
}

/// One designated producer publishes the capture; consumers can never initialize or retry it.
#[cfg(any(feature = "local", test))]
#[derive(Debug)]
pub(crate) struct CaptureSlot<T> {
    value: OnceLock<T>,
    ready: Notify,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[cfg(any(feature = "local", test))]
impl<T> CaptureSlot<T> {
    fn new() -> Self {
        Self {
            value: OnceLock::new(),
            ready: Notify::new(),
        }
    }

    pub(crate) fn get(&self) -> Option<&T> {
        self.value.get()
    }

    pub(crate) fn publish(&self, value: T) -> Result<(), T> {
        self.value.set(value)?;
        // Only the batch coordinator waits here. notify_one retains its permit if
        // capture completes during the first creation future's current poll.
        self.ready.notify_one();
        Ok(())
    }

    async fn wait(&self) {
        while self.get().is_none() {
            self.ready.notified().await;
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(not(feature = "local"))]
pub(super) async fn branch_many(
    _backend: Arc<dyn Backend>,
    _source: &str,
    _identity: SandboxIdentity,
    _options: SandboxConfig,
    _record_integrity: bool,
    _names: Vec<String>,
    _guest_flush: microsandbox_types::GuestFlush,
) -> MicrosandboxResult<Vec<BranchOutcome>> {
    Err(MicrosandboxError::InvalidConfig(
        "direct branching requires a local backend".into(),
    ))
}

#[cfg(feature = "local")]
pub(super) async fn branch_many(
    backend: Arc<dyn Backend>,
    source: &str,
    identity: SandboxIdentity,
    mut options: SandboxConfig,
    record_integrity: bool,
    names: Vec<String>,
    guest_flush: microsandbox_types::GuestFlush,
) -> MicrosandboxResult<Vec<BranchOutcome>> {
    validate_names(source, &names)?;
    let local = backend.as_local().ok_or_else(|| {
        MicrosandboxError::InvalidConfig("direct branching requires a local backend".into())
    })?;
    // Fail known conflicts before capture. Each create still performs its authoritative,
    // locked reservation: preflight cannot promise atomicity against another process.
    for name in &names {
        local.validate_sandbox_name_for_runtime(name)?;
        match backend.sandboxes().get(backend.clone(), name).await {
            Ok(_) => return Err(MicrosandboxError::SandboxAlreadyExists(name.clone())),
            Err(MicrosandboxError::SandboxNotFound(_)) => (),
            Err(error) => return Err(error),
        }
        match std::fs::symlink_metadata(local.sandboxes_dir().join(name)) {
            Ok(_) => return Err(MicrosandboxError::SandboxAlreadyExists(name.clone())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    options.spec.name = names[0].clone();
    let mut template = super::branch::prepare_branch(
        backend.clone(),
        source,
        identity,
        options,
        record_integrity,
        guest_flush,
    )
    .await?;
    let capture = Arc::new(CaptureSlot::new());
    template
        .branch_source
        .as_mut()
        .expect("prepared branch source")
        .batch = Some(capture.clone());
    let results =
        launch_captured_children(&capture, names.len(), BATCH_STARTUP_CONCURRENCY, |index| {
            // Configs are cloned only as launch slots become free. Every clone references
            // the same completed capture; no sibling can enter the producer path.
            let mut config = template.clone();
            config.spec.name = names[index].clone();
            backend.sandboxes().create_detached(backend.clone(), config)
        })
        .await?;
    Ok(names
        .into_iter()
        .zip(results)
        .map(|(name, result)| BranchOutcome { name, result })
        .collect())
}

/// Preserve the first child's existing reservation/cleanup owner while separating
/// capture from startup. Its continuation joins siblings as soon as capture is ready,
/// not when its VM is ready. No task is detached from the caller's cancellation scope.
#[cfg(any(feature = "local", test))]
async fn launch_captured_children<C, T, F, Fut>(
    capture: &CaptureSlot<C>,
    count: usize,
    limit: usize,
    mut launch: F,
) -> MicrosandboxResult<Vec<MicrosandboxResult<T>>>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = MicrosandboxResult<T>>,
{
    assert!(count > 0 && limit > 0);
    let first = launch(0);
    futures::pin_mut!(first);
    let first_result = tokio::select! {
        _ = capture.wait() => None,
        result = &mut first => Some(result),
    };
    if capture.get().is_none() {
        // Failure before publication is terminal: never recapture for another child.
        return Err(first_result
            .expect("producer finished without a capture")
            .err()
            .unwrap_or_else(|| {
                MicrosandboxError::Runtime("branch did not retain its shared capture".into())
            }));
    }
    let start = usize::from(first_result.is_some());
    let mut outcomes = std::iter::repeat_with(|| None)
        .take(count)
        .collect::<Vec<_>>();
    outcomes[0] = first_result;
    let mut first = Some(first);
    let launches = stream::iter(start..count)
        .map(|index| {
            let future = if index == 0 {
                Either::Left(first.take().expect("first continuation is consumed once"))
            } else {
                Either::Right(launch(index))
            };
            async move { (index, future.await) }
        })
        .buffer_unordered(limit);
    futures::pin_mut!(launches);
    while let Some((index, result)) = launches.next().await {
        // Completion order is deliberately independent of result order. A child
        // error is a value, not a reason to cancel or roll back its siblings.
        outcomes[index] = Some(result);
    }
    Ok(outcomes
        .into_iter()
        .map(|outcome| outcome.expect("every child completed"))
        .collect())
}

#[cfg(any(feature = "local", test))]
fn validate_names(source: &str, names: &[String]) -> MicrosandboxResult<()> {
    if names.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "branch batch requires at least one child name".into(),
        ));
    }
    let mut seen = HashSet::new();
    for name in names {
        super::validate_sandbox_name(name)?;
        // Reject case-only collisions consistently, including on case-insensitive hosts.
        if name.eq_ignore_ascii_case(source) || !seen.insert(name.to_ascii_lowercase()) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "duplicate or source child name: {name}"
            )));
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct ActiveLaunch {
        active: Arc<AtomicUsize>,
    }

    impl ActiveLaunch {
        fn new(active: Arc<AtomicUsize>, peak: &AtomicUsize) -> Self {
            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(current, Ordering::SeqCst);
            Self { active }
        }
    }

    impl Drop for ActiveLaunch {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn concurrent_children_include_first_and_refill_in_completion_order() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let capture = Arc::new(CaptureSlot::new());
            let active = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let gates = Arc::new((0..6).map(|_| Notify::new()).collect::<Vec<_>>());
            let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
            let task = {
                let capture = capture.clone();
                let active = active.clone();
                let peak = peak.clone();
                let gates = gates.clone();
                tokio::spawn(async move {
                    launch_captured_children(&capture, 6, 3, |index| {
                        let capture = capture.clone();
                        let active = active.clone();
                        let peak = peak.clone();
                        let gates = gates.clone();
                        let started = started.clone();
                        async move {
                            let _owner = ActiveLaunch::new(active, &peak);
                            if index == 0 {
                                capture.publish(42).unwrap();
                            }
                            assert_eq!(capture.get(), Some(&42));
                            started.send(index).unwrap();
                            gates[index].notified().await;
                            if index == 1 {
                                Err(MicrosandboxError::Runtime("one child failed".into()))
                            } else {
                                Ok(index)
                            }
                        }
                    })
                    .await
                })
            };
            for expected in 0..3 {
                assert_eq!(starts.recv().await, Some(expected));
            }
            // Child zero is still blocked: siblings must not wait for its readiness.
            assert_eq!(active.load(Ordering::SeqCst), 3);
            gates[2].notify_one();
            assert_eq!(starts.recv().await, Some(3));
            gates[1].notify_one();
            assert_eq!(starts.recv().await, Some(4));
            gates[4].notify_one();
            assert_eq!(starts.recv().await, Some(5));
            for index in [0, 3, 5] {
                gates[index].notify_one();
            }
            let outcomes = task.await.unwrap().unwrap();
            assert!(outcomes[1].is_err());
            for index in [0, 2, 3, 4, 5] {
                assert_eq!(*outcomes[index].as_ref().unwrap(), index);
            }
            assert_eq!(peak.load(Ordering::SeqCst), 3);
            assert_eq!(active.load(Ordering::SeqCst), 0);
        })
        .await
        .expect("batch deadlocked behind a blocked child");
    }

    #[tokio::test]
    async fn failed_capture_never_starts_or_recaptures_for_siblings() {
        let capture = CaptureSlot::<u8>::new();
        let launched = AtomicUsize::new(0);
        let result = launch_captured_children(&capture, 4, 4, |_| {
            launched.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(MicrosandboxError::Runtime("capture failed".into())) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(launched.load(Ordering::SeqCst), 1);
        assert!(capture.get().is_none());
    }

    #[tokio::test]
    async fn first_child_failure_after_publication_keeps_siblings() {
        let capture = CaptureSlot::new();
        let outcomes = launch_captured_children(&capture, 4, 2, |index| {
            let capture = &capture;
            async move {
                if index == 0 {
                    capture.publish(7).unwrap();
                    Err(MicrosandboxError::Runtime("first startup failed".into()))
                } else {
                    assert_eq!(capture.get(), Some(&7));
                    Ok(index)
                }
            }
        })
        .await
        .unwrap();
        assert!(outcomes[0].is_err());
        for (index, outcome) in outcomes.iter().enumerate().skip(1) {
            assert_eq!(*outcome.as_ref().unwrap(), index);
        }
    }

    #[tokio::test]
    async fn cancellation_drops_inflight_owners_and_never_admits_waiting_children() {
        let capture = CaptureSlot::new();
        let active = Arc::new(AtomicUsize::new(0));
        let peak = AtomicUsize::new(0);
        let launched = AtomicUsize::new(0);
        let mut batch = Box::pin(launch_captured_children(&capture, 10, 4, |index| {
            launched.fetch_add(1, Ordering::SeqCst);
            let active = active.clone();
            let capture = &capture;
            let peak = &peak;
            async move {
                let _owner = ActiveLaunch::new(active, peak);
                if index == 0 {
                    capture.publish(9).unwrap();
                }
                std::future::pending::<MicrosandboxResult<()>>().await
            }
        }));
        assert!(futures::poll!(batch.as_mut()).is_pending());
        // The producer's ready notification can require one additional poll.
        assert!(futures::poll!(batch.as_mut()).is_pending());
        assert_eq!(active.load(Ordering::SeqCst), 4);
        drop(batch);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(launched.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn validate_all_names_before_capture() {
        for names in [
            vec![],
            vec!["source"],
            vec!["a", "a"],
            vec!["a", "A"],
            vec!["good", "../bad"],
        ] {
            assert!(
                validate_names(
                    "source",
                    &names.into_iter().map(String::from).collect::<Vec<_>>()
                )
                .is_err()
            );
        }
        assert!(validate_names("source", &["alice".into(), "bob".into()]).is_ok());
    }

    #[test]
    #[cfg(feature = "local")]
    fn local_capture_uses_independent_links_not_payload_copies() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        std::fs::create_dir_all(first.join("layers")).unwrap();
        std::fs::write(first.join("branch.json"), b"capture").unwrap();
        std::fs::write(first.join("local-disk-admission.json"), b"disk receipts").unwrap();
        std::fs::write(first.join("layers/base.raw"), b"immutable disk").unwrap();
        std::fs::write(first.join("memory.ram"), b"not part of the closure").unwrap();
        let retained = root.path().join("retained");
        crate::snapshot::stage_local_branch_closure(&first, &retained).unwrap();
        assert!(!retained.join("memory.ram").exists());
        assert_eq!(
            std::fs::read(retained.join("local-disk-admission.json")).unwrap(),
            b"disk receipts"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                std::fs::metadata(first.join("layers/base.raw"))
                    .unwrap()
                    .ino(),
                std::fs::metadata(retained.join("layers/base.raw"))
                    .unwrap()
                    .ino()
            );
        }
        std::fs::remove_dir_all(first).unwrap();
        let sibling = root.path().join("sibling");
        crate::snapshot::stage_local_branch_closure(&retained, &sibling).unwrap();
        std::fs::remove_dir_all(retained).unwrap();
        assert_eq!(
            std::fs::read(sibling.join("layers/base.raw")).unwrap(),
            b"immutable disk"
        );
    }

    #[test]
    #[cfg(all(feature = "local", unix))]
    fn local_capture_refuses_symlink_payloads() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        std::fs::create_dir_all(first.join("layers")).unwrap();
        std::fs::write(first.join("branch.json"), b"capture").unwrap();
        std::os::unix::fs::symlink("/dev/null", first.join("layers/not-a-disk")).unwrap();
        assert!(
            crate::snapshot::stage_local_branch_closure(&first, &root.path().join("child"))
                .is_err()
        );
    }
}
