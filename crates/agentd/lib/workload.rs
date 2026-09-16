//! Checkpoint-time execution latch for agentd-managed workloads.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CGROUP_ROOT: &str = "/sys/fs/cgroup/microsandbox-workload";
const FREEZE_TIMEOUT: Duration = Duration::from_secs(5);
const FREEZE_STATE_RECHECK_INTERVAL: Duration = Duration::from_millis(1);
const FREEZE_FAST_RECHECK_INTERVAL: Duration = Duration::from_micros(100);
const FREEZE_FAST_RECHECK_WINDOW: Duration = Duration::from_millis(1);
const MAX_ATTEMPT_ID_BYTES: usize = 128;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Guest-side latch for processes launched through agentd.
///
/// Failure to initialize the freezer does not affect ordinary execution. It
/// only makes full checkpoint preparation unavailable.
pub(crate) struct WorkloadLatch {
    freezer: Option<Box<dyn FreezerControl>>,
    unavailable_reason: Option<String>,
    state: LatchState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LatchState {
    Running { last_thawed: Option<String> },
    Frozen { attempt_id: String },
    RecoveryRequired { attempt_id: String },
}

trait FreezerControl: Send {
    fn placement(&self) -> io::Result<WorkloadPlacement>;
    fn set_frozen(&self, frozen: bool) -> io::Result<()>;
}

struct CgroupFreezer {
    root: PathBuf,
    cgroup_procs: File,
    cgroup_events: File,
}

/// A child-owned cgroup placement handle prepared before `fork`.
///
/// `place_current` uses only `write(2)`, so it is safe in the restricted
/// fork-to-exec window used by both agentd spawn paths.
pub(crate) struct WorkloadPlacement {
    cgroup_procs: OwnedFd,
}

/// A workload-latch operation failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum WorkloadLatchError {
    /// The guest kernel or cgroup mount cannot provide the freezer.
    #[error("workload freezer is unavailable: {0}")]
    Unavailable(String),

    /// The attempt identity is unsafe or malformed.
    #[error("invalid checkpoint attempt identity: {0}")]
    InvalidAttempt(String),

    /// Another checkpoint attempt owns the current latch state.
    #[error("workload latch conflict: {0}")]
    Conflict(String),

    /// A cgroup operation failed.
    #[error("workload freezer operation failed: {0}")]
    Io(#[from] io::Error),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WorkloadLatch {
    /// Initialize the workload cgroup, preserving ordinary sandbox operation
    /// when the host kernel does not expose a usable cgroup-v2 freezer.
    pub(crate) fn initialize() -> Self {
        match CgroupFreezer::open(Path::new(CGROUP_ROOT)) {
            Ok(freezer) => Self::with_freezer(Box::new(freezer)),
            Err(error) => Self {
                freezer: None,
                unavailable_reason: Some(error.to_string()),
                state: LatchState::Running { last_thawed: None },
            },
        }
    }

    /// Construct a latch whose checkpoint capability is intentionally disabled.
    pub(crate) fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            freezer: None,
            unavailable_reason: Some(reason.into()),
            state: LatchState::Running { last_thawed: None },
        }
    }

    /// Returns why full-checkpoint workload freezing is unavailable, if applicable.
    pub(crate) fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable_reason.as_deref()
    }

    /// Prepare a cgroup handle for placing a newly forked workload process.
    ///
    /// `None` deliberately means the freezer was unavailable at boot; normal
    /// exec remains usable in that case.
    pub(crate) fn placement(&self) -> Result<Option<WorkloadPlacement>, WorkloadLatchError> {
        self.freezer
            .as_ref()
            .map(|freezer| freezer.placement().map_err(WorkloadLatchError::Io))
            .transpose()
    }

    /// Whether an attempt blocks new work, including an uncertain freezer transition.
    pub(crate) fn is_frozen(&self) -> bool {
        !matches!(self.state, LatchState::Running { .. })
    }

    /// Freeze every process in the agentd-managed workload cgroup.
    pub(crate) fn freeze(&mut self, attempt_id: &str) -> Result<(), WorkloadLatchError> {
        validate_attempt_id(attempt_id)?;
        match &self.state {
            LatchState::Frozen {
                attempt_id: current,
            } if current == attempt_id => return Ok(()),
            LatchState::Frozen {
                attempt_id: current,
            }
            | LatchState::RecoveryRequired {
                attempt_id: current,
            } => {
                return Err(WorkloadLatchError::Conflict(format!(
                    "attempt {current:?} owns the latch; thaw it before another freeze"
                )));
            }
            LatchState::Running { .. } => {}
        }

        self.freezer()?;
        // Record ownership before writing: an error may follow a successful cgroup write.
        // Only a confirmed thaw can release an uncertain transition.
        self.state = LatchState::RecoveryRequired {
            attempt_id: attempt_id.to_string(),
        };
        self.freezer()?.set_frozen(true)?;
        // This latch stops execution, not guest writeback. Full captures preserve dirty guest
        // cache pages in RAM alongside the matching device/disk cut; disk-only extraction is
        // crash-consistent. Host block draining and durable publication remain separate gates.
        self.state = LatchState::Frozen {
            attempt_id: attempt_id.to_string(),
        };
        Ok(())
    }

    /// Validate restore ownership before changing any host-client state.
    pub(crate) fn require_frozen_attempt(
        &self,
        attempt_id: &str,
    ) -> Result<(), WorkloadLatchError> {
        validate_attempt_id(attempt_id)?;
        match &self.state {
            LatchState::Frozen {
                attempt_id: current,
            } if current == attempt_id => Ok(()),
            _ => Err(WorkloadLatchError::Conflict(
                "restore requires its matching active freeze".into(),
            )),
        }
    }

    /// Release the freeze owned by `attempt_id`.
    pub(crate) fn thaw(&mut self, attempt_id: &str) -> Result<(), WorkloadLatchError> {
        validate_attempt_id(attempt_id)?;
        match &self.state {
            LatchState::Running {
                last_thawed: Some(previous),
            } if previous == attempt_id => return Ok(()),
            LatchState::Running { .. } => {
                return Err(WorkloadLatchError::Conflict(
                    "no matching workload freeze is active".into(),
                ));
            }
            LatchState::Frozen {
                attempt_id: current,
            }
            | LatchState::RecoveryRequired {
                attempt_id: current,
            } if current != attempt_id => {
                return Err(WorkloadLatchError::Conflict(format!(
                    "attempt {current:?} owns the freeze"
                )));
            }
            LatchState::Frozen { .. } | LatchState::RecoveryRequired { .. } => {}
        }

        // A failed thaw must not leave a state that freeze retries can acknowledge as frozen.
        self.state = LatchState::RecoveryRequired {
            attempt_id: attempt_id.to_string(),
        };
        self.freezer()?.set_frozen(false)?;
        self.state = LatchState::Running {
            last_thawed: Some(attempt_id.to_string()),
        };
        Ok(())
    }

    fn with_freezer(freezer: Box<dyn FreezerControl>) -> Self {
        Self {
            freezer: Some(freezer),
            unavailable_reason: None,
            state: LatchState::Running { last_thawed: None },
        }
    }

    fn freezer(&self) -> Result<&dyn FreezerControl, WorkloadLatchError> {
        self.freezer.as_deref().ok_or_else(|| {
            WorkloadLatchError::Unavailable(
                self.unavailable_reason
                    .clone()
                    .unwrap_or_else(|| "unknown initialization failure".into()),
            )
        })
    }
}

impl CgroupFreezer {
    fn open(root: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(root)?;
        let freeze = root.join("cgroup.freeze");
        let events = root.join("cgroup.events");
        if !freeze.is_file() || !events.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cgroup v2 freezer files are absent",
            ));
        }
        let cgroup_procs = OpenOptions::new()
            .write(true)
            .open(root.join("cgroup.procs"))?;
        Ok(Self {
            root: root.to_path_buf(),
            cgroup_procs,
            cgroup_events: File::open(events)?,
        })
    }

    fn wait_for_state(&self, expected: bool) -> io::Result<()> {
        let mut events = &self.cgroup_events;
        let fd = events.as_raw_fd();
        let mut contents = String::with_capacity(128);
        // cgroup.events sends POLLPRI/POLLERR when frozen changes. Read on the same open
        // descriptor before each wait: an early completion is observed immediately, and a
        // change between read and poll remains pending on this descriptor's kernfs counter.
        // cgroup_file_notify rate-limits notifications, however, so bounded poll timeouts
        // also recheck authoritative state instead of waiting for a delayed notification.
        wait_for_frozen_event(
            expected,
            Instant::now() + FREEZE_TIMEOUT,
            || {
                events.seek(SeekFrom::Start(0))?;
                contents.clear();
                events.read_to_string(&mut contents)?;
                parse_frozen_event(&contents).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "cgroup.events omitted frozen state",
                    )
                })
            },
            |remaining| wait_for_cgroup_event(fd, remaining),
            Instant::now,
        )
    }
}

impl WorkloadPlacement {
    /// Move the calling child into the workload cgroup before it executes user code.
    pub(crate) fn place_current(&self) -> io::Result<()> {
        let bytes = b"0";
        loop {
            let written = unsafe {
                libc::write(
                    self.cgroup_procs.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                )
            };
            if written == bytes.len() as isize {
                return Ok(());
            }
            if written < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write to cgroup.procs",
            ));
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FreezerControl for CgroupFreezer {
    fn placement(&self) -> io::Result<WorkloadPlacement> {
        Ok(WorkloadPlacement {
            cgroup_procs: self.cgroup_procs.try_clone()?.into(),
        })
    }

    fn set_frozen(&self, frozen: bool) -> io::Result<()> {
        std::fs::write(
            self.root.join("cgroup.freeze"),
            if frozen { b"1" } else { b"0" },
        )?;
        self.wait_for_state(frozen)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn wait_for_frozen_event(
    expected: bool,
    deadline: Instant,
    mut read_state: impl FnMut() -> io::Result<bool>,
    mut wait: impl FnMut(Duration) -> io::Result<()>,
    mut now: impl FnMut() -> Instant,
) -> io::Result<()> {
    let fast_until = now() + FREEZE_FAST_RECHECK_WINDOW;
    loop {
        let interrupted = match read_state() {
            Ok(state) if state == expected => return Ok(()),
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => true,
            Err(error) => return Err(error),
        };
        let observed_at = now();
        let remaining = deadline.saturating_duration_since(observed_at);
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "cgroup did not report frozen={} within {FREEZE_TIMEOUT:?}",
                    expected as u8
                ),
            ));
        }
        if interrupted {
            continue;
        }
        // Cgroup notifications can be delayed even after frozen=1. Brief sleeping rechecks
        // avoid a whole millisecond of observation lag without spinning for the deadline.
        let interval = if observed_at < fast_until {
            FREEZE_FAST_RECHECK_INTERVAL
        } else {
            FREEZE_STATE_RECHECK_INTERVAL
        };
        match wait(remaining.min(interval)) {
            Ok(()) => {}
            // Recheck state and the original deadline after interruptions or spurious events.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn wait_for_cgroup_event(fd: RawFd, remaining: Duration) -> io::Result<()> {
    let mut event = libc::pollfd {
        fd,
        events: libc::POLLPRI | libc::POLLERR,
        revents: 0,
    };
    // Linux guests use ppoll so sub-millisecond waits are not rounded back up to 1 ms.
    // Non-Linux builds only exercise the portable unit-test fallback, never a guest freezer.
    #[cfg(target_os = "linux")]
    let result = {
        let timeout = libc::timespec {
            // Infer the platform's field type: naming libc::time_t is deprecated on musl.
            tv_sec: remaining.as_secs().try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cgroup wait duration is too large",
                )
            })?,
            tv_nsec: remaining.subsec_nanos().into(),
        };
        unsafe { libc::ppoll(&mut event, 1, &timeout, std::ptr::null()) }
    };
    #[cfg(not(target_os = "linux"))]
    let result = {
        let timeout = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as i32;
        unsafe { libc::poll(&mut event, 1, timeout) }
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if event.revents & (libc::POLLNVAL | libc::POLLHUP) != 0 {
        return Err(io::Error::other(
            "cgroup.events descriptor became unavailable",
        ));
    }
    // POLLERR accompanies normal kernfs notifications; it is not by itself an I/O failure.
    // Timeout and other wakeups both lead to a fresh state read and deadline check.
    Ok(())
}

fn validate_attempt_id(attempt_id: &str) -> Result<(), WorkloadLatchError> {
    if attempt_id.is_empty()
        || attempt_id.len() > MAX_ATTEMPT_ID_BYTES
        || !attempt_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(WorkloadLatchError::InvalidAttempt(
            "must be 1-128 printable ASCII bytes without spaces".into(),
        ));
    }
    Ok(())
}

fn parse_frozen_event(events: &str) -> Option<bool> {
    events.lines().find_map(|line| {
        let (key, value) = line.split_once(' ')?;
        if key != "frozen" {
            return None;
        }
        match value {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        }
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn completed_freezer_transition_does_not_wait() {
        let start = Instant::now();
        wait_for_frozen_event(
            true,
            start + FREEZE_TIMEOUT,
            || Ok(true),
            |_| panic!("already frozen"),
            || start,
        )
        .unwrap();
    }

    #[test]
    fn freezer_transition_between_read_and_wait_is_not_lost() {
        let start = Instant::now();
        let frozen = Cell::new(false);
        let waits = Cell::new(0);
        wait_for_frozen_event(
            true,
            start + FREEZE_TIMEOUT,
            || Ok(frozen.get()),
            |_| {
                // Model a pending kernfs notification from a transition after the state read.
                frozen.set(true);
                waits.set(waits.get() + 1);
                Ok(())
            },
            || start,
        )
        .unwrap();
        assert_eq!(waits.get(), 1);
    }

    #[test]
    fn freezer_spurious_notifications_and_eintr_recheck_state() {
        let start = Instant::now();
        let waits = Cell::new(0);
        wait_for_frozen_event(
            false,
            start + FREEZE_TIMEOUT,
            || Ok(waits.get() < 3),
            |_| {
                waits.set(waits.get() + 1);
                if waits.get() == 2 {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(())
                }
            },
            || start,
        )
        .unwrap();
        assert_eq!(waits.get(), 3);
    }

    #[test]
    fn freezer_delayed_notification_does_not_delay_the_authoritative_state_read() {
        let start = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let frozen = Cell::new(false);
        let waits = Cell::new(0);
        wait_for_frozen_event(
            true,
            start + FREEZE_TIMEOUT,
            || Ok(frozen.get()),
            |remaining| {
                assert_eq!(remaining, FREEZE_FAST_RECHECK_INTERVAL);
                // The state is ready but cgroup_file_notify defers its notification by
                // roughly 10 ms. A bounded timeout observes readiness without that event.
                frozen.set(true);
                elapsed.set(elapsed.get() + remaining);
                waits.set(waits.get() + 1);
                Ok(())
            },
            || start + elapsed.get(),
        )
        .unwrap();
        assert_eq!(waits.get(), 1);
        assert_eq!(elapsed.get(), FREEZE_FAST_RECHECK_INTERVAL);
    }

    #[test]
    fn freezer_interruptions_do_not_extend_original_deadline() {
        let start = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let error = wait_for_frozen_event(
            true,
            start + Duration::from_millis(3),
            || Ok(false),
            |remaining| {
                assert_eq!(
                    remaining,
                    (Duration::from_millis(3) - elapsed.get()).min(
                        if elapsed.get() < FREEZE_FAST_RECHECK_WINDOW {
                            FREEZE_FAST_RECHECK_INTERVAL
                        } else {
                            FREEZE_STATE_RECHECK_INTERVAL
                        }
                    )
                );
                elapsed.set(elapsed.get() + Duration::from_millis(1));
                Err(io::ErrorKind::Interrupted.into())
            },
            || start + elapsed.get(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(elapsed.get(), Duration::from_millis(3));
    }

    #[test]
    fn freezer_fast_rechecks_back_off_and_respect_short_final_wait() {
        let start = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let waits = Cell::new(0);
        let timeout = Duration::from_micros(2_050);
        let error = wait_for_frozen_event(
            true,
            start + timeout,
            || Ok(false),
            |duration| {
                let expected = if elapsed.get() < FREEZE_FAST_RECHECK_WINDOW {
                    FREEZE_FAST_RECHECK_INTERVAL
                } else {
                    FREEZE_STATE_RECHECK_INTERVAL
                };
                assert_eq!(duration, expected.min(timeout - elapsed.get()));
                elapsed.set(elapsed.get() + duration);
                waits.set(waits.get() + 1);
                Ok(())
            },
            || start + elapsed.get(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(waits.get(), 12);
        assert_eq!(elapsed.get(), timeout);
    }

    #[test]
    fn freezer_read_interruptions_retry_with_a_bounded_deadline() {
        let start = Instant::now();
        let reads = Cell::new(0);
        let error = wait_for_frozen_event(
            true,
            start + Duration::from_millis(3),
            || {
                reads.set(reads.get() + 1);
                Err(io::ErrorKind::Interrupted.into())
            },
            |_| panic!("an interrupted read must be retried before waiting"),
            || start + Duration::from_millis(reads.get()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(reads.get(), 3);
    }

    #[test]
    fn freezer_read_and_notification_errors_are_not_success() {
        let start = Instant::now();
        let error = wait_for_frozen_event(
            true,
            start + FREEZE_TIMEOUT,
            || Err(io::ErrorKind::InvalidData.into()),
            |_| unreachable!(),
            || start,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let error = wait_for_frozen_event(
            true,
            start + FREEZE_TIMEOUT,
            || Ok(false),
            |_| Err(io::ErrorKind::BrokenPipe.into()),
            || start,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn freezer_reads_final_state_before_reporting_timeout() {
        let start = Instant::now();
        let completed = Cell::new(false);
        wait_for_frozen_event(
            true,
            start + FREEZE_TIMEOUT,
            || Ok(completed.get()),
            |_| {
                completed.set(true);
                Ok(())
            },
            || {
                if completed.get() {
                    start + FREEZE_TIMEOUT
                } else {
                    start
                }
            },
        )
        .unwrap();
    }

    #[test]
    fn invalid_cgroup_poll_descriptor_is_an_error() {
        assert!(wait_for_cgroup_event(i32::MAX, Duration::from_millis(1)).is_err());
    }

    struct FakeFreezer {
        states: Arc<Mutex<Vec<bool>>>,
    }

    struct FailingFreezer {
        outcomes: Mutex<VecDeque<bool>>,
    }

    impl FreezerControl for FailingFreezer {
        fn placement(&self) -> io::Result<WorkloadPlacement> {
            unreachable!()
        }

        fn set_frozen(&self, _frozen: bool) -> io::Result<()> {
            // Model either a failed write or a write that succeeded before acknowledgement failed.
            if self.outcomes.lock().unwrap().pop_front().unwrap() {
                Ok(())
            } else {
                Err(io::Error::other("injected freezer transition failure"))
            }
        }
    }

    #[test]
    fn failed_freeze_retains_ownership_until_confirmed_thaw() {
        let mut latch = WorkloadLatch::with_freezer(Box::new(FailingFreezer {
            outcomes: Mutex::new(VecDeque::from([false, false, true])),
        }));
        assert!(latch.freeze("a").is_err());
        assert!(latch.is_frozen());
        assert!(latch.freeze("a").is_err());
        assert!(latch.freeze("b").is_err());
        assert!(latch.thaw("b").is_err());
        assert!(latch.thaw("a").is_err());
        assert!(latch.is_frozen());
        latch.thaw("a").unwrap();
        assert!(!latch.is_frozen());
        latch.thaw("a").unwrap();
    }

    #[test]
    fn failed_thaw_never_acknowledges_a_freeze_retry() {
        let mut latch = WorkloadLatch::with_freezer(Box::new(FailingFreezer {
            outcomes: Mutex::new(VecDeque::from([true, false, true])),
        }));
        latch.freeze("a").unwrap();
        assert!(latch.thaw("a").is_err());
        assert!(latch.is_frozen());
        assert!(latch.freeze("a").is_err());
        latch.thaw("a").unwrap();
        assert!(!latch.is_frozen());
    }

    #[test]
    fn known_unavailable_never_takes_ownership() {
        let mut latch = WorkloadLatch::unavailable("no cgroup freezer");
        for attempt in ["a", "b"] {
            assert!(matches!(
                latch.freeze(attempt),
                Err(WorkloadLatchError::Unavailable(_))
            ));
            assert!(!latch.is_frozen());
        }
    }

    impl FreezerControl for FakeFreezer {
        fn placement(&self) -> io::Result<WorkloadPlacement> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not needed"))
        }

        fn set_frozen(&self, frozen: bool) -> io::Result<()> {
            self.states.lock().unwrap().push(frozen);
            Ok(())
        }
    }

    /// Exercise the real latch/handler without freezing the test runner's cgroup.
    pub(crate) fn fake_latch() -> WorkloadLatch {
        WorkloadLatch::with_freezer(Box::new(FakeFreezer {
            states: Arc::new(Mutex::new(Vec::new())),
        }))
    }

    #[test]
    fn attempt_retries_are_idempotent_and_cross_attempt_release_is_rejected() {
        let states = Arc::new(Mutex::new(Vec::new()));
        let mut latch = WorkloadLatch::with_freezer(Box::new(FakeFreezer {
            states: Arc::clone(&states),
        }));

        latch.freeze("checkpoint-42").unwrap();
        latch.freeze("checkpoint-42").unwrap();
        assert!(latch.thaw("checkpoint-99").is_err());
        latch.thaw("checkpoint-42").unwrap();
        latch.thaw("checkpoint-42").unwrap();

        assert_eq!(*states.lock().unwrap(), vec![true, false]);
    }

    #[test]
    fn unavailable_freezer_does_not_disable_process_placement() {
        let latch = WorkloadLatch {
            freezer: None,
            unavailable_reason: Some("missing cgroup2".into()),
            state: LatchState::Running { last_thawed: None },
        };

        assert!(latch.placement().unwrap().is_none());
        assert_eq!(latch.unavailable_reason(), Some("missing cgroup2"));
    }

    #[test]
    fn parses_cgroup_v2_frozen_event() {
        assert_eq!(parse_frozen_event("populated 1\nfrozen 1\n"), Some(true));
        assert_eq!(parse_frozen_event("populated 0\nfrozen 0\n"), Some(false));
        assert_eq!(parse_frozen_event("populated 0\n"), None);
    }

    #[test]
    fn validates_bounded_printable_attempt_ids() {
        assert!(validate_attempt_id("checkpoint_42").is_ok());
        assert!(validate_attempt_id("").is_err());
        assert!(validate_attempt_id("contains space").is_err());
        assert!(validate_attempt_id(&"x".repeat(129)).is_err());
    }
}
