//! Host-side clock synchronization for guest agents.

use std::time::{Duration, SystemTime};

use bytes::Bytes;
use microsandbox_protocol::codec;
use microsandbox_protocol::core::ClockSync;
use microsandbox_protocol::message::{Message, MessageType};
use microsandbox_types::GuestClockPolicy;
use tokio::task::JoinHandle;

use crate::relay::{ControlWrite, ControlWriter};
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// How often the host checks for a wake-sized wall-clock jump.
const CLOCK_SYNC_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Normal steady-state clock sync interval.
const CLOCK_SYNC_INTERVAL: Duration = Duration::from_secs(60);

/// Wall-clock gap that indicates the host likely slept or was suspended.
const CLOCK_SYNC_WAKE_THRESHOLD: Duration = Duration::from_secs(6);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Kernel request published before a restored full snapshot runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreActivationMode {
    /// Publish a new VM generation and step the guest wall clock to host time.
    IdentityAndClock,
    /// Publish a new VM generation only; the guest keeps its captured wall clock.
    IdentityOnly,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RestoreActivationMode {
    /// Select the restore activation for a guest clock policy.
    pub(crate) fn for_policy(policy: GuestClockPolicy) -> Self {
        match policy {
            GuestClockPolicy::Sync => Self::IdentityAndClock,
            GuestClockPolicy::Off => Self::IdentityOnly,
        }
    }

    /// Describe the kernel activation required by this restore policy.
    pub(crate) fn description(self) -> &'static str {
        match self {
            Self::IdentityAndClock => "identity-and-clock activation",
            Self::IdentityOnly => "VM Generation ID activation",
        }
    }

    /// Publish this activation. `None` means the guest kernel lacks the needed transport.
    pub(crate) fn install(
        self,
        vm: &msb_krun::VmControl,
        id: msb_krun::VmGenerationId,
    ) -> Option<msb_krun::VmGenerationRequest> {
        match self {
            Self::IdentityAndClock => vm.install_vm_generation_and_clock(id),
            Self::IdentityOnly => vm.install_vm_generation_id(id),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawns a background task that keeps the guest wall clock aligned with the host.
///
/// Returns `None` without sending anything when the policy leaves the guest clock alone.
pub(crate) fn spawn_clock_sync_task(
    agent_tx: ControlWriter,
    policy: GuestClockPolicy,
    already_synchronized: bool,
) -> Option<JoinHandle<()>> {
    policy
        .is_sync()
        .then(|| tokio::spawn(clock_sync_task(agent_tx, already_synchronized)))
}

async fn clock_sync_task(agent_tx: ControlWriter, already_synchronized: bool) {
    let mut last_wall = SystemTime::now();
    // Full restore completed the kernel clock barrier before workload thaw. Do not immediately
    // overwrite it with a queued userspace timestamp. Ordinary boot keeps its existing sync.
    let mut last_sync = if already_synchronized {
        last_wall
    } else {
        match send_clock_sync(&agent_tx).await {
            Ok(sent_at) => sent_at,
            Err(err) => {
                tracing::debug!(error = %err, "agent relay: initial clock sync failed");
                return;
            }
        }
    };

    let mut interval = tokio::time::interval(CLOCK_SYNC_POLL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;

        let now = SystemTime::now();
        let wall_gap = now
            .duration_since(last_wall)
            .unwrap_or(CLOCK_SYNC_WAKE_THRESHOLD);
        let since_sync = now.duration_since(last_sync).unwrap_or(CLOCK_SYNC_INTERVAL);

        if wall_gap >= CLOCK_SYNC_WAKE_THRESHOLD || since_sync >= CLOCK_SYNC_INTERVAL {
            match send_clock_sync(&agent_tx).await {
                Ok(sent_at) => last_sync = sent_at,
                Err(err) => {
                    tracing::debug!(error = %err, "agent relay: clock sync task exiting");
                    break;
                }
            }
        }

        last_wall = now;
    }
}

async fn send_clock_sync(agent_tx: &ControlWriter) -> RuntimeResult<SystemTime> {
    let now = SystemTime::now();
    agent_tx
        .send(ControlWrite::clock_sync()?)
        .await
        .map_err(|_| RuntimeError::Custom("agent relay ring writer channel closed".into()))?;
    Ok(now)
}

/// Sample only when the ordinary writer can admit the maintenance frame to the console queue.
pub(crate) fn current_clock_sync_frame() -> RuntimeResult<Bytes> {
    let elapsed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| RuntimeError::Custom(format!("clock sync before Unix epoch: {e}")))?;
    let unix_time_nanos = u64::try_from(elapsed.as_nanos()).map_err(|_| {
        RuntimeError::Custom("clock sync timestamp does not fit in u64 nanoseconds".into())
    })?;
    encode_clock_sync_frame(unix_time_nanos)
}

/// The queue initially reserves the maximum encoded timestamp size, then sends the actual value.
pub(crate) fn encode_clock_sync_frame(unix_time_nanos: u64) -> RuntimeResult<Bytes> {
    let sync = ClockSync { unix_time_nanos };
    let msg = Message::with_payload(MessageType::ClockSync, 0, &sync)
        .map_err(|e| RuntimeError::Custom(format!("encode clock sync: {e}")))?;

    let mut buf = Vec::new();
    codec::encode_to_buf(&msg, &mut buf)
        .map_err(|e| RuntimeError::Custom(format!("encode clock sync frame: {e}")))?;
    Ok(Bytes::from(buf))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_activation_steps_the_clock_only_when_synchronizing() {
        assert_eq!(
            RestoreActivationMode::for_policy(GuestClockPolicy::Sync),
            RestoreActivationMode::IdentityAndClock
        );
        assert_eq!(
            RestoreActivationMode::for_policy(GuestClockPolicy::Off),
            RestoreActivationMode::IdentityOnly
        );
    }
}
