//! Host-side clock synchronization for guest agents.

use std::time::{Duration, SystemTime};

use microsandbox_protocol::codec;
use microsandbox_protocol::core::ClockSync;
use microsandbox_protocol::message::{Message, MessageType};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

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
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawns a background task that keeps the guest wall clock aligned with the host.
pub(crate) fn spawn_clock_sync_task(agent_tx: mpsc::Sender<Vec<u8>>) -> JoinHandle<()> {
    tokio::spawn(clock_sync_task(agent_tx))
}

async fn clock_sync_task(agent_tx: mpsc::Sender<Vec<u8>>) {
    let mut last_wall = SystemTime::now();
    let mut last_sync = match send_clock_sync(&agent_tx).await {
        Ok(sent_at) => sent_at,
        Err(err) => {
            tracing::debug!(error = %err, "agent relay: initial clock sync failed");
            return;
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

async fn send_clock_sync(agent_tx: &mpsc::Sender<Vec<u8>>) -> RuntimeResult<SystemTime> {
    let now = SystemTime::now();
    let elapsed = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| RuntimeError::Custom(format!("clock sync before Unix epoch: {e}")))?;
    let unix_time_nanos = u64::try_from(elapsed.as_nanos()).map_err(|_| {
        RuntimeError::Custom("clock sync timestamp does not fit in u64 nanoseconds".into())
    })?;
    let sync = ClockSync { unix_time_nanos };
    let msg = Message::with_payload(MessageType::ClockSync, 0, &sync)
        .map_err(|e| RuntimeError::Custom(format!("encode clock sync: {e}")))?;

    let mut buf = Vec::new();
    codec::encode_to_buf(&msg, &mut buf)
        .map_err(|e| RuntimeError::Custom(format!("encode clock sync frame: {e}")))?;
    agent_tx
        .send(buf)
        .await
        .map_err(|_| RuntimeError::Custom("agent relay ring writer channel closed".into()))?;

    Ok(now)
}
