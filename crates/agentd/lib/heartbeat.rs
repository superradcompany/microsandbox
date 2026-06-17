//! Periodic heartbeat writer for the guest agent.

use std::path::Path;

use microsandbox_protocol::heartbeat::Heartbeat;

use crate::error::AgentdResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Path to the heartbeat JSON file (under [`microsandbox_protocol::RUNTIME_MOUNT_POINT`]).
const HEARTBEAT_PATH: &str = "/.msb/heartbeat.json";

/// Path to the temporary heartbeat file (for atomic rename).
const HEARTBEAT_TMP_PATH: &str = "/.msb/heartbeat.tmp";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Atomically writes the heartbeat JSON to `/.msb/heartbeat.json`.
pub async fn write_heartbeat(heartbeat: &Heartbeat) -> AgentdResult<()> {
    let json = serde_json::to_vec(&heartbeat)?;

    tokio::fs::write(HEARTBEAT_TMP_PATH, json).await?;
    tokio::fs::rename(HEARTBEAT_TMP_PATH, HEARTBEAT_PATH).await?;

    Ok(())
}

/// Returns `true` if the heartbeat directory exists (i.e., the runtime mount is available).
pub fn heartbeat_dir_exists() -> bool {
    Path::new(microsandbox_protocol::RUNTIME_MOUNT_POINT).is_dir()
}
