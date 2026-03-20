//! Virtio serial port discovery.

use std::{fs, path::PathBuf};

use crate::error::{AgentdError, AgentdResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The sysfs path where virtio ports are listed.
const VIRTIO_PORTS_PATH: &str = "/sys/class/virtio-ports";

/// Re-export the canonical agent port name from the protocol crate.
pub use microsandbox_protocol::AGENT_PORT_NAME;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Discovers the device path for a virtio serial port by its name.
///
/// Scans `/sys/class/virtio-ports/` entries, reads each `name` file,
/// and returns `/dev/{port_id}` for the matching port.
pub fn find_serial_port(name: &str) -> AgentdResult<PathBuf> {
    let ports_dir = PathBuf::from(VIRTIO_PORTS_PATH);

    let entries = fs::read_dir(&ports_dir).map_err(|e| {
        AgentdError::SerialPortNotFound(format!("cannot read {VIRTIO_PORTS_PATH}: {e}"))
    })?;

    for entry in entries {
        let entry = entry?;
        let name_file = entry.path().join("name");

        if let Ok(port_name) = fs::read_to_string(&name_file)
            && port_name.trim() == name
        {
            let port_id = entry.file_name();
            return Ok(PathBuf::from("/dev").join(port_id));
        }
    }

    Err(AgentdError::SerialPortNotFound(format!(
        "no virtio port with name '{name}' found"
    )))
}
