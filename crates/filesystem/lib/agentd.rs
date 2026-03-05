//! Embedded agentd binary for inclusion in guest filesystem images.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The agentd binary, embedded at compile time.
pub const AGENTD_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/agentd"));
