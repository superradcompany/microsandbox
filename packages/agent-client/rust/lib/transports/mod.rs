//! Native byte transports for the shared agent client.

/// Windows named-pipe transport support.
#[cfg(all(feature = "named-pipe", windows))]
pub mod named_pipe;

/// Unix domain socket transport support.
#[cfg(all(feature = "uds", unix))]
pub mod uds;
