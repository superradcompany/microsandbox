//! Execution types for running commands inside sandboxes.

mod io;
mod session;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub(crate) use io::InputWindow;
pub use session::{
    ExecControl, ExecEvent, ExecHandle, ExecOptions, ExecOptionsBuilder, ExecOutput, ExecSink,
    ExitStatus, Rlimit, RlimitResource, StdinMode,
};
pub(crate) use session::{agent, validate_rlimits};
