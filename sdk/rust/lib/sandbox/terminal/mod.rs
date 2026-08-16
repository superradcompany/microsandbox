//! Host terminal integration shared by interactive sandbox sessions.

mod encoding;
#[cfg(windows)]
mod windows;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(windows)]
pub(crate) use windows::{
    WindowsTerminalEvent, WindowsTerminalEventPump, WindowsTerminalGuard, current_terminal_size,
};
