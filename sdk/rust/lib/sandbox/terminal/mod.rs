//! Host terminal integration shared by interactive sandbox sessions.

mod encoding;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) use windows::{
    WindowsTerminalEvent, WindowsTerminalEventPump, WindowsTerminalGuard, current_terminal_size,
};
