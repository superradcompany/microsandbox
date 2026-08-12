//! Host local-IPC backends for microsandbox virtio-vsock routes.

mod common;
#[cfg(unix)]
mod dgram;
#[cfg(unix)]
mod stream;
#[cfg(windows)]
mod windows;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
pub use dgram::UnixDatagramPortBackend;
#[cfg(unix)]
pub use stream::UnixStreamPortBackend;
#[cfg(windows)]
pub use windows::WindowsNamedPipePortBackend;
