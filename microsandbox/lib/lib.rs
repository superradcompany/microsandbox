//! `microsandbox` is the core library for the microsandbox project.

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Returns a hello world message.
pub fn hello() -> &'static str {
    "Hello, microsandbox!"
}
