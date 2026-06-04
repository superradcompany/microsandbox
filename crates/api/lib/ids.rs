//! Identifier generation.

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Generate a local Devbox ID that is also a valid Microsandbox sandbox name.
pub fn new_devbox_id() -> String {
    format!("dbx_{}", uuid::Uuid::new_v4().simple())
}

/// Generate a local execution ID.
pub fn new_execution_id() -> String {
    format!("exec_{}", uuid::Uuid::new_v4().simple())
}
