//! Owner-private catalog storage. Unix permission checks exclude root and same-user attackers.

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos_acl;
#[cfg(all(test, target_os = "macos"))]
mod macos_acl_tests;
mod storage;
#[cfg(test)]
mod tests;

#[cfg(unix)]
pub use storage::{PRIVATE_DATABASE_DIRECTORY_MODE, PRIVATE_DATABASE_FILE_MODE};
pub use storage::{
    ensure_private_database_directory, harden_database_files, prepare_database_file,
};
