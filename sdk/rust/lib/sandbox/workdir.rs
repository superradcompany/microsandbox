//! Sandbox workdir validation, shared by create, the builder and modify.

use crate::MicrosandboxResult;

use super::{FsEntryKind, Sandbox};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate a sandbox workdir: a non-empty absolute guest path without NUL.
/// agentd refuses an empty or NUL-bearing one at boot, and an init handoff a
/// relative one. Checked textually, since `Path::is_absolute` follows host
/// rules.
pub(crate) fn validate_workdir(workdir: Option<&str>) -> MicrosandboxResult<()> {
    let Some(workdir) = workdir else {
        return Ok(());
    };
    if workdir.is_empty() {
        return Err(crate::MicrosandboxError::InvalidConfig(
            "workdir must not be empty".into(),
        ));
    }
    if workdir.contains('\0') {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "workdir must not contain NUL: {workdir:?}"
        )));
    }
    if !workdir.starts_with('/') {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "workdir must be an absolute guest path, got: {workdir:?}"
        )));
    }
    Ok(())
}

/// Check that `workdir` is a directory inside the running guest.
pub(crate) async fn validate_guest_workdir(
    sandbox: &Sandbox,
    workdir: &str,
) -> MicrosandboxResult<()> {
    match sandbox.fs().stat(workdir).await {
        Ok(metadata) if metadata.kind == FsEntryKind::Directory => Ok(()),
        Ok(_) => Err(crate::MicrosandboxError::InvalidConfig(format!(
            "workdir is not a directory in guest: {workdir}"
        ))),
        // A fast-exiting startup command can close the transport during stat.
        // Preserve that cause instead of claiming the directory is missing.
        Err(cause) => Err(crate::MicrosandboxError::InvalidConfig(format!(
            "could not validate workdir in guest {workdir:?}: {cause}"
        ))),
    }
}
