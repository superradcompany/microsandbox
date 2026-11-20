//! Atomic member retirement paired with its operation-owned head decision.

use std::path::Path;

use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn publish(
    group: &Path,
    id: &str,
    head: Option<String>,
) -> MicrosandboxResult<Vec<String>> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        super::generation::remove(group, id, head)
    }
    #[cfg(windows)]
    {
        publish_windows(group, id, head)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (id, head);
        Err(crate::MicrosandboxError::InvalidConfig(format!(
            "atomic checkpoint removal is unavailable at {}: this platform has no qualified atomic publisher",
            group.display()
        )))
    }
}

#[cfg(windows)]
fn publish_windows(
    group: &Path,
    id: &str,
    head: Option<String>,
) -> MicrosandboxResult<Vec<String>> {
    super::txf::check(group).map_err(|error| {
        crate::MicrosandboxError::InvalidConfig(
            error
                .to_string()
                .replace("atomic snapshot import", "atomic checkpoint removal"),
        )
    })?;
    let (receipt, _receipt_lock) =
        super::super::deletion::prepare_retirement(group, std::ffi::OsStr::new(id))?;
    super::write_group(&receipt, head)?;
    let mut transaction = super::txf::Transaction::new()?;
    transaction.rename(&group.join(id), &receipt.join("payload"), false)?;
    transaction.rename(
        &receipt.join(super::GROUP_FILENAME),
        &group.join(super::GROUP_FILENAME),
        true,
    )?;
    #[cfg(test)]
    publication_boundary(group, "prepared");
    transaction.commit().map_err(|error| super::integrity(format!(
        "checkpoint removal commit is unconfirmed: {error}; recovery receipt retained at {}; recover the group before retrying", receipt.display()
    )))?;
    #[cfg(test)]
    publication_boundary(group, "committed");
    // Catalog roots remain until the caller commits their removal or recovery observes
    // the missing source. A cleanup error cannot turn a committed removal into a rollback.
    if let Err(error) = std::fs::remove_dir_all(receipt.join("payload")) {
        return Ok(vec![format!(
            "checkpoint removal committed; cleanup remains at {}: {error}",
            receipt.display()
        )]);
    }
    Ok(Vec::new())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Process-scoped hook only present in test executables. The controlling test kills the
/// worker at this boundary to exercise recovery without changing production behavior.
#[cfg(test)]
pub(super) fn publication_boundary(group: &Path, boundary: &str) {
    use std::io::Write;
    if std::env::var_os("MSB_TEST_REMOVAL_GROUP").as_deref() == Some(group.as_os_str())
        && std::env::var("MSB_TEST_REMOVAL_BOUNDARY").as_deref() == Ok(boundary)
    {
        println!("ATOMIC_REMOVAL_BOUNDARY_READY");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }
}

#[cfg(test)]
#[path = "removal_tests.rs"]
mod tests;
