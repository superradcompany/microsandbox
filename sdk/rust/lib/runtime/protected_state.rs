//! Host configuration admission for sandbox storage, shared by launch and stopped operations.

use std::path::Path;

use microsandbox_runtime::checkpoint::layout::{self, LegacyRootBinding};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

use crate::backend::local::creation::CreationStorage;
use crate::sandbox::{RootDisk, RootfsSource, SandboxConfig};
use crate::{LocalBackend, MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Caller owns the sandbox lifecycle and creation/storage guards for the entire operation.
pub(crate) async fn prepare(
    backend: &LocalBackend,
    config: &SandboxConfig,
    storage: &CreationStorage,
) -> MicrosandboxResult<()> {
    let db = backend.db().await?;
    let row = db
        .write()
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT id, creation_state FROM sandbox WHERE name = ?",
            [config.spec.name.clone().into()],
        ))
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(config.spec.name.clone()))?;
    let id: i32 = row.try_get("", "id")?;
    let creating: Option<String> = row.try_get("", "creation_state")?;
    // Commit before touching files: the downgrade preflight must see crash-interrupted admission.
    db.write().execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
        "INSERT INTO protected_sandbox_state (sandbox_id, layout_version) VALUES (?, 1) ON CONFLICT(sandbox_id) DO NOTHING",
        [id.into()],
    )).await?;
    let binding = root_binding(config, storage.path());
    // Admission performs bounded metadata work only. Keep it in this poll so cancellation
    // cannot release the caller's lifecycle guard while a detached blocking worker migrates.
    let runtime = storage.join("runtime");
    let result = if creating.is_some() {
        layout::initialize_new(&runtime)
    } else {
        layout::prepare(&runtime, binding.as_ref())
    };
    result.map_err(MicrosandboxError::Runtime)
}

/// A live legacy VM cannot be migrated under its lifecycle lock. Its checkpoint and disk
/// journals remain guest-writable until a protected restart, so do not consume them as authority.
pub(crate) fn require_running(backend: &LocalBackend, name: &str) -> MicrosandboxResult<()> {
    layout::require_ready(&backend.sandboxes_dir().join(name).join("runtime")).map_err(|_| {
        MicrosandboxError::Runtime(format!(
            "upgrade required: sandbox '{name}' is not running with protected sandbox state. \
             Update the SDK/CLI and runtime, then stop and restart this sandbox before taking \
             snapshots, forking, growing disks, or compacting disks. Exec and stop remain available."
        ))
    })
}

fn root_binding(config: &SandboxConfig, sandbox: &Path) -> Option<LegacyRootBinding> {
    let RootfsSource::Oci(oci) = &config.spec.image else {
        return None;
    };
    let (path, format, flat) = match &oci.root_disk {
        Some(RootDisk::Flat { .. }) => (sandbox.join("rootfs.raw"), "raw".to_owned(), true),
        Some(RootDisk::DiskImage { path, format, .. }) => (path.clone(), format.to_string(), false),
        _ => (sandbox.join("upper.ext4"), "raw".to_owned(), false),
    };
    Some(LegacyRootBinding { path, format, flat })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn live_storage_requires_completed_protection_without_migrating_the_source() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = crate::test_support::local_backend_builder(temporary.path())
            .build()
            .await
            .unwrap();
        let sandbox = backend.sandboxes_dir().join("source");
        std::fs::create_dir_all(sandbox.join("runtime")).unwrap();
        let journal = sandbox.join("runtime/root-disk.json");
        std::fs::write(&journal, b"legacy authority").unwrap();
        let error = require_running(&backend, "source").unwrap_err().to_string();
        assert!(error.contains("upgrade required") && error.contains("stop and restart"));
        assert_eq!(std::fs::read(&journal).unwrap(), b"legacy authority");
        assert!(!sandbox.join("state-layout.json").exists());
        std::fs::remove_file(journal).unwrap();
        layout::initialize_new(&sandbox.join("runtime")).unwrap();
        require_running(&backend, "source").unwrap();
        std::fs::remove_dir(sandbox.join("runtime/heartbeat.json")).unwrap();
        assert!(require_running(&backend, "source").is_err());
    }
}
