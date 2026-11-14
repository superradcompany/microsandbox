//! Opt-in limits for a self-contained raw-disk archive. The ordinary importer
//! keeps accepting its existing archive formats and dependency workflows.

use std::future::Future;
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};

use microsandbox_types::SnapshotManifest;
use microsandbox_types::snapshot::SnapshotFormat;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_ENTRIES: usize = 256;
const MAX_PATH_BYTES: usize = 4096;
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const ENTRY_HEADROOM: u64 = 64 * 1024;
// The supported archive has at most three metadata members (descriptor,
// labels and inventory). Cover their maximum size plus every entry's fixed
// allocation allowance, separately from the raw disk's copy allowance.
const IMPORT_HEADROOM: u64 = 3 * MAX_METADATA_BYTES * 4 + MAX_ENTRIES as u64 * ENTRY_HEADROOM;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct ImportBudget {
    remaining: u64,
    maximum_disk: u64,
    entries: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ImportBudget {
    fn charge(&mut self, path: &Path, header: &tokio_tar::Header) -> MicrosandboxResult<()> {
        self.entries += 1;
        if self.entries > MAX_ENTRIES || path.as_os_str().len() > MAX_PATH_BYTES {
            return Err(invalid(
                "bounded snapshot import exceeds its entry or path limit",
            ));
        }
        let components: Vec<_> = path
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => name.to_str(),
                _ => None,
            })
            .collect();
        if components.iter().any(|component| {
            matches!(
                *component,
                "cache" | "images" | "checkpoints" | "owned" | "owned-volumes"
            )
        }) {
            return Err(invalid(
                "bounded snapshot import accepts disk-only payloads without bundled images or volumes",
            ));
        }
        // Header::size reads the logical size of GNU sparse members. Using the
        // encoded size here would allow a tiny archive to create a huge file.
        let apparent = header.size()?;
        let metadata = matches!(components.as_slice(), ["archive.json"])
            || components.last().is_some_and(|name| {
                matches!(*name, "snapshot.json" | "manifest.json" | "metadata.json")
            });
        let limit = if metadata {
            MAX_METADATA_BYTES
        } else {
            self.maximum_disk
        };
        if apparent > limit {
            return Err(invalid(
                "snapshot import member exceeds the maximum disk size or metadata limit",
            ));
        }
        // This profile admits exactly one raw layer and no dependency sources.
        // Four copies cover extraction, layer placement, descriptor
        // normalization and publication, without relying on reflink support.
        let cost = apparent
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(ENTRY_HEADROOM))
            .ok_or_else(|| invalid("snapshot import byte bound overflow"))?;
        self.remaining = self
            .remaining
            .checked_sub(cost)
            .ok_or_else(|| invalid("snapshot import exceeds its aggregate byte budget"))?;
        Ok(())
    }

    fn verify_manifest(&self, manifest: &SnapshotManifest) -> MicrosandboxResult<()> {
        let Some(file) = manifest.state.as_file() else {
            return Err(invalid("bounded import requires a disk-only snapshot"));
        };
        if file.virtual_size == 0
            || file.virtual_size > self.maximum_disk
            || file.layers.len() != 1
            || file.disk_format != SnapshotFormat::Raw
            || file.layers.iter().any(|layer| {
                layer.format != SnapshotFormat::Raw
                    || layer.virtual_size != file.virtual_size
                    || layer.backing.is_some()
            })
            || !manifest.owned_volumes()?.is_empty()
        {
            return Err(invalid(
                "bounded import requires one self-contained raw disk within the maximum disk size",
            ));
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn active() -> bool {
    BUDGET.try_with(|_| ()).is_ok()
}

pub(crate) fn peak_bytes(maximum_disk: u64) -> MicrosandboxResult<u64> {
    if maximum_disk == 0 {
        return Err(invalid("snapshot maximum disk size must be positive"));
    }
    maximum_disk
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(IMPORT_HEADROOM))
        .ok_or_else(|| invalid("snapshot import byte bound overflow"))
}

pub(crate) async fn scope<F, T>(maximum_disk: u64, operation: F) -> MicrosandboxResult<T>
where
    F: Future<Output = MicrosandboxResult<T>>,
{
    let bytes = peak_bytes(maximum_disk)?;
    BUDGET
        .scope(
            Arc::new(Mutex::new(ImportBudget {
                remaining: bytes,
                maximum_disk,
                entries: 0,
            })),
            operation,
        )
        .await
}

pub(crate) fn charge(path: &Path, header: &tokio_tar::Header) -> MicrosandboxResult<()> {
    BUDGET
        .try_with(|budget| {
            budget
                .lock()
                .map_err(|_| invalid("snapshot import budget poisoned"))?
                .charge(path, header)
        })
        .unwrap_or(Ok(()))
}

pub(crate) fn verify_manifest(manifest: &SnapshotManifest) -> MicrosandboxResult<()> {
    BUDGET
        .try_with(|budget| {
            budget
                .lock()
                .map_err(|_| invalid("snapshot import budget poisoned"))?
                .verify_manifest(manifest)
        })
        .unwrap_or(Ok(()))
}

fn invalid(message: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(message.into())
}

//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------

tokio::task_local! {
    static BUDGET: Arc<Mutex<ImportBudget>>;
}
