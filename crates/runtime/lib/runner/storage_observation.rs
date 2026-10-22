//! In-memory evidence from filesystem backends actually admitted during VM construction.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use microsandbox_protocol::bootstrap::GuestBootstrap;
use microsandbox_types::snapshot::saved_config::MAX_SAVED_CONFIG_ENTRIES;

use crate::retention::MountedStorageEvidence;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Bound to the owning executor's VM lifetime. No paths, named-volume names, metadata
/// tokens or file contents are retained here. Missing/ambiguous entries stay unknown.
#[derive(Default)]
pub(crate) struct MountedFilesystemInventory {
    mounted: BTreeMap<String, MountedFilesystem>,
    ambiguous: BTreeSet<String>,
    exhausted: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MountedFilesystemInventory {
    /// Freeze the guest mapping from this VM's admitted bootstrap. A missing or
    /// contradictory entry stays unknown; no host source is reopened at capture.
    pub(crate) fn guest_evidence(&self, bootstrap: &GuestBootstrap) -> MountedStorageEvidence {
        let mut evidence = MountedStorageEvidence::default();
        // Several guest mappings can share one admitted tag. Bound the mapping itself,
        // not only the backend inventory, so optional evidence cannot fail capture later.
        if self.exhausted
            || bootstrap
                .file_mounts
                .len()
                .saturating_add(bootstrap.dir_mounts.len())
                > MAX_SAVED_CONFIG_ENTRIES
        {
            return evidence;
        }
        for guest in bootstrap
            .file_mounts
            .iter()
            .map(|m| &m.guest_path)
            .chain(bootstrap.dir_mounts.iter().map(|m| &m.guest_path))
        {
            if guest.len() <= 4096
                && guest.starts_with('/')
                && !guest.contains('\0')
                && let Some(observed) = self.for_guest(bootstrap, guest)
            {
                evidence.0.insert(guest.clone(), observed);
            }
        }
        evidence
    }

    /// Called only after backend construction succeeds. An unavailable placeholder is
    /// deliberately not registered. Optional observation must not change launch admission.
    pub(crate) fn record_available(
        &mut self,
        tag: &str,
        kind: MountedFilesystemKind,
        quota_bytes: Option<u64>,
    ) {
        if self.exhausted || self.ambiguous.contains(tag) {
            return;
        }
        if self.mounted.remove(tag).is_some() {
            self.ambiguous.insert(tag.to_owned());
            return;
        }
        if tag.len() > 4096 || self.mounted.len() + self.ambiguous.len() >= MAX_SAVED_CONFIG_ENTRIES
        {
            // Never present a truncated inventory as complete, and never fail an otherwise
            // supported launch merely because optional configuration evidence is too large.
            self.mounted.clear();
            self.ambiguous.clear();
            self.exhausted = true;
            return;
        }
        self.mounted
            .insert(tag.to_owned(), MountedFilesystem { kind, quota_bytes });
    }

    /// Resolve by the exact admitted guest transport, never by a source-host path or name.
    /// Contradictory bootstrap mappings cannot turn a file into a directory observation.
    pub(crate) fn for_guest(
        &self,
        bootstrap: &GuestBootstrap,
        guest: &str,
    ) -> Option<MountedFilesystem> {
        let mut bindings = bootstrap
            .file_mounts
            .iter()
            .filter(|mount| mount.guest_path == guest)
            .map(|mount| (mount.tag.as_str(), MountedFilesystemKind::File))
            .chain(
                bootstrap
                    .dir_mounts
                    .iter()
                    .filter(|mount| mount.guest_path == guest)
                    .map(|mount| (mount.tag.as_str(), MountedFilesystemKind::Directory)),
            );
        let (tag, expected) = bindings.next()?;
        if bindings.next().is_some() || self.exhausted || self.ambiguous.contains(tag) {
            return None;
        }
        let observed = *self.mounted.get(tag)?;
        (observed.kind == expected).then_some(observed)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for MountedFilesystemInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MountedFilesystemInventory")
            .field("available_count", &self.mounted.len())
            .field("ambiguous_count", &self.ambiguous.len())
            .field("exhausted", &self.exhausted)
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_protocol::bootstrap::{BootstrapDirMount, BootstrapMountFlags};

    use super::*;

    fn bootstrap() -> GuestBootstrap {
        let mut bootstrap = GuestBootstrap::default();
        bootstrap.dir_mounts.push(BootstrapDirMount {
            tag: "PRIVATE_TAG".into(),
            guest_path: "/data".into(),
            flags: BootstrapMountFlags::default(),
        });
        bootstrap
    }

    #[test]
    fn mounted_storage_keeps_zero_and_unlimited_distinct_without_host_lookup() {
        for quota in [None, Some(0), Some(32 * 1024 * 1024)] {
            let mut inventory = MountedFilesystemInventory::default();
            inventory.record_available("PRIVATE_TAG", MountedFilesystemKind::Directory, quota);
            assert_eq!(
                inventory.for_guest(&bootstrap(), "/data"),
                Some(MountedFilesystem {
                    kind: MountedFilesystemKind::Directory,
                    quota_bytes: quota,
                })
            );
            assert!(!format!("{inventory:?}").contains("PRIVATE"));
        }
    }

    #[test]
    fn mounted_storage_refuses_unavailable_contradictory_and_ambiguous_backing() {
        let mut inventory = MountedFilesystemInventory::default();
        assert!(inventory.for_guest(&bootstrap(), "/data").is_none());
        inventory.record_available("PRIVATE_TAG", MountedFilesystemKind::File, None);
        assert!(inventory.for_guest(&bootstrap(), "/data").is_none());
        inventory.record_available("PRIVATE_TAG", MountedFilesystemKind::Directory, None);
        inventory.record_available("PRIVATE_TAG", MountedFilesystemKind::Directory, None);
        assert!(inventory.for_guest(&bootstrap(), "/data").is_none());
    }

    #[test]
    fn mounted_storage_duplicate_guest_mapping_is_never_selected_arbitrarily() {
        let mut inventory = MountedFilesystemInventory::default();
        inventory.record_available("PRIVATE_TAG", MountedFilesystemKind::Directory, None);
        let mut bootstrap = bootstrap();
        bootstrap.dir_mounts.push(bootstrap.dir_mounts[0].clone());
        assert!(inventory.for_guest(&bootstrap, "/data").is_none());
    }

    #[test]
    fn mounted_storage_bounds_guest_aliases_independently_of_backend_count() {
        let mut inventory = MountedFilesystemInventory::default();
        inventory.record_available("PRIVATE_TAG", MountedFilesystemKind::Directory, None);
        let mut bootstrap = bootstrap();
        for index in 0..MAX_SAVED_CONFIG_ENTRIES {
            let mut alias = bootstrap.dir_mounts[0].clone();
            alias.guest_path = format!("/alias{index}");
            bootstrap.dir_mounts.push(alias);
        }
        assert!(!inventory.exhausted);
        assert!(inventory.guest_evidence(&bootstrap).0.is_empty());
    }

    #[test]
    fn mounted_storage_exhaustion_does_not_keep_a_truncated_trusted_prefix() {
        let mut inventory = MountedFilesystemInventory::default();
        inventory.record_available("PRIVATE_TAG", MountedFilesystemKind::Directory, None);
        for index in 0..MAX_SAVED_CONFIG_ENTRIES {
            inventory.record_available(
                &format!("tag{index}"),
                MountedFilesystemKind::Directory,
                None,
            );
        }
        assert!(inventory.for_guest(&bootstrap(), "/data").is_none());
        assert!(inventory.exhausted && inventory.mounted.is_empty());
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub(crate) use crate::retention::{MountedFilesystem, MountedFilesystemKind};
