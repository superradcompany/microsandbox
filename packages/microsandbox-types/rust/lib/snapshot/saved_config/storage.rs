//! Portable guest mount and IPC requirements, never executable source-host bindings.

use serde::{Deserialize, Serialize};

use super::value::deserialize_present;
use super::{SavedBindingReference, SavedValue};
use crate::{
    DiskImageFormat, HostPermissions, MountOptions, OwnedVolumeStorage, StatVirtualization,
    VsockSocketType,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Storage defaults and required external resources. Full-state identity must also be
/// established from the authoritative checkpoint; this record cannot waive that check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedStorageConfig {
    /// Complete normalized mount list when known; owned backing stays in its existing extension.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub mounts: Option<SavedValue<Vec<SavedMount>>>,
    /// Guest-side socket routes, excluding source host socket or named-pipe paths.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub vsock: Option<SavedValue<Vec<SavedVsockRoute>>>,
}

/// Strict common mount flags; no source host owner or path is stored.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedMountOptions {
    /// Reject guest writes.
    pub readonly: bool,
    /// Forbid direct execution from this mount.
    pub noexec: bool,
    /// Ignore setuid/setgid bits.
    pub nosuid: bool,
    /// Ignore device nodes.
    pub nodev: bool,
    /// Guest-presented ownership; must be paired and requires a virtiofs overlay.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub override_uid: Option<u32>,
    /// Guest-presented group, paired with override_uid.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub override_gid: Option<u32>,
}

/// Backing kind observed for a bind root; do not infer it from a source filename suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedBindRootKind {
    /// One ordinary file exported through the runtime filesystem share.
    File,
    /// A directory tree exported through the runtime filesystem share.
    Directory,
}

/// Observed named-volume storage. No creation mode or source-local volume name is reusable.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedNamedStorage {
    /// Directory quota; omission retains its unlimited/default source policy.
    Directory {
        /// Source-configured write quota in MiB, including an explicit zero.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_present"
        )]
        quota_mib: Option<u32>,
    },
    /// Named ext4 disk with a known positive capacity.
    Disk {
        /// Required disk capacity in MiB, not a destination grow/shrink request.
        capacity_mib: u32,
    },
}

/// Each kind retains its guest-visible semantics while replacing source-host references.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedMount {
    /// Next-start owned-storage declaration, never evidence of captured private backing.
    /// Only pending configuration may contain this variant.
    RequestedOwned {
        /// Canonical guest destination, without a captured mount identity.
        guest: String,
        /// Requested future storage; no data or payload membership is implied.
        storage: OwnedVolumeStorage,
        /// Requested guest mount policy.
        options: SavedMountOptions,
        /// Requested guest metadata behavior.
        stat_virtualization: StatVirtualization,
        /// Requested host permission behavior, not authorization to apply it.
        host_permissions: HostPermissions,
    },
    /// Exact reference to existing captured private backing; no duplicate options/layout.
    Owned {
        /// Canonical guest destination.
        guest: String,
        /// Existing owned-volume identity derived from guest, never a host directory.
        mount_id: String,
    },
    /// Host file or directory supplied by a destination binding.
    Bind {
        /// Canonical guest destination.
        guest: String,
        /// Observed file/directory kind, checked again against the destination.
        root_kind: SavedBindRootKind,
        /// Destination filesystem binding.
        binding: SavedBindingReference,
        /// Guest mount policy; a saved relaxation is not destination permission.
        options: SavedMountOptions,
        /// Guest metadata behavior.
        stat_virtualization: StatVirtualization,
        /// Host permission behavior; mirror requires explicit destination approval.
        host_permissions: HostPermissions,
        /// Recorded source policy, never approval to follow a destination symlink.
        follow_root_symlinks: bool,
        /// Source write quota in MiB; no counters are inherited.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_present"
        )]
        quota_mib: Option<u32>,
    },
    /// Existing named storage supplied explicitly at the destination.
    Named {
        /// Canonical guest destination.
        guest: String,
        /// Destination named-volume binding; never look up a same-named source volume.
        binding: SavedBindingReference,
        /// Observed active storage kind/capacity, not transient ensure/create intent.
        storage: SavedNamedStorage,
        /// Guest mount policy.
        options: SavedMountOptions,
        /// Directory metadata behavior; strict for disk storage.
        stat_virtualization: StatVirtualization,
        /// Directory host permission behavior; private for disk storage.
        host_permissions: HostPermissions,
        /// Recorded policy; explicit destination authorization remains required.
        follow_root_symlinks: bool,
    },
    /// An external disk image, whose layout/backing is validated before activation.
    DiskImage {
        /// Canonical guest destination.
        guest: String,
        /// Destination disk-image resource.
        binding: SavedBindingReference,
        /// Existing disk-image format vocabulary.
        format: DiskImageFormat,
        /// Inner guest filesystem; omission preserves the existing probe behavior.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_present"
        )]
        fstype: Option<String>,
        /// Guest mount flags; host ownership overrides are invalid for block mounts.
        options: SavedMountOptions,
    },
    /// Guest-memory filesystem. Disk boot starts empty; full resume retains captured contents.
    Tmpfs {
        /// Canonical guest destination.
        guest: String,
        /// Guest memory cap in MiB, without a claim that disk capture contains its data.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_present"
        )]
        size_mib: Option<u32>,
        /// Guest mount flags.
        options: SavedMountOptions,
    },
}

/// Guest socket semantics and a logical destination endpoint.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedVsockRoute {
    /// Guest-to-host port; zero, wildcard and the reserved datagram clock port are invalid.
    pub port: u32,
    /// Existing stream/datagram vocabulary, with independent port namespaces.
    pub socket_type: VsockSocketType,
    /// Destination Unix socket or local Windows pipe, never the original host path.
    pub binding: SavedBindingReference,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedMount {
    /// Canonical guest identity used for ordering, collision and checkpoint checks.
    pub fn guest(&self) -> &str {
        match self {
            Self::Owned { guest, .. }
            | Self::RequestedOwned { guest, .. }
            | Self::Bind { guest, .. }
            | Self::Named { guest, .. }
            | Self::DiskImage { guest, .. }
            | Self::Tmpfs { guest, .. } => guest,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<&MountOptions> for SavedMountOptions {
    fn from(value: &MountOptions) -> Self {
        // Exhaustive projection: a new host-affecting option requires a policy decision.
        let MountOptions {
            readonly,
            noexec,
            nosuid,
            nodev,
            override_uid,
            override_gid,
        } = value;
        Self {
            readonly: *readonly,
            noexec: *noexec,
            nosuid: *nosuid,
            nodev: *nodev,
            override_uid: *override_uid,
            override_gid: *override_gid,
        }
    }
}

impl From<SavedMountOptions> for MountOptions {
    fn from(value: SavedMountOptions) -> Self {
        Self {
            readonly: value.readonly,
            noexec: value.noexec,
            nosuid: value.nosuid,
            nodev: value.nodev,
            override_uid: value.override_uid,
            override_gid: value.override_gid,
        }
    }
}
