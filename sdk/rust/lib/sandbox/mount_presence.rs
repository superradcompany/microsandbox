//! Private evidence for omitted guest ownership defaults; never source-host identity.

use microsandbox_types::{MountOptions, VolumeMount, canonicalize_volume_mounts};
use serde::{Deserialize, Serialize};
use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MountKind {
    Owned,
    Bind,
    Named,
    Tmpfs,
    DiskImage,
}

/// Certifies only `override_uid == None && override_gid == None` for this guest mount.
/// Changing kind/path or either override invalidates it. It says nothing about backing.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DefaultMountOwnership {
    kind: MountKind,
    guest: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DefaultMountOwnership {
    pub(crate) fn for_mount(mount: &VolumeMount) -> Option<Self> {
        let (kind, options) = match mount {
            VolumeMount::Owned { options, .. } => (MountKind::Owned, options),
            VolumeMount::Bind { options, .. } => (MountKind::Bind, options),
            VolumeMount::Named { options, .. } => (MountKind::Named, options),
            VolumeMount::Tmpfs { options, .. } => (MountKind::Tmpfs, options),
            VolumeMount::DiskImage { options, .. } => (MountKind::DiskImage, options),
        };
        if options.override_uid.is_some() || options.override_gid.is_some() {
            return None;
        }
        // Builders canonicalize guest paths after layering. Normalize only this synthetic
        // guest path with the same grammar; never copy or resolve the mount's host path.
        let mut probe = VolumeMount::Tmpfs {
            guest: mount.guest().to_owned(),
            size_mib: None,
            options: MountOptions::default(),
        };
        canonicalize_volume_mounts(std::slice::from_mut(&mut probe)).ok()?;
        Some(Self {
            kind,
            guest: probe.guest().to_owned(),
        })
    }

    pub(crate) fn recorded_options(raw: &Value) -> Option<Self> {
        let options = raw.get("options")?.as_object()?;
        // These flags are always serialized by this producer. If any disappeared, retire
        // the ownership hint before decoding can manufacture policy on a later rewrite.
        if ["readonly", "noexec", "nosuid", "nodev"]
            .iter()
            .any(|field| !options.contains_key(*field))
        {
            return None;
        }
        let kind = match raw.get("type")?.as_str()? {
            "Owned" => MountKind::Owned,
            "Bind" => MountKind::Bind,
            "Named" => MountKind::Named,
            "Tmpfs" => MountKind::Tmpfs,
            "DiskImage" => MountKind::DiskImage,
            _ => return None,
        };
        Some(Self {
            kind,
            guest: raw.get("guest")?.as_str()?.to_owned(),
        })
    }
}
