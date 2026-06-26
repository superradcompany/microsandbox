use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::VolumeKind as RustVolumeKind;
use microsandbox::sandbox::{
    DiskImageFormat as RustDiskImageFormat, HostPermissions as RustHostPermissions,
    MountBuilder as RustMountBuilder, NamedVolumeMode as RustNamedVolumeMode,
    StatVirtualization as RustStatVirtualization, VolumeMount as RustVolumeMount,
};
use microsandbox::size::Mebibytes;

use crate::error::to_napi_error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Volume mount specification produced by `MountBuilder.build()`.
/// Flat representation of the `VolumeMount` enum: `kind`
/// discriminator + per-variant fields.
#[derive(Clone)]
#[napi(object, js_name = "VolumeMount")]
pub struct JsBuiltVolumeMount {
    pub kind: String,
    pub guest: String,
    pub readonly: bool,
    pub noexec: bool,
    pub nosuid: bool,
    pub nodev: bool,
    pub host: Option<String>,
    pub name: Option<String>,
    pub named_mode: Option<String>,
    pub named_kind: Option<String>,
    pub size_mib: Option<u32>,
    pub quota_mib: Option<u32>,
    pub format: Option<String>,
    pub fstype: Option<String>,
    /// `"strict" | "relaxed" | "off"` for bind/named mounts; `None` for tmpfs/disk.
    pub stat_virtualization: Option<String>,
    /// `"private" | "mirror"` for bind/named mounts; `None` for tmpfs/disk.
    pub host_permissions: Option<String>,
}

/// Fluent builder for a sandbox volume mount.
///
/// Pick exactly one mount kind via `.bind()`, `.named()`, `.tmpfs()`, or
/// `.disk(...)`, then chain modifiers (`.readonly()`, `.noexec()`, `.nosuid()`, `.nodev()`,
/// `.size(mib)` for tmpfs, `.format(fmt)` / `.fstype(s)` for disk).
/// Validation is deferred to the terminal `.build()` call.
#[napi(js_name = "MountBuilder")]
pub struct JsMountBuilder {
    inner: Option<RustMountBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsMountBuilder {
    #[napi(constructor)]
    pub fn new(guest: String) -> Self {
        Self {
            inner: Some(RustMountBuilder::new(guest)),
        }
    }

    /// Bind a host directory at the guest path.
    #[napi]
    pub fn bind(&mut self, host: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.bind(PathBuf::from(host)));
        self
    }

    /// Mount a named volume created via `Volume.builder(name).create()`.
    #[napi]
    pub fn named(&mut self, name: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.named(name));
        self
    }

    /// Mount a named volume with explicit existence behavior.
    #[napi]
    pub fn named_with(
        &mut self,
        name: String,
        mode: Option<String>,
        kind: Option<String>,
        size_mib: Option<u32>,
        quota_mib: Option<u32>,
    ) -> napi::Result<&Self> {
        let mode = mode.unwrap_or_else(|| "existing".to_string());
        let kind = kind.unwrap_or_else(|| "dir".to_string());
        if !matches!(mode.as_str(), "existing" | "create" | "ensure-exists") {
            return Err(napi::Error::new(
                Status::InvalidArg,
                format!("invalid named volume mode {mode:?}"),
            ));
        }
        if !matches!(kind.as_str(), "dir" | "directory" | "disk") {
            return Err(napi::Error::new(
                Status::InvalidArg,
                format!("invalid named volume kind {kind:?}"),
            ));
        }
        let prev = self.take_inner();
        self.inner = Some(prev.named_with(name, |mut v| {
            v = match mode.as_str() {
                "existing" => v.existing(),
                "create" => v.create(),
                "ensure-exists" => v.ensure_exists(),
                _ => unreachable!("validated named volume mode"),
            };
            v = match kind.as_str() {
                "dir" | "directory" => v.directory(),
                "disk" => v.disk(),
                _ => unreachable!("validated named volume kind"),
            };
            if let Some(size_mib) = size_mib {
                v = v.size(size_mib);
            }
            if let Some(quota_mib) = quota_mib {
                v = v.quota(quota_mib);
            }
            v
        }));
        Ok(self)
    }

    /// Mount an in-memory tmpfs at the guest path.
    #[napi]
    pub fn tmpfs(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.tmpfs());
        self
    }

    /// Mount a host disk image file as a virtio-blk device.
    #[napi]
    pub fn disk(&mut self, host: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.disk(PathBuf::from(host)));
        self
    }

    /// Override the disk image format (`"qcow2" | "raw" | "vmdk"`). Only
    /// valid when paired with `.disk()`.
    #[napi]
    pub fn format(&mut self, format: String) -> Result<&Self> {
        let f = match format.as_str() {
            "qcow2" => RustDiskImageFormat::Qcow2,
            "raw" => RustDiskImageFormat::Raw,
            "vmdk" => RustDiskImageFormat::Vmdk,
            other => {
                return Err(napi::Error::from_reason(format!(
                    "invalid disk image format `{other}` (expected qcow2 | raw | vmdk)"
                )));
            }
        };
        let prev = self.take_inner();
        self.inner = Some(prev.format(f));
        Ok(self)
    }

    /// Inner filesystem type for a `.disk()` mount (e.g. `"ext4"`).
    #[napi]
    pub fn fstype(&mut self, fstype: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.fstype(fstype));
        self
    }

    /// Mark the mount read-only.
    #[napi]
    pub fn readonly(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.readonly());
        self
    }

    /// Prevent direct execution from the mount.
    #[napi]
    pub fn noexec(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.noexec());
        self
    }

    /// Ignore setuid and setgid privilege elevation from files on the mount.
    #[napi]
    pub fn nosuid(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.nosuid());
        self
    }

    /// Ignore device files on the mount.
    #[napi]
    pub fn nodev(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.nodev());
        self
    }

    /// Tmpfs size cap in MiB (only valid with `.tmpfs()`).
    #[napi]
    pub fn size(&mut self, mib: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.size(Mebibytes::from(mib)));
        self
    }

    /// Guest-write quota in MiB (only valid with `.bind()`).
    ///
    /// Bounds how much the guest may add beyond the bind-mounted directory's
    /// existing contents. Without it, a protective default is applied.
    #[napi]
    pub fn quota(&mut self, mib: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.quota(Mebibytes::from(mib)));
        self
    }

    /// Set the guest stat virtualization policy.
    ///
    /// Accepts `"strict"`, `"relaxed"`, or `"off"`. Valid only for bind and
    /// directory-backed named volume mounts.
    #[napi]
    pub fn stat_virtualization(&mut self, policy: String) -> Result<&Self> {
        let p = match policy.as_str() {
            "strict" => RustStatVirtualization::Strict,
            "relaxed" => RustStatVirtualization::Relaxed,
            "off" => RustStatVirtualization::Off,
            other => {
                return Err(napi::Error::from_reason(format!(
                    "invalid stat_virtualization `{other}` (expected strict | relaxed | off)"
                )));
            }
        };
        let prev = self.take_inner();
        self.inner = Some(prev.stat_virtualization(p));
        Ok(self)
    }

    /// Set the host permission propagation policy.
    ///
    /// Accepts `"private"` or `"mirror"`. Valid only for bind and
    /// directory-backed named volume mounts.
    #[napi]
    pub fn host_permissions(&mut self, policy: String) -> Result<&Self> {
        let p = match policy.as_str() {
            "private" => RustHostPermissions::Private,
            "mirror" => RustHostPermissions::Mirror,
            other => {
                return Err(napi::Error::from_reason(format!(
                    "invalid host_permissions `{other}` (expected private | mirror)"
                )));
            }
        };
        let prev = self.take_inner();
        self.inner = Some(prev.host_permissions(p));
        Ok(self)
    }

    /// Materialize the mount spec. Returns a flat `VolumeMount` with a
    /// `kind` discriminator and per-variant fields.
    #[napi]
    pub fn build(&mut self) -> Result<JsBuiltVolumeMount> {
        let mount = self
            .inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("MountBuilder already consumed"))?
            .build()
            .map_err(to_napi_error)?;
        Ok(to_built_mount(mount))
    }
}

fn to_built_mount(mount: RustVolumeMount) -> JsBuiltVolumeMount {
    fn sv_str(s: RustStatVirtualization) -> String {
        match s {
            RustStatVirtualization::Strict => "strict",
            RustStatVirtualization::Relaxed => "relaxed",
            RustStatVirtualization::Off => "off",
        }
        .into()
    }
    fn hp_str(h: RustHostPermissions) -> String {
        match h {
            RustHostPermissions::Private => "private",
            RustHostPermissions::Mirror => "mirror",
        }
        .into()
    }

    match mount {
        RustVolumeMount::Bind {
            host,
            guest,
            options,
            stat_virtualization,
            host_permissions,
            quota_mib,
        } => JsBuiltVolumeMount {
            kind: "bind".into(),
            guest,
            readonly: options.readonly,
            noexec: options.noexec,
            nosuid: options.nosuid,
            nodev: options.nodev,
            host: Some(host.to_string_lossy().into_owned()),
            name: None,
            named_mode: None,
            named_kind: None,
            size_mib: None,
            quota_mib,
            format: None,
            fstype: None,
            stat_virtualization: Some(sv_str(stat_virtualization)),
            host_permissions: Some(hp_str(host_permissions)),
        },
        RustVolumeMount::Named {
            name,
            guest,
            create,
            options,
            stat_virtualization,
            host_permissions,
        } => {
            let named_mode = create.as_ref().map(|create| match create.mode() {
                RustNamedVolumeMode::Existing => "existing".to_string(),
                RustNamedVolumeMode::Create => "create".to_string(),
                RustNamedVolumeMode::EnsureExists => "ensure-exists".to_string(),
            });
            let named_kind = create.as_ref().map(|create| match create.kind() {
                RustVolumeKind::Directory => "dir".to_string(),
                RustVolumeKind::Disk => "disk".to_string(),
            });
            let size_mib = create.as_ref().and_then(|create| create.capacity_mib());
            let quota_mib = create.as_ref().and_then(|create| create.quota_mib());

            JsBuiltVolumeMount {
                kind: "named".into(),
                guest,
                readonly: options.readonly,
                noexec: options.noexec,
                nosuid: options.nosuid,
                nodev: options.nodev,
                host: None,
                name: Some(name),
                named_mode,
                named_kind,
                size_mib,
                quota_mib,
                format: None,
                fstype: None,
                stat_virtualization: Some(sv_str(stat_virtualization)),
                host_permissions: Some(hp_str(host_permissions)),
            }
        }
        RustVolumeMount::Tmpfs {
            guest,
            size_mib,
            options,
        } => JsBuiltVolumeMount {
            kind: "tmpfs".into(),
            guest,
            readonly: options.readonly,
            noexec: options.noexec,
            nosuid: options.nosuid,
            nodev: options.nodev,
            host: None,
            name: None,
            named_mode: None,
            named_kind: None,
            size_mib,
            quota_mib: None,
            format: None,
            fstype: None,
            stat_virtualization: None,
            host_permissions: None,
        },
        RustVolumeMount::DiskImage {
            host,
            guest,
            format,
            fstype,
            options,
        } => JsBuiltVolumeMount {
            kind: "disk".into(),
            guest,
            readonly: options.readonly,
            noexec: options.noexec,
            nosuid: options.nosuid,
            nodev: options.nodev,
            host: Some(host.to_string_lossy().into_owned()),
            name: None,
            named_mode: None,
            named_kind: None,
            size_mib: None,
            quota_mib: None,
            format: Some(
                match format {
                    RustDiskImageFormat::Qcow2 => "qcow2",
                    RustDiskImageFormat::Raw => "raw",
                    RustDiskImageFormat::Vmdk => "vmdk",
                }
                .into(),
            ),
            fstype,
            stat_virtualization: None,
            host_permissions: None,
        },
    }
}

impl JsMountBuilder {
    fn take_inner(&mut self) -> RustMountBuilder {
        self.inner
            .take()
            .expect("MountBuilder used after consumption")
    }

    /// Internal: extract the underlying Rust builder. Used by
    /// `SandboxBuilder.volume()` to route through the public closure
    /// callback in the core SDK.
    #[allow(dead_code)]
    pub(crate) fn take_inner_builder(&mut self) -> Result<RustMountBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("MountBuilder already consumed"))
    }
}
