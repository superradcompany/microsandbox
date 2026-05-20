use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::sandbox::{
    DiskImageFormat as RustDiskImageFormat, HostPermissions as RustHostPermissions,
    MountBuilder as RustMountBuilder, StatVirtualization as RustStatVirtualization,
    VolumeMount as RustVolumeMount,
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
    pub host: Option<String>,
    pub name: Option<String>,
    pub size_mib: Option<u32>,
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
/// `.disk(...)`, then chain modifiers (`.readonly()`, `.size(mib)` for
/// tmpfs, `.format(fmt)` / `.fstype(s)` for disk). Validation is deferred
/// to the terminal `.build()` call.
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

    /// Tmpfs size cap in MiB (only valid with `.tmpfs()`).
    #[napi]
    pub fn size(&mut self, mib: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.size(Mebibytes::from(mib)));
        self
    }

    /// Set the guest stat virtualization policy.
    ///
    /// Accepts `"strict"`, `"relaxed"`, or `"off"`. Valid only for bind and
    /// named volume mounts.
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
    /// Accepts `"private"` or `"mirror"`. Valid only for bind and named volume
    /// mounts.
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

    /// Materialize the mount spec. Returns a flat `BuiltVolumeMount`
    /// with a `kind` discriminator and per-variant fields.
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
            readonly,
            stat_virtualization,
            host_permissions,
        } => JsBuiltVolumeMount {
            kind: "bind".into(),
            guest,
            readonly,
            host: Some(host.to_string_lossy().into_owned()),
            name: None,
            size_mib: None,
            format: None,
            fstype: None,
            stat_virtualization: Some(sv_str(stat_virtualization)),
            host_permissions: Some(hp_str(host_permissions)),
        },
        RustVolumeMount::Named {
            name,
            guest,
            readonly,
            stat_virtualization,
            host_permissions,
        } => JsBuiltVolumeMount {
            kind: "named".into(),
            guest,
            readonly,
            host: None,
            name: Some(name),
            size_mib: None,
            format: None,
            fstype: None,
            stat_virtualization: Some(sv_str(stat_virtualization)),
            host_permissions: Some(hp_str(host_permissions)),
        },
        RustVolumeMount::Tmpfs {
            guest,
            size_mib,
            readonly,
        } => JsBuiltVolumeMount {
            kind: "tmpfs".into(),
            guest,
            readonly,
            host: None,
            name: None,
            size_mib,
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
            readonly,
        } => JsBuiltVolumeMount {
            kind: "disk".into(),
            guest,
            readonly,
            host: Some(host.to_string_lossy().into_owned()),
            name: None,
            size_mib: None,
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
