use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::sandbox::{
    DiskImageFormat as RustDiskImageFormat, MountBuilder as RustMountBuilder,
};
use microsandbox::size::Mebibytes;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

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

    // Build is intentionally not exposed here — the sandbox builder
    // consumes `MountBuilder` via the `volume(...)` callback, which
    // invokes the underlying validation. Use that flow instead.
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
