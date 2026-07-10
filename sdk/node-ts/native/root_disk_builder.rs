use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::sandbox::{
    DiskImageFormat as RustDiskImageFormat, RootDiskBuilder as RustRootDiskBuilder,
};
use microsandbox::size::Mebibytes;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for the writable rootfs layer (root disk) of an OCI image.
///
/// Used inside `ImageBuilder.rootDisk((d) => ...)`:
///
/// ```ts
/// .imageWith((i) => i.oci("python:3.12").rootDisk(8192))                       // managed, sized
/// .imageWith((i) => i.oci("python:3.12").rootDisk((d) => d.tmpfs().size(512))) // RAM-backed
/// .imageWith((i) => i.oci("python:3.12").rootDisk((d) => d.disk("./scratch.img").fstype("ext4")))
/// ```
#[napi(js_name = "RootDiskBuilder")]
pub struct JsRootDiskBuilder {
    inner: Option<RustRootDiskBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsRootDiskBuilder {
    #[napi(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustRootDiskBuilder::default()),
        }
    }

    /// Size in MiB. Valid for the managed (default) and tmpfs kinds; a
    /// user-supplied disk image is sized by the image file itself.
    #[napi]
    pub fn size(&mut self, mib: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.size(Mebibytes::from(mib)));
        self
    }

    /// Use a RAM-backed tmpfs upper. Ephemeral: the rootfs is pristine on
    /// every boot, and the size counts against guest memory.
    #[napi]
    pub fn tmpfs(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.tmpfs());
        self
    }

    /// Use a user-supplied disk image as the upper, attached writable. The
    /// format is derived from the file extension (`.img`/`.raw` → raw,
    /// `.qcow2` → qcow2) unless set explicitly with `.format()`.
    #[napi]
    pub fn disk(&mut self, path: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.disk_image(PathBuf::from(path)));
        self
    }

    /// Set the disk image format explicitly (`"raw" | "qcow2"`). Only valid
    /// after `.disk()`; vmdk is not supported as a root disk.
    #[napi]
    pub fn format(&mut self, format: String) -> Result<&Self> {
        let f = match format.as_str() {
            "qcow2" => RustDiskImageFormat::Qcow2,
            "raw" => RustDiskImageFormat::Raw,
            "vmdk" => RustDiskImageFormat::Vmdk,
            other => {
                return Err(napi::Error::from_reason(format!(
                    "invalid root disk image format `{other}` (expected raw | qcow2)"
                )));
            }
        };
        let prev = self.take_inner();
        self.inner = Some(prev.format(f));
        Ok(self)
    }

    /// Inner filesystem type of the disk image (e.g. `"ext4"`). Only valid
    /// after `.disk()`.
    #[napi]
    pub fn fstype(&mut self, fstype: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.fstype(fstype));
        self
    }
}

impl JsRootDiskBuilder {
    fn take_inner(&mut self) -> RustRootDiskBuilder {
        self.inner
            .take()
            .expect("RootDiskBuilder used after consumption")
    }

    /// Internal: extract the underlying Rust builder. Used by
    /// `ImageBuilder.rootDisk()` to route through the core SDK closure.
    pub(crate) fn take_inner_builder(&mut self) -> Result<RustRootDiskBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("RootDiskBuilder already consumed"))
    }
}
