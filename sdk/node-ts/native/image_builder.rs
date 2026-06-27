use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::sandbox::ImageBuilder as RustImageBuilder;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for an explicit rootfs image source.
///
/// Used inside `Sandbox.builder(...).imageWith((i) => i.disk(...).fstype(...))`.
/// The writable disk size is set at the sandbox level via `.diskSize(...)`.
/// Standalone use is rare; `.image("python:3.12")` and `.image("./ubuntu.qcow2")`
/// resolve the common cases automatically.
#[napi(js_name = "ImageBuilder")]
pub struct JsImageBuilder {
    inner: Option<RustImageBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsImageBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustImageBuilder::new()),
        }
    }

    /// Use an OCI image reference as the root filesystem.
    #[napi]
    pub fn oci(&mut self, reference: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.oci(reference));
        self
    }

    /// Use a host disk image file as the root filesystem. The format is
    /// derived from the file extension: `.qcow2`, `.raw`, or `.vmdk`.
    #[napi]
    pub fn disk(&mut self, path: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.disk(PathBuf::from(path)));
        self
    }

    /// Use a host directory directly as the root filesystem (bind rootfs).
    /// The directory's contents become the guest rootfs as-is — no OCI pull
    /// and no overlay.
    #[napi]
    pub fn bind(&mut self, host: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.bind(PathBuf::from(host)));
        self
    }

    /// Set the inner filesystem type (e.g. `"ext4"`). Omit to let agentd
    /// auto-detect by probing `/proc/filesystems`.
    #[napi]
    pub fn fstype(&mut self, fstype: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.fstype(fstype));
        self
    }
}

impl JsImageBuilder {
    fn take_inner(&mut self) -> RustImageBuilder {
        self.inner
            .take()
            .expect("ImageBuilder used after consumption")
    }

    /// Internal: extract the underlying Rust builder. Used by
    /// `SandboxBuilder.imageWith()` to route through the core SDK closure.
    #[allow(dead_code)]
    pub(crate) fn take_inner_builder(&mut self) -> Result<RustImageBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("ImageBuilder already consumed"))
    }
}
