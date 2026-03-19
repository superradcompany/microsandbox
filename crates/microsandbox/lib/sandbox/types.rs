//! Types for sandbox configuration.
//!
//! These types are referenced by [`SandboxConfig`](super::SandboxConfig).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::size::Mebibytes;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Disk image format for virtio-blk rootfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskImageFormat {
    /// QEMU Copy-on-Write v2.
    Qcow2,
    /// Raw disk image.
    Raw,
    /// VMware Disk (FLAT/ZERO only, no delta links).
    Vmdk,
}

/// Root filesystem source for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RootfsSource {
    /// Use a host directory directly as the root filesystem.
    Bind(PathBuf),

    /// Use an OCI image reference (e.g. `python:3.12`).
    Oci(String),

    /// Use a disk image file as the root filesystem via virtio-blk.
    DiskImage {
        /// Path to the disk image file on the host.
        path: PathBuf,
        /// Disk image format.
        format: DiskImageFormat,
        /// Inner filesystem type (optional; auto-detected if absent).
        fstype: Option<String>,
    },
}

/// Intermediate type for parsing user input into a [`RootfsSource`].
///
/// Accepts `&str`, `String`, or `PathBuf` and resolves to the correct
/// [`RootfsSource`] variant:
///
/// - **`PathBuf`** → always local (bind mount or disk image based on extension).
/// - **`&str` / `String`** → local path if prefixed with `/`, `./`, or `../`;
///   otherwise [`RootfsSource::Oci`].
///
/// Disk image extensions (`.qcow2`, `.raw`, `.vmdk`) resolve to
/// [`RootfsSource::DiskImage`].
pub enum ImageSource {
    /// A string that needs to be resolved.
    Text(String),

    /// An explicit path (always local).
    Path(PathBuf),
}

/// Builder for configuring a disk image rootfs.
///
/// Used with the closure form of [`SandboxBuilder::image`]:
///
/// ```ignore
/// .image(|i| i.disk("./ubuntu.qcow2").fstype("ext4"))
/// ```
#[derive(Default)]
pub struct ImageBuilder {
    source: Option<RootfsSource>,
    error: Option<crate::MicrosandboxError>,
}

/// Trait for types that can be passed to [`SandboxBuilder::image`].
///
/// Implemented for:
/// - `&str`, `String`, `PathBuf` — resolved via [`ImageSource`].
/// - `FnOnce(ImageBuilder) -> ImageBuilder` — closure-based disk image configuration.
pub trait IntoImage {
    /// Resolve this value into a concrete root filesystem source.
    fn into_rootfs_source(self) -> crate::MicrosandboxResult<RootfsSource>;
}

/// A volume mount specification for a sandbox.
pub enum VolumeMount {
    /// Bind mount a host directory into the guest.
    Bind {
        /// Host path to bind mount.
        host: PathBuf,
        /// Guest mount path.
        guest: String,
        /// Whether the mount is read-only.
        readonly: bool,
    },

    /// Mount a named volume into the guest.
    Named {
        /// Volume name.
        name: String,
        /// Guest mount path.
        guest: String,
        /// Whether the mount is read-only.
        readonly: bool,
    },

    /// Temporary filesystem (memory-backed).
    Tmpfs {
        /// Guest mount path.
        guest: String,
        /// Size limit in MiB.
        size_mib: Option<u32>,
    },
}

/// Builder for constructing a [`VolumeMount`].
pub struct MountBuilder {
    guest: String,
    mount: MountKind,
    readonly: bool,
    size_mib: Option<u32>,
}

/// Internal kind for the mount builder.
enum MountKind {
    Bind(PathBuf),
    Named(String),
    Tmpfs,
    Unset,
}

/// A rootfs patch applied as an overlay layer before VM start.
///
/// Fully implemented in Phase 13 (Patches).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Patch {}

/// Secrets configuration for a sandbox.
///
/// Fully implemented in Phase 11 (Secrets).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretsConfig {}

/// SSH configuration for a sandbox.
///
/// Fully implemented in Phase 14 (Polish).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshConfig {}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MountBuilder {
    /// Create a new mount builder for the given guest path.
    pub fn new(guest: impl Into<String>) -> Self {
        Self {
            guest: guest.into(),
            mount: MountKind::Unset,
            readonly: false,
            size_mib: None,
        }
    }

    /// Bind mount from a host path.
    pub fn bind(mut self, host: impl Into<PathBuf>) -> Self {
        self.mount = MountKind::Bind(host.into());
        self
    }

    /// Use a named volume.
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.mount = MountKind::Named(name.into());
        self
    }

    /// Use tmpfs (memory-backed).
    pub fn tmpfs(mut self) -> Self {
        self.mount = MountKind::Tmpfs;
        self
    }

    /// Make the mount read-only.
    pub fn readonly(mut self) -> Self {
        self.readonly = true;
        self
    }

    /// Set size limit (for tmpfs).
    ///
    /// Accepts bare `u32` (interpreted as MiB) or a [`SizeExt`](crate::size::SizeExt) helper:
    /// ```ignore
    /// .tmpfs().size(100)         // 100 MiB
    /// .tmpfs().size(100.mib())   // 100 MiB (explicit)
    /// .tmpfs().size(1.gib())     // 1 GiB = 1024 MiB
    /// ```
    pub fn size(mut self, size: impl Into<Mebibytes>) -> Self {
        self.size_mib = Some(size.into().as_u32());
        self
    }

    /// Build the volume mount.
    pub(crate) fn build(self) -> crate::MicrosandboxResult<VolumeMount> {
        match self.mount {
            MountKind::Bind(host) => Ok(VolumeMount::Bind {
                host,
                guest: self.guest,
                readonly: self.readonly,
            }),
            MountKind::Named(name) => Ok(VolumeMount::Named {
                name,
                guest: self.guest,
                readonly: self.readonly,
            }),
            MountKind::Tmpfs => Ok(VolumeMount::Tmpfs {
                guest: self.guest,
                size_mib: self.size_mib,
            }),
            MountKind::Unset => Err(crate::MicrosandboxError::InvalidConfig(
                "MountBuilder: no mount type set (call .bind(), .named(), or .tmpfs())".into(),
            )),
        }
    }
}

impl VolumeMount {
    /// Get the guest mount path.
    pub fn guest(&self) -> &str {
        match self {
            Self::Bind { guest, .. } | Self::Named { guest, .. } | Self::Tmpfs { guest, .. } => {
                guest
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: ImageSource
//--------------------------------------------------------------------------------------------------

impl ImageSource {
    /// Resolve into a [`RootfsSource`].
    pub fn into_rootfs_source(self) -> crate::MicrosandboxResult<RootfsSource> {
        match self {
            Self::Path(path) => Self::resolve_path(path),
            Self::Text(s) => {
                if s.starts_with('/') || s.starts_with("./") || s.starts_with("../") {
                    Self::resolve_path(PathBuf::from(s))
                } else {
                    Ok(RootfsSource::Oci(s))
                }
            }
        }
    }

    /// Resolve a local path into either a bind mount or a disk image source.
    fn resolve_path(path: PathBuf) -> crate::MicrosandboxResult<RootfsSource> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if let Some(format) = DiskImageFormat::from_extension(ext) {
            Ok(RootfsSource::DiskImage {
                path,
                format,
                fstype: None,
            })
        } else {
            Ok(RootfsSource::Bind(path))
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: DiskImageFormat
//--------------------------------------------------------------------------------------------------

impl DiskImageFormat {
    /// Returns the format as a CLI-safe lowercase string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Qcow2 => "qcow2",
            Self::Raw => "raw",
            Self::Vmdk => "vmdk",
        }
    }

    /// Parse a disk image format from a file extension.
    ///
    /// Returns `None` if the extension is not a recognized disk image format.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "qcow2" => Some(Self::Qcow2),
            "raw" => Some(Self::Raw),
            "vmdk" => Some(Self::Vmdk),
            _ => None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: ImageBuilder
//--------------------------------------------------------------------------------------------------

impl ImageBuilder {
    /// Create a new image builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Use a disk image file as the root filesystem.
    ///
    /// The format is derived from the file extension:
    /// `.qcow2`, `.raw`, `.vmdk`.
    ///
    /// ```ignore
    /// .image(|i| i.disk("./ubuntu.qcow2"))
    /// .image(|i| i.disk("./alpine.raw").fstype("ext4"))
    /// ```
    pub fn disk(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let format = match DiskImageFormat::from_extension(ext) {
            Some(f) => f,
            None => {
                self.error = Some(crate::MicrosandboxError::InvalidConfig(format!(
                    "unrecognized disk image extension: {ext:?} (expected .qcow2, .raw, or .vmdk)"
                )));
                return self;
            }
        };
        self.source = Some(RootfsSource::DiskImage {
            path,
            format,
            fstype: None,
        });
        self
    }

    /// Set the inner filesystem type for a disk image.
    ///
    /// If omitted, agentd auto-detects the filesystem by probing
    /// `/proc/filesystems`.
    ///
    /// ```ignore
    /// .image(|i| i.disk("./ubuntu.raw").fstype("ext4"))
    /// ```
    pub fn fstype(mut self, fstype: impl Into<String>) -> Self {
        let fstype = fstype.into();
        if fstype.contains(',') || fstype.contains('=') {
            self.error = Some(crate::MicrosandboxError::InvalidConfig(format!(
                "fstype must not contain ',' or '=': {fstype}"
            )));
            return self;
        }
        match &mut self.source {
            Some(RootfsSource::DiskImage { fstype: ft, .. }) => {
                *ft = Some(fstype);
            }
            _ => {
                if self.error.is_none() {
                    self.error = Some(crate::MicrosandboxError::InvalidConfig(
                        "fstype() requires disk() to be called first".into(),
                    ));
                }
            }
        }
        self
    }

    /// Consume the builder and return the resolved [`RootfsSource`].
    pub(crate) fn build(self) -> crate::MicrosandboxResult<RootfsSource> {
        if let Some(e) = self.error {
            return Err(e);
        }
        self.source.ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(
                "ImageBuilder: no image source set (call .disk())".into(),
            )
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: IntoImage
//--------------------------------------------------------------------------------------------------

impl IntoImage for &str {
    fn into_rootfs_source(self) -> crate::MicrosandboxResult<RootfsSource> {
        ImageSource::from(self).into_rootfs_source()
    }
}

impl IntoImage for String {
    fn into_rootfs_source(self) -> crate::MicrosandboxResult<RootfsSource> {
        ImageSource::from(self).into_rootfs_source()
    }
}

impl IntoImage for PathBuf {
    fn into_rootfs_source(self) -> crate::MicrosandboxResult<RootfsSource> {
        ImageSource::from(self).into_rootfs_source()
    }
}

impl<F> IntoImage for F
where
    F: FnOnce(ImageBuilder) -> ImageBuilder,
{
    fn into_rootfs_source(self) -> crate::MicrosandboxResult<RootfsSource> {
        self(ImageBuilder::new()).build()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Display for DiskImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DiskImageFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "qcow2" => Ok(Self::Qcow2),
            "raw" => Ok(Self::Raw),
            "vmdk" => Ok(Self::Vmdk),
            _ => Err(format!("unknown disk image format: {s}")),
        }
    }
}

impl Default for RootfsSource {
    fn default() -> Self {
        Self::Oci(String::new())
    }
}

impl From<&str> for ImageSource {
    fn from(s: &str) -> Self {
        Self::Text(s.to_string())
    }
}

impl From<String> for ImageSource {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}

impl From<PathBuf> for ImageSource {
    fn from(p: PathBuf) -> Self {
        Self::Path(p)
    }
}

/// Custom serialization — only serializable variants are written.
/// Custom serialization for `VolumeMount`.
impl Serialize for VolumeMount {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        match self {
            Self::Bind {
                host,
                guest,
                readonly,
            } => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("type", "Bind")?;
                map.serialize_entry("host", host)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("readonly", readonly)?;
                map.end()
            }
            Self::Named {
                name,
                guest,
                readonly,
            } => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("type", "Named")?;
                map.serialize_entry("name", name)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("readonly", readonly)?;
                map.end()
            }
            Self::Tmpfs { guest, size_mib } => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("type", "Tmpfs")?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("size_mib", size_mib)?;
                map.end()
            }
        }
    }
}

/// Custom deserialization — only Bind, Named, Tmpfs are expected.
impl<'de> Deserialize<'de> for VolumeMount {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Helper for tagged deserialization.
        #[derive(Deserialize)]
        #[serde(tag = "type")]
        enum VolumeMountHelper {
            Bind {
                host: PathBuf,
                guest: String,
                #[serde(default)]
                readonly: bool,
            },
            Named {
                name: String,
                guest: String,
                #[serde(default)]
                readonly: bool,
            },
            Tmpfs {
                guest: String,
                #[serde(default)]
                size_mib: Option<u32>,
            },
        }

        let helper = VolumeMountHelper::deserialize(deserializer)?;
        Ok(match helper {
            VolumeMountHelper::Bind {
                host,
                guest,
                readonly,
            } => Self::Bind {
                host,
                guest,
                readonly,
            },
            VolumeMountHelper::Named {
                name,
                guest,
                readonly,
            } => Self::Named {
                name,
                guest,
                readonly,
            },
            VolumeMountHelper::Tmpfs { guest, size_mib } => Self::Tmpfs { guest, size_mib },
        })
    }
}

impl std::fmt::Debug for VolumeMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind {
                host,
                guest,
                readonly,
            } => f
                .debug_struct("Bind")
                .field("host", host)
                .field("guest", guest)
                .field("readonly", readonly)
                .finish(),
            Self::Named {
                name,
                guest,
                readonly,
            } => f
                .debug_struct("Named")
                .field("name", name)
                .field("guest", guest)
                .field("readonly", readonly)
                .finish(),
            Self::Tmpfs { guest, size_mib } => f
                .debug_struct("Tmpfs")
                .field("guest", guest)
                .field("size_mib", size_mib)
                .finish(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disk_image_format_from_extension() {
        assert_eq!(
            DiskImageFormat::from_extension("qcow2"),
            Some(DiskImageFormat::Qcow2)
        );
        assert_eq!(
            DiskImageFormat::from_extension("raw"),
            Some(DiskImageFormat::Raw)
        );
        assert_eq!(
            DiskImageFormat::from_extension("vmdk"),
            Some(DiskImageFormat::Vmdk)
        );
        assert_eq!(DiskImageFormat::from_extension("ext4"), None);
        assert_eq!(DiskImageFormat::from_extension(""), None);
    }

    #[test]
    fn test_disk_image_format_display_roundtrip() {
        for fmt in [
            DiskImageFormat::Qcow2,
            DiskImageFormat::Raw,
            DiskImageFormat::Vmdk,
        ] {
            let s = fmt.to_string();
            let parsed: DiskImageFormat = s.parse().unwrap();
            assert_eq!(parsed, fmt);
        }
    }

    #[test]
    fn test_disk_image_format_from_str_unknown() {
        assert!("ext4".parse::<DiskImageFormat>().is_err());
    }

    #[test]
    fn test_image_source_resolves_qcow2() {
        let source = ImageSource::from("./disk.qcow2");
        let rootfs = source.into_rootfs_source().unwrap();
        match rootfs {
            RootfsSource::DiskImage { format, .. } => assert_eq!(format, DiskImageFormat::Qcow2),
            _ => panic!("expected DiskImage"),
        }
    }

    #[test]
    fn test_image_source_resolves_raw() {
        let source = ImageSource::from("/images/test.raw");
        let rootfs = source.into_rootfs_source().unwrap();
        match rootfs {
            RootfsSource::DiskImage { format, .. } => assert_eq!(format, DiskImageFormat::Raw),
            _ => panic!("expected DiskImage"),
        }
    }

    #[test]
    fn test_image_source_resolves_directory_as_bind() {
        let source = ImageSource::from("./rootfs");
        let rootfs = source.into_rootfs_source().unwrap();
        assert!(matches!(rootfs, RootfsSource::Bind(_)));
    }

    #[test]
    fn test_image_source_resolves_oci_reference() {
        let source = ImageSource::from("python:3.12");
        let rootfs = source.into_rootfs_source().unwrap();
        assert!(matches!(rootfs, RootfsSource::Oci(_)));
    }

    #[test]
    fn test_image_builder_disk_with_fstype() {
        let rootfs = (|i: ImageBuilder| i.disk("./test.qcow2").fstype("ext4"))
            .into_rootfs_source()
            .unwrap();
        match rootfs {
            RootfsSource::DiskImage { format, fstype, .. } => {
                assert_eq!(format, DiskImageFormat::Qcow2);
                assert_eq!(fstype.as_deref(), Some("ext4"));
            }
            _ => panic!("expected DiskImage"),
        }
    }

    #[test]
    fn test_image_builder_disk_without_fstype() {
        let rootfs = (|i: ImageBuilder| i.disk("./test.raw"))
            .into_rootfs_source()
            .unwrap();
        match rootfs {
            RootfsSource::DiskImage { format, fstype, .. } => {
                assert_eq!(format, DiskImageFormat::Raw);
                assert_eq!(fstype, None);
            }
            _ => panic!("expected DiskImage"),
        }
    }

    #[test]
    fn test_image_builder_bad_extension_errors() {
        let result = (|i: ImageBuilder| i.disk("./test.txt")).into_rootfs_source();
        assert!(result.is_err());
    }

    #[test]
    fn test_image_builder_fstype_without_disk_errors() {
        let result = (|i: ImageBuilder| i.fstype("ext4")).into_rootfs_source();
        assert!(result.is_err());
    }

    #[test]
    fn test_image_builder_fstype_rejects_comma() {
        let result =
            (|i: ImageBuilder| i.disk("./test.qcow2").fstype("ext4,size=100")).into_rootfs_source();
        assert!(result.is_err());
    }

    #[test]
    fn test_image_builder_fstype_rejects_equals() {
        let result =
            (|i: ImageBuilder| i.disk("./test.qcow2").fstype("key=value")).into_rootfs_source();
        assert!(result.is_err());
    }
}
