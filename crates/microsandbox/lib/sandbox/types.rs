//! Types for sandbox configuration.
//!
//! These types are referenced by [`SandboxConfig`](super::SandboxConfig).

use std::path::{Path, PathBuf};

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

    /// Use an OCI image reference with an EROFS lower and ext4 overlay upper.
    Oci(OciRootfsSource),

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

/// OCI root filesystem source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciRootfsSource {
    /// OCI image reference (e.g. `python`).
    pub reference: String,

    /// Writable overlay upper size in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upper_size_mib: Option<u32>,
}

/// Intermediate type for parsing user input into a [`RootfsSource`].
///
/// Accepts `&str`, `String`, or `PathBuf` and resolves to the correct
/// [`RootfsSource`] variant:
///
/// - **`PathBuf`** → always local (bind mount or disk image based on extension).
/// - **`&str` / `String`** → local path if `.`, `..`, or prefixed with `/`,
///   `./`, or `../`; otherwise [`RootfsSource::Oci`].
///
/// Disk image extensions (`.qcow2`, `.raw`, `.vmdk`) resolve to
/// [`RootfsSource::DiskImage`].
pub enum ImageSource {
    /// A string that needs to be resolved.
    Text(String),

    /// An explicit path (always local).
    Path(PathBuf),
}

/// Builder for configuring an image rootfs.
///
/// Used with [`crate::sandbox::SandboxBuilder::image_with`]:
///
/// ```ignore
/// .image_with(|i| i.oci("python:3.12").upper_size(8.gib()))
/// .image_with(|i| i.disk("./ubuntu.qcow2").fstype("ext4"))
/// ```
#[derive(Default)]
pub struct ImageBuilder {
    source: Option<RootfsSource>,
    error: Option<crate::MicrosandboxError>,
}

/// Trait for types that can be passed to [`crate::sandbox::SandboxBuilder::image`].
///
/// Implemented for:
/// - `&str`, `String`, `PathBuf` — resolved via [`ImageSource`].
/// - `FnOnce(ImageBuilder) -> ImageBuilder` — closure-based image configuration.
pub trait IntoImage {
    /// Resolve this value into a concrete root filesystem source.
    fn into_rootfs_source(self) -> crate::MicrosandboxResult<RootfsSource>;
}

/// Stat virtualization policy for a virtiofs-backed volume mount.
///
/// Mirrors `microsandbox_filesystem::StatVirtualization`. See
/// `design/filesystems/stat-virtualization.md` for the threat model.
///
/// Serializes/deserializes as the lowercase variant name (`"strict"`,
/// `"relaxed"`, `"off"`) so persisted JSON aligns with the CLI grammar
/// (`stat-virt=strict|relaxed|off`) and the NAPI string contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatVirtualization {
    /// Fail-closed: probe the host backing path; require xattr support.
    Strict,
    /// Opportunistic: apply the overlay when present; tolerate missing xattr support.
    Relaxed,
    /// Literal host metadata: do not read or apply the override xattr.
    Off,
}

/// Host permission propagation policy for a virtiofs-backed volume mount.
///
/// Mirrors `microsandbox_filesystem::HostPermissions`.
///
/// Serializes/deserializes as the lowercase variant name (`"private"`,
/// `"mirror"`) to align with the CLI and NAPI spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostPermissions {
    /// Guest chmod stays in the metadata overlay only.
    Private,
    /// Mirror ordinary rwx bits for regular files and directories to the host inode.
    Mirror,
}

/// Guest mount behavior shared by every volume mount kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountOptions {
    /// Whether the mount is read-only.
    ///
    /// Guest writes fail with the kernel's read-only filesystem behavior.
    /// Virtiofs-backed mounts also reject writes on the host-side filesystem
    /// server as defense in depth.
    pub readonly: bool,

    /// Whether direct execution from the mount is disabled.
    ///
    /// This prevents `execve` of binaries or scripts located on the mount.
    /// Interpreters can still read files from the mount, for example
    /// `sh /mnt/script.sh`, because the interpreter itself executes from a
    /// different filesystem. Guest volume mounts always also use internal
    /// `nosuid` and `nodev` safety defaults.
    pub noexec: bool,
}

/// A volume mount specification for a sandbox.
#[derive(Clone)]
pub enum VolumeMount {
    /// Bind mount a host directory into the guest.
    Bind {
        /// Host path to bind mount.
        host: PathBuf,
        /// Guest mount path.
        guest: String,
        /// Guest mount behavior.
        options: MountOptions,
        /// Guest-visible stat virtualization policy.
        stat_virtualization: StatVirtualization,
        /// Host permission propagation policy.
        host_permissions: HostPermissions,
    },

    /// Mount a named volume into the guest.
    Named {
        /// Volume name.
        name: String,
        /// Guest mount path.
        guest: String,
        /// Guest mount behavior.
        options: MountOptions,
        /// Guest-visible stat virtualization policy.
        stat_virtualization: StatVirtualization,
        /// Host permission propagation policy.
        host_permissions: HostPermissions,
    },

    /// Temporary filesystem (memory-backed).
    Tmpfs {
        /// Guest mount path.
        guest: String,
        /// Size limit in MiB.
        size_mib: Option<u32>,
        /// Guest mount behavior.
        options: MountOptions,
    },

    /// Mount a disk image file as a virtio-blk device at a guest path.
    ///
    /// The guest OS owns the inner filesystem; microsandbox just attaches
    /// the image and agentd mounts it. Use this for persistent state that
    /// should be isolated from the host filesystem, for distributing
    /// pre-built ext4/squashfs datasets, or for read-only seed volumes.
    DiskImage {
        /// Host path to the disk image file.
        host: PathBuf,
        /// Guest mount path.
        guest: String,
        /// Disk image format (qcow2 / raw / vmdk).
        format: DiskImageFormat,
        /// Inner filesystem type. When `None`, agentd probes `/proc/filesystems`.
        fstype: Option<String>,
        /// Guest mount behavior.
        options: MountOptions,
    },
}

/// Builder for constructing a [`VolumeMount`].
pub struct MountBuilder {
    guest: String,
    mount: MountKind,
    options: MountOptions,
    size_mib: Option<u32>,
    disk_format: Option<DiskImageFormat>,
    disk_fstype: Option<String>,
    stat_virtualization: Option<StatVirtualization>,
    host_permissions: Option<HostPermissions>,
    error: Option<crate::MicrosandboxError>,
}

/// Internal kind for the mount builder.
enum MountKind {
    Bind(PathBuf),
    Named(String),
    Tmpfs,
    Disk(PathBuf),
    Unset,
}

/// Rootfs patch applied before VM startup.
///
/// How patches are applied depends on the root filesystem type:
/// - **OCI images (EROFS + ext4 overlay):** Patches are baked into `upper.ext4` under
///   the overlayfs `upperdir` so the shared EROFS lower layers remain untouched.
/// - **Bind/Passthrough roots:** Patches are applied directly to the host directory.
/// - **Block device roots (Qcow2, Raw):** Patches are not supported. Returns an error at
///   create time.
///
/// By default, patches that target a path already present in the rootfs (the visible lower
/// overlay view for OCI, existing files for bind roots) will return an error. Set `replace: true` on
/// the relevant variant to allow shadowing existing files.
///
/// For `Append` patches targeting a file in a lower layer, the file is first copied up to
/// the writable overlay layer before appending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Patch {
    /// Write text content to a file.
    Text {
        /// Absolute guest path (e.g., `/etc/app.conf`).
        path: String,
        /// Text content to write.
        content: String,
        /// File permissions (e.g., `0o644`). `None` uses the default.
        mode: Option<u32>,
        /// Allow replacing a file that already exists in the rootfs.
        replace: bool,
    },
    /// Write raw bytes to a file.
    File {
        /// Absolute guest path.
        path: String,
        /// Raw byte content to write.
        content: Vec<u8>,
        /// File permissions (e.g., `0o644`). `None` uses the default.
        mode: Option<u32>,
        /// Allow replacing a file that already exists in the rootfs.
        replace: bool,
    },
    /// Copy a file from host into the rootfs.
    CopyFile {
        /// Host path to copy from.
        src: PathBuf,
        /// Absolute guest destination path.
        dst: String,
        /// File permissions. `None` preserves source permissions.
        mode: Option<u32>,
        /// Allow replacing a file that already exists in the rootfs.
        replace: bool,
    },
    /// Copy a directory from host into the rootfs.
    CopyDir {
        /// Host directory to copy from.
        src: PathBuf,
        /// Absolute guest destination path.
        dst: String,
        /// Allow replacing files that already exist in the rootfs.
        replace: bool,
    },
    /// Create a symlink.
    Symlink {
        /// Symlink target path.
        target: String,
        /// Absolute guest path where the symlink is created.
        link: String,
        /// Allow replacing a path that already exists in the rootfs.
        replace: bool,
    },
    /// Create a directory (idempotent — does not error if the directory already exists).
    Mkdir {
        /// Absolute guest path.
        path: String,
        /// Directory permissions (e.g., `0o755`). `None` uses the default.
        mode: Option<u32>,
    },
    /// Remove a file or directory (idempotent — does not error if the path does not exist).
    Remove {
        /// Absolute guest path to remove.
        path: String,
    },
    /// Append content to an existing file. If the file lives in a lower layer,
    /// it is copied up to the writable overlay layer first, then the content is
    /// appended.
    Append {
        /// Absolute guest path of the file to append to.
        path: String,
        /// Content to append.
        content: String,
    },
}

/// Builder for constructing a list of [`Patch`] operations.
pub struct PatchBuilder {
    patches: Vec<Patch>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MountBuilder {
    /// Create a new mount builder for the given guest path.
    pub fn new(guest: impl Into<String>) -> Self {
        Self {
            guest: guest.into(),
            mount: MountKind::Unset,
            options: MountOptions::default(),
            size_mib: None,
            disk_format: None,
            disk_fstype: None,
            stat_virtualization: None,
            host_permissions: None,
            error: None,
        }
    }

    /// Bind mount from a host path.
    pub fn bind(mut self, host: impl Into<PathBuf>) -> Self {
        self.mount = MountKind::Bind(host.into());
        self
    }

    /// Mount a named volume created via [`Volume::create`](crate::volume::Volume::create).
    /// The volume persists across sandbox restarts and can be shared between sandboxes.
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.mount = MountKind::Named(name.into());
        self
    }

    /// Use tmpfs (memory-backed).
    pub fn tmpfs(mut self) -> Self {
        self.mount = MountKind::Tmpfs;
        self
    }

    /// Mount a disk image file as a virtio-blk device at the guest path.
    ///
    /// Format defaults to the extension of `host` (`.qcow2` → Qcow2, `.vmdk`
    /// → Vmdk, anything else → Raw). Use [`Self::format`] to override.
    pub fn disk(mut self, host: impl Into<PathBuf>) -> Self {
        self.mount = MountKind::Disk(host.into());
        self
    }

    /// Override the disk image format for the current `disk()` mount.
    ///
    /// Only valid alongside [`Self::disk`]. Calling on bind / named / tmpfs
    /// mounts produces an error when the surrounding `SandboxBuilder` is
    /// finalized so the option does not silently get dropped.
    pub fn format(mut self, format: DiskImageFormat) -> Self {
        self.disk_format = Some(format);
        self
    }

    /// Set the inner filesystem type for the current `disk()` mount. When
    /// unset, agentd probes `/proc/filesystems` to find a type that mounts
    /// cleanly.
    pub fn fstype(mut self, fstype: impl Into<String>) -> Self {
        let fstype = fstype.into();
        if fstype.is_empty() {
            self.error.get_or_insert_with(|| {
                crate::MicrosandboxError::InvalidConfig("fstype must not be empty".into())
            });
            return self;
        }
        if fstype.contains(',')
            || fstype.contains(';')
            || fstype.contains(':')
            || fstype.contains('=')
        {
            self.error.get_or_insert_with(|| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "fstype must not contain ',', ';', ':', or '=': {fstype}"
                ))
            });
            return self;
        }
        self.disk_fstype = Some(fstype);
        self
    }

    /// Prevent writes to this mount. Enforced both at the host (virtiofs
    /// server rejects writes) and guest (kernel returns `EROFS`).
    pub fn readonly(mut self) -> Self {
        self.options.readonly = true;
        self
    }

    /// Prevent direct execution from this mount.
    ///
    /// This blocks executing a file located on the mount directly. It does
    /// not block interpreters from reading files on the mount, such as
    /// `sh /mnt/script.sh`, because the interpreter binary executes from a
    /// different filesystem.
    pub fn noexec(mut self) -> Self {
        self.options.noexec = true;
        self
    }

    /// Set the guest stat virtualization policy. Default: [`StatVirtualization::Strict`].
    ///
    /// Valid only for bind and named-directory/file mounts. Calling this on
    /// a tmpfs or disk-image mount produces an error at `.build()` time.
    pub fn stat_virtualization(mut self, policy: StatVirtualization) -> Self {
        self.stat_virtualization = Some(policy);
        self
    }

    /// Set the host permission propagation policy. Default: [`HostPermissions::Private`].
    ///
    /// Valid only for bind and named-directory/file mounts. Calling this on
    /// a tmpfs or disk-image mount produces an error at `.build()` time.
    pub fn host_permissions(mut self, policy: HostPermissions) -> Self {
        self.host_permissions = Some(policy);
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
    pub fn build(self) -> crate::MicrosandboxResult<VolumeMount> {
        if let Some(err) = self.error {
            return Err(err);
        }

        // Validate guest path.
        if !self.guest.starts_with('/') {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "guest mount path must be absolute: {}",
                self.guest
            )));
        }
        if self.guest == "/" {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "cannot mount a volume at guest root /".into(),
            ));
        }
        if self.guest.contains(':') || self.guest.contains(';') || self.guest.contains(',') {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "guest mount path must not contain ':', ';', or ',': {}",
                self.guest
            )));
        }

        // Reject options set on the wrong kind.
        let is_tmpfs = matches!(self.mount, MountKind::Tmpfs);
        let is_disk = matches!(self.mount, MountKind::Disk(_));
        let is_virtiofs = matches!(self.mount, MountKind::Bind(_) | MountKind::Named(_));
        if self.size_mib.is_some() && !is_tmpfs {
            return Err(crate::MicrosandboxError::InvalidConfig(
                ".size() is only valid for tmpfs mounts".into(),
            ));
        }
        if self.disk_format.is_some() && !is_disk {
            return Err(crate::MicrosandboxError::InvalidConfig(
                ".format() is only valid for disk image mounts".into(),
            ));
        }
        if self.disk_fstype.is_some() && !is_disk {
            return Err(crate::MicrosandboxError::InvalidConfig(
                ".fstype() is only valid for disk image mounts".into(),
            ));
        }
        if self.stat_virtualization.is_some() && !is_virtiofs {
            return Err(crate::MicrosandboxError::InvalidConfig(
                ".stat_virtualization() is only valid for bind and named volume mounts".into(),
            ));
        }
        if self.host_permissions.is_some() && !is_virtiofs {
            return Err(crate::MicrosandboxError::InvalidConfig(
                ".host_permissions() is only valid for bind and named volume mounts".into(),
            ));
        }

        // `Off + Mirror` is a contradiction. With xattr disabled there is no
        // overlay to keep guest chmod private, so chmod always hits the host —
        // `Mirror` would silently be a no-op as a distinct policy. Reject only
        // when the caller explicitly chose both, so the conservative defaults
        // never trip the check.
        if matches!(self.stat_virtualization, Some(StatVirtualization::Off))
            && matches!(self.host_permissions, Some(HostPermissions::Mirror))
        {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "stat_virtualization=Off cannot be combined with host_permissions=Mirror: \
                 Off has no overlay, so chmod already operates on the host inode and Mirror \
                 would be a no-op. Drop one or the other."
                    .into(),
            ));
        }

        let stat_virtualization = self
            .stat_virtualization
            .unwrap_or(StatVirtualization::Strict);
        let host_permissions = self.host_permissions.unwrap_or(HostPermissions::Private);

        let mount = match self.mount {
            MountKind::Bind(host) => {
                // The spawn → VM wire format encodes mount specs as
                // `tag:host[:opts]`. Embedded separators in the host
                // path would collide with that grammar and could
                // silently inject policy options. Reject at the SDK
                // boundary so callers get a clear error rather than a
                // confusing parse failure later.
                if let Some(s) = host.to_str() {
                    if s.contains(',') {
                        return Err(crate::MicrosandboxError::InvalidConfig(format!(
                            "bind host path must not contain ',': {s}"
                        )));
                    }
                    if s.contains(':') {
                        return Err(crate::MicrosandboxError::InvalidConfig(format!(
                            "bind host path must not contain ':': {s}"
                        )));
                    }
                    if s.contains(';') {
                        return Err(crate::MicrosandboxError::InvalidConfig(format!(
                            "bind host path must not contain ';': {s}"
                        )));
                    }
                } else {
                    return Err(crate::MicrosandboxError::InvalidConfig(
                        "bind host path must be valid UTF-8".into(),
                    ));
                }
                VolumeMount::Bind {
                    host,
                    guest: self.guest,
                    options: self.options,
                    stat_virtualization,
                    host_permissions,
                }
            }
            MountKind::Named(name) => {
                crate::volume::validate_volume_name(&name)?;
                VolumeMount::Named {
                    name,
                    guest: self.guest,
                    options: self.options,
                    stat_virtualization,
                    host_permissions,
                }
            }
            MountKind::Tmpfs => VolumeMount::Tmpfs {
                guest: self.guest,
                size_mib: self.size_mib,
                options: self.options,
            },
            MountKind::Disk(host) => {
                let format = self.disk_format.unwrap_or_else(|| {
                    host.extension()
                        .and_then(|e| e.to_str())
                        .and_then(DiskImageFormat::from_extension)
                        .unwrap_or(DiskImageFormat::Raw)
                });
                VolumeMount::DiskImage {
                    host,
                    guest: self.guest,
                    format,
                    fstype: self.disk_fstype,
                    options: self.options,
                }
            }
            MountKind::Unset => {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "MountBuilder: no mount type set (call .bind(), .named(), .tmpfs(), or .disk())"
                        .into(),
                ));
            }
        };

        validate_volume_mount(&mount)?;
        Ok(mount)
    }
}

impl Default for PatchBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PatchBuilder {
    /// Create a new patch builder.
    pub fn new() -> Self {
        Self {
            patches: Vec::new(),
        }
    }

    /// Write text content to a file.
    pub fn text(
        mut self,
        path: impl Into<String>,
        content: impl Into<String>,
        mode: Option<u32>,
        replace: bool,
    ) -> Self {
        self.patches.push(Patch::Text {
            path: path.into(),
            content: content.into(),
            mode,
            replace,
        });
        self
    }

    /// Write raw bytes to a file.
    pub fn file(
        mut self,
        path: impl Into<String>,
        content: impl Into<Vec<u8>>,
        mode: Option<u32>,
        replace: bool,
    ) -> Self {
        self.patches.push(Patch::File {
            path: path.into(),
            content: content.into(),
            mode,
            replace,
        });
        self
    }

    /// Copy a file from host into the rootfs.
    pub fn copy_file(
        mut self,
        src: impl Into<PathBuf>,
        dst: impl Into<String>,
        mode: Option<u32>,
        replace: bool,
    ) -> Self {
        self.patches.push(Patch::CopyFile {
            src: src.into(),
            dst: dst.into(),
            mode,
            replace,
        });
        self
    }

    /// Copy a directory from host into the rootfs.
    pub fn copy_dir(
        mut self,
        src: impl Into<PathBuf>,
        dst: impl Into<String>,
        replace: bool,
    ) -> Self {
        self.patches.push(Patch::CopyDir {
            src: src.into(),
            dst: dst.into(),
            replace,
        });
        self
    }

    /// Create a symlink.
    pub fn symlink(
        mut self,
        target: impl Into<String>,
        link: impl Into<String>,
        replace: bool,
    ) -> Self {
        self.patches.push(Patch::Symlink {
            target: target.into(),
            link: link.into(),
            replace,
        });
        self
    }

    /// Create a directory (idempotent).
    pub fn mkdir(mut self, path: impl Into<String>, mode: Option<u32>) -> Self {
        self.patches.push(Patch::Mkdir {
            path: path.into(),
            mode,
        });
        self
    }

    /// Remove a file or directory (idempotent).
    pub fn remove(mut self, path: impl Into<String>) -> Self {
        self.patches.push(Patch::Remove { path: path.into() });
        self
    }

    /// Append content to an existing file. Copies up from lower layer if needed.
    pub fn append(mut self, path: impl Into<String>, content: impl Into<String>) -> Self {
        self.patches.push(Patch::Append {
            path: path.into(),
            content: content.into(),
        });
        self
    }

    /// Build the list of patches.
    pub fn build(self) -> Vec<Patch> {
        self.patches
    }
}

impl VolumeMount {
    /// The absolute path where this mount appears inside the guest.
    pub fn guest(&self) -> &str {
        match self {
            Self::Bind { guest, .. }
            | Self::Named { guest, .. }
            | Self::Tmpfs { guest, .. }
            | Self::DiskImage { guest, .. } => guest,
        }
    }
}

impl OciRootfsSource {
    /// Create a new OCI rootfs source.
    pub fn new(reference: impl Into<String>) -> Self {
        Self {
            reference: reference.into(),
            upper_size_mib: None,
        }
    }

    /// Set the writable overlay upper size.
    pub fn upper_size(mut self, size: impl Into<Mebibytes>) -> Self {
        self.upper_size_mib = Some(size.into().as_u32());
        self
    }
}

impl RootfsSource {
    /// Create an OCI rootfs source from an image reference.
    pub fn oci(reference: impl Into<String>) -> Self {
        Self::Oci(OciRootfsSource::new(reference))
    }

    /// Return the OCI image reference if this is an OCI rootfs.
    pub fn oci_reference(&self) -> Option<&str> {
        match self {
            Self::Oci(oci) => Some(&oci.reference),
            _ => None,
        }
    }

    /// Return the configured OCI upper size in MiB if this is an OCI rootfs.
    pub fn oci_upper_size_mib(&self) -> Option<u32> {
        match self {
            Self::Oci(oci) => oci.upper_size_mib,
            _ => None,
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
                if microsandbox_utils::looks_like_local_path_text(&s) {
                    Self::resolve_path(PathBuf::from(s))
                } else {
                    Ok(RootfsSource::oci(s))
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

    /// Use an OCI image reference as the root filesystem.
    ///
    /// ```ignore
    /// .image_with(|i| i.oci("python:3.12").upper_size(8.gib()))
    /// ```
    pub fn oci(mut self, reference: impl Into<String>) -> Self {
        self.source = Some(RootfsSource::oci(reference));
        self
    }

    /// Set the writable overlay upper size for an OCI rootfs.
    ///
    /// This is valid only after [`oci`](Self::oci).
    pub fn upper_size(mut self, size: impl Into<Mebibytes>) -> Self {
        let size_mib = size.into().as_u32();
        match &mut self.source {
            Some(RootfsSource::Oci(oci)) => {
                oci.upper_size_mib = Some(size_mib);
            }
            _ => {
                if self.error.is_none() {
                    self.error = Some(crate::MicrosandboxError::InvalidConfig(
                        "upper_size() requires oci() to be called first".into(),
                    ));
                }
            }
        }
        self
    }

    /// Use a disk image file as the root filesystem.
    ///
    /// The format is derived from the file extension:
    /// `.qcow2`, `.raw`, `.vmdk`.
    ///
    /// ```ignore
    /// .image_with(|i| i.disk("./ubuntu.qcow2"))
    /// .image_with(|i| i.disk("./alpine.raw").fstype("ext4"))
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
    /// .image_with(|i| i.disk("./ubuntu.raw").fstype("ext4"))
    /// ```
    pub fn fstype(mut self, fstype: impl Into<String>) -> Self {
        let fstype = fstype.into();
        if fstype.is_empty() {
            self.error = Some(crate::MicrosandboxError::InvalidConfig(
                "fstype must not be empty".into(),
            ));
            return self;
        }
        if fstype.contains(',')
            || fstype.contains(';')
            || fstype.contains(':')
            || fstype.contains('=')
        {
            self.error = Some(crate::MicrosandboxError::InvalidConfig(format!(
                "fstype must not contain ',', ';', ':', or '=': {fstype}"
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
    pub fn build(self) -> crate::MicrosandboxResult<RootfsSource> {
        if let Some(e) = self.error {
            return Err(e);
        }
        self.source.ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(
                "ImageBuilder: no image source set (call .oci() or .disk())".into(),
            )
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn validate_volume_mounts(mounts: &[VolumeMount]) -> crate::MicrosandboxResult<()> {
    for mount in mounts {
        validate_volume_mount(mount)?;
    }
    Ok(())
}

fn validate_volume_mount(mount: &VolumeMount) -> crate::MicrosandboxResult<()> {
    match mount {
        VolumeMount::Bind {
            host,
            guest,
            stat_virtualization,
            host_permissions,
            ..
        } => {
            validate_guest_mount_path(guest)?;
            validate_host_path_wire_safe(host, "bind host path")?;
            validate_virtiofs_policies(*stat_virtualization, *host_permissions)?;
        }
        VolumeMount::Named {
            name,
            guest,
            stat_virtualization,
            host_permissions,
            ..
        } => {
            validate_guest_mount_path(guest)?;
            crate::volume::validate_volume_name(name)?;
            validate_virtiofs_policies(*stat_virtualization, *host_permissions)?;
        }
        VolumeMount::Tmpfs { guest, .. } => {
            validate_guest_mount_path(guest)?;
        }
        VolumeMount::DiskImage {
            host,
            guest,
            fstype,
            ..
        } => {
            validate_guest_mount_path(guest)?;
            validate_host_path_wire_safe(host, "disk image host path")?;
            if let Some(fstype) = fstype {
                validate_fstype(fstype)?;
            }
        }
    }
    Ok(())
}

fn validate_guest_mount_path(guest: &str) -> crate::MicrosandboxResult<()> {
    if !guest.starts_with('/') {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "guest mount path must be absolute: {guest}"
        )));
    }
    if guest == "/" {
        return Err(crate::MicrosandboxError::InvalidConfig(
            "cannot mount a volume at guest root /".into(),
        ));
    }
    if guest.contains(':') || guest.contains(';') || guest.contains(',') {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "guest mount path must not contain ':', ';', or ',': {guest}"
        )));
    }
    Ok(())
}

fn validate_host_path_wire_safe(path: &Path, label: &str) -> crate::MicrosandboxResult<()> {
    let Some(path) = path.to_str() else {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "{label} must be valid UTF-8"
        )));
    };

    if path.contains(',') || path.contains(':') || path.contains(';') {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "{label} must not contain ',', ':', or ';': {path}"
        )));
    }
    Ok(())
}

fn validate_fstype(fstype: &str) -> crate::MicrosandboxResult<()> {
    if fstype.is_empty() {
        return Err(crate::MicrosandboxError::InvalidConfig(
            "fstype must not be empty".into(),
        ));
    }
    if fstype.contains(',') || fstype.contains(';') || fstype.contains(':') || fstype.contains('=')
    {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "fstype must not contain ',', ';', ':', or '=': {fstype}"
        )));
    }
    Ok(())
}

fn validate_virtiofs_policies(
    stat_virtualization: StatVirtualization,
    host_permissions: HostPermissions,
) -> crate::MicrosandboxResult<()> {
    if stat_virtualization == StatVirtualization::Off && host_permissions == HostPermissions::Mirror
    {
        return Err(crate::MicrosandboxError::InvalidConfig(
            "stat_virtualization=Off cannot be combined with host_permissions=Mirror: Off has no \
             overlay, so chmod already operates on the host inode and Mirror would be a no-op. \
             Drop one or the other."
                .into(),
        ));
    }
    Ok(())
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
        Self::oci(String::new())
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

/// Custom serialization for `VolumeMount` covering all four variants.
impl Serialize for VolumeMount {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        match self {
            Self::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
            } => {
                let mut map = serializer.serialize_map(Some(6))?;
                map.serialize_entry("type", "Bind")?;
                map.serialize_entry("host", host)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("options", options)?;
                map.serialize_entry("stat_virtualization", stat_virtualization)?;
                map.serialize_entry("host_permissions", host_permissions)?;
                map.end()
            }
            Self::Named {
                name,
                guest,
                options,
                stat_virtualization,
                host_permissions,
            } => {
                let mut map = serializer.serialize_map(Some(6))?;
                map.serialize_entry("type", "Named")?;
                map.serialize_entry("name", name)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("options", options)?;
                map.serialize_entry("stat_virtualization", stat_virtualization)?;
                map.serialize_entry("host_permissions", host_permissions)?;
                map.end()
            }
            Self::Tmpfs {
                guest,
                size_mib,
                options,
            } => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("type", "Tmpfs")?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("size_mib", size_mib)?;
                map.serialize_entry("options", options)?;
                map.end()
            }
            Self::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            } => {
                let mut map = serializer.serialize_map(Some(6))?;
                map.serialize_entry("type", "DiskImage")?;
                map.serialize_entry("host", host)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("format", format)?;
                map.serialize_entry("fstype", fstype)?;
                map.serialize_entry("options", options)?;
                map.end()
            }
        }
    }
}

/// Custom deserialization for `VolumeMount` covering all four variants.
impl<'de> Deserialize<'de> for VolumeMount {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Helper for tagged deserialization.
        fn default_strict() -> StatVirtualization {
            StatVirtualization::Strict
        }
        fn default_private() -> HostPermissions {
            HostPermissions::Private
        }

        #[derive(Deserialize)]
        #[serde(tag = "type")]
        enum VolumeMountHelper {
            Bind {
                host: PathBuf,
                guest: String,
                options: MountOptions,
                #[serde(default = "default_strict")]
                stat_virtualization: StatVirtualization,
                #[serde(default = "default_private")]
                host_permissions: HostPermissions,
            },
            Named {
                name: String,
                guest: String,
                options: MountOptions,
                #[serde(default = "default_strict")]
                stat_virtualization: StatVirtualization,
                #[serde(default = "default_private")]
                host_permissions: HostPermissions,
            },
            Tmpfs {
                guest: String,
                #[serde(default)]
                size_mib: Option<u32>,
                options: MountOptions,
            },
            DiskImage {
                host: PathBuf,
                guest: String,
                format: DiskImageFormat,
                #[serde(default)]
                fstype: Option<String>,
                options: MountOptions,
            },
        }

        let helper = VolumeMountHelper::deserialize(deserializer)?;
        Ok(match helper {
            VolumeMountHelper::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
            } => Self::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
            },
            VolumeMountHelper::Named {
                name,
                guest,
                options,
                stat_virtualization,
                host_permissions,
            } => Self::Named {
                name,
                guest,
                options,
                stat_virtualization,
                host_permissions,
            },
            VolumeMountHelper::Tmpfs {
                guest,
                size_mib,
                options,
            } => Self::Tmpfs {
                guest,
                size_mib,
                options,
            },
            VolumeMountHelper::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            } => Self::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            },
        })
    }
}

impl std::fmt::Debug for VolumeMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
            } => f
                .debug_struct("Bind")
                .field("host", host)
                .field("guest", guest)
                .field("options", options)
                .field("stat_virtualization", stat_virtualization)
                .field("host_permissions", host_permissions)
                .finish(),
            Self::Named {
                name,
                guest,
                options,
                stat_virtualization,
                host_permissions,
            } => f
                .debug_struct("Named")
                .field("name", name)
                .field("guest", guest)
                .field("options", options)
                .field("stat_virtualization", stat_virtualization)
                .field("host_permissions", host_permissions)
                .finish(),
            Self::Tmpfs {
                guest,
                size_mib,
                options,
            } => f
                .debug_struct("Tmpfs")
                .field("guest", guest)
                .field("size_mib", size_mib)
                .field("options", options)
                .finish(),
            Self::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            } => f
                .debug_struct("DiskImage")
                .field("host", host)
                .field("guest", guest)
                .field("format", format)
                .field("fstype", fstype)
                .field("options", options)
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

    //----------------------------------------------------------------------------------------------
    // MountBuilder validation
    //----------------------------------------------------------------------------------------------

    #[test]
    fn test_mount_builder_size_rejected_on_disk() {
        let err = MountBuilder::new("/data")
            .disk("/host/data.qcow2")
            .size(64u32)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains(".size() is only valid for tmpfs"));
    }

    #[test]
    fn test_mount_builder_size_rejected_on_bind() {
        let err = MountBuilder::new("/data")
            .bind("/host/data")
            .size(64u32)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains(".size() is only valid for tmpfs"));
    }

    #[test]
    fn test_mount_builder_format_rejected_on_non_disk() {
        let err = MountBuilder::new("/data")
            .bind("/host/data")
            .format(DiskImageFormat::Qcow2)
            .build()
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(".format() is only valid for disk image mounts")
        );
    }

    #[test]
    fn test_mount_builder_fstype_rejected_on_non_disk() {
        let err = MountBuilder::new("/data")
            .tmpfs()
            .fstype("ext4")
            .build()
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(".fstype() is only valid for disk image mounts")
        );
    }

    #[test]
    fn test_mount_builder_accepts_valid_named_volume() {
        let mount = MountBuilder::new("/data").named("cache_1").build().unwrap();
        match mount {
            VolumeMount::Named { name, guest, .. } => {
                assert_eq!(name, "cache_1");
                assert_eq!(guest, "/data");
            }
            other => panic!("expected Named, got {other:?}"),
        }
    }

    #[test]
    fn test_mount_builder_rejects_invalid_named_volume() {
        let err = MountBuilder::new("/data")
            .named("cache/../../secrets")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("volume name"));
    }

    #[test]
    fn test_validate_volume_mounts_rejects_direct_guest_separators() {
        let mount = VolumeMount::Tmpfs {
            guest: "/data,ro".to_string(),
            size_mib: None,
            options: MountOptions::default(),
        };

        let err = validate_volume_mounts(&[mount]).unwrap_err();
        assert!(err.to_string().contains("guest mount path"));
    }

    #[test]
    fn test_validate_volume_mounts_rejects_direct_disk_host_separators() {
        let mount = VolumeMount::DiskImage {
            host: PathBuf::from("/host/data:ro.raw"),
            guest: "/data".to_string(),
            format: DiskImageFormat::Raw,
            fstype: None,
            options: MountOptions::default(),
        };

        let err = validate_volume_mounts(&[mount]).unwrap_err();
        assert!(err.to_string().contains("disk image host path"));
    }

    #[test]
    fn test_validate_volume_mounts_rejects_direct_empty_fstype() {
        let mount = VolumeMount::DiskImage {
            host: PathBuf::from("/host/data.raw"),
            guest: "/data".to_string(),
            format: DiskImageFormat::Raw,
            fstype: Some(String::new()),
            options: MountOptions::default(),
        };

        let err = validate_volume_mounts(&[mount]).unwrap_err();
        assert!(err.to_string().contains("fstype must not be empty"));
    }

    #[test]
    fn test_validate_volume_mounts_rejects_direct_off_mirror() {
        let mount = VolumeMount::Bind {
            host: PathBuf::from("/host/data"),
            guest: "/data".to_string(),
            options: MountOptions::default(),
            stat_virtualization: StatVirtualization::Off,
            host_permissions: HostPermissions::Mirror,
        };

        let err = validate_volume_mounts(&[mount]).unwrap_err();
        assert!(err.to_string().contains("stat_virtualization=Off"));
    }

    #[test]
    fn test_volume_mount_json_uses_options_object() {
        let mount = VolumeMount::Bind {
            host: PathBuf::from("/host/data"),
            guest: "/data".to_string(),
            options: MountOptions {
                readonly: true,
                noexec: true,
            },
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
        };

        let value = serde_json::to_value(&mount).unwrap();
        assert!(value.get("readonly").is_none());
        assert!(value.get("noexec").is_none());
        assert_eq!(value["options"]["readonly"], true);
        assert_eq!(value["options"]["noexec"], true);

        let decoded: VolumeMount = serde_json::from_value(value).unwrap();
        match decoded {
            VolumeMount::Bind { options, .. } => {
                assert!(options.readonly);
                assert!(options.noexec);
            }
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[test]
    fn test_mount_builder_disk_then_format_overrides_inference() {
        // .disk(qcow2 path) would infer Qcow2; .format(Raw) afterwards must win.
        let mount = MountBuilder::new("/data")
            .disk("/host/data.qcow2")
            .format(DiskImageFormat::Raw)
            .build()
            .unwrap();
        match mount {
            VolumeMount::DiskImage { format, .. } => assert_eq!(format, DiskImageFormat::Raw),
            other => panic!("expected DiskImage, got {other:?}"),
        }
    }

    #[test]
    fn test_mount_builder_format_before_disk_still_overrides() {
        // Builder methods are call-order independent on the disk path.
        let mount = MountBuilder::new("/data")
            .format(DiskImageFormat::Vmdk)
            .disk("/host/data.qcow2")
            .build()
            .unwrap();
        match mount {
            VolumeMount::DiskImage { format, .. } => assert_eq!(format, DiskImageFormat::Vmdk),
            other => panic!("expected DiskImage, got {other:?}"),
        }
    }

    #[test]
    fn test_mount_builder_disk_extension_inference() {
        // No explicit format → infer from extension.
        for (path, expected) in [
            ("/host/data.qcow2", DiskImageFormat::Qcow2),
            ("/host/data.vmdk", DiskImageFormat::Vmdk),
            ("/host/data.raw", DiskImageFormat::Raw),
            ("/host/data.img", DiskImageFormat::Raw), // unknown → Raw fallback
        ] {
            let mount = MountBuilder::new("/data").disk(path).build().unwrap();
            match mount {
                VolumeMount::DiskImage { format, .. } => assert_eq!(format, expected, "{path}"),
                other => panic!("expected DiskImage for {path}, got {other:?}"),
            }
        }
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
    fn test_image_source_resolves_dot_as_bind() {
        let source = ImageSource::from(".");
        let rootfs = source.into_rootfs_source().unwrap();
        match rootfs {
            RootfsSource::Bind(path) => assert_eq!(path, PathBuf::from(".")),
            _ => panic!("expected Bind"),
        }
    }

    #[test]
    fn test_image_source_resolves_dot_dot_as_bind() {
        let source = ImageSource::from("..");
        let rootfs = source.into_rootfs_source().unwrap();
        match rootfs {
            RootfsSource::Bind(path) => assert_eq!(path, PathBuf::from("..")),
            _ => panic!("expected Bind"),
        }
    }

    #[test]
    fn test_image_source_resolves_oci_reference() {
        let source = ImageSource::from("python");
        let rootfs = source.into_rootfs_source().unwrap();
        match rootfs {
            RootfsSource::Oci(oci) => {
                assert_eq!(oci.reference, "python");
                assert_eq!(oci.upper_size_mib, None);
            }
            _ => panic!("expected Oci"),
        }
    }

    #[test]
    fn test_image_builder_oci_with_upper_size() {
        let rootfs = ImageBuilder::new()
            .oci("python:3.12")
            .upper_size(8192u32)
            .build()
            .unwrap();

        match rootfs {
            RootfsSource::Oci(oci) => {
                assert_eq!(oci.reference, "python:3.12");
                assert_eq!(oci.upper_size_mib, Some(8192));
            }
            _ => panic!("expected Oci"),
        }
    }

    #[test]
    fn test_image_builder_upper_size_requires_oci() {
        let result = ImageBuilder::new().upper_size(8192u32).build();
        let err = result.unwrap_err();

        assert!(err.to_string().contains("upper_size() requires oci()"));
    }

    #[test]
    fn test_image_builder_disk_with_fstype() {
        let rootfs = ImageBuilder::new()
            .disk("./test.qcow2")
            .fstype("ext4")
            .build()
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
        let rootfs = ImageBuilder::new().disk("./test.raw").build().unwrap();
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
        let result = ImageBuilder::new().disk("./test.txt").build();
        assert!(result.is_err());
    }

    #[test]
    fn test_image_builder_fstype_without_disk_errors() {
        let result = ImageBuilder::new().fstype("ext4").build();
        assert!(result.is_err());
    }

    #[test]
    fn test_image_builder_fstype_rejects_comma() {
        let result = ImageBuilder::new()
            .disk("./test.qcow2")
            .fstype("ext4,size=100")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_image_builder_fstype_rejects_equals() {
        let result = ImageBuilder::new()
            .disk("./test.qcow2")
            .fstype("key=value")
            .build();
        assert!(result.is_err());
    }
}
