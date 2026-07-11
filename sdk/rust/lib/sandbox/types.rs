//! Types for sandbox configuration.
//!
//! These types are referenced by [`SandboxConfig`](super::SandboxConfig).

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use crate::size::Mebibytes;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

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
/// .image_with(|i| i.oci("python:3.12").root_disk(8.gib()))
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

/// Builder for constructing a [`VolumeMount`].
pub struct MountBuilder {
    guest: String,
    mount: MountKind,
    options: MountOptions,
    size_mib: Option<u32>,
    quota_mib: Option<u32>,
    disk_format: Option<DiskImageFormat>,
    disk_fstype: Option<String>,
    stat_virtualization: Option<StatVirtualization>,
    host_permissions: Option<HostPermissions>,
    follow_root_symlinks: bool,
    error: Option<crate::MicrosandboxError>,
}

/// Internal kind for the mount builder.
enum MountKind {
    Bind(PathBuf),
    Named {
        name: String,
        create: Option<NamedVolumeCreate>,
    },
    Tmpfs,
    Disk(PathBuf),
    Unset,
}

/// Builder for the writable rootfs layer (root disk) of an OCI image.
///
/// Used with [`ImageBuilder::root_disk_with`] or
/// [`crate::sandbox::SandboxBuilder::root_disk_with`]:
///
/// ```ignore
/// .root_disk_with(|d| d.size(8.gib()))                       // managed ext4 (default kind)
/// .root_disk_with(|d| d.tmpfs().size(2.gib()))               // RAM-backed, ephemeral
/// .root_disk_with(|d| d.disk_image("./scratch.img"))         // user-supplied image
/// ```
#[derive(Default)]
pub struct RootDiskBuilder {
    kind: RootDiskKind,
    size_mib: Option<u32>,
    format: Option<DiskImageFormat>,
    fstype: Option<String>,
    error: Option<crate::MicrosandboxError>,
}

/// Internal kind for the root disk builder. `Unset` resolves to managed.
#[derive(Default)]
enum RootDiskKind {
    #[default]
    Unset,
    Tmpfs,
    DiskImage(PathBuf),
}

/// Sub-builder for [`MountBuilder::named_with`].
pub struct NamedVolumeBuilder {
    create: NamedVolumeCreate,
}

impl NamedVolumeBuilder {
    pub(crate) fn new(name: String) -> Self {
        Self {
            create: NamedVolumeCreate {
                mode: NamedVolumeMode::Existing,
                name,
                kind: VolumeKind::Directory,
                quota_mib: None,
                capacity_mib: None,
                labels: Vec::new(),
            },
        }
    }

    /// Require the volume to already exist.
    pub fn existing(mut self) -> Self {
        self.create.mode = NamedVolumeMode::Existing;
        self
    }

    /// Create the volume and fail if it already exists.
    pub fn create(mut self) -> Self {
        self.create.mode = NamedVolumeMode::Create;
        self
    }

    /// Create the volume if it does not exist, or reuse a compatible existing volume.
    pub fn ensure_exists(mut self) -> Self {
        self.create.mode = NamedVolumeMode::EnsureExists;
        self
    }

    /// Override the volume name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.create.name = name.into();
        self
    }

    /// Use directory-backed storage.
    pub fn directory(mut self) -> Self {
        self.create.kind = VolumeKind::Directory;
        self.create.capacity_mib = None;
        self
    }

    /// Use raw ext4 disk-image storage.
    pub fn disk(mut self) -> Self {
        self.create.kind = VolumeKind::Disk;
        self.create.quota_mib = None;
        self
    }

    /// Set a storage quota for the volume.
    pub fn quota(mut self, size: impl Into<Mebibytes>) -> Self {
        self.create.quota_mib = Some(size.into().as_u32());
        self
    }

    /// Set disk volume capacity.
    pub fn size(mut self, size: impl Into<Mebibytes>) -> Self {
        self.create.capacity_mib = Some(size.into().as_u32());
        self
    }

    /// Attach a label to the volume. Can be called multiple times.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.create.labels.push((key.into(), value.into()));
        self
    }

    pub(crate) fn build(self) -> NamedVolumeCreate {
        self.create
    }
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
            quota_mib: None,
            disk_format: None,
            disk_fstype: None,
            stat_virtualization: None,
            host_permissions: None,
            follow_root_symlinks: false,
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
        self.mount = MountKind::Named {
            name: name.into(),
            create: None,
        };
        self
    }

    /// Mount a named volume with explicit existence behavior.
    pub fn named_with(
        mut self,
        name: impl Into<String>,
        f: impl FnOnce(NamedVolumeBuilder) -> NamedVolumeBuilder,
    ) -> Self {
        let name = name.into();
        let create = f(NamedVolumeBuilder::new(name)).build();
        let name = create.name.clone();
        let create = (create.mode != NamedVolumeMode::Existing).then_some(create);
        self.mount = MountKind::Named { name, create };
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

    /// Ignore setuid and setgid privilege elevation from files on this mount.
    pub fn nosuid(mut self) -> Self {
        self.options.nosuid = true;
        self
    }

    /// Ignore device files on this mount.
    pub fn nodev(mut self) -> Self {
        self.options.nodev = true;
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

    /// Follow symlinks when resolving the host mount root.
    ///
    /// By default the host path is resolved following no symlink in any
    /// component, so a symlink planted at or under the mount root cannot
    /// redirect the mount. Pass `true` to opt out when the host path
    /// legitimately traverses a symlink. Valid only for bind and named-directory
    /// mounts.
    pub fn follow_root_symlinks(mut self, follow: bool) -> Self {
        self.follow_root_symlinks = follow;
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

    /// Set a guest-write quota for a bind mount.
    ///
    /// Bounds how much the guest may add beyond the directory's existing
    /// contents. Without this, a protective default is applied. Valid only for
    /// bind mounts; for named volumes use
    /// [`named_with`](Self::named_with) with the named builder's `quota`.
    ///
    /// ```ignore
    /// .bind("./data").quota(2.gib())   // guest may add up to 2 GiB
    /// ```
    pub fn quota(mut self, size: impl Into<Mebibytes>) -> Self {
        self.quota_mib = Some(size.into().as_u32());
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
        let is_virtiofs = matches!(self.mount, MountKind::Bind(_) | MountKind::Named { .. });
        if self.size_mib.is_some() && !is_tmpfs {
            return Err(crate::MicrosandboxError::InvalidConfig(
                ".size() is only valid for tmpfs mounts".into(),
            ));
        }
        let is_bind = matches!(self.mount, MountKind::Bind(_));
        if self.quota_mib.is_some() && !is_bind {
            return Err(crate::MicrosandboxError::InvalidConfig(
                ".quota() is only valid for bind mounts; for named volumes use \
                 .named_with(|v| v.quota(..))"
                    .into(),
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
                ".stat_virtualization() is only valid for bind and directory-backed named volume mounts"
                    .into(),
            ));
        }
        if self.host_permissions.is_some() && !is_virtiofs {
            return Err(crate::MicrosandboxError::InvalidConfig(
                ".host_permissions() is only valid for bind and directory-backed named volume mounts"
                    .into(),
            ));
        }
        if let MountKind::Named {
            name,
            create: Some(create),
        } = &self.mount
            && create.kind() == VolumeKind::Disk
        {
            // Disk-backed named volumes are passed to the VMM as block
            // devices, so virtiofs-only policies are invalid even when the
            // caller explicitly sets the same values as the defaults.
            if self.stat_virtualization.is_some() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "stat_virtualization is only valid for directory named volumes: {name}"
                )));
            }
            if self.host_permissions.is_some() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "host_permissions is only valid for directory named volumes: {name}"
                )));
            }
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
                // boundary so callers get a clear error. Windows drive
                // prefixes are the one allowed colon shape.
                validate_host_path_wire_safe(&host, "bind host path")?;
                VolumeMount::Bind {
                    host,
                    guest: self.guest,
                    options: self.options,
                    stat_virtualization,
                    host_permissions,
                    follow_root_symlinks: self.follow_root_symlinks,
                    quota_mib: self.quota_mib,
                }
            }
            MountKind::Named { name, create } => {
                crate::volume::validate_volume_name(&name)?;
                VolumeMount::Named {
                    name,
                    guest: self.guest,
                    create,
                    options: self.options,
                    stat_virtualization,
                    host_permissions,
                    follow_root_symlinks: self.follow_root_symlinks,
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
            Ok(RootfsSource::Bind {
                path,
                follow_root_symlinks: false,
            })
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: RootDiskBuilder
//--------------------------------------------------------------------------------------------------

impl RootDiskBuilder {
    /// Set the size in MiB. Valid for the managed (default) and tmpfs kinds;
    /// a user-supplied disk image takes its size from the image file.
    pub fn size(mut self, size: impl Into<Mebibytes>) -> Self {
        if matches!(self.kind, RootDiskKind::DiskImage(_)) {
            self.set_error(
                "size() is not valid for a disk-image root disk; the image file determines the size",
            );
            return self;
        }
        self.size_mib = Some(size.into().as_u32());
        self
    }

    /// Use a RAM-backed tmpfs upper. Ephemeral: the rootfs is pristine on
    /// every boot, and the size counts against guest memory.
    pub fn tmpfs(mut self) -> Self {
        match self.kind {
            RootDiskKind::Unset => self.kind = RootDiskKind::Tmpfs,
            RootDiskKind::Tmpfs => {}
            RootDiskKind::DiskImage(_) => {
                self.set_error("tmpfs() cannot be combined with disk_image()");
            }
        }
        self
    }

    /// Use a user-supplied disk image as the upper, attached writable.
    ///
    /// The format is derived from the file extension (`.img`/`.raw` → raw,
    /// `.qcow2` → qcow2) unless set explicitly with [`format`](Self::format).
    pub fn disk_image(mut self, path: impl Into<PathBuf>) -> Self {
        if matches!(self.kind, RootDiskKind::Tmpfs) {
            self.set_error("disk_image() cannot be combined with tmpfs()");
            return self;
        }
        if self.size_mib.is_some() {
            self.set_error(
                "size() is not valid for a disk-image root disk; the image file determines the size",
            );
            return self;
        }
        self.kind = RootDiskKind::DiskImage(path.into());
        self
    }

    /// Set the disk image format explicitly. Valid only after
    /// [`disk_image`](Self::disk_image). vmdk is not supported as a root disk.
    pub fn format(mut self, format: DiskImageFormat) -> Self {
        if !matches!(self.kind, RootDiskKind::DiskImage(_)) {
            self.set_error("format() requires disk_image() to be called first");
            return self;
        }
        if matches!(format, DiskImageFormat::Vmdk) {
            self.set_error("vmdk is not supported as a root disk (writable vmdk is unavailable)");
            return self;
        }
        self.format = Some(format);
        self
    }

    /// Set the inner filesystem type of the disk image. Defaults to ext4.
    /// Valid only after [`disk_image`](Self::disk_image).
    pub fn fstype(mut self, fstype: impl Into<String>) -> Self {
        if !matches!(self.kind, RootDiskKind::DiskImage(_)) {
            self.set_error("fstype() requires disk_image() to be called first");
            return self;
        }
        let fstype = fstype.into();
        if fstype.is_empty()
            || fstype.contains(',')
            || fstype.contains(';')
            || fstype.contains(':')
            || fstype.contains('=')
        {
            self.set_error("fstype must be non-empty and free of ',', ';', ':', '='");
            return self;
        }
        self.fstype = Some(fstype);
        self
    }

    /// Consume the builder and return the resolved [`RootDisk`].
    pub fn build(self) -> crate::MicrosandboxResult<RootDisk> {
        if let Some(e) = self.error {
            return Err(e);
        }
        match self.kind {
            RootDiskKind::Unset => Ok(RootDisk::Managed {
                size_mib: self.size_mib,
            }),
            RootDiskKind::Tmpfs => Ok(RootDisk::Tmpfs {
                size_mib: self.size_mib,
            }),
            RootDiskKind::DiskImage(path) => {
                let format = match self.format {
                    Some(format) => format,
                    None => {
                        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                        match ext {
                            "img" | "raw" => DiskImageFormat::Raw,
                            "qcow2" => DiskImageFormat::Qcow2,
                            _ => {
                                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                                    "unrecognized root disk image extension: {ext:?} (expected .img, .raw, or .qcow2; or set format() explicitly)"
                                )));
                            }
                        }
                    }
                };
                Ok(RootDisk::DiskImage {
                    path,
                    format,
                    fstype: self.fstype,
                })
            }
        }
    }

    fn set_error(&mut self, msg: &str) {
        if self.error.is_none() {
            self.error = Some(crate::MicrosandboxError::InvalidConfig(msg.into()));
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
    /// .image_with(|i| i.oci("python:3.12").root_disk(8.gib()))
    /// ```
    pub fn oci(mut self, reference: impl Into<String>) -> Self {
        self.source = Some(RootfsSource::oci(reference));
        self
    }

    /// Set a managed root disk of the given size for an OCI rootfs.
    ///
    /// Sugar for `root_disk_with(|d| d.size(size))`. Valid only after
    /// [`oci`](Self::oci).
    pub fn root_disk(self, size: impl Into<Mebibytes>) -> Self {
        let size = size.into();
        self.root_disk_with(|d| d.size(size))
    }

    /// Configure the writable rootfs layer (root disk) for an OCI rootfs.
    ///
    /// Valid only after [`oci`](Self::oci).
    ///
    /// ```ignore
    /// .image_with(|i| i.oci("python:3.12").root_disk(8.gib()))
    /// .image_with(|i| i.oci("python:3.12").root_disk_with(|d| d.tmpfs().size(2.gib())))
    /// .image_with(|i| i.oci("python:3.12").root_disk_with(|d| d.disk_image("./scratch.img")))
    /// ```
    pub fn root_disk_with(
        mut self,
        configure: impl FnOnce(RootDiskBuilder) -> RootDiskBuilder,
    ) -> Self {
        let root_disk = match configure(RootDiskBuilder::default()).build() {
            Ok(root_disk) => root_disk,
            Err(e) => {
                if self.error.is_none() {
                    self.error = Some(e);
                }
                return self;
            }
        };
        match &mut self.source {
            Some(RootfsSource::Oci(oci)) => {
                oci.root_disk = Some(root_disk);
            }
            _ => {
                if self.error.is_none() {
                    self.error = Some(crate::MicrosandboxError::InvalidConfig(
                        "root_disk() requires oci() to be called first".into(),
                    ));
                }
            }
        }
        self
    }

    /// Set the writable overlay upper size for an OCI rootfs.
    ///
    /// This is valid only after [`oci`](Self::oci).
    #[deprecated(since = "0.6.0", note = "use `root_disk` instead")]
    pub fn upper_size(self, size: impl Into<Mebibytes>) -> Self {
        self.root_disk(size)
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

    /// Use a host directory directly as the root filesystem (bind rootfs).
    ///
    /// The directory's contents become the guest root filesystem as-is — no
    /// OCI pull and no overlay. Mutually exclusive with [`oci`](Self::oci) and
    /// [`disk`](Self::disk).
    ///
    /// ```ignore
    /// .image_with(|i| i.bind("/srv/rootfs"))
    /// ```
    pub fn bind(mut self, host: impl Into<PathBuf>) -> Self {
        self.source = Some(RootfsSource::Bind {
            path: host.into(),
            follow_root_symlinks: false,
        });
        self
    }

    /// Follow symlinks when resolving a bind rootfs host path.
    ///
    /// By default the bind rootfs path is resolved following no symlink, so a
    /// symlink at or under it cannot redirect the mount. Pass `true` to opt out
    /// when the host path legitimately traverses a symlink. Only valid after
    /// [`bind`](Self::bind); produces an error at build time otherwise.
    pub fn follow_root_symlinks(mut self, follow: bool) -> Self {
        match &mut self.source {
            Some(RootfsSource::Bind {
                follow_root_symlinks,
                ..
            }) => *follow_root_symlinks = follow,
            _ if self.error.is_none() => {
                self.error = Some(crate::MicrosandboxError::InvalidConfig(
                    "follow_root_symlinks is only valid for a bind rootfs (call .bind() first)"
                        .into(),
                ));
            }
            _ => {}
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
                "ImageBuilder: no image source set (call .oci(), .disk(), or .bind())".into(),
            )
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn validate_volume_mounts(mounts: &[VolumeMount]) -> crate::MicrosandboxResult<()> {
    let mut guests = HashSet::new();

    for mount in mounts {
        validate_volume_mount(mount)?;
        let guest = mount.guest();
        if !guests.insert(guest) {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "multiple volumes cannot mount the same guest path: {guest}"
            )));
        }
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
            create,
            ..
        } => {
            validate_guest_mount_path(guest)?;
            crate::volume::validate_volume_name(name)?;
            if create
                .as_ref()
                .is_some_and(|create| create.kind() == VolumeKind::Disk)
            {
                validate_named_disk_mount_options(name, *stat_virtualization, *host_permissions)?;
            } else {
                validate_virtiofs_policies(*stat_virtualization, *host_permissions)?;
            }
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

    if path.contains(',') || path.contains(';') || has_forbidden_host_path_colon(path) {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "{label} must not contain ',', ':', or ';': {path}"
        )));
    }
    Ok(())
}

fn has_forbidden_host_path_colon(path: &str) -> bool {
    path.char_indices().any(|(index, c)| {
        c == ':' && {
            #[cfg(windows)]
            {
                !microsandbox_utils::is_windows_drive_separator_at(path, index)
            }
            #[cfg(not(windows))]
            {
                let _ = index;
                true
            }
        }
    })
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

pub(crate) fn validate_named_disk_mount_options(
    name: &str,
    stat_virtualization: StatVirtualization,
    host_permissions: HostPermissions,
) -> crate::MicrosandboxResult<()> {
    if stat_virtualization != StatVirtualization::Strict {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "stat_virtualization is only valid for directory named volumes: {name}"
        )));
    }
    if host_permissions != HostPermissions::Private {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "host_permissions is only valid for directory named volumes: {name}"
        )));
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
    fn test_mount_builder_quota_on_bind() {
        let mount = MountBuilder::new("/data")
            .bind("/host/data")
            .quota(2048u32)
            .build()
            .unwrap();
        match mount {
            VolumeMount::Bind { quota_mib, .. } => assert_eq!(quota_mib, Some(2048)),
            other => panic!("expected bind mount, got {other:?}"),
        }
    }

    #[test]
    fn test_mount_builder_quota_rejected_on_tmpfs() {
        let err = MountBuilder::new("/data")
            .tmpfs()
            .quota(64u32)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains(".quota() is only valid for bind"));
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
    fn test_mount_builder_rejects_named_disk_virtiofs_policy() {
        let err = MountBuilder::new("/data")
            .named_with("cache-disk", |v| v.disk().size(1024u32).ensure_exists())
            .stat_virtualization(StatVirtualization::Relaxed)
            .build()
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("only valid for directory named volumes"),
            "got: {err}"
        );
    }

    #[test]
    fn test_mount_builder_rejects_named_disk_explicit_default_stat_policy() {
        let err = MountBuilder::new("/data")
            .named_with("cache-disk", |v| v.disk().size(1024u32).ensure_exists())
            .stat_virtualization(StatVirtualization::Strict)
            .build()
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("only valid for directory named volumes"),
            "got: {err}"
        );
    }

    #[test]
    fn test_mount_builder_rejects_named_disk_explicit_default_host_policy() {
        let err = MountBuilder::new("/data")
            .named_with("cache-disk", |v| v.disk().size(1024u32).ensure_exists())
            .host_permissions(HostPermissions::Private)
            .build()
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("only valid for directory named volumes"),
            "got: {err}"
        );
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
    fn test_validate_volume_mounts_rejects_duplicate_guest_paths() {
        let mounts = vec![
            VolumeMount::Tmpfs {
                guest: "/data".to_string(),
                size_mib: None,
                options: MountOptions::default(),
            },
            VolumeMount::Named {
                name: "cache".to_string(),
                guest: "/data".to_string(),
                create: None,
                options: MountOptions::default(),
                stat_virtualization: StatVirtualization::Strict,
                host_permissions: HostPermissions::Private,
                follow_root_symlinks: false,
            },
        ];

        let err = validate_volume_mounts(&mounts).unwrap_err();
        assert!(err.to_string().contains("same guest path"));
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
    #[cfg(windows)]
    fn test_validate_volume_mounts_accepts_windows_drive_host_paths() {
        let mounts = vec![
            VolumeMount::Bind {
                host: PathBuf::from(r"C:\Users\Stephen\data"),
                guest: "/data".to_string(),
                options: MountOptions::default(),
                stat_virtualization: StatVirtualization::Strict,
                host_permissions: HostPermissions::Private,
                quota_mib: None,
            },
            VolumeMount::DiskImage {
                host: PathBuf::from(r"C:\Users\Stephen\data.raw"),
                guest: "/disk".to_string(),
                format: DiskImageFormat::Raw,
                fstype: None,
                options: MountOptions::default(),
            },
        ];

        validate_volume_mounts(&mounts).unwrap();
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
            follow_root_symlinks: false,
            quota_mib: None,
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
                ..MountOptions::default()
            },
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            follow_root_symlinks: false,
            quota_mib: None,
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
    fn test_volume_mount_json_accepts_legacy_readonly_field() {
        let bind: VolumeMount = serde_json::from_str(
            r#"{"type":"Bind","host":"/host/data","guest":"/data","readonly":true}"#,
        )
        .unwrap();
        match bind {
            VolumeMount::Bind { options, .. } => {
                assert!(options.readonly);
                assert!(!options.noexec);
            }
            other => panic!("expected Bind, got {other:?}"),
        }

        let named: VolumeMount =
            serde_json::from_str(r#"{"type":"Named","name":"cache","guest":"/cache"}"#).unwrap();
        match named {
            VolumeMount::Named { options, .. } => assert_eq!(options, MountOptions::default()),
            other => panic!("expected Named, got {other:?}"),
        }

        let tmpfs: VolumeMount =
            serde_json::from_str(r#"{"type":"Tmpfs","guest":"/tmp","readonly":false}"#).unwrap();
        match tmpfs {
            VolumeMount::Tmpfs { options, .. } => assert_eq!(options, MountOptions::default()),
            other => panic!("expected Tmpfs, got {other:?}"),
        }

        let disk: VolumeMount = serde_json::from_str(
            r#"{"type":"DiskImage","host":"/host/data.raw","guest":"/data","format":"Raw","readonly":true}"#,
        )
        .unwrap();
        match disk {
            VolumeMount::DiskImage { options, .. } => {
                assert!(options.readonly);
                assert!(!options.noexec);
            }
            other => panic!("expected DiskImage, got {other:?}"),
        }
    }

    #[test]
    fn test_mount_options_json_defaults_missing_fields() {
        let options: MountOptions = serde_json::from_str(r#"{"readonly":true}"#).unwrap();

        assert!(options.readonly);
        assert!(!options.noexec);
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
        assert!(matches!(rootfs, RootfsSource::Bind { .. }));
    }

    #[test]
    fn test_image_source_resolves_dot_as_bind() {
        let source = ImageSource::from(".");
        let rootfs = source.into_rootfs_source().unwrap();
        match rootfs {
            RootfsSource::Bind { path, .. } => assert_eq!(path, PathBuf::from(".")),
            _ => panic!("expected Bind"),
        }
    }

    #[test]
    fn test_image_source_resolves_dot_dot_as_bind() {
        let source = ImageSource::from("..");
        let rootfs = source.into_rootfs_source().unwrap();
        match rootfs {
            RootfsSource::Bind { path, .. } => assert_eq!(path, PathBuf::from("..")),
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
                assert_eq!(oci.root_disk, None);
            }
            _ => panic!("expected Oci"),
        }
    }

    #[test]
    fn test_image_builder_oci_with_root_disk() {
        let rootfs = ImageBuilder::new()
            .oci("python:3.12")
            .root_disk(8192u32)
            .build()
            .unwrap();

        match rootfs {
            RootfsSource::Oci(oci) => {
                assert_eq!(oci.reference, "python:3.12");
                assert_eq!(oci.root_disk, Some(RootDisk::managed(8192)));
            }
            _ => panic!("expected Oci"),
        }
    }

    #[test]
    fn test_image_builder_oci_with_deprecated_upper_size_alias() {
        #[allow(deprecated)]
        let rootfs = ImageBuilder::new()
            .oci("python:3.12")
            .upper_size(8192u32)
            .build()
            .unwrap();

        match rootfs {
            RootfsSource::Oci(oci) => {
                assert_eq!(oci.root_disk, Some(RootDisk::managed(8192)));
            }
            _ => panic!("expected Oci"),
        }
    }

    #[test]
    fn test_image_builder_root_disk_requires_oci() {
        let result = ImageBuilder::new().root_disk(8192u32).build();
        let err = result.unwrap_err();

        assert!(err.to_string().contains("root_disk() requires oci()"));
    }

    #[test]
    fn test_root_disk_builder_tmpfs() {
        let root_disk = RootDiskBuilder::default()
            .tmpfs()
            .size(2048u32)
            .build()
            .unwrap();
        assert_eq!(root_disk, RootDisk::tmpfs(2048));
    }

    #[test]
    fn test_root_disk_builder_disk_image_infers_format() {
        let root_disk = RootDiskBuilder::default()
            .disk_image("./scratch.img")
            .fstype("ext4")
            .build()
            .unwrap();
        assert_eq!(
            root_disk,
            RootDisk::DiskImage {
                path: PathBuf::from("./scratch.img"),
                format: DiskImageFormat::Raw,
                fstype: Some("ext4".into()),
            }
        );
    }

    #[test]
    fn test_root_disk_builder_rejects_size_with_disk_image() {
        let err = RootDiskBuilder::default()
            .disk_image("./scratch.img")
            .size(8192u32)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("not valid for a disk-image"));
    }

    #[test]
    fn test_root_disk_builder_rejects_tmpfs_with_disk_image() {
        let err = RootDiskBuilder::default()
            .tmpfs()
            .disk_image("./scratch.img")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("cannot be combined"));
    }

    #[test]
    fn test_root_disk_builder_rejects_vmdk_format() {
        let err = RootDiskBuilder::default()
            .disk_image("./scratch.vmdk")
            .format(DiskImageFormat::Vmdk)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("vmdk is not supported"));
    }

    #[test]
    fn test_root_disk_builder_rejects_unknown_extension_without_format() {
        let err = RootDiskBuilder::default()
            .disk_image("./scratch.bin")
            .build()
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("unrecognized root disk image extension")
        );
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

    #[test]
    fn test_image_builder_bind() {
        let rootfs = ImageBuilder::new().bind("/srv/rootfs").build().unwrap();
        match rootfs {
            RootfsSource::Bind {
                path,
                follow_root_symlinks,
            } => {
                assert_eq!(path, std::path::PathBuf::from("/srv/rootfs"));
                // Protected by default.
                assert!(!follow_root_symlinks);
            }
            _ => panic!("expected Bind"),
        }
    }

    #[test]
    fn test_image_builder_bind_follow_root_symlinks_opt_out() {
        let rootfs = ImageBuilder::new()
            .bind("/srv/rootfs")
            .follow_root_symlinks(true)
            .build()
            .unwrap();
        match rootfs {
            RootfsSource::Bind {
                follow_root_symlinks,
                ..
            } => assert!(follow_root_symlinks),
            _ => panic!("expected Bind"),
        }
    }

    #[test]
    fn test_image_builder_follow_root_symlinks_without_bind_errors() {
        // The opt-out only applies to a bind rootfs.
        let result = ImageBuilder::new()
            .oci("python:3.12")
            .follow_root_symlinks(true)
            .build();
        assert!(result.is_err());
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::{
    DiskImageFormat, HostPermissions, MountOptions, NamedVolumeCreate, NamedVolumeMode,
    OciRootfsSource, Patch, RootDisk, RootfsSource, SecurityProfile, StatVirtualization,
    VolumeKind, VolumeMount,
};
