//! Patch application logic for rootfs modification before VM start.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions, Permissions};
#[cfg(unix)]
use cap_std::fs::{DirBuilder, DirBuilderExt, OpenOptionsExt};
use microsandbox_image::erofs::{ErofsEntryInfo, ErofsEntryKind, ErofsReader};
use microsandbox_image::tree::{
    DeviceNode, DirectoryNode, FileData, FileTree, FileTreeError, InodeMetadata, RegularFileId,
    RegularFileNode, SymlinkNode, TreeNode,
};
use tokio::fs;
use tokio::io::AsyncReadExt;

use super::types::{Patch, RootfsSource};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Pre-opened EROFS readers for the lower layer images.
///
/// Avoids repeatedly opening, parsing the superblock, and closing each
/// `.erofs` file on every path lookup during patch resolution.
struct LowerLayers {
    readers: Vec<ErofsReader>,
}

/// Capability-scoped view of a host-directory rootfs.
///
/// Every patch destination is resolved relative to `root`, so a symlink or
/// concurrent rename cannot redirect host filesystem operations outside the
/// configured bind root.
struct RootedPatchFs {
    root: Dir,
}

/// One unresolved component while applying guest-root symlink semantics.
enum PendingComponent {
    Parent { clamp_at_root: bool },
    Normal(OsString),
    RequireDirectory,
}

/// One frame in the iterative Windows removal walk.
#[cfg(windows)]
enum WindowsRemovalFrame {
    Visit(std::fs::File),
    Directory {
        entry: std::fs::File,
        pending: VecDeque<OsString>,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LowerLayers {
    fn open(paths: &[PathBuf]) -> MicrosandboxResult<Self> {
        let mut readers = Vec::with_capacity(paths.len());
        for path in paths {
            let file = std::fs::File::open(path).map_err(|e| {
                crate::MicrosandboxError::PatchFailed(format!(
                    "failed to open lower layer {}: {e}",
                    path.display()
                ))
            })?;
            let reader = ErofsReader::new(file).map_err(|e| {
                crate::MicrosandboxError::PatchFailed(format!(
                    "failed to parse EROFS image {}: {e}",
                    path.display()
                ))
            })?;
            readers.push(reader);
        }
        Ok(Self { readers })
    }

    fn len(&self) -> usize {
        self.readers.len()
    }

    fn entry_info(
        &mut self,
        layer_idx: usize,
        guest_path: &str,
    ) -> MicrosandboxResult<Option<ErofsEntryInfo>> {
        match self.readers[layer_idx].entry_info(guest_path) {
            Ok(info) => Ok(Some(info)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(crate::MicrosandboxError::PatchFailed(format!(
                "failed to inspect lower layer '{guest_path}': {err}",
            ))),
        }
    }

    fn read_file(&mut self, layer_idx: usize, guest_path: &str) -> MicrosandboxResult<Vec<u8>> {
        self.readers[layer_idx]
            .read_file(guest_path)
            .map_err(|err| {
                crate::MicrosandboxError::PatchFailed(format!(
                    "failed to read lower layer file '{guest_path}': {err}",
                ))
            })
    }
}

impl RootedPatchFs {
    /// Open and pin the bind root before any patch destination is resolved.
    fn open(path: &Path, follow_root_symlinks: bool) -> MicrosandboxResult<Self> {
        let root = if follow_root_symlinks {
            Dir::open_ambient_dir(path, ambient_authority()).map_err(|err| {
                crate::MicrosandboxError::PatchFailed(format!(
                    "failed to open bind root {}: {err}",
                    path.display()
                ))
            })?
        } else {
            open_root_without_links(path)?
        };
        Ok(Self { root })
    }

    fn write_all(&self, writer: &mut impl Write, content: &[u8]) -> MicrosandboxResult<()> {
        writer.write_all(content)?;
        Ok(())
    }

    fn copy_stream(
        &self,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) -> MicrosandboxResult<()> {
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                return Ok(());
            }
            writer.write_all(&buffer[..read])?;
        }
    }

    /// Resolve a guest path beneath the pinned root.
    ///
    /// Existing symlinks are expanded explicitly so absolute targets restart
    /// at the guest root instead of the host root. The final capability-based
    /// operation repeats containment during use, which closes rename races
    /// between this semantic resolution and the mutation itself.
    fn resolve(&self, guest_path: &str, follow_final: bool) -> MicrosandboxResult<PathBuf> {
        self.resolve_components(guest_path_components(guest_path)?, follow_final, guest_path)
    }

    /// Resolve an already-normalized capability-relative path.
    ///
    /// `CopyDir` uses this for source names, which may not be valid UTF-8 on
    /// Unix and therefore cannot be round-tripped through a guest path string.
    fn resolve_relative(&self, path: &Path, follow_final: bool) -> MicrosandboxResult<PathBuf> {
        let mut remaining = VecDeque::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::Normal(name) => {
                    remaining.push_back(PendingComponent::Normal(name.to_os_string()));
                }
                _ => {
                    return Err(crate::MicrosandboxError::PatchFailed(format!(
                        "internal patch path is not root-relative: {}",
                        path.display()
                    )));
                }
            }
        }

        let display = format!("/{}", path.display());
        self.resolve_components(remaining, follow_final, &display)
    }

    fn resolve_components(
        &self,
        mut remaining: VecDeque<PendingComponent>,
        follow_final: bool,
        guest_path: &str,
    ) -> MicrosandboxResult<PathBuf> {
        let mut resolved = Vec::<OsString>::new();
        let mut followed = 0usize;

        while let Some(component) = remaining.pop_front() {
            match component {
                PendingComponent::Parent { clamp_at_root } => {
                    if resolved.pop().is_none() && !clamp_at_root {
                        return Err(crate::MicrosandboxError::PatchFailed(format!(
                            "patch path escapes rootfs: '{guest_path}'"
                        )));
                    }
                }
                PendingComponent::RequireDirectory => {
                    let candidate = join_components(&resolved, None);
                    self.root.open_dir(candidate).map_err(|err| {
                        crate::MicrosandboxError::PatchFailed(format!(
                            "symlink target must resolve to a directory while resolving '{guest_path}': {err}"
                        ))
                    })?;
                }
                PendingComponent::Normal(name) => {
                    let is_final = remaining.is_empty();
                    if is_final && !follow_final {
                        resolved.push(name);
                        continue;
                    }

                    let candidate = join_components(&resolved, Some(&name));
                    match self.root.symlink_metadata(&candidate) {
                        Ok(metadata) if metadata.file_type().is_symlink() => {
                            followed += 1;
                            if followed > 40 {
                                return Err(crate::MicrosandboxError::PatchFailed(format!(
                                    "too many symlinks while resolving patch path: '{guest_path}'"
                                )));
                            }
                            let target = self.root.read_link_contents(&candidate)?;
                            prepend_link_target(
                                &target,
                                &mut resolved,
                                &mut remaining,
                                guest_path,
                            )?;
                        }
                        Ok(_) => resolved.push(name),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                            resolved.push(name);
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
            }
        }

        if resolved.is_empty() {
            return Err(crate::MicrosandboxError::PatchFailed(
                "patch path must not be '/'".into(),
            ));
        }
        Ok(join_components(&resolved, None))
    }

    fn ensure_parent(&self, path: &Path) -> MicrosandboxResult<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            self.root.create_dir_all(parent)?;
        }
        Ok(())
    }

    /// Open a patch destination with mutation-level replacement semantics.
    ///
    /// `create_new` makes `replace = false` atomic: a concurrent creator wins
    /// or loses the same filesystem operation instead of racing a prior stat.
    fn open_file_for_write(
        &self,
        path: &Path,
        guest_path: &str,
        replace: bool,
        mode: Option<u32>,
    ) -> MicrosandboxResult<File> {
        self.ensure_parent(path)?;
        let mut options = OpenOptions::new();
        options.write(true);
        if replace {
            // Defer truncation until the opened handle has its requested mode.
            // Otherwise replacing a public file with private content exposes a
            // window where readers can observe the new bytes under the old mode.
            options.create(true);
        } else {
            options.create_new(true);
        }
        #[cfg(unix)]
        if let Some(mode) = mode {
            options.mode(mode);
        }

        let file = self.root.open_with(path, &options).map_err(|err| {
            if !replace && err.kind() == std::io::ErrorKind::AlreadyExists {
                path_exists_error(guest_path)
            } else {
                err.into()
            }
        })?;

        if let Some(mode) = mode {
            set_file_mode(&file, mode)?;
        }
        if replace {
            file.set_len(0)?;
        }
        Ok(file)
    }

    fn write_file(
        &self,
        path: &Path,
        guest_path: &str,
        content: &[u8],
        replace: bool,
        mode: Option<u32>,
    ) -> MicrosandboxResult<()> {
        let mut file = self.open_file_for_write(path, guest_path, replace, mode)?;
        self.write_all(&mut file, content)?;
        // Writing may clear set-id bits, so restore the exact requested mode.
        if let Some(mode) = mode {
            set_file_mode(&file, mode)?;
        }
        Ok(())
    }

    fn copy_file(
        &self,
        src: &Path,
        dst: &Path,
        guest_path: &str,
        replace: bool,
        mode: Option<u32>,
    ) -> MicrosandboxResult<()> {
        let mut source_options = std::fs::OpenOptions::new();
        source_options.read(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::custom_flags(&mut source_options, libc::O_NONBLOCK);
        let mut source = source_options.open(src)?;
        let source_metadata = source.metadata()?;
        if !source_metadata.is_file() {
            return Err(crate::MicrosandboxError::PatchFailed(format!(
                "CopyFile source is not a regular file: {}",
                src.display()
            )));
        }
        let source_mode = source_std_permissions_mode(&source_metadata.permissions());
        #[cfg(windows)]
        let source_permissions = source_metadata.permissions();
        let destination_mode = mode.or(source_mode);
        let mut destination =
            self.open_file_for_write(dst, guest_path, replace, destination_mode)?;
        self.copy_stream(&mut source, &mut destination)?;
        if let Some(mode) = destination_mode {
            set_file_mode(&destination, mode)?;
        }
        #[cfg(windows)]
        destination.set_permissions(Permissions::from_std(source_permissions))?;
        Ok(())
    }

    fn copy_dir(
        &self,
        src: &Path,
        dst: &Path,
        guest_path: &str,
        replace: bool,
    ) -> MicrosandboxResult<()> {
        let source = Dir::open_ambient_dir(src, ambient_authority()).map_err(|err| {
            crate::MicrosandboxError::PatchFailed(format!(
                "failed to open CopyDir source {}: {err}",
                src.display()
            ))
        })?;
        self.validate_copy_dir_source(&source)?;
        self.copy_dir_from(&source, dst, guest_path, replace)
    }

    /// Validate the complete source tree before creating a destination.
    fn validate_copy_dir_source(&self, source: &Dir) -> MicrosandboxResult<()> {
        for entry in source.entries()? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                #[cfg(unix)]
                continue;
                #[cfg(windows)]
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "CopyDir source contains a symlink unsupported for Windows host bind roots: '{}'",
                    entry.file_name().to_string_lossy()
                )));
            }
            if file_type.is_dir() {
                let source_file = source.try_clone()?.into_std_file();
                let child = cap_primitives::fs::open_dir_nofollow(
                    &source_file,
                    Path::new(&entry.file_name()),
                )?;
                self.validate_copy_dir_source(&Dir::from_std_file(child))?;
            } else if !file_type.is_file() {
                return Err(crate::MicrosandboxError::PatchFailed(format!(
                    "CopyDir source contains an unsupported file type: '{}'",
                    entry.file_name().to_string_lossy()
                )));
            }
        }
        Ok(())
    }

    /// Copy one already-pinned source directory without following child links.
    fn copy_dir_from(
        &self,
        source: &Dir,
        dst: &Path,
        guest_path: &str,
        replace: bool,
    ) -> MicrosandboxResult<()> {
        #[cfg(unix)]
        let source_mode = source_cap_permissions_mode(&source.dir_metadata()?.permissions());
        self.ensure_parent(dst)?;
        #[cfg(unix)]
        {
            if replace {
                self.root.create_dir_all(dst)?;
            } else {
                let mut builder = DirBuilder::new();
                builder.mode(source_mode.unwrap_or(0o755));
                self.root.create_dir_with(dst, &builder).map_err(|err| {
                    if err.kind() == std::io::ErrorKind::AlreadyExists {
                        path_exists_error(guest_path)
                    } else {
                        err.into()
                    }
                })?;
            }
            if let Some(mode) = source_mode {
                set_dir_mode(&self.root.open_dir(dst)?, mode)?;
            }
        }
        #[cfg(windows)]
        {
            if replace {
                self.root.create_dir_all(dst)?;
            } else {
                self.root.create_dir(dst).map_err(|err| {
                    if err.kind() == std::io::ErrorKind::AlreadyExists {
                        path_exists_error(guest_path)
                    } else {
                        err.into()
                    }
                })?;
            }
        }

        for entry in source.entries()? {
            let entry = entry?;
            let unresolved_dst = dst.join(entry.file_name());
            let child_guest_path = format!("/{}", unresolved_dst.display());
            let file_type = entry.file_type()?;
            // A copied source symlink replaces the destination entry itself.
            // Regular files and directories retain the existing patch rule
            // that replace=true follows a final destination symlink.
            let resolved_dst =
                self.resolve_relative(&unresolved_dst, replace && !file_type.is_symlink())?;

            if file_type.is_symlink() {
                #[cfg(unix)]
                {
                    let target = source.read_link_contents(entry.file_name())?;
                    self.create_symlink(&target, &resolved_dst, &child_guest_path, replace)?;
                    continue;
                }
                #[cfg(windows)]
                {
                    return Err(crate::MicrosandboxError::InvalidConfig(format!(
                        "CopyDir source contains a symlink unsupported for Windows host bind roots: '{}'",
                        entry.file_name().to_string_lossy()
                    )));
                }
            }

            if file_type.is_dir() {
                let source_file = source.try_clone()?.into_std_file();
                let child = cap_primitives::fs::open_dir_nofollow(
                    &source_file,
                    Path::new(&entry.file_name()),
                )?;
                self.copy_dir_from(
                    &Dir::from_std_file(child),
                    &resolved_dst,
                    &child_guest_path,
                    replace,
                )?;
                continue;
            }

            if !file_type.is_file() {
                return Err(crate::MicrosandboxError::PatchFailed(format!(
                    "CopyDir source contains an unsupported file type: '{}'",
                    entry.file_name().to_string_lossy()
                )));
            }

            let mut source_options = OpenOptions::new();
            source_options.read(true);
            source_options._cap_fs_ext_follow(cap_primitives::fs::FollowSymlinks::No);
            #[cfg(unix)]
            source_options.custom_flags(libc::O_NONBLOCK);
            let mut source_file = source.open_with(entry.file_name(), &source_options)?;
            if !source_file.metadata()?.is_file() {
                return Err(crate::MicrosandboxError::PatchFailed(format!(
                    "CopyDir source changed to an unsupported file type: '{}'",
                    entry.file_name().to_string_lossy()
                )));
            }
            let source_permissions = source_file.metadata()?.permissions();
            let source_mode = source_cap_permissions_mode(&source_permissions);
            let mut destination =
                self.open_file_for_write(&resolved_dst, &child_guest_path, replace, source_mode)?;
            self.copy_stream(&mut source_file, &mut destination)?;
            if let Some(mode) = source_mode {
                set_file_mode(&destination, mode)?;
            }
            #[cfg(windows)]
            destination.set_permissions(source_permissions)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn create_symlink(
        &self,
        target: &Path,
        link_path: &Path,
        guest_path: &str,
        replace: bool,
    ) -> MicrosandboxResult<()> {
        self.ensure_parent(link_path)?;
        if replace {
            self.remove_entry(link_path)?;
        }
        self.root
            .symlink_contents(target, link_path)
            .map_err(|err| {
                if !replace && err.kind() == std::io::ErrorKind::AlreadyExists {
                    path_exists_error(guest_path)
                } else {
                    err.into()
                }
            })
    }

    fn create_dir(&self, path: &Path, mode: Option<u32>) -> MicrosandboxResult<()> {
        let Some(mode) = mode else {
            self.root.create_dir_all(path)?;
            return Ok(());
        };

        #[cfg(unix)]
        {
            match self.root.open_dir(path) {
                Ok(existing) => return set_dir_mode(&existing, mode),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }

            self.ensure_parent(path)?;
            let mut builder = DirBuilder::new();
            builder.mode(mode);
            match self.root.create_dir_with(path, &builder) {
                Ok(()) => {
                    let created = self.root.open_dir(path)?;
                    set_dir_mode(&created, mode)
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing = self.root.open_dir(path)?;
                    set_dir_mode(&existing, mode)
                }
                Err(err) => Err(err.into()),
            }
        }

        #[cfg(windows)]
        {
            let _ = (path, mode);
            Err(crate::MicrosandboxError::InvalidConfig(
                "POSIX patch modes are not supported for Windows host bind roots".into(),
            ))
        }
    }

    fn remove_entry(&self, path: &Path) -> MicrosandboxResult<()> {
        #[cfg(unix)]
        {
            match self.root.symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_dir() => {
                    let directory = self.root.open_dir(path)?;
                    directory.remove_open_dir_all()?;
                }
                Ok(_) => {
                    self.root.remove_file(path)?;
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
            return Ok(());
        }

        #[cfg(windows)]
        {
            let parent_path = path.parent().unwrap_or_else(|| Path::new(""));
            let name = path.file_name().ok_or_else(|| {
                crate::MicrosandboxError::PatchFailed(format!(
                    "patch removal path has no final component: {}",
                    path.display()
                ))
            })?;
            let parent = if parent_path.as_os_str().is_empty() {
                self.root.try_clone()?
            } else {
                self.root.open_dir(parent_path)?
            };
            let parent = parent.into_std_file();
            match windows_open_relative_for_removal(&parent, name) {
                Ok(entry) => windows_remove_open_entry(entry)?,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
            return Ok(());
        }

        #[allow(unreachable_code)]
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Apply patches to the rootfs before VM start.
///
/// This host-filesystem path is used for bind roots. OCI roots are normalized
/// into an in-memory tree and baked into `upper.ext4` instead.
pub(crate) async fn apply_patches(
    image: &RootfsSource,
    patches: &[Patch],
) -> MicrosandboxResult<()> {
    if patches.is_empty() {
        return Ok(());
    }

    let (target_dir, follow_root_symlinks) = match image {
        RootfsSource::Bind {
            path,
            follow_root_symlinks,
        } => (path.clone(), *follow_root_symlinks),
        RootfsSource::Oci(_) => {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "OCI patches are baked into upper.ext4 before VM start".into(),
            ));
        }
        RootfsSource::DiskImage { .. } => {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "patches are not compatible with disk image rootfs".into(),
            ));
        }
    };

    // Validate the complete batch before touching a bind root. This matters on
    // Windows, where POSIX modes and symlink patches are predictably
    // unsupported and must not fail after earlier patches have been applied.
    validate_bind_patches(patches)?;

    let root =
        tokio::task::spawn_blocking(move || RootedPatchFs::open(&target_dir, follow_root_symlinks))
            .await
            .map_err(|err| {
                crate::MicrosandboxError::PatchFailed(format!("bind-root open task failed: {err}"))
            })??;
    let root = Arc::new(root);

    // Dispatch one patch at a time. Dropping this future lets the active patch
    // finish, but never starts the rest of the batch. This avoids leaving a
    // partially written persistent root while bounding payload clones.
    for patch in patches {
        let root = Arc::clone(&root);
        let patch = patch.clone();
        tokio::task::spawn_blocking(move || apply_one_to_bind(&root, &patch))
            .await
            .map_err(|err| {
                crate::MicrosandboxError::PatchFailed(format!("bind-root patch task failed: {err}"))
            })??;
    }
    Ok(())
}

pub(crate) async fn build_upper_tree(
    patches: &[Patch],
    lower_erofs: &[PathBuf],
) -> MicrosandboxResult<FileTree> {
    // Pre-open all EROFS readers once — avoids repeated open/parse/close
    // per path lookup (hundreds of file opens for multi-patch scenarios).
    let mut lowers = LowerLayers::open(lower_erofs)?;
    let mut tree = FileTree::new();
    for patch in patches {
        apply_one_to_tree(&mut tree, &mut lowers, patch).await?;
    }
    Ok(tree)
}

async fn apply_one_to_tree(
    tree: &mut FileTree,
    lowers: &mut LowerLayers,
    patch: &Patch,
) -> MicrosandboxResult<()> {
    match patch {
        Patch::Text {
            path,
            content,
            mode,
            replace,
        } => {
            let rel = normalize_guest_path_bytes(path)?;
            check_replace_tree(tree, lowers, path, *replace)?;
            ensure_tree_parents(tree, lowers, &rel)?;
            insert_tree_node(
                tree,
                &rel,
                TreeNode::RegularFile(RegularFileNode {
                    id: RegularFileId::new(),
                    metadata: metadata_with_mode(mode.unwrap_or(0o644) as u16),
                    xattrs: Vec::new(),
                    data: FileData::Memory(content.as_bytes().to_vec()),
                    nlink: 1,
                }),
            )?;
        }
        Patch::File {
            path,
            content,
            mode,
            replace,
        } => {
            let rel = normalize_guest_path_bytes(path)?;
            check_replace_tree(tree, lowers, path, *replace)?;
            ensure_tree_parents(tree, lowers, &rel)?;
            insert_tree_node(
                tree,
                &rel,
                TreeNode::RegularFile(RegularFileNode {
                    id: RegularFileId::new(),
                    metadata: metadata_with_mode(mode.unwrap_or(0o644) as u16),
                    xattrs: Vec::new(),
                    data: FileData::Memory(content.clone()),
                    nlink: 1,
                }),
            )?;
        }
        Patch::CopyFile {
            src,
            dst,
            mode,
            replace,
        } => {
            let rel = normalize_guest_path_bytes(dst)?;
            check_replace_tree(tree, lowers, dst, *replace)?;
            ensure_tree_parents(tree, lowers, &rel)?;
            let (data, source_mode) = read_regular_source(src).await?;
            let file_mode = mode.map_or(source_mode, |mode| mode as u16);
            insert_tree_node(
                tree,
                &rel,
                TreeNode::RegularFile(RegularFileNode {
                    id: RegularFileId::new(),
                    metadata: metadata_with_mode(file_mode),
                    xattrs: Vec::new(),
                    data: FileData::Memory(data),
                    nlink: 1,
                }),
            )?;
        }
        Patch::CopyDir { src, dst, replace } => {
            let rel = normalize_guest_path_bytes(dst)?;
            check_replace_tree(tree, lowers, dst, *replace)?;
            copy_dir_into_tree(tree, lowers, src, &rel).await?;
        }
        Patch::Symlink {
            target,
            link,
            replace,
        } => {
            let rel = normalize_guest_path_bytes(link)?;
            check_replace_tree(tree, lowers, link, *replace)?;
            ensure_tree_parents(tree, lowers, &rel)?;
            insert_tree_node(
                tree,
                &rel,
                TreeNode::Symlink(SymlinkNode {
                    metadata: metadata_with_mode(0o777),
                    target: target.as_bytes().to_vec(),
                }),
            )?;
        }
        Patch::Mkdir { path, mode } => {
            let rel = normalize_guest_path_bytes(path)?;
            ensure_tree_parents(tree, lowers, &rel)?;
            if let Some(existing) = tree.get(&rel)
                && !matches!(existing, TreeNode::Directory(_))
                && !is_whiteout(existing)
            {
                return Err(crate::MicrosandboxError::PatchFailed(format!(
                    "cannot create directory at '{path}': path exists and is not a directory"
                )));
            }
            if matches!(tree.get(&rel), Some(node) if is_whiteout(node)) {
                tree.remove(&rel);
            }
            match lower_entry_kind(lowers, path)? {
                Some(ErofsEntryKind::Directory) if tree.get(&rel).is_none() => return Ok(()),
                Some(kind) if tree.get(&rel).is_none() => {
                    return Err(crate::MicrosandboxError::PatchFailed(format!(
                        "cannot create directory at '{path}': path exists and is not a directory ({})",
                        lower_kind_name(kind)
                    )));
                }
                _ => {}
            }
            insert_tree_node(
                tree,
                &rel,
                TreeNode::Directory(DirectoryNode::new(metadata_with_mode(
                    mode.unwrap_or(0o755) as u16,
                ))),
            )?;
        }
        Patch::Remove { path } => {
            let rel = normalize_guest_path_bytes(path)?;
            let removed_upper = tree.remove(&rel).is_some();
            let lower_kind = lower_entry_kind(lowers, path)?;
            if (removed_upper || lower_kind.is_some()) && lower_kind.is_some() {
                ensure_tree_parents(tree, lowers, &rel)?;
                insert_tree_node(tree, &rel, make_whiteout())?;
            }
        }
        Patch::Append { path, content } => {
            let rel = normalize_guest_path_bytes(path)?;
            if matches!(tree.get(&rel), Some(node) if is_whiteout(node)) {
                return Err(crate::MicrosandboxError::PatchFailed(format!(
                    "cannot append to '{path}': file not found in rootfs"
                )));
            }

            if let Some(TreeNode::RegularFile(file)) = tree.get_mut(&rel) {
                let mut existing = file.data.read_all().map_err(|e| {
                    crate::MicrosandboxError::PatchFailed(format!("read file data: {e}"))
                })?;
                existing.extend_from_slice(content.as_bytes());
                file.data = FileData::Memory(existing);
                return Ok(());
            }

            if let Some(existing) = tree.get(&rel) {
                return Err(crate::MicrosandboxError::PatchFailed(format!(
                    "cannot append to '{path}': target is not a regular file ({})",
                    upper_kind_name(existing)
                )));
            }

            match lower_entry_kind(lowers, path)? {
                Some(ErofsEntryKind::RegularFile) => {
                    let mut data = read_lower_file(lowers, path)?;
                    data.extend_from_slice(content.as_bytes());
                    ensure_tree_parents(tree, lowers, &rel)?;
                    insert_tree_node(
                        tree,
                        &rel,
                        TreeNode::RegularFile(RegularFileNode {
                            id: RegularFileId::new(),
                            metadata: metadata_with_mode(0o644),
                            xattrs: Vec::new(),
                            data: FileData::Memory(data),
                            nlink: 1,
                        }),
                    )?;
                }
                Some(kind) => {
                    return Err(crate::MicrosandboxError::PatchFailed(format!(
                        "cannot append to '{path}': target in lower layer is not a regular file ({})",
                        lower_kind_name(kind)
                    )));
                }
                None => {
                    return Err(crate::MicrosandboxError::PatchFailed(format!(
                        "cannot append to '{path}': file not found in rootfs"
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Apply one patch through a capability-scoped bind-root handle.
fn apply_one_to_bind(root: &RootedPatchFs, patch: &Patch) -> MicrosandboxResult<()> {
    match patch {
        Patch::Text {
            path,
            content,
            mode,
            replace,
        } => {
            let dest = root.resolve(path, *replace)?;
            root.write_file(&dest, path, content.as_bytes(), *replace, *mode)?;
        }
        Patch::File {
            path,
            content,
            mode,
            replace,
        } => {
            let dest = root.resolve(path, *replace)?;
            root.write_file(&dest, path, content, *replace, *mode)?;
        }
        Patch::CopyFile {
            src,
            dst,
            mode,
            replace,
        } => {
            let dest = root.resolve(dst, *replace)?;
            root.copy_file(src, &dest, dst, *replace, *mode)?;
        }
        Patch::CopyDir { src, dst, replace } => {
            let dest = root.resolve(dst, *replace)?;
            root.copy_dir(src, &dest, dst, *replace)?;
        }
        Patch::Symlink {
            target,
            link,
            replace,
        } => {
            #[cfg(unix)]
            {
                let link_path = root.resolve(link, false)?;
                root.create_symlink(Path::new(target), &link_path, link, *replace)?;
            }
            #[cfg(windows)]
            {
                let _ = (root, target, link, replace);
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "symlink patches are not supported for Windows host bind roots".into(),
                ));
            }
        }
        Patch::Mkdir { path, mode } => {
            let dest = root.resolve(path, true)?;
            root.create_dir(&dest, *mode)?;
        }
        Patch::Remove { path } => {
            let dest = root.resolve(path, false)?;
            root.remove_entry(&dest)?;
        }
        Patch::Append { path, content } => {
            let dest = root.resolve(path, true)?;
            let mut options = OpenOptions::new();
            options.append(true);
            let mut file = root.root.open_with(&dest, &options).map_err(|err| {
                if err.kind() == std::io::ErrorKind::NotFound {
                    crate::MicrosandboxError::PatchFailed(format!(
                        "cannot append to '{path}': file not found in rootfs"
                    ))
                } else {
                    err.into()
                }
            })?;
            root.write_all(&mut file, content.as_bytes())?;
        }
    }

    Ok(())
}

fn normalize_guest_path_bytes(guest_path: &str) -> MicrosandboxResult<Vec<u8>> {
    if !guest_path.starts_with('/') {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "patch path must be absolute: '{guest_path}'"
        )));
    }

    let relative = guest_path.strip_prefix('/').unwrap_or(guest_path);
    if relative.is_empty() {
        return Err(crate::MicrosandboxError::PatchFailed(
            "patch path must not be '/'".into(),
        ));
    }

    let components: Vec<&str> = relative
        .split('/')
        .filter(|component| !component.is_empty())
        .collect();
    if components.contains(&"..") {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "patch path escapes rootfs: '{guest_path}'"
        )));
    }

    Ok(components.join("/").into_bytes())
}

fn check_replace_tree(
    tree: &FileTree,
    lowers: &mut LowerLayers,
    guest_path: &str,
    replace: bool,
) -> MicrosandboxResult<()> {
    if replace {
        return Ok(());
    }

    let rel = normalize_guest_path_bytes(guest_path)?;
    match tree.get(&rel) {
        Some(node) if !is_whiteout(node) => {
            return Err(crate::MicrosandboxError::PatchFailed(format!(
                "path already exists in rootfs: '{guest_path}' (set replace to allow)"
            )));
        }
        _ => {}
    }

    if lower_entry_kind(lowers, guest_path)?.is_some() {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "path exists in image layer: '{guest_path}' (set replace to allow)"
        )));
    }

    Ok(())
}

/// Ensure all parent directories exist in the upper tree for a given path.
///
/// Walks each path component (excluding the final one) and creates missing
/// intermediate directories with default metadata (root:root, 0755).
///
/// If a parent slot is occupied by a whiteout (from a Remove patch), the
/// whiteout is replaced with a real directory — the patch is explicitly
/// re-creating content at that path.
fn ensure_tree_parents(
    tree: &mut FileTree,
    lowers: &mut LowerLayers,
    relative: &[u8],
) -> MicrosandboxResult<()> {
    let components: Vec<&[u8]> = relative
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty())
        .collect();
    if components.len() <= 1 {
        return Ok(());
    }

    let mut prefix = Vec::new();
    for component in &components[..components.len() - 1] {
        if !prefix.is_empty() {
            prefix.push(b'/');
        }
        prefix.extend_from_slice(component);

        // If this parent was previously whiteout'd, remove the whiteout so we
        // can recreate it as a real directory.
        let needs_recreate = matches!(tree.get(&prefix), Some(node) if is_whiteout(node));
        if needs_recreate {
            tree.remove(&prefix);
        }

        match tree.get(&prefix) {
            Some(TreeNode::Directory(_)) => {}
            Some(_) => {
                return Err(crate::MicrosandboxError::PatchFailed(format!(
                    "patch path parent is not a directory: '/{}'",
                    String::from_utf8_lossy(&prefix)
                )));
            }
            None => {
                // Verify the lower layers don't have a non-directory at this path.
                let guest_path = guest_path_from_relative(&prefix);
                if let Some(kind) = lower_entry_kind(lowers, &guest_path)?
                    && kind != ErofsEntryKind::Directory
                {
                    return Err(crate::MicrosandboxError::PatchFailed(format!(
                        "patch path parent is not a directory: '{guest_path}' ({})",
                        lower_kind_name(kind)
                    )));
                }
                insert_tree_node(
                    tree,
                    &prefix,
                    TreeNode::Directory(DirectoryNode::new(metadata_with_mode(0o755))),
                )?;
            }
        }
    }

    Ok(())
}

async fn copy_dir_into_tree(
    tree: &mut FileTree,
    lowers: &mut LowerLayers,
    src: &Path,
    dst_relative: &[u8],
) -> MicrosandboxResult<()> {
    ensure_tree_parents(tree, lowers, dst_relative)?;
    insert_tree_node(
        tree,
        dst_relative,
        TreeNode::Directory(DirectoryNode::new(metadata_with_mode(
            source_mode(src, true).await?,
        ))),
    )?;

    let mut entries = fs::read_dir(src).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name_bytes = os_str_bytes(&name);
        let child_relative = join_relative(dst_relative, &name_bytes);
        let file_type = entry.file_type().await?;
        let child_path = entry.path();

        if file_type.is_dir() {
            Box::pin(copy_dir_into_tree(
                tree,
                lowers,
                &child_path,
                &child_relative,
            ))
            .await?;
            continue;
        }

        ensure_tree_parents(tree, lowers, &child_relative)?;
        if file_type.is_symlink() {
            let target = fs::read_link(&child_path).await?;
            insert_tree_node(
                tree,
                &child_relative,
                TreeNode::Symlink(SymlinkNode {
                    metadata: metadata_with_mode(0o777),
                    target: os_str_bytes(target.as_os_str()),
                }),
            )?;
        } else if file_type.is_file() {
            let (data, mode) = read_regular_source(&child_path).await?;
            insert_tree_node(
                tree,
                &child_relative,
                TreeNode::RegularFile(RegularFileNode {
                    id: RegularFileId::new(),
                    metadata: metadata_with_mode(mode),
                    xattrs: Vec::new(),
                    data: FileData::Memory(data),
                    nlink: 1,
                }),
            )?;
        } else {
            return Err(crate::MicrosandboxError::PatchFailed(format!(
                "CopyDir source contains an unsupported file type: '{}'",
                child_path.display()
            )));
        }
    }

    Ok(())
}

async fn source_mode(_path: &Path, is_dir: bool) -> MicrosandboxResult<u16> {
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(_path).await?;
        let mode = metadata.permissions().mode() as u16 & 0o7777;
        if mode == 0 {
            Ok(if is_dir { 0o755 } else { 0o644 })
        } else {
            Ok(mode)
        }
    }

    #[cfg(not(unix))]
    {
        Ok(if is_dir { 0o755 } else { 0o644 })
    }
}

/// Read a regular patch source through one opened handle.
async fn read_regular_source(path: &Path) -> MicrosandboxResult<(Vec<u8>, u16)> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK);
    let mut file = options.open(path).await?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "patch source is not a regular file: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    let mode = metadata.permissions().mode() as u16 & 0o7777;
    #[cfg(not(unix))]
    let mode = 0o644;
    let mut data = Vec::new();
    file.read_to_end(&mut data).await?;
    Ok((data, if mode == 0 { 0o644 } else { mode }))
}

fn metadata_with_mode(mode: u16) -> InodeMetadata {
    InodeMetadata {
        uid: 0,
        gid: 0,
        mode,
        mtime: 0,
        mtime_nsec: 0,
    }
}

/// Create an overlayfs whiteout marker node.
///
/// In the overlayfs on-disk format, a character device with major=0, minor=0
/// signals that the named entry is deleted — the guest kernel's overlayfs
/// driver hides the corresponding lower-layer entry.
fn make_whiteout() -> TreeNode {
    TreeNode::CharDevice(DeviceNode {
        metadata: metadata_with_mode(0),
        major: 0,
        minor: 0,
    })
}

/// Check whether a node is an overlayfs whiteout (char device 0,0).
fn is_whiteout(node: &TreeNode) -> bool {
    matches!(node, TreeNode::CharDevice(device) if device.major == 0 && device.minor == 0)
}

fn insert_tree_node(tree: &mut FileTree, path: &[u8], node: TreeNode) -> MicrosandboxResult<()> {
    tree.insert(path, node).map_err(map_tree_error)
}

fn map_tree_error(error: FileTreeError) -> crate::MicrosandboxError {
    crate::MicrosandboxError::PatchFailed(error.to_string())
}

fn join_relative(base: &[u8], child: &[u8]) -> Vec<u8> {
    if base.is_empty() {
        return child.to_vec();
    }
    let mut joined = Vec::with_capacity(base.len() + 1 + child.len());
    joined.extend_from_slice(base);
    joined.push(b'/');
    joined.extend_from_slice(child);
    joined
}

struct ResolvedLowerEntry {
    layer_idx: usize,
    kind: ErofsEntryKind,
}

fn upper_kind_name(node: &TreeNode) -> &'static str {
    match node {
        TreeNode::RegularFile(_) => "regular file",
        TreeNode::Directory(_) => "directory",
        TreeNode::Symlink(_) => "symlink",
        TreeNode::CharDevice(_) => "character device",
        TreeNode::BlockDevice(_) => "block device",
        TreeNode::Fifo(_) => "fifo",
        TreeNode::Socket(_) => "socket",
    }
}

fn lower_kind_name(kind: ErofsEntryKind) -> &'static str {
    match kind {
        ErofsEntryKind::RegularFile => "regular file",
        ErofsEntryKind::Directory => "directory",
        ErofsEntryKind::Symlink => "symlink",
        ErofsEntryKind::CharDevice => "character device",
        ErofsEntryKind::BlockDevice => "block device",
        ErofsEntryKind::Fifo => "fifo",
        ErofsEntryKind::Socket => "socket",
    }
}

fn guest_path_from_relative(relative: &[u8]) -> String {
    format!("/{}", String::from_utf8_lossy(relative))
}

fn lower_entry_info(
    lowers: &mut LowerLayers,
    layer_idx: usize,
    guest_path: &str,
) -> MicrosandboxResult<Option<ErofsEntryInfo>> {
    lowers.entry_info(layer_idx, guest_path)
}

/// Resolve a guest path across the stacked EROFS lower layers.
///
/// Walks path components top-down through the layer stack (highest layer
/// first) to determine which layer contributes the final entry, honoring
/// overlayfs semantics:
///
/// - **Whiteouts** (char device 0,0): if the topmost contributor for a
///   component is a whiteout and no higher layer already contributed a
///   directory, the path is considered deleted → returns `None`.
/// - **Opaque directories** (`trusted.overlay.opaque=y` xattr): stop
///   searching lower layers for this component — the opaque dir hides
///   everything beneath it.
/// - **Non-directory at intermediate component**: the path cannot exist
///   (you can't traverse through a file) → returns `None`.
///
/// The `contributors` list narrows at each component: only layers that
/// contain a directory entry for the current prefix can contribute to
/// deeper components.
fn resolve_lower_entry(
    lowers: &mut LowerLayers,
    guest_path: &str,
) -> MicrosandboxResult<Option<ResolvedLowerEntry>> {
    let relative = guest_path.strip_prefix('/').unwrap_or(guest_path);
    if relative.is_empty() {
        return Ok(None);
    }

    let components: Vec<&str> = relative
        .split('/')
        .filter(|component| !component.is_empty())
        .collect();

    // Start with all layers, topmost first (reversed OCI order).
    let mut contributors: Vec<usize> = (0..lowers.len()).rev().collect();
    let mut prefix = String::new();

    for (component_index, component) in components.iter().enumerate() {
        prefix.push('/');
        prefix.push_str(component);
        let is_final = component_index + 1 == components.len();
        let mut next_contributors = Vec::new();

        for &layer_idx in &contributors {
            let Some(info) = lower_entry_info(lowers, layer_idx, &prefix)? else {
                continue;
            };

            // A whiteout in the topmost layer hides this path entirely.
            if info.whiteout {
                if next_contributors.is_empty() {
                    return Ok(None);
                }
                continue;
            }

            match info.kind {
                ErofsEntryKind::Directory => {
                    next_contributors.push(layer_idx);
                    // Opaque dir: stop searching lower layers for this component.
                    if info.opaque {
                        break;
                    }
                }
                kind => {
                    // Non-directory found. If no higher layer already contributed
                    // a directory at this prefix, this is the resolved entry (if
                    // final) or the path is unreachable (if intermediate).
                    if next_contributors.is_empty() {
                        return Ok(if is_final {
                            Some(ResolvedLowerEntry { layer_idx, kind })
                        } else {
                            None
                        });
                    }
                }
            }
        }

        if next_contributors.is_empty() {
            return Ok(None);
        }

        if is_final {
            return Ok(Some(ResolvedLowerEntry {
                layer_idx: next_contributors[0],
                kind: ErofsEntryKind::Directory,
            }));
        }

        contributors = next_contributors;
    }

    Ok(None)
}

fn lower_entry_kind(
    lowers: &mut LowerLayers,
    guest_path: &str,
) -> MicrosandboxResult<Option<ErofsEntryKind>> {
    Ok(resolve_lower_entry(lowers, guest_path)?.map(|entry| entry.kind))
}

fn read_lower_file(lowers: &mut LowerLayers, guest_path: &str) -> MicrosandboxResult<Vec<u8>> {
    let Some(entry) = resolve_lower_entry(lowers, guest_path)? else {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "cannot append to '{guest_path}': file not found in rootfs"
        )));
    };

    if entry.kind != ErofsEntryKind::RegularFile {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "cannot append to '{guest_path}': target in lower layer is not a regular file ({})",
            lower_kind_name(entry.kind)
        )));
    }

    match lowers.read_file(entry.layer_idx, guest_path) {
        Ok(data) => Ok(data),
        Err(err) => Err(crate::MicrosandboxError::PatchFailed(format!(
            "failed to read lower layer file '{guest_path}': {err}"
        ))),
    }
}

fn os_str_bytes(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        value.as_bytes().to_vec()
    }

    #[cfg(not(unix))]
    {
        value.to_string_lossy().as_bytes().to_vec()
    }
}

/// Apply a requested mode through the pinned file handle.
///
/// Using the handle prevents a concurrent rename from redirecting the
/// permission change to a different file installed at the destination path.
fn set_file_mode(file: &File, mode: u32) -> MicrosandboxResult<()> {
    #[cfg(unix)]
    {
        file.set_permissions(Permissions::from_std(std::fs::Permissions::from_mode(mode)))?;
        Ok(())
    }

    #[cfg(windows)]
    {
        let _ = (file, mode);
        Err(crate::MicrosandboxError::InvalidConfig(
            "POSIX patch modes are not supported for Windows host bind roots".into(),
        ))
    }
}

fn source_std_permissions_mode(_permissions: &std::fs::Permissions) -> Option<u32> {
    #[cfg(unix)]
    {
        Some(_permissions.mode() & 0o7777)
    }

    #[cfg(windows)]
    {
        None
    }
}

fn source_cap_permissions_mode(_permissions: &Permissions) -> Option<u32> {
    #[cfg(unix)]
    {
        Some(cap_std::fs::PermissionsExt::mode(_permissions) & 0o7777)
    }

    #[cfg(windows)]
    {
        None
    }
}

#[cfg(unix)]
fn set_dir_mode(dir: &Dir, mode: u32) -> MicrosandboxResult<()> {
    dir.set_permissions(
        Path::new("."),
        Permissions::from_std(std::fs::Permissions::from_mode(mode)),
    )?;
    Ok(())
}

/// Open one child relative to a pinned Windows directory without processing
/// a reparse point in the child's final component.
#[cfg(windows)]
fn windows_open_relative_for_removal(
    parent: &std::fs::File,
    name: &OsStr,
) -> std::io::Result<std::fs::File> {
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let mut wide_name: Vec<u16> = name.encode_wide().collect();
    if wide_name.is_empty() || wide_name.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "removal component is empty or contains NUL",
        ));
    }
    let byte_length = wide_name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "component is too long")
        })?;
    let unicode_name = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: wide_name.as_mut_ptr(),
    };
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: std::ptr::from_ref(&unicode_name),
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut handle = INVALID_HANDLE_VALUE;
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            DELETE
                | FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | SYNCHRONIZE,
            &object_attributes,
            &mut io_status,
            std::ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        let win32_error = unsafe { RtlNtStatusToDosError(status) };
        return Err(std::io::Error::from_raw_os_error(win32_error as i32));
    }
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(std::io::Error::other(
            "NtCreateFile succeeded without returning a handle",
        ));
    }

    Ok(unsafe { std::fs::File::from_raw_handle(handle as RawHandle) })
}

/// Recursively remove an entry by handle on Windows.
///
/// Reparse points are deleted as links and never traversed. Directory names
/// are enumerated from the open handle, and every child is opened relative to
/// that same handle, so no ambient pathname is reconstructed during removal.
#[cfg(windows)]
fn windows_remove_open_entry(entry: std::fs::File) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let mut stack = vec![WindowsRemovalFrame::Visit(entry)];
    while let Some(frame) = stack.pop() {
        match frame {
            WindowsRemovalFrame::Visit(entry) => {
                let attributes = entry.metadata()?.file_attributes();
                if attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                    && attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                {
                    stack.push(WindowsRemovalFrame::Directory {
                        entry,
                        pending: VecDeque::new(),
                    });
                } else {
                    windows_mark_delete(&entry)?;
                }
            }
            WindowsRemovalFrame::Directory { entry, mut pending } => {
                if pending.is_empty() {
                    pending.extend(windows_read_directory_names(&entry)?);
                }
                if let Some(name) = pending.pop_front() {
                    let child = windows_open_relative_for_removal(&entry, &name)?;
                    stack.push(WindowsRemovalFrame::Directory { entry, pending });
                    stack.push(WindowsRemovalFrame::Visit(child));
                } else {
                    windows_mark_delete(&entry)?;
                }
            }
        }
    }
    Ok(())
}

/// Read the next batch of names from an open Windows directory handle.
#[cfg(windows)]
fn windows_read_directory_names(directory: &std::fs::File) -> std::io::Result<Vec<OsString>> {
    use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_BOTH_DIR_INFO, FileIdBothDirectoryInfo, GetFileInformationByHandleEx,
    };

    // The API writes FILE_ID_BOTH_DIR_INFO records into this storage. A u64
    // backing allocation provides enough alignment for safely viewing them.
    let mut buffer = vec![0u64; (64 * 1024) / std::mem::size_of::<u64>()];
    let buffer_len = buffer.len() * std::mem::size_of::<u64>();
    let result = unsafe {
        GetFileInformationByHandleEx(
            directory.as_raw_handle() as HANDLE,
            FileIdBothDirectoryInfo,
            buffer.as_mut_ptr().cast(),
            buffer_len as u32,
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
            return Ok(Vec::new());
        }
        return Err(error);
    }

    let mut names = Vec::new();
    let mut offset = 0usize;
    loop {
        if !offset.is_multiple_of(std::mem::align_of::<FILE_ID_BOTH_DIR_INFO>())
            || offset + std::mem::size_of::<FILE_ID_BOTH_DIR_INFO>() > buffer_len
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Windows directory enumeration buffer",
            ));
        }
        let info = unsafe {
            &*(buffer
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<FILE_ID_BOTH_DIR_INFO>())
        };
        let name_length = usize::try_from(info.FileNameLength)
            .ok()
            .filter(|length| length % 2 == 0)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid Windows directory entry name length",
                )
            })?;
        let name_units = name_length / 2;
        let name_offset = offset
            .checked_add(std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName))
            .and_then(|start| start.checked_add(name_length).map(|end| (start, end)))
            .filter(|(_, end)| *end <= buffer_len)
            .map(|(start, _)| start)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Windows directory entry name exceeds enumeration buffer",
                )
            })?;
        let name_ptr = unsafe { buffer.as_ptr().cast::<u8>().add(name_offset).cast::<u16>() };
        let name_slice = unsafe { std::slice::from_raw_parts(name_ptr, name_units) };
        let name = OsString::from_wide(name_slice);
        if name != "." && name != ".." {
            names.push(name);
        }

        if info.NextEntryOffset == 0 {
            break;
        }
        offset = offset
            .checked_add(info.NextEntryOffset as usize)
            .filter(|next| *next < buffer_len)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid Windows directory entry offset",
                )
            })?;
    }
    Ok(names)
}

/// Mark an opened Windows file, directory, or reparse point for deletion.
#[cfg(windows)]
fn windows_mark_delete(entry: &std::fs::File) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_BASIC_INFO, FILE_DISPOSITION_INFO,
        FileBasicInfo, FileDispositionInfo, GetFileInformationByHandleEx,
        SetFileInformationByHandle,
    };

    let mut basic = FILE_BASIC_INFO::default();
    let result = unsafe {
        GetFileInformationByHandleEx(
            entry.as_raw_handle() as HANDLE,
            FileBasicInfo,
            std::ptr::from_mut(&mut basic).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if basic.FileAttributes & FILE_ATTRIBUTE_READONLY != 0 {
        basic.FileAttributes &= !FILE_ATTRIBUTE_READONLY;
        if basic.FileAttributes == 0 {
            basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        }
        let result = unsafe {
            SetFileInformationByHandle(
                entry.as_raw_handle() as HANDLE,
                FileBasicInfo,
                std::ptr::from_ref(&basic).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        };
        if result == 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let result = unsafe {
        SetFileInformationByHandle(
            entry.as_raw_handle() as HANDLE,
            FileDispositionInfo,
            std::ptr::from_ref(&disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reserved_name(name: &str) -> bool {
    let stem = name.split_once('.').map_or(name, |(stem, _)| stem);
    matches!(
        stem.trim_end().to_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM0"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "COM\u{b9}"
            | "COM\u{b2}"
            | "COM\u{b3}"
            | "LPT0"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "LPT\u{b9}"
            | "LPT\u{b2}"
            | "LPT\u{b3}"
    )
}

/// Parse a guest path with Unix semantics on every host platform.
fn guest_path_components(guest_path: &str) -> MicrosandboxResult<VecDeque<PendingComponent>> {
    use typed_path::{Utf8UnixComponent, Utf8UnixPath};

    if !guest_path.starts_with('/') {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "patch path must be absolute: '{guest_path}'"
        )));
    }
    if guest_path.len() > 1 && guest_path.ends_with('/') {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "patch path must not have a trailing slash: '{guest_path}'"
        )));
    }
    if guest_path[1..]
        .split('/')
        .any(|component| component.is_empty() || component == ".")
    {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "patch path must be canonical: '{guest_path}'"
        )));
    }

    let mut components = VecDeque::new();
    for component in Utf8UnixPath::new(guest_path).components() {
        match component {
            Utf8UnixComponent::RootDir | Utf8UnixComponent::CurDir => {}
            Utf8UnixComponent::ParentDir => {
                return Err(crate::MicrosandboxError::PatchFailed(format!(
                    "patch path must not contain '..': '{guest_path}'"
                )));
            }
            Utf8UnixComponent::Normal(c) => {
                if c.contains('\0') {
                    return Err(crate::MicrosandboxError::PatchFailed(format!(
                        "patch path contains null byte: '{guest_path}'"
                    )));
                }
                #[cfg(windows)]
                if c.chars().any(|character| {
                    character <= '\u{1f}'
                        || matches!(character, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
                }) || c.ends_with([' ', '.'])
                {
                    return Err(crate::MicrosandboxError::PatchFailed(format!(
                        "patch path uses syntax that cannot represent a Linux guest name on a Windows host: '{guest_path}'"
                    )));
                }
                #[cfg(windows)]
                if is_windows_reserved_name(c) {
                    return Err(crate::MicrosandboxError::PatchFailed(format!(
                        "patch path uses a reserved Windows device name: '{guest_path}'"
                    )));
                }
                components.push_back(PendingComponent::Normal(OsString::from(c)));
            }
        }
    }

    if components.is_empty() {
        return Err(crate::MicrosandboxError::PatchFailed(
            "patch path must not be '/'".into(),
        ));
    }
    Ok(components)
}

fn validate_bind_patches(patches: &[Patch]) -> MicrosandboxResult<()> {
    for patch in patches {
        guest_path_components(patch_destination(patch))?;

        if let Patch::Symlink { target, .. } = patch
            && (target.is_empty() || target.contains('\0'))
        {
            return Err(crate::MicrosandboxError::PatchFailed(
                "symlink patch target must be non-empty and contain no null bytes".into(),
            ));
        }

        #[cfg(windows)]
        match patch {
            Patch::Text { mode: Some(_), .. }
            | Patch::File { mode: Some(_), .. }
            | Patch::CopyFile { mode: Some(_), .. }
            | Patch::Mkdir { mode: Some(_), .. } => {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "POSIX patch modes are not supported for Windows host bind roots".into(),
                ));
            }
            Patch::Symlink { .. } => {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "symlink patches are not supported for Windows host bind roots".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn patch_destination(patch: &Patch) -> &str {
    match patch {
        Patch::Text { path, .. }
        | Patch::File { path, .. }
        | Patch::Mkdir { path, .. }
        | Patch::Remove { path }
        | Patch::Append { path, .. } => path,
        Patch::CopyFile { dst, .. } | Patch::CopyDir { dst, .. } => dst,
        Patch::Symlink { link, .. } => link,
    }
}

fn path_exists_error(guest_path: &str) -> crate::MicrosandboxError {
    crate::MicrosandboxError::PatchFailed(format!(
        "path already exists in rootfs: '{guest_path}' (set replace to allow)"
    ))
}

/// Expand a host symlink target using Linux guest-root semantics.
fn prepend_link_target(
    target: &Path,
    resolved: &mut Vec<OsString>,
    remaining: &mut VecDeque<PendingComponent>,
    guest_path: &str,
) -> MicrosandboxResult<()> {
    let mut target_components = Vec::new();
    let requires_directory = path_requires_directory(target);

    for component in target.components() {
        match component {
            std::path::Component::Prefix(_) => {
                return Err(crate::MicrosandboxError::PatchFailed(format!(
                    "unsupported symlink target while resolving patch path '{guest_path}': {}",
                    target.display()
                )));
            }
            std::path::Component::RootDir => resolved.clear(),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                // Linux clamps `..` at `/` while following a symlink target.
                target_components.push(PendingComponent::Parent {
                    clamp_at_root: true,
                });
            }
            std::path::Component::Normal(name) => {
                target_components.push(PendingComponent::Normal(name.to_os_string()));
            }
        }
    }
    if requires_directory {
        target_components.push(PendingComponent::RequireDirectory);
    }

    for component in target_components.into_iter().rev() {
        remaining.push_front(component);
    }
    Ok(())
}

fn path_requires_directory(path: &Path) -> bool {
    #[cfg(unix)]
    {
        let bytes = path.as_os_str().as_bytes();
        bytes.ends_with(b"/") || bytes.ends_with(b"/.")
    }

    #[cfg(windows)]
    {
        let target = path.as_os_str().to_string_lossy();
        target.ends_with(['/', '\\']) || target.ends_with("/.") || target.ends_with("\\.")
    }
}

fn join_components(components: &[OsString], final_name: Option<&OsStr>) -> PathBuf {
    let mut path = PathBuf::new();
    for component in components {
        path.push(component);
    }
    if let Some(final_name) = final_name {
        path.push(final_name);
    }
    path
}

/// Open a configured bind root without trusting any path component.
///
/// Each directory is opened relative to the previous directory handle and is
/// held open while the next component is resolved. This both rejects links and
/// prevents a component from being renamed out from under the root walk.
fn open_root_without_links(path: &Path) -> MicrosandboxResult<Dir> {
    #[cfg(windows)]
    if path
        .as_os_str()
        .to_string_lossy()
        .split(['\\', '/'])
        .any(|segment| segment == "..")
    {
        return Err(root_open_error(path, "contains '..'"));
    }

    // Opening `.` pins the process working directory directly. Converting it
    // through `current_dir()` would create an ambient pathname race if an
    // ancestor were renamed before the directory was reopened.
    let mut base = if path.is_absolute() {
        PathBuf::new()
    } else {
        PathBuf::from(".")
    };
    let mut names = Vec::new();

    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => {
                if !base.as_os_str().is_empty() {
                    return Err(root_open_error(path, "uses a drive-relative prefix"));
                }
                base.push(prefix.as_os_str());
            }
            std::path::Component::RootDir => base.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(root_open_error(path, "contains '..'"));
            }
            std::path::Component::Normal(name) => names.push(name.to_os_string()),
        }
    }

    let mut current = Dir::open_ambient_dir(&base, ambient_authority())
        .map_err(|err| root_open_error(path, &format!("could not open base: {err}")))?
        .into_std_file();
    for name in names {
        let next = cap_primitives::fs::open_dir_nofollow(&current, Path::new(&name))
            .map_err(|err| root_open_error(path, &format!("contains a linked component: {err}")))?;

        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;

            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
            if next.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(root_open_error(path, "contains a reparse point"));
            }
        }

        current = next;
    }
    Ok(Dir::from_std_file(current))
}

fn root_open_error(path: &Path, reason: &str) -> crate::MicrosandboxError {
    crate::MicrosandboxError::PatchFailed(format!(
        "bind root {} {reason}; set follow_root_symlinks to allow linked root components",
        path.display()
    ))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use microsandbox_image::erofs::write_erofs;
    use microsandbox_image::tree::Xattr;

    fn bind_root(path: PathBuf, follow_root_symlinks: bool) -> RootfsSource {
        RootfsSource::Bind {
            path,
            follow_root_symlinks,
        }
    }

    fn text_patch(path: &str, content: &str) -> Patch {
        Patch::Text {
            path: path.into(),
            content: content.into(),
            mode: None,
            replace: false,
        }
    }

    #[cfg(windows)]
    fn create_windows_junction(link: &Path, target: &Path) {
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "failed to create junction: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn make_regular_file(data: &[u8]) -> TreeNode {
        TreeNode::RegularFile(RegularFileNode {
            id: RegularFileId::new(),
            metadata: metadata_with_mode(0o644),
            xattrs: Vec::new(),
            data: FileData::Memory(data.to_vec()),
            nlink: 1,
        })
    }

    fn make_opaque_directory() -> TreeNode {
        TreeNode::Directory(DirectoryNode {
            metadata: metadata_with_mode(0o755),
            xattrs: vec![Xattr {
                name: b"trusted.overlay.opaque".to_vec(),
                value: b"y".to_vec(),
            }],
            entries: Default::default(),
        })
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_confines_host_absolute_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(temp.path()).unwrap();
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("escape")).unwrap();

        apply_patches(
            &bind_root(root.clone(), false),
            &[text_patch("/escape/pwned.txt", "contained")],
        )
        .await
        .unwrap();

        assert!(!outside.join("pwned.txt").exists());
        let confined = root
            .join(outside.strip_prefix(Path::new("/")).unwrap())
            .join("pwned.txt");
        assert_eq!(std::fs::read_to_string(confined).unwrap(), "contained");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_clamps_parent_symlink_at_guest_root() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(temp.path()).unwrap();
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink("../outside", root.join("escape")).unwrap();

        apply_patches(
            &bind_root(root.clone(), false),
            &[text_patch("/escape/pwned.txt", "contained")],
        )
        .await
        .unwrap();

        assert!(!outside.join("pwned.txt").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("outside/pwned.txt")).unwrap(),
            "contained"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_follows_internal_absolute_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        symlink("/usr/bin", root.join("bin")).unwrap();

        apply_patches(
            &bind_root(root.clone(), false),
            &[text_patch("/bin/tool", "hello")],
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(root.join("usr/bin/tool")).unwrap(),
            "hello"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_honors_follow_root_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(temp.path()).unwrap();
        let actual_root = base.join("actual-root");
        let linked_root = base.join("linked-root");
        std::fs::create_dir_all(&actual_root).unwrap();
        symlink(&actual_root, &linked_root).unwrap();
        let patch = text_patch("/allowed.txt", "hello");

        let error = apply_patches(&bind_root(linked_root.clone(), false), &[patch.clone()])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("follow_root_symlinks"));
        assert!(!actual_root.join("allowed.txt").exists());

        apply_patches(&bind_root(linked_root, true), &[patch])
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(actual_root.join("allowed.txt")).unwrap(),
            "hello"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_remove_unlinks_final_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::write(root.join("target.txt"), "keep").unwrap();
        symlink("target.txt", root.join("link.txt")).unwrap();

        apply_patches(
            &bind_root(root.clone(), false),
            &[Patch::Remove {
                path: "/link.txt".into(),
            }],
        )
        .await
        .unwrap();

        assert!(std::fs::symlink_metadata(root.join("link.txt")).is_err());
        assert_eq!(
            std::fs::read_to_string(root.join("target.txt")).unwrap(),
            "keep"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_copy_dir_confines_nested_host_absolute_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(temp.path()).unwrap();
        let root = base.join("root");
        let outside = base.join("outside");
        let source = base.join("source");
        std::fs::create_dir_all(root.join("dest")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(outside.join("sentinel.txt"), "outside").unwrap();
        std::fs::write(source.join("nested/payload.txt"), "contained").unwrap();
        symlink(&outside, root.join("dest/nested")).unwrap();

        apply_patches(
            &bind_root(root.clone(), false),
            &[Patch::CopyDir {
                src: source,
                dst: "/dest".into(),
                replace: true,
            }],
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(outside.join("sentinel.txt")).unwrap(),
            "outside"
        );
        assert!(!outside.join("payload.txt").exists());
        let confined = root
            .join(outside.strip_prefix(Path::new("/")).unwrap())
            .join("payload.txt");
        assert_eq!(std::fs::read_to_string(confined).unwrap(), "contained");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_copy_dir_preserves_source_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let source = temp.path().join("source");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("target.txt"), "source").unwrap();
        symlink("target.txt", source.join("relative-link")).unwrap();
        symlink("/outside/target.txt", source.join("absolute-link")).unwrap();

        apply_patches(
            &bind_root(root.clone(), true),
            &[Patch::CopyDir {
                src: source,
                dst: "/copied".into(),
                replace: false,
            }],
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read_link(root.join("copied/relative-link")).unwrap(),
            Path::new("target.txt")
        );
        assert_eq!(
            std::fs::read_link(root.join("copied/absolute-link")).unwrap(),
            Path::new("/outside/target.txt")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_copy_dir_replaces_destination_link_not_its_target() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let source = temp.path().join("source");
        std::fs::create_dir_all(root.join("copied")).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(root.join("victim.txt"), "keep").unwrap();
        symlink("../../victim.txt", root.join("copied/link")).unwrap();
        symlink("source-target", source.join("link")).unwrap();

        apply_patches(
            &bind_root(root.clone(), true),
            &[Patch::CopyDir {
                src: source,
                dst: "/copied".into(),
                replace: true,
            }],
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(root.join("victim.txt")).unwrap(),
            "keep"
        );
        assert_eq!(
            std::fs::read_link(root.join("copied/link")).unwrap(),
            Path::new("source-target")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_copy_dir_rejects_special_source_files() {
        use std::ffi::CString;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let source = temp.path().join("source");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        let fifo = CString::new(source.join("pipe").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let error = apply_patches(
            &bind_root(root.clone(), true),
            &[Patch::CopyDir {
                src: source,
                dst: "/copied".into(),
                replace: false,
            }],
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("unsupported file type"));
        assert!(!root.join("copied").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_copy_file_rejects_fifo_source_without_creating_destination() {
        use std::ffi::CString;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let fifo_path = temp.path().join("pipe");
        let fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let error = apply_patches(
            &bind_root(root.clone(), true),
            &[Patch::CopyFile {
                src: fifo_path,
                dst: "/copied.txt".into(),
                mode: None,
                replace: false,
            }],
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("not a regular file"));
        assert!(!root.join("copied.txt").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_copy_dir_preserves_directory_modes() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let source = temp.path().join("source");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(source.join("private")).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o710)).unwrap();
        std::fs::set_permissions(
            source.join("private"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        apply_patches(
            &bind_root(root.clone(), true),
            &[Patch::CopyDir {
                src: source,
                dst: "/copied".into(),
                replace: false,
            }],
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::metadata(root.join("copied"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o710
        );
        assert_eq!(
            std::fs::metadata(root.join("copied/private"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_preserves_symlink_target_directory_requirement() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        std::fs::write(root.join("target.txt"), "keep").unwrap();
        symlink("target.txt/", root.join("link")).unwrap();

        let error = apply_patches(
            &bind_root(root.clone(), true),
            &[Patch::Text {
                path: "/link".into(),
                content: "overwrite".into(),
                mode: None,
                replace: true,
            }],
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("must resolve to a directory"));
        assert_eq!(
            std::fs::read_to_string(root.join("target.txt")).unwrap(),
            "keep"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_no_replace_rejects_existing_final_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::write(root.join("target.txt"), "keep").unwrap();
        symlink("target.txt", root.join("link.txt")).unwrap();

        let error = apply_patches(
            &bind_root(root.clone(), false),
            &[text_patch("/link.txt", "overwrite")],
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("set replace to allow"));
        assert_eq!(
            std::fs::read_to_string(root.join("target.txt")).unwrap(),
            "keep"
        );
        assert!(
            std::fs::symlink_metadata(root.join("link.txt"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_no_replace_preserves_dangling_final_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        symlink("missing.txt", root.join("link.txt")).unwrap();

        let error = apply_patches(
            &bind_root(root.clone(), false),
            &[text_patch("/link.txt", "must-not-write")],
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("set replace to allow"));
        assert_eq!(
            std::fs::read_link(root.join("link.txt")).unwrap(),
            Path::new("missing.txt")
        );
        assert!(!root.join("missing.txt").exists());
    }

    #[test]
    fn bind_patch_no_replace_allows_exactly_one_concurrent_writer() {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let root = Arc::new(RootedPatchFs::open(temp.path(), true).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();

        for content in [b"alpha".as_slice(), b"beta".as_slice()] {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                root.write_file(Path::new("winner.txt"), "/winner.txt", content, false, None)
            }));
        }

        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);

        let content = std::fs::read(temp.path().join("winner.txt")).unwrap();
        assert!(content == b"alpha" || content == b"beta");
    }

    #[cfg(unix)]
    #[test]
    fn bind_patch_file_mode_follows_open_handle_across_rename() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = RootedPatchFs::open(temp.path(), true).unwrap();
        let mut opened = root
            .open_file_for_write(
                Path::new("destination.txt"),
                "/destination.txt",
                false,
                None,
            )
            .unwrap();
        opened.write_all(b"created").unwrap();

        std::fs::rename(
            temp.path().join("destination.txt"),
            temp.path().join("renamed.txt"),
        )
        .unwrap();
        std::fs::write(temp.path().join("destination.txt"), "replacement").unwrap();
        std::fs::set_permissions(
            temp.path().join("destination.txt"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        set_file_mode(&opened, 0o600).unwrap();

        assert_eq!(
            std::fs::metadata(temp.path().join("renamed.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(temp.path().join("destination.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn bind_patch_directory_mode_follows_open_handle_across_rename() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = RootedPatchFs::open(temp.path(), true).unwrap();
        std::fs::create_dir(temp.path().join("destination")).unwrap();
        let opened = root.root.open_dir("destination").unwrap();

        std::fs::rename(temp.path().join("destination"), temp.path().join("renamed")).unwrap();
        std::fs::create_dir(temp.path().join("destination")).unwrap();
        std::fs::set_permissions(
            temp.path().join("destination"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        set_dir_mode(&opened, 0o700).unwrap();

        assert_eq!(
            std::fs::metadata(temp.path().join("renamed"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(temp.path().join("destination"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_modes_existing_directory_without_parent_write_access() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("existing")).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = apply_patches(
            &bind_root(root.clone(), true),
            &[Patch::Mkdir {
                path: "/existing".into(),
                mode: Some(0o700),
            }],
        )
        .await;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        result.unwrap();

        assert_eq!(
            std::fs::metadata(root.join("existing"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_applies_requested_file_modes() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let source = temp.path().join("source.txt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&source, "copied").unwrap();

        apply_patches(
            &bind_root(root.clone(), true),
            &[
                Patch::Text {
                    path: "/text.txt".into(),
                    content: "text".into(),
                    mode: Some(0o600),
                    replace: false,
                },
                Patch::File {
                    path: "/file.bin".into(),
                    content: b"file".to_vec(),
                    mode: Some(0o640),
                    replace: false,
                },
                Patch::CopyFile {
                    src: source,
                    dst: "/copied.txt".into(),
                    mode: Some(0o644),
                    replace: false,
                },
                Patch::Mkdir {
                    path: "/mode-dir".into(),
                    mode: Some(0o700),
                },
            ],
        )
        .await
        .unwrap();

        for (name, expected) in [
            ("text.txt", 0o600),
            ("file.bin", 0o640),
            ("copied.txt", 0o644),
            ("mode-dir", 0o700),
        ] {
            let actual = std::fs::metadata(root.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(actual, expected, "unexpected mode for {name}");
        }
    }

    #[tokio::test]
    async fn bind_patch_preflights_all_destinations_before_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();

        let error = apply_patches(
            &bind_root(root.clone(), true),
            &[
                text_patch("/first.txt", "must-not-write"),
                text_patch("relative.txt", "invalid"),
            ],
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("must be absolute"));
        assert!(!root.join("first.txt").exists());
    }

    #[tokio::test]
    async fn bind_patch_preflights_parent_escape_before_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();

        let error = apply_patches(
            &bind_root(root.clone(), true),
            &[
                text_patch("/first.txt", "must-not-write"),
                text_patch("/../escaped.txt", "invalid"),
            ],
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("must not contain '..'"));
        assert!(!root.join("first.txt").exists());
        assert!(!temp.path().join("escaped.txt").exists());
    }

    #[tokio::test]
    async fn bind_patch_preflights_noncanonical_path_before_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();

        for invalid in ["/trailing/", "/double//slash", "/dot/./segment"] {
            let error = apply_patches(
                &bind_root(root.clone(), true),
                &[
                    text_patch("/first.txt", "must-not-write"),
                    text_patch(invalid, "invalid"),
                ],
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("patch path"));
            assert!(!root.join("first.txt").exists());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_preflights_invalid_symlink_target_before_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();

        let error = apply_patches(
            &bind_root(root.clone(), true),
            &[
                text_patch("/first.txt", "must-not-write"),
                Patch::Symlink {
                    target: String::new(),
                    link: "/link".into(),
                    replace: false,
                },
            ],
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("symlink patch target"));
        assert!(!root.join("first.txt").exists());
    }

    #[tokio::test]
    async fn bind_patch_copy_dir_opens_source_before_destination() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();

        apply_patches(
            &bind_root(root.clone(), true),
            &[Patch::CopyDir {
                src: temp.path().join("missing"),
                dst: "/copied".into(),
                replace: false,
            }],
        )
        .await
        .unwrap_err();

        assert!(!root.join("copied").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_rejects_parent_components_before_symlink_resolution() {
        use std::os::unix::fs::symlink;

        for (target, destination) in [("/", "/link/../file"), ("/a/b", "/link/../../file")] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().to_path_buf();
            symlink(target, root.join("link")).unwrap();

            let error = apply_patches(
                &bind_root(root.clone(), true),
                &[
                    text_patch("/first.txt", "must-not-write"),
                    text_patch(destination, "invalid"),
                ],
            )
            .await
            .unwrap_err();

            assert!(error.to_string().contains("must not contain '..'"));
            assert!(!root.join("first.txt").exists());
        }
    }

    #[tokio::test]
    async fn bind_patch_copy_dir_no_replace_preserves_existing_destination() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let source = temp.path().join("source");
        std::fs::create_dir_all(root.join("destination")).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(root.join("destination/sentinel.txt"), "keep").unwrap();
        std::fs::write(source.join("payload.txt"), "copy").unwrap();

        let error = apply_patches(
            &bind_root(root.clone(), true),
            &[Patch::CopyDir {
                src: source,
                dst: "/destination".into(),
                replace: false,
            }],
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("set replace to allow"));
        assert_eq!(
            std::fs::read_to_string(root.join("destination/sentinel.txt")).unwrap(),
            "keep"
        );
        assert!(!root.join("destination/payload.txt").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_patch_symlink_no_replace_preserves_existing_destination() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        std::fs::write(root.join("link"), "keep").unwrap();

        let error = apply_patches(
            &bind_root(root.clone(), true),
            &[Patch::Symlink {
                target: "/target".into(),
                link: "/link".into(),
                replace: false,
            }],
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("set replace to allow"));
        assert_eq!(std::fs::read_to_string(root.join("link")).unwrap(), "keep");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn bind_patch_windows_preflights_complete_batch() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        std::fs::write(root.join("link.txt"), "keep").unwrap();

        let error = apply_patches(
            &bind_root(root.clone(), true),
            &[
                text_patch("/first.txt", "must-not-write"),
                Patch::Symlink {
                    target: "/target.txt".into(),
                    link: "/link.txt".into(),
                    replace: true,
                },
            ],
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("symlink patches are not supported")
        );
        assert!(!root.join("first.txt").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("link.txt")).unwrap(),
            "keep"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn bind_patch_windows_rejects_modes_before_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let source = temp.path().join("source.txt");
        std::fs::write(&source, "source").unwrap();
        std::fs::write(root.join("victim.txt"), "keep").unwrap();

        let patches = [
            Patch::Text {
                path: "/victim.txt".into(),
                content: "overwrite".into(),
                mode: Some(0o600),
                replace: true,
            },
            Patch::File {
                path: "/victim.txt".into(),
                content: b"overwrite".to_vec(),
                mode: Some(0o600),
                replace: true,
            },
            Patch::CopyFile {
                src: source,
                dst: "/victim.txt".into(),
                mode: Some(0o600),
                replace: true,
            },
            Patch::Mkdir {
                path: "/new-directory".into(),
                mode: Some(0o700),
            },
        ];

        for patch in patches {
            let error = apply_patches(&bind_root(root.clone(), true), &[patch])
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("POSIX patch modes are not supported")
            );
        }

        assert_eq!(
            std::fs::read_to_string(root.join("victim.txt")).unwrap(),
            "keep"
        );
        assert!(!root.join("new-directory").exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn bind_patch_windows_rejects_host_path_syntax() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();

        let error = apply_patches(
            &bind_root(root.clone(), true),
            &[text_patch("/safe\\..\\escaped.txt", "must-not-write")],
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("Windows host"));
        assert!(!root.join("escaped.txt").exists());
        assert!(!root.join("safe").exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn bind_patch_windows_preflights_reserved_name_before_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();

        let error = apply_patches(
            &bind_root(root.clone(), true),
            &[
                text_patch("/first.txt", "must-not-write"),
                text_patch("/NUL.txt", "invalid"),
            ],
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("reserved Windows device name"));
        assert!(!root.join("first.txt").exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn bind_patch_windows_applies_supported_operations() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let source = temp.path().join("source.txt");
        let source_dir = temp.path().join("source-dir");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(&source, "copied").unwrap();
        std::fs::write(source_dir.join("nested.txt"), "nested").unwrap();
        std::fs::write(root.join("append.txt"), "before").unwrap();
        std::fs::write(root.join("remove.txt"), "remove").unwrap();

        apply_patches(
            &bind_root(root.clone(), true),
            &[
                text_patch("/text.txt", "text"),
                Patch::File {
                    path: "/file.bin".into(),
                    content: b"file".to_vec(),
                    mode: None,
                    replace: false,
                },
                Patch::CopyFile {
                    src: source,
                    dst: "/copied.txt".into(),
                    mode: None,
                    replace: false,
                },
                Patch::CopyDir {
                    src: source_dir,
                    dst: "/copied-dir".into(),
                    replace: false,
                },
                Patch::Mkdir {
                    path: "/new-dir".into(),
                    mode: None,
                },
                Patch::Append {
                    path: "/append.txt".into(),
                    content: "-after".into(),
                },
                Patch::Remove {
                    path: "/remove.txt".into(),
                },
            ],
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(root.join("text.txt")).unwrap(),
            "text"
        );
        assert_eq!(std::fs::read(root.join("file.bin")).unwrap(), b"file");
        assert_eq!(
            std::fs::read_to_string(root.join("copied.txt")).unwrap(),
            "copied"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("copied-dir/nested.txt")).unwrap(),
            "nested"
        );
        assert!(root.join("new-dir").is_dir());
        assert_eq!(
            std::fs::read_to_string(root.join("append.txt")).unwrap(),
            "before-after"
        );
        assert!(!root.join("remove.txt").exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn bind_patch_windows_rejects_descendant_junction_escape() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("sentinel.txt"), "keep").unwrap();
        create_windows_junction(&root.join("escape"), &outside);

        let error = apply_patches(
            &bind_root(root.clone(), true),
            &[text_patch("/escape/pwned.txt", "must-not-write")],
        )
        .await
        .unwrap_err();

        assert!(!error.to_string().is_empty());
        assert_eq!(
            std::fs::read_to_string(outside.join("sentinel.txt")).unwrap(),
            "keep"
        );
        assert!(!outside.join("pwned.txt").exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn bind_patch_windows_honors_junction_root_policy() {
        let temp = tempfile::tempdir().unwrap();
        let actual_root = temp.path().join("actual-root");
        let linked_root = temp.path().join("linked-root");
        std::fs::create_dir_all(&actual_root).unwrap();
        create_windows_junction(&linked_root, &actual_root);
        let patch = text_patch("/allowed.txt", "hello");

        let error = apply_patches(&bind_root(linked_root.clone(), false), &[patch.clone()])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("follow_root_symlinks"));
        assert!(!actual_root.join("allowed.txt").exists());

        apply_patches(&bind_root(linked_root, true), &[patch])
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(actual_root.join("allowed.txt")).unwrap(),
            "hello"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn bind_patch_windows_remove_recurses_without_following_junctions() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(root.join("remove/nested")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(root.join("remove/nested/file.txt"), "remove").unwrap();
        std::fs::write(outside.join("sentinel.txt"), "keep").unwrap();
        create_windows_junction(&root.join("remove").join("link"), &outside);

        apply_patches(
            &bind_root(root.clone(), true),
            &[Patch::Remove {
                path: "/remove".into(),
            }],
        )
        .await
        .unwrap();

        assert!(!root.join("remove").exists());
        assert_eq!(
            std::fs::read_to_string(outside.join("sentinel.txt")).unwrap(),
            "keep"
        );
    }

    #[tokio::test]
    async fn build_upper_tree_creates_missing_parents_for_text_patch() {
        let patches = vec![Patch::Text {
            path: "/etc/app.conf".into(),
            content: "hello".into(),
            mode: None,
            replace: false,
        }];

        let tree = build_upper_tree(&patches, &[]).await.unwrap();
        assert!(matches!(tree.get(b"etc"), Some(TreeNode::Directory(_))));
        match tree.get(b"etc/app.conf").unwrap() {
            TreeNode::RegularFile(file) => assert_eq!(file.data.read_all().unwrap(), b"hello"),
            _ => panic!("expected regular file"),
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn bind_patch_windows_preserves_copy_source_readonly_attribute() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let source_file = temp.path().join("source.txt");
        let source_dir = temp.path().join("source-dir");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(&source_file, "file").unwrap();
        std::fs::write(source_dir.join("nested.txt"), "nested").unwrap();
        for path in [&source_file, &source_dir.join("nested.txt")] {
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(path, permissions).unwrap();
        }

        apply_patches(
            &bind_root(root.clone(), true),
            &[
                Patch::CopyFile {
                    src: source_file,
                    dst: "/copied.txt".into(),
                    mode: None,
                    replace: false,
                },
                Patch::CopyDir {
                    src: source_dir,
                    dst: "/copied-dir".into(),
                    replace: false,
                },
            ],
        )
        .await
        .unwrap();

        assert!(
            std::fs::metadata(root.join("copied.txt"))
                .unwrap()
                .permissions()
                .readonly()
        );
        assert!(
            std::fs::metadata(root.join("copied-dir/nested.txt"))
                .unwrap()
                .permissions()
                .readonly()
        );
    }

    #[tokio::test]
    async fn build_upper_tree_remove_lower_file_creates_whiteout() {
        let dir = tempfile::tempdir().unwrap();
        let lower_path = dir.path().join("lower.erofs");
        let mut lower = FileTree::new();
        lower
            .insert(b"etc/secret.txt", make_regular_file(b"top-secret"))
            .unwrap();
        write_erofs(&lower, &lower_path).unwrap();

        let patches = vec![Patch::Remove {
            path: "/etc/secret.txt".into(),
        }];

        let tree = build_upper_tree(&patches, &[lower_path]).await.unwrap();
        assert!(matches!(tree.get(b"etc"), Some(TreeNode::Directory(_))));
        assert!(matches!(tree.get(b"etc/secret.txt"), Some(node) if is_whiteout(node)));
    }

    #[tokio::test]
    async fn build_upper_tree_append_reads_lower_erofs() {
        let dir = tempfile::tempdir().unwrap();
        let lower_path = dir.path().join("lower.erofs");
        let mut lower = FileTree::new();
        lower
            .insert(b"etc/config.txt", make_regular_file(b"alpha"))
            .unwrap();
        write_erofs(&lower, &lower_path).unwrap();

        let patches = vec![Patch::Append {
            path: "/etc/config.txt".into(),
            content: "-beta".into(),
        }];

        let tree = build_upper_tree(&patches, &[lower_path]).await.unwrap();
        match tree.get(b"etc/config.txt").unwrap() {
            TreeNode::RegularFile(file) => assert_eq!(file.data.read_all().unwrap(), b"alpha-beta"),
            _ => panic!("expected regular file"),
        }
    }

    #[tokio::test]
    async fn build_upper_tree_append_uses_topmost_visible_lower_file() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("base.erofs");
        let top_path = dir.path().join("top.erofs");

        let mut base = FileTree::new();
        base.insert(b"etc/config.txt", make_regular_file(b"base"))
            .unwrap();
        write_erofs(&base, &base_path).unwrap();

        let mut top = FileTree::new();
        top.insert(b"etc/config.txt", make_regular_file(b"top"))
            .unwrap();
        write_erofs(&top, &top_path).unwrap();

        let patches = vec![Patch::Append {
            path: "/etc/config.txt".into(),
            content: "-patched".into(),
        }];

        let tree = build_upper_tree(&patches, &[base_path, top_path])
            .await
            .unwrap();
        match tree.get(b"etc/config.txt").unwrap() {
            TreeNode::RegularFile(file) => {
                assert_eq!(file.data.read_all().unwrap(), b"top-patched")
            }
            _ => panic!("expected regular file"),
        }
    }

    #[tokio::test]
    async fn build_upper_tree_treats_whiteouted_lower_path_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("base.erofs");
        let top_path = dir.path().join("top.erofs");

        let mut base = FileTree::new();
        base.insert(b"etc/hidden.txt", make_regular_file(b"base"))
            .unwrap();
        write_erofs(&base, &base_path).unwrap();

        let mut top = FileTree::new();
        top.insert(b"etc/hidden.txt", make_whiteout()).unwrap();
        write_erofs(&top, &top_path).unwrap();

        let patches = vec![Patch::Text {
            path: "/etc/hidden.txt".into(),
            content: "fresh".into(),
            mode: None,
            replace: false,
        }];

        let tree = build_upper_tree(&patches, &[base_path, top_path])
            .await
            .unwrap();
        match tree.get(b"etc/hidden.txt").unwrap() {
            TreeNode::RegularFile(file) => assert_eq!(file.data.read_all().unwrap(), b"fresh"),
            _ => panic!("expected regular file"),
        }
    }

    #[tokio::test]
    async fn build_upper_tree_treats_opaque_lower_dir_as_hiding_deeper_entries() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("base.erofs");
        let top_path = dir.path().join("top.erofs");

        let mut base = FileTree::new();
        base.insert(b"etc/from-base.txt", make_regular_file(b"base"))
            .unwrap();
        write_erofs(&base, &base_path).unwrap();

        let mut top = FileTree::new();
        top.insert(b"etc", make_opaque_directory()).unwrap();
        top.insert(b"etc/from-top.txt", make_regular_file(b"top"))
            .unwrap();
        write_erofs(&top, &top_path).unwrap();

        let patches = vec![Patch::Text {
            path: "/etc/from-base.txt".into(),
            content: "fresh".into(),
            mode: None,
            replace: false,
        }];

        let tree = build_upper_tree(&patches, &[base_path, top_path])
            .await
            .unwrap();
        match tree.get(b"etc/from-base.txt").unwrap() {
            TreeNode::RegularFile(file) => assert_eq!(file.data.read_all().unwrap(), b"fresh"),
            _ => panic!("expected regular file"),
        }
    }

    #[tokio::test]
    async fn build_upper_tree_rejects_non_directory_parent_visible_in_lower_stack() {
        let dir = tempfile::tempdir().unwrap();
        let lower_path = dir.path().join("lower.erofs");
        let mut lower = FileTree::new();
        lower
            .insert(b"etc/profile", make_regular_file(b"profile"))
            .unwrap();
        write_erofs(&lower, &lower_path).unwrap();

        let patches = vec![Patch::Text {
            path: "/etc/profile/app.sh".into(),
            content: "echo hi".into(),
            mode: None,
            replace: false,
        }];

        let err = match build_upper_tree(&patches, &[lower_path]).await {
            Ok(_) => panic!("expected non-directory parent to fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("parent is not a directory"));
        assert!(err.to_string().contains("/etc/profile"));
    }

    #[tokio::test]
    async fn build_upper_tree_remove_new_upper_file_drops_it_without_whiteout() {
        let patches = vec![
            Patch::Text {
                path: "/tmp/demo.txt".into(),
                content: "hello".into(),
                mode: None,
                replace: false,
            },
            Patch::Remove {
                path: "/tmp/demo.txt".into(),
            },
        ];

        let tree = build_upper_tree(&patches, &[]).await.unwrap();
        assert!(tree.get(b"tmp/demo.txt").is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn build_upper_tree_copy_dir_rejects_special_source_files() {
        use std::ffi::CString;

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        let fifo = CString::new(source.join("pipe").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let error = match build_upper_tree(
            &[Patch::CopyDir {
                src: source,
                dst: "/copied".into(),
                replace: false,
            }],
            &[],
        )
        .await
        {
            Ok(_) => panic!("expected special source file to fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("unsupported file type"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn build_upper_tree_copy_file_rejects_fifo_source() {
        use std::ffi::CString;

        let temp = tempfile::tempdir().unwrap();
        let fifo_path = temp.path().join("pipe");
        let fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let error = match build_upper_tree(
            &[Patch::CopyFile {
                src: fifo_path,
                dst: "/copied.txt".into(),
                mode: None,
                replace: false,
            }],
            &[],
        )
        .await
        {
            Ok(_) => panic!("expected FIFO source to fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("not a regular file"));
    }
}
