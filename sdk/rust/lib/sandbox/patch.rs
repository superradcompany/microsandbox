//! Patch application logic for rootfs modification before VM start.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions, Permissions};
use microsandbox_image::erofs::{ErofsEntryInfo, ErofsEntryKind, ErofsReader};
use microsandbox_image::tree::{
    DeviceNode, DirectoryNode, FileData, FileTree, FileTreeError, InodeMetadata, RegularFileId,
    RegularFileNode, SymlinkNode, TreeNode,
};
use tokio::fs;

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

    /// Resolve a guest path beneath the pinned root.
    ///
    /// Existing symlinks are expanded explicitly so absolute targets restart
    /// at the guest root instead of the host root. The final capability-based
    /// operation repeats containment during use, which closes rename races
    /// between this semantic resolution and the mutation itself.
    fn resolve(&self, guest_path: &str, follow_final: bool) -> MicrosandboxResult<PathBuf> {
        let mut remaining = guest_path_components(guest_path)?;
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

    fn check_replace(
        &self,
        path: &Path,
        guest_path: &str,
        replace: bool,
    ) -> MicrosandboxResult<()> {
        if !replace && self.root.try_exists(path)? {
            return Err(crate::MicrosandboxError::PatchFailed(format!(
                "path already exists in rootfs: '{guest_path}' (set replace to allow)"
            )));
        }
        Ok(())
    }

    fn write_file(&self, path: &Path, content: &[u8]) -> MicrosandboxResult<()> {
        self.ensure_parent(path)?;
        self.root.write(path, content)?;
        Ok(())
    }

    fn copy_file(&self, src: &Path, dst: &Path) -> MicrosandboxResult<()> {
        self.ensure_parent(dst)?;
        let mut source = std::fs::File::open(src)?;
        let permissions = source.metadata()?.permissions();
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        let mut destination = self.root.open_with(dst, &options)?;
        std::io::copy(&mut source, &mut destination)?;
        destination.set_permissions(Permissions::from_std(permissions))?;
        Ok(())
    }

    fn copy_dir(&self, src: &Path, dst: &Path) -> MicrosandboxResult<()> {
        self.root.create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                self.copy_dir(&src_path, &dst_path)?;
            } else {
                self.copy_file(&src_path, &dst_path)?;
            }
        }
        Ok(())
    }

    fn remove_entry(&self, path: &Path) -> MicrosandboxResult<()> {
        match self.root.symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                self.root.remove_dir_all(path)?;
            }
            Ok(_) => {
                self.root.remove_file(path)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        Ok(())
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> MicrosandboxResult<()> {
        #[cfg(unix)]
        {
            self.root.set_permissions(
                path,
                Permissions::from_std(std::fs::Permissions::from_mode(mode)),
            )?;
            Ok(())
        }

        #[cfg(windows)]
        {
            let _ = (path, mode);
            Err(crate::MicrosandboxError::InvalidConfig(
                "POSIX patch modes are not supported for Windows host bind roots".into(),
            ))
        }
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

    let patches = patches.to_vec();
    tokio::task::spawn_blocking(move || -> MicrosandboxResult<()> {
        let root = RootedPatchFs::open(&target_dir, follow_root_symlinks)?;
        for patch in &patches {
            apply_one_to_bind(&root, patch)?;
        }
        Ok(())
    })
    .await
    .map_err(|err| {
        crate::MicrosandboxError::PatchFailed(format!("bind-root patch task failed: {err}"))
    })?
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
            let data = fs::read(src).await?;
            let file_mode = if let Some(mode) = mode {
                *mode as u16
            } else {
                source_mode(src, false).await?
            };
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
            let dest = root.resolve(path, true)?;
            root.check_replace(&dest, path, *replace)?;
            root.write_file(&dest, content.as_bytes())?;
            if let Some(mode) = mode {
                root.set_permissions(&dest, *mode)?;
            }
        }
        Patch::File {
            path,
            content,
            mode,
            replace,
        } => {
            let dest = root.resolve(path, true)?;
            root.check_replace(&dest, path, *replace)?;
            root.write_file(&dest, content)?;
            if let Some(mode) = mode {
                root.set_permissions(&dest, *mode)?;
            }
        }
        Patch::CopyFile {
            src,
            dst,
            mode,
            replace,
        } => {
            let dest = root.resolve(dst, true)?;
            root.check_replace(&dest, dst, *replace)?;
            root.copy_file(src, &dest)?;
            if let Some(mode) = mode {
                root.set_permissions(&dest, *mode)?;
            }
        }
        Patch::CopyDir { src, dst, replace } => {
            let dest = root.resolve(dst, true)?;
            root.check_replace(&dest, dst, *replace)?;
            root.copy_dir(src, &dest)?;
        }
        Patch::Symlink {
            target,
            link,
            replace,
        } => {
            let link_path = root.resolve(link, false)?;
            root.check_replace(&link_path, link, *replace)?;
            root.ensure_parent(&link_path)?;
            if *replace {
                root.remove_entry(&link_path)?;
            }
            #[cfg(unix)]
            root.root.symlink_contents(target, &link_path)?;
            #[cfg(windows)]
            {
                let _ = target;
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "symlink patches are not supported for Windows host bind roots".into(),
                ));
            }
        }
        Patch::Mkdir { path, mode } => {
            let dest = root.resolve(path, true)?;
            root.root.create_dir_all(&dest)?;
            if let Some(mode) = mode {
                root.set_permissions(&dest, *mode)?;
            }
        }
        Patch::Remove { path } => {
            let dest = root.resolve(path, false)?;
            root.remove_entry(&dest)?;
        }
        Patch::Append { path, content } => {
            let dest = root.resolve(path, true)?;
            if root.root.try_exists(&dest)? {
                let mut options = OpenOptions::new();
                options.append(true);
                let mut file = root.root.open_with(&dest, &options)?;
                file.write_all(content.as_bytes())?;
            } else {
                return Err(crate::MicrosandboxError::PatchFailed(format!(
                    "cannot append to '{path}': file not found in rootfs"
                )));
            }
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
        } else {
            let mode = source_mode(&child_path, false).await?;
            let data = fs::read(&child_path).await?;
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

/// Parse a guest path with Unix semantics on every host platform.
fn guest_path_components(guest_path: &str) -> MicrosandboxResult<VecDeque<PendingComponent>> {
    use typed_path::{Utf8UnixComponent, Utf8UnixPath};

    if !guest_path.starts_with('/') {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "patch path must be absolute: '{guest_path}'"
        )));
    }

    let mut components = VecDeque::new();
    for component in Utf8UnixPath::new(guest_path).components() {
        match component {
            Utf8UnixComponent::RootDir | Utf8UnixComponent::CurDir => {}
            Utf8UnixComponent::ParentDir => {
                components.push_back(PendingComponent::Parent {
                    clamp_at_root: false,
                });
            }
            Utf8UnixComponent::Normal(c) => {
                if c.contains('\0') {
                    return Err(crate::MicrosandboxError::PatchFailed(format!(
                        "patch path contains null byte: '{guest_path}'"
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

/// Expand a host symlink target using Linux guest-root semantics.
fn prepend_link_target(
    target: &Path,
    resolved: &mut Vec<OsString>,
    remaining: &mut VecDeque<PendingComponent>,
    guest_path: &str,
) -> MicrosandboxResult<()> {
    let mut target_components = Vec::new();

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

    for component in target_components.into_iter().rev() {
        remaining.push_front(component);
    }
    Ok(())
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

    let mut base = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir()?
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
}
