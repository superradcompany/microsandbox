//! Patch application logic for rootfs modification before VM start.

use std::ffi::OsStr;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use microsandbox_image::erofs::{ErofsEntryInfo, ErofsEntryKind, ErofsReader};
use microsandbox_image::filetree::{
    DeviceNode, DirectoryNode, FileData, FileTree, FileTreeError, InodeMetadata, RegularFileNode,
    SymlinkNode, TreeNode,
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

    let target_dir = match image {
        RootfsSource::Bind(host_dir) => host_dir.clone(),
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

    for patch in patches {
        apply_one(&target_dir, &[], patch).await?;
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

/// Apply a single patch operation.
async fn apply_one(
    target_dir: &Path,
    lower_layers: &[PathBuf],
    patch: &Patch,
) -> MicrosandboxResult<()> {
    match patch {
        Patch::Text {
            path,
            content,
            mode,
            replace,
        } => {
            let dest = resolve_guest_path(target_dir, path)?;
            check_replace(&dest, lower_layers, path, *replace)?;
            ensure_parent(&dest).await?;
            fs::write(&dest, content.as_bytes()).await?;
            if let Some(mode) = mode {
                set_permissions(&dest, *mode).await?;
            }
        }
        Patch::File {
            path,
            content,
            mode,
            replace,
        } => {
            let dest = resolve_guest_path(target_dir, path)?;
            check_replace(&dest, lower_layers, path, *replace)?;
            ensure_parent(&dest).await?;
            fs::write(&dest, content).await?;
            if let Some(mode) = mode {
                set_permissions(&dest, *mode).await?;
            }
        }
        Patch::CopyFile {
            src,
            dst,
            mode,
            replace,
        } => {
            let dest = resolve_guest_path(target_dir, dst)?;
            check_replace(&dest, lower_layers, dst, *replace)?;
            ensure_parent(&dest).await?;
            fs::copy(src, &dest).await?;
            if let Some(mode) = mode {
                set_permissions(&dest, *mode).await?;
            }
        }
        Patch::CopyDir { src, dst, replace } => {
            let dest = resolve_guest_path(target_dir, dst)?;
            check_replace(&dest, lower_layers, dst, *replace)?;
            copy_dir_recursive(src, &dest).await?;
        }
        Patch::Symlink {
            target,
            link,
            replace,
        } => {
            let link_path = resolve_guest_path(target_dir, link)?;
            check_replace(&link_path, lower_layers, link, *replace)?;
            ensure_parent(&link_path).await?;
            // Remove existing if replace was allowed and something exists.
            if link_path.exists() {
                fs::remove_file(&link_path).await.ok();
            }
            #[cfg(unix)]
            tokio::fs::symlink(target, &link_path).await?;
        }
        Patch::Mkdir { path, mode } => {
            let dest = resolve_guest_path(target_dir, path)?;
            fs::create_dir_all(&dest).await?;
            if let Some(mode) = mode {
                set_permissions(&dest, *mode).await?;
            }
        }
        Patch::Remove { path } => {
            let dest = resolve_guest_path(target_dir, path)?;
            if dest.is_dir() {
                fs::remove_dir_all(&dest).await.ok();
            } else {
                fs::remove_file(&dest).await.ok();
            }
        }
        Patch::Append { path, content } => {
            let dest = resolve_guest_path(target_dir, path)?;
            // If the file doesn't exist in the target dir, try to copy up from lower layers.
            if !dest.exists()
                && let Some(source) = find_in_layers(lower_layers, path)
            {
                ensure_parent(&dest).await?;
                fs::copy(&source, &dest).await?;
            }
            if dest.exists() {
                use tokio::io::AsyncWriteExt;
                let mut file = fs::OpenOptions::new().append(true).open(&dest).await?;
                file.write_all(content.as_bytes()).await?;
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

async fn source_mode(path: &Path, is_dir: bool) -> MicrosandboxResult<u16> {
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path).await?;
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

/// Resolve a guest absolute path to a host path within the target directory.
///
/// Collapses `..` components lexically before checking containment, so that
/// paths like `/etc/foo/../../bar` are caught even without filesystem access.
fn resolve_guest_path(target_dir: &Path, guest_path: &str) -> MicrosandboxResult<PathBuf> {
    use std::path::Component;

    if !guest_path.starts_with('/') {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "patch path must be absolute: '{guest_path}'"
        )));
    }

    // Build a normalized relative path by collapsing `.` and `..` lexically.
    let mut normalized = PathBuf::new();
    for component in Path::new(guest_path).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(crate::MicrosandboxError::PatchFailed(format!(
                        "patch path escapes rootfs: '{guest_path}'"
                    )));
                }
            }
            Component::Normal(c) => {
                if c.as_encoded_bytes().contains(&b'\0') {
                    return Err(crate::MicrosandboxError::PatchFailed(format!(
                        "patch path contains null byte: '{guest_path}'"
                    )));
                }
                normalized.push(c);
            }
            Component::Prefix(_) => {}
        }
    }

    let resolved = target_dir.join(&normalized);

    if !resolved.starts_with(target_dir) {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "patch path escapes rootfs: '{guest_path}'"
        )));
    }

    Ok(resolved)
}

/// Check if a path already exists in the target dir or lower layers.
/// Returns an error if it exists and `replace` is false.
fn check_replace(
    dest: &Path,
    lower_layers: &[PathBuf],
    guest_path: &str,
    replace: bool,
) -> MicrosandboxResult<()> {
    if replace {
        return Ok(());
    }

    // Check the target directory (rw layer for OCI, host dir for bind).
    if dest.exists() {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "path already exists in rootfs: '{guest_path}' (set replace to allow)"
        )));
    }

    // Check lower layers (OCI image layers).
    if find_in_layers(lower_layers, guest_path).is_some() {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "path exists in image layer: '{guest_path}' (set replace to allow)"
        )));
    }

    Ok(())
}

/// Search lower layers (bottom-to-top) for a guest path. Returns the first match.
fn find_in_layers(layers: &[PathBuf], guest_path: &str) -> Option<PathBuf> {
    let relative = guest_path.strip_prefix('/').unwrap_or(guest_path);
    // Search top-to-bottom (last layer = topmost).
    for layer in layers.iter().rev() {
        let candidate = layer.join(relative);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Ensure parent directories exist.
async fn ensure_parent(path: &Path) -> MicrosandboxResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    Ok(())
}

/// Set Unix file permissions.
#[cfg(unix)]
async fn set_permissions(path: &Path, mode: u32) -> MicrosandboxResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perms).await?;
    Ok(())
}

/// Recursively copy a directory.
async fn copy_dir_recursive(src: &Path, dst: &Path) -> MicrosandboxResult<()> {
    fs::create_dir_all(dst).await?;
    let mut entries = fs::read_dir(src).await?;
    while let Some(entry) = entries.next_entry().await? {
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type().await?.is_dir() {
            Box::pin(copy_dir_recursive(&src_path, &dst_path)).await?;
        } else {
            fs::copy(&src_path, &dst_path).await?;
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use microsandbox_image::erofs::write_erofs;
    use microsandbox_image::filetree::Xattr;

    fn make_regular_file(data: &[u8]) -> TreeNode {
        TreeNode::RegularFile(RegularFileNode {
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
