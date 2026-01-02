use std::{
    ffi::{CStr, CString},
    io::ErrorKind,
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
};

use anyhow::anyhow;
use futures::StreamExt;
use tokio::{
    fs::{self, DirBuilder},
    io::AsyncRead,
};
use tokio_tar::{Archive, Entry};

use crate::{MicrosandboxError, MicrosandboxResult, oci::LayerDependencies};

/// Helper function to get full mode with file type bits
fn get_full_mode(entry_type: &tokio_tar::EntryType, permission_bits: u32) -> u32 {
    let file_type_bits = if entry_type.is_file() {
        libc::S_IFREG as u32
    } else if entry_type.is_dir() {
        libc::S_IFDIR as u32
    } else if entry_type.is_symlink() {
        libc::S_IFLNK as u32
    } else if entry_type.is_block_special() {
        libc::S_IFBLK as u32
    } else if entry_type.is_character_special() {
        libc::S_IFCHR as u32
    } else if entry_type.is_fifo() {
        libc::S_IFIFO as u32
    } else {
        0 // Unknown type
    };

    file_type_bits | permission_bits
}

/// Helper function to set xattr with stat information
fn set_stat_xattr(
    path: &Path,
    xattr_name: &CStr,
    uid: u64,
    gid: u64,
    mode: u32,
) -> Result<(), MicrosandboxError> {
    use std::ffi::CString;

    let stat_data = format!("{}:{}:0{:o}", uid, gid, mode);
    let path_cstring = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| MicrosandboxError::LayerExtraction(format!("Invalid path: {:?}", e)))?;

    let result = unsafe {
        #[cfg(target_os = "macos")]
        {
            libc::setxattr(
                path_cstring.as_ptr(),
                xattr_name.as_ptr(),
                stat_data.as_ptr() as *const libc::c_void,
                stat_data.len(),
                0, // position parameter for macOS
                0, // options
            )
        }
        #[cfg(target_os = "linux")]
        {
            libc::setxattr(
                path_cstring.as_ptr(),
                xattr_name.as_ptr(),
                stat_data.as_ptr() as *const libc::c_void,
                stat_data.len(),
                0, // flags
            )
        }
    };

    if result != 0 {
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() == Some(libc::ENOTSUP) {
            tracing::warn!(
                "Filesystem does not support xattrs for {}, continuing without stat shadowing",
                path.display()
            );
        } else {
            return Err(MicrosandboxError::LayerExtraction(format!(
                "Failed to set xattr on {}: {}",
                path.display(),
                errno
            )));
        }
    }
    Ok(())
}

/// Extracts a layer from the downloaded tar.gz file into an extracted directory.
/// The extracted directory will be named as <layer-name>.extracted
/// Custom extraction function that modifies file ownership during extraction
pub(crate) async fn extract_tar_with_ownership_override<R: AsyncRead + Unpin>(
    archive: &mut Archive<R>,
    extract_dir: &Path,
    parent_layers: LayerDependencies,
) -> MicrosandboxResult<()> {
    // Cache the xattr name to avoid repeated allocations
    let xattr_name = CString::new("user.containers.override_stat")
        .map_err(|e| anyhow::anyhow!("Invalid attr name: {e:?}"))?;

    // Store hard links to process after all regular files are extracted
    let mut hard_links = HardLinkVec::default();
    let mut entries = archive.entries()?;

    while let Some(entry) = entries.next().await {
        let entry = entry?;
        let entry_path = entry.path()?.to_path_buf();
        let dst_path = extract_dir.join(&entry_path);

        // Get the original metadata from the tar entry
        let original_uid = entry.header().uid()?;
        let original_gid = entry.header().gid()?;
        let permission_bits = entry.header().mode()?;

        // Check the entry type
        let entry_type = entry.header().entry_type();
        let is_symlink = entry_type.is_symlink();
        let is_hard_link = entry_type.is_hard_link();

        // Calculate the full mode with file type bits
        let original_mode = get_full_mode(&entry_type, permission_bits);

        // Handle hard links separately - collect them for processing after all files are extracted
        if is_hard_link {
            if let Ok(Some(link_name)) = entry.link_name() {
                hard_links.push(HardLink {
                    link_path: dst_path.clone(),
                    target_path: extract_dir.join(link_name.as_ref()),
                    uid: original_uid,
                    gid: original_gid,
                    mode: original_mode,
                });
            }
            continue;
        }

        // Extract the entry (regular files, directories, symlinks)
        tracing::debug!(path = %dst_path.display(), "Extracting entry");
        unpack(
            entry,
            &entry_path,
            &dst_path,
            extract_dir,
            parent_layers.clone(),
        )
        .await?;

        tracing::debug!(dst_path = %dst_path.display(), "Done unpacking entry");

        // Skip all operations for symlinks
        if is_symlink {
            tracing::trace!(
                dst_path = %dst_path.display(),
                "Extracted symlink with original uid:gid:mode {}:{}:{:o}",
                original_uid,
                original_gid,
                original_mode
            );
            continue;
        }

        // For regular files and directories, handle permissions and xattrs
        let metadata = std::fs::metadata(&dst_path)?;
        let is_dir = metadata.is_dir();
        let current_mode = metadata.permissions().mode();
        let current_permission_bits = current_mode & 0o7777; // Extract only permission bits

        // Calculate the final desired permissions
        let desired_permission_bits = if is_dir {
            // For directories, ensure at least u+rwx (0o700)
            current_permission_bits | 0o700
        } else {
            // For files, ensure at least u+rw (0o600)
            current_permission_bits | 0o600
        };

        // If we need to modify permissions, do it once
        if current_permission_bits != desired_permission_bits {
            let mut permissions = metadata.permissions();
            permissions.set_mode(desired_permission_bits);
            std::fs::set_permissions(&dst_path, permissions)?;
        }

        // Store original uid/gid/mode in xattrs
        set_stat_xattr(
            &dst_path,
            &xattr_name,
            original_uid,
            original_gid,
            original_mode,
        )?;

        tracing::trace!(
            "Extracted {} with original uid:gid:mode {}:{}:{:o}, stored in xattr",
            dst_path.display(),
            original_uid,
            original_gid,
            original_mode
        );
    }

    hard_links.extract(&xattr_name).await?;
    Ok(())
}

/// Unpacks a tar entry into a destination path, copying ancestor directories from parent layers if needed
///
/// ## Arguments
///
/// * `entry` - The tar entry to unpack
/// * `entry_path` - The path of the tar entry
/// * `dst_path` - The path to unpack the tar entry to
/// * `extract_dir` - The directory to extract the tar entry to
/// * `parent_layers` - The parent layers to copy ancestor directories from
async fn unpack<R: AsyncRead + Unpin>(
    mut entry: Entry<Archive<R>>,
    entry_path: &Path,
    dst_path: &Path,
    extract_dir: &Path,
    parent_layers: LayerDependencies,
) -> MicrosandboxResult<()> {
    let Err(err) = entry.unpack(&dst_path).await else {
        tracing::debug!(path = %dst_path.display(), "Done unpacking entry");
        return Ok(());
    };

    if !matches!(err.kind(), ErrorKind::NotFound) {
        return Err(err.into());
    }

    // Copy every ancestor directory from the parent layers, excluding the root
    // directory component i.e. "."
    let parent = entry_path.parent().expect("tar entry to have a parent");
    let ancestors = parent.ancestors().collect::<Vec<_>>();
    for (_, ancestor) in ancestors.into_iter().rev().skip(1).enumerate() {
        // To avoid directory traversal attacks, skip relative parent directories entries
        let dir_name = ancestor.components().next();
        if dir_name == Some(Component::ParentDir) {
            tracing::debug!(ancestor = %ancestor.display(), "Skipping parent directory");
            break;
        }

        let (digest, parent_path) = parent_layers.find_dir(ancestor).await?.ok_or_else(|| {
            anyhow!(
                "ancestor directory not found in any parent layer: {}",
                ancestor.display()
            )
        })?;

        let dest_dir = extract_dir.join(dir_name.expect("ancestor directory should have a name"));
        tracing::debug!(
            %digest,
            parent_layer_path = %parent_path.display(),
            extract_dir = %dest_dir.display(),
            "Found dir in a parent layer. Proceeding to copy"
        );

        create_and_copy_dir_attr(&parent_path, &dest_dir).await?;
        tracing::debug!("Copied parent directory for: {}", entry_path.display());
    }

    // Try to unpack the entry again after creating the ancestor directories
    if let Err(err) = entry.unpack(&dst_path).await {
        return Err(MicrosandboxError::LayerExtraction(format!(
            "layer extraction failed after retry: {err}",
        )));
    }

    Ok(())
}

/// Creates a directory and copies over permissions and xattrs from the template directory
///
/// ## Arguments
///
/// * `template_dir` - The template directory to copy permissions and xattrs from
/// * `dest_dir` - The destination directory to create and copy permissions and xattrs to
async fn create_and_copy_dir_attr(template_dir: &Path, dest_dir: &Path) -> MicrosandboxResult<()> {
    if dest_dir.exists() {
        tracing::debug!(dest_dir = %dest_dir.display(), "Destination directory already exists");
        return Ok(());
    }

    if !template_dir.is_dir() {
        return Err(MicrosandboxError::LayerExtraction(format!(
            "Source directory is not a directory or does not exist: {}",
            template_dir.display()
        )));
    }

    // Create new directory, and copy over permissions and xattrs from template directory
    let mode = fs::metadata(&template_dir).await?.permissions().mode();
    DirBuilder::new().mode(mode).create(&dest_dir).await?;
    if let Ok(xattrs) = xattr::list(&template_dir) {
        for attr in xattrs {
            if let Ok(Some(value)) = xattr::get(&template_dir, &attr) {
                if let Err(e) = xattr::set(&dest_dir, &attr, &value) {
                    tracing::warn!("Failed to set xattr: {}", e);
                }
            }
        }
    }

    Ok(())
}

// Structure to store hard link information
struct HardLink {
    link_path: PathBuf,
    target_path: PathBuf,
    uid: u64,
    gid: u64,
    mode: u32,
}

#[derive(Default)]
struct HardLinkVec {
    hard_links: Vec<HardLink>,
}

impl From<Vec<HardLink>> for HardLinkVec {
    fn from(value: Vec<HardLink>) -> Self {
        Self { hard_links: value }
    }
}

impl HardLinkVec {
    pub fn push(&mut self, link: HardLink) {
        self.hard_links.push(link);
    }

    async fn extract(&self, xattr_name: &CStr) -> MicrosandboxResult<()> {
        // Second pass: process hard links after all regular files are extracted
        for link_info in &self.hard_links {
            // Create the hard link
            match std::fs::hard_link(&link_info.target_path, &link_info.link_path) {
                Ok(_) => {
                    // Hard link created successfully, now handle xattrs
                    // Get metadata and ensure proper permissions
                    let metadata = match std::fs::metadata(&link_info.link_path) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!(
                                "Failed to get metadata for hard link {}: {}",
                                link_info.link_path.display(),
                                e
                            );
                            continue;
                        }
                    };

                    let current_mode = metadata.permissions().mode();
                    let current_permission_bits = current_mode & 0o7777; // Extract only permission bits
                    let desired_permission_bits = current_permission_bits | 0o600; // Ensure at least u+rw

                    // Set permissions if needed
                    if current_permission_bits != desired_permission_bits {
                        let mut permissions = metadata.permissions();
                        permissions.set_mode(desired_permission_bits);
                        if let Err(e) = std::fs::set_permissions(&link_info.link_path, permissions)
                        {
                            tracing::warn!(
                                "Failed to set permissions for hard link {}: {}",
                                link_info.link_path.display(),
                                e
                            );
                            continue;
                        }
                    }

                    // Store original uid/gid/mode in xattrs
                    if let Err(e) = set_stat_xattr(
                        &link_info.link_path,
                        &xattr_name,
                        link_info.uid,
                        link_info.gid,
                        link_info.mode,
                    ) {
                        // For hard links, we just warn on xattr errors instead of failing
                        tracing::warn!(
                            "Failed to set xattr on hard link {}: {}",
                            link_info.link_path.display(),
                            e
                        );
                    }

                    tracing::trace!(
                        "Created hard link {} -> {} with original uid:gid:mode {}:{}:{:o}",
                        link_info.link_path.display(),
                        link_info.target_path.display(),
                        link_info.uid,
                        link_info.gid,
                        link_info.mode
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to create hard link {} -> {}: {}",
                        link_info.link_path.display(),
                        link_info.target_path.display(),
                        e
                    );
                }
            }
        }

        Ok(())
    }
}
