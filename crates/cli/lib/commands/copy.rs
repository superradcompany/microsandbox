//! `msb copy` command — copy files between the host and a sandbox.

#[cfg(unix)]
mod host;
#[cfg(windows)]
#[path = "copy/host_windows.rs"]
mod host;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::Args;
use futures::future::BoxFuture;
use microsandbox::sandbox::{FsEntryKind, FsMetadata, FsSetAttrs, SandboxFsOps};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum guest-reported symlink target accepted during copy-out.
///
/// The agent protocol permits frames up to 4 MiB, while host filesystems
/// accept much smaller symlink targets. Bounding before component parsing
/// prevents an adversarial response from causing allocation amplification.
#[cfg(unix)]
const MAX_COPY_SYMLINK_TARGET_BYTES: usize = 4096;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Copy files between the host and a sandbox.
#[derive(Debug, Args)]
pub struct CopyArgs {
    /// Source path. Use SANDBOX:/absolute/path for a sandbox path.
    pub source: String,

    /// Destination path. Use SANDBOX:/absolute/path for a sandbox path.
    pub destination: String,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

/// A parsed copy endpoint.
#[derive(Debug, Clone)]
enum Endpoint {
    Local(PathBuf),
    Sandbox { name: String, path: String },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Endpoint {
    /// Parse a CLI endpoint.
    fn parse(value: &str) -> anyhow::Result<Self> {
        if is_explicit_local_path(value) {
            return Ok(Self::Local(PathBuf::from(value)));
        }

        if let Some((name, path)) = value.split_once(':') {
            if !path.starts_with('/') {
                anyhow::bail!(
                    "ambiguous copy endpoint `{value}`; use SANDBOX:/absolute/path for sandbox paths or prefix local paths with ./"
                );
            }
            microsandbox::validate_sandbox_name(name)
                .map_err(|e| anyhow::anyhow!("invalid sandbox endpoint `{value}`: {e}"))?;
            return Ok(Self::Sandbox {
                name: name.to_string(),
                path: path.to_string(),
            });
        }

        Ok(Self::Local(PathBuf::from(value)))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb copy` command.
pub async fn run(args: CopyArgs) -> anyhow::Result<()> {
    let source = Endpoint::parse(&args.source)?;
    let destination = Endpoint::parse(&args.destination)?;

    match (source, destination) {
        (Endpoint::Local(src), Endpoint::Sandbox { name, path }) => {
            let sandbox = super::resolve_and_start(&name, args.quiet).await?;
            let fs = sandbox.fs();
            let result = copy_local_to_sandbox(&fs, &src, &path).await;
            super::maybe_stop(&sandbox).await;
            result
        }
        (Endpoint::Sandbox { name, path }, Endpoint::Local(dst)) => {
            let sandbox = super::resolve_and_start(&name, args.quiet).await?;
            let fs = sandbox.fs();
            let result = copy_sandbox_to_local(&fs, &path, &dst).await;
            super::maybe_stop(&sandbox).await;
            result
        }
        (
            Endpoint::Sandbox {
                name: src_name,
                path: src_path,
            },
            Endpoint::Sandbox {
                name: dst_name,
                path: dst_path,
            },
        ) => {
            if src_name == dst_name {
                let sandbox = super::resolve_and_start(&src_name, args.quiet).await?;
                let fs = sandbox.fs();
                let result = copy_sandbox_to_sandbox(&fs, &src_path, &dst_path).await;
                super::maybe_stop(&sandbox).await;
                return result;
            }

            let src_sandbox = super::resolve_and_start(&src_name, args.quiet).await?;
            let dst_sandbox = match super::resolve_and_start(&dst_name, args.quiet).await {
                Ok(sandbox) => sandbox,
                Err(e) => {
                    super::maybe_stop(&src_sandbox).await;
                    return Err(e);
                }
            };
            let src_fs = src_sandbox.fs();
            let dst_fs = dst_sandbox.fs();
            let result =
                copy_sandbox_to_other_sandbox(&src_fs, &src_path, &dst_fs, &dst_path).await;
            super::maybe_stop(&dst_sandbox).await;
            super::maybe_stop(&src_sandbox).await;
            result
        }
        (Endpoint::Local(_), Endpoint::Local(_)) => {
            anyhow::bail!("msb copy requires at least one sandbox endpoint (SANDBOX:/path)")
        }
    }
}

/// Copy a host path into a sandbox.
async fn copy_local_to_sandbox(fs: &SandboxFsOps<'_>, src: &Path, dst: &str) -> anyhow::Result<()> {
    let metadata = tokio::fs::symlink_metadata(src)
        .await
        .with_context(|| format!("stat {}", src.display()))?;
    let basename = local_basename(src)?;
    let dst = sandbox_destination(fs, dst, basename).await?;
    copy_local_entry_to_sandbox(fs, src.to_path_buf(), dst, metadata).await
}

/// Copy a sandbox path to the host.
async fn copy_sandbox_to_local(fs: &SandboxFsOps<'_>, src: &str, dst: &Path) -> anyhow::Result<()> {
    let metadata = fs
        .stat_with_follow(src, false)
        .await
        .with_context(|| format!("stat {src}"))?;
    let basename = guest_basename(src)?;
    let dst = local_destination(dst, basename).await?;

    #[cfg(unix)]
    {
        copy_sandbox_to_local_unix(fs, src, &dst, metadata).await
    }
    #[cfg(windows)]
    {
        copy_sandbox_to_local_windows(fs, src, &dst, metadata).await
    }
}

/// Copy a sandbox entry beneath a pinned host destination on Unix.
#[cfg(unix)]
async fn copy_sandbox_to_local_unix(
    fs: &SandboxFsOps<'_>,
    src: &str,
    dst: &Path,
    metadata: FsMetadata,
) -> anyhow::Result<()> {
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    if metadata.kind == FsEntryKind::Directory {
        // `cp` historically created missing parents for a directory target.
        // This path is entirely operator supplied; guest-derived traversal
        // begins only after the resulting parent directory is pinned below.
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create destination parent {}", parent.display()))?;
    }

    let destination_root = host::CopyRoot::open(parent)?;
    let destination_name = dst
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("copy destination {} has no file name", dst.display()))?;
    let destination_path = PathBuf::from(destination_name);

    if metadata.kind == FsEntryKind::Directory {
        let directory = destination_root.ensure_directory(&destination_path)?;
        let copied_tree = host::CopyRoot::from_directory(directory);
        return copy_sandbox_entry_to_local_unix(
            fs,
            src.to_string(),
            PathBuf::new(),
            &copied_tree,
            metadata,
        )
        .await;
    }

    copy_sandbox_entry_to_local_unix(
        fs,
        src.to_string(),
        destination_path,
        &destination_root,
        metadata,
    )
    .await
}

/// Copy a sandbox entry beneath a pinned host destination on Windows.
#[cfg(windows)]
async fn copy_sandbox_to_local_windows(
    fs: &SandboxFsOps<'_>,
    src: &str,
    dst: &Path,
    metadata: FsMetadata,
) -> anyhow::Result<()> {
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    if metadata.kind == FsEntryKind::Directory {
        // Only the operator-selected parent is resolved through normal Win32
        // path handling. Sandbox-derived names below the pinned handle are
        // opened relative to that handle without processing reparse points.
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create destination parent {}", parent.display()))?;
    }

    let destination_root = host::CopyRoot::open(parent)?;
    let destination_name = dst
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("copy destination {} has no file name", dst.display()))?;
    let destination_path = PathBuf::from(destination_name);

    if metadata.kind == FsEntryKind::Directory {
        let directory = destination_root.ensure_directory(&destination_path)?;
        let copied_tree = host::CopyRoot::from_directory(directory);
        return copy_sandbox_entry_to_local_windows(
            fs,
            src.to_string(),
            PathBuf::new(),
            &copied_tree,
            metadata,
        )
        .await;
    }

    copy_sandbox_entry_to_local_windows(
        fs,
        src.to_string(),
        destination_path,
        &destination_root,
        metadata,
    )
    .await
}

/// Copy a sandbox path within the same sandbox.
async fn copy_sandbox_to_sandbox(
    fs: &SandboxFsOps<'_>,
    src: &str,
    dst: &str,
) -> anyhow::Result<()> {
    let metadata = fs
        .stat_with_follow(src, false)
        .await
        .with_context(|| format!("stat {src}"))?;
    let basename = guest_basename(src)?;
    let dst = sandbox_destination(fs, dst, basename).await?;
    copy_sandbox_entry_to_sandbox(fs, src.to_string(), dst, metadata).await
}

/// Copy a sandbox path into another sandbox.
async fn copy_sandbox_to_other_sandbox(
    src_fs: &SandboxFsOps<'_>,
    src: &str,
    dst_fs: &SandboxFsOps<'_>,
    dst: &str,
) -> anyhow::Result<()> {
    let metadata = src_fs
        .stat_with_follow(src, false)
        .await
        .with_context(|| format!("stat {src}"))?;
    let basename = guest_basename(src)?;
    let dst = sandbox_destination(dst_fs, dst, basename).await?;
    copy_sandbox_entry_to_other_sandbox(src_fs, src.to_string(), dst_fs, dst, metadata).await
}

/// Recursively copy a host entry into a sandbox.
fn copy_local_entry_to_sandbox<'a>(
    fs: &'a SandboxFsOps<'a>,
    src: PathBuf,
    dst: String,
    metadata: std::fs::Metadata,
) -> BoxFuture<'a, anyhow::Result<()>> {
    Box::pin(async move {
        if metadata.is_dir() {
            fs.mkdir(&dst).await?;
            set_guest_mode(fs, &dst, local_mode(&metadata), true).await?;

            let mut entries = tokio::fs::read_dir(&src)
                .await
                .with_context(|| format!("read directory {}", src.display()))?;
            while let Some(entry) = entries.next_entry().await? {
                let child_src = entry.path();
                let child_metadata = tokio::fs::symlink_metadata(&child_src)
                    .await
                    .with_context(|| format!("stat {}", child_src.display()))?;
                let child_name = entry.file_name();
                let child_name = child_name.to_string_lossy();
                let child_dst = guest_join(&dst, &child_name);
                copy_local_entry_to_sandbox(fs, child_src, child_dst, child_metadata).await?;
            }
            return Ok(());
        }

        if metadata.is_symlink() {
            let target = tokio::fs::read_link(&src)
                .await
                .with_context(|| format!("readlink {}", src.display()))?;
            fs.symlink(&target.to_string_lossy(), &dst).await?;
            return Ok(());
        }

        if metadata.is_file() {
            copy_local_file_to_sandbox(fs, &src, &dst).await?;
            set_guest_mode(fs, &dst, local_mode(&metadata), true).await?;
            return Ok(());
        }

        anyhow::bail!("unsupported file type: {}", src.display())
    })
}

/// Recursively copy a sandbox entry beneath a pinned Unix destination root.
#[cfg(unix)]
fn copy_sandbox_entry_to_local_unix<'a>(
    fs: &'a SandboxFsOps<'a>,
    src: String,
    dst: PathBuf,
    root: &'a host::CopyRoot,
    metadata: FsMetadata,
) -> BoxFuture<'a, anyhow::Result<()>> {
    Box::pin(async move {
        match metadata.kind {
            FsEntryKind::Directory => {
                let directory = root.ensure_directory(&dst)?;

                for entry in fs.list(&src).await? {
                    let child_name = guest_basename(&entry.path)?;
                    let child_src = guest_join(&src, child_name);
                    let child_dst = dst.join(child_name);
                    let child_metadata = fs.stat_with_follow(&child_src, false).await?;
                    copy_sandbox_entry_to_local_unix(
                        fs,
                        child_src,
                        child_dst,
                        root,
                        child_metadata,
                    )
                    .await?;
                }

                // Apply restrictive guest modes only after all children have
                // been created, and chmod the inode already pinned above.
                host::set_directory_mode(&directory, metadata.mode)?;
            }
            FsEntryKind::Symlink => {
                let target = fs.read_link(&src).await?;
                let safe_target = confine_symlink_target(&dst, &target)?;
                root.replace_symlink(&dst, &safe_target)?;
            }
            FsEntryKind::File => {
                copy_sandbox_file_to_local_unix(fs, &src, root, &dst, metadata.mode).await?;
            }
            FsEntryKind::Other => {
                anyhow::bail!("unsupported file type: {src}");
            }
        }

        Ok(())
    })
}

/// Recursively copy a sandbox entry beneath a pinned Windows destination root.
#[cfg(windows)]
fn copy_sandbox_entry_to_local_windows<'a>(
    fs: &'a SandboxFsOps<'a>,
    src: String,
    dst: PathBuf,
    root: &'a host::CopyRoot,
    metadata: FsMetadata,
) -> BoxFuture<'a, anyhow::Result<()>> {
    Box::pin(async move {
        match metadata.kind {
            FsEntryKind::Directory => {
                let directory = root.ensure_directory(&dst)?;

                for entry in fs.list(&src).await? {
                    let child_name = guest_basename(&entry.path)?;
                    let child_src = guest_join(&src, child_name);
                    let child_dst = dst.join(child_name);
                    let child_metadata = fs.stat_with_follow(&child_src, false).await?;
                    copy_sandbox_entry_to_local_windows(
                        fs,
                        child_src,
                        child_dst,
                        root,
                        child_metadata,
                    )
                    .await?;
                }

                host::set_directory_mode(&directory, metadata.mode)?;
            }
            FsEntryKind::Symlink => {
                anyhow::bail!("copying sandbox symlinks to the Windows host is not supported yet");
            }
            FsEntryKind::File => {
                copy_sandbox_file_to_local_windows(fs, &src, root, &dst, metadata.mode).await?;
            }
            FsEntryKind::Other => {
                anyhow::bail!("unsupported file type: {src}");
            }
        }

        Ok(())
    })
}

/// Resolve an untrusted symlink target within the copy tree.
///
/// The returned target is relative to the recreated link's parent. Absolute
/// guest targets are rerooted inside the copy tree, and `..` is rejected if
/// it would walk above that tree. Copy-out operations independently refuse
/// to follow every symlink beneath the pinned destination root.
#[cfg(unix)]
fn confine_symlink_target(dst: &Path, target: &str) -> anyhow::Result<PathBuf> {
    if target.is_empty() {
        anyhow::bail!(
            "refusing to create symlink {} with an empty target",
            dst.display()
        );
    }
    if target.len() > MAX_COPY_SYMLINK_TARGET_BYTES {
        anyhow::bail!(
            "refusing to create symlink {}: target is {} bytes (maximum {})",
            dst.display(),
            target.len(),
            MAX_COPY_SYMLINK_TARGET_BYTES
        );
    }
    if target.as_bytes().contains(&0) {
        anyhow::bail!(
            "refusing to create symlink {}: target contains NUL",
            dst.display()
        );
    }

    let parent = dst.parent().unwrap_or_else(|| Path::new(""));
    let parent_components: Vec<std::ffi::OsString> = parent
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name.to_os_string()),
            _ => anyhow::bail!(
                "destination path {} is not relative to the copy root",
                dst.display()
            ),
        })
        .collect::<anyhow::Result<_>>()?;

    let mut resolved = if target.starts_with('/') {
        Vec::new()
    } else {
        parent_components.clone()
    };

    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if resolved.pop().is_none() {
                    anyhow::bail!(
                        "refusing to create symlink {} -> {target}: target escapes the copy destination",
                        dst.display()
                    );
                }
            }
            other => resolved.push(std::ffi::OsString::from(other)),
        }
    }

    let common = parent_components
        .iter()
        .zip(&resolved)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative_target = PathBuf::new();
    for _ in common..parent_components.len() {
        relative_target.push("..");
    }
    for component in &resolved[common..] {
        relative_target.push(component);
    }
    if relative_target.as_os_str().is_empty() {
        relative_target.push(".");
    }

    Ok(relative_target)
}

/// Recursively copy a sandbox entry within the same sandbox.
fn copy_sandbox_entry_to_sandbox<'a>(
    fs: &'a SandboxFsOps<'a>,
    src: String,
    dst: String,
    metadata: FsMetadata,
) -> BoxFuture<'a, anyhow::Result<()>> {
    Box::pin(async move {
        match metadata.kind {
            FsEntryKind::Directory => {
                fs.mkdir(&dst).await?;
                set_guest_mode(fs, &dst, metadata.mode, true).await?;

                for entry in fs.list(&src).await? {
                    let child_name = guest_basename(&entry.path)?;
                    let child_src = guest_join(&src, child_name);
                    let child_dst = guest_join(&dst, child_name);
                    let child_metadata = fs.stat_with_follow(&child_src, false).await?;
                    copy_sandbox_entry_to_sandbox(fs, child_src, child_dst, child_metadata).await?;
                }
            }
            FsEntryKind::Symlink => {
                let target = fs.read_link(&src).await?;
                fs.symlink(&target, &dst).await?;
            }
            FsEntryKind::File => {
                fs.copy(&src, &dst).await?;
                set_guest_mode(fs, &dst, metadata.mode, true).await?;
            }
            FsEntryKind::Other => {
                anyhow::bail!("unsupported file type: {src}");
            }
        }

        Ok(())
    })
}

/// Recursively copy a sandbox entry into another sandbox.
fn copy_sandbox_entry_to_other_sandbox<'a>(
    src_fs: &'a SandboxFsOps<'a>,
    src: String,
    dst_fs: &'a SandboxFsOps<'a>,
    dst: String,
    metadata: FsMetadata,
) -> BoxFuture<'a, anyhow::Result<()>> {
    Box::pin(async move {
        match metadata.kind {
            FsEntryKind::Directory => {
                dst_fs.mkdir(&dst).await?;
                set_guest_mode(dst_fs, &dst, metadata.mode, true).await?;

                for entry in src_fs.list(&src).await? {
                    let child_name = guest_basename(&entry.path)?;
                    let child_src = guest_join(&src, child_name);
                    let child_dst = guest_join(&dst, child_name);
                    let child_metadata = src_fs.stat_with_follow(&child_src, false).await?;
                    copy_sandbox_entry_to_other_sandbox(
                        src_fs,
                        child_src,
                        dst_fs,
                        child_dst,
                        child_metadata,
                    )
                    .await?;
                }
            }
            FsEntryKind::Symlink => {
                let target = src_fs.read_link(&src).await?;
                dst_fs.symlink(&target, &dst).await?;
            }
            FsEntryKind::File => {
                copy_sandbox_file_to_sandbox(src_fs, &src, dst_fs, &dst).await?;
                set_guest_mode(dst_fs, &dst, metadata.mode, true).await?;
            }
            FsEntryKind::Other => {
                anyhow::bail!("unsupported file type: {src}");
            }
        }

        Ok(())
    })
}

/// Copy a host file into a sandbox using streaming I/O.
async fn copy_local_file_to_sandbox(
    fs: &SandboxFsOps<'_>,
    src: &Path,
    dst: &str,
) -> anyhow::Result<()> {
    let mut file = tokio::fs::File::open(src)
        .await
        .with_context(|| format!("open {}", src.display()))?;
    let sink = fs.write_stream(dst).await?;
    let mut buf = vec![0u8; microsandbox_protocol::fs::FS_CHUNK_SIZE];

    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        sink.write(&buf[..n]).await?;
    }

    sink.close().await?;
    Ok(())
}

/// Copy a sandbox file beneath a pinned Unix root using streaming I/O.
#[cfg(unix)]
async fn copy_sandbox_file_to_local_unix(
    fs: &SandboxFsOps<'_>,
    src: &str,
    root: &host::CopyRoot,
    dst: &Path,
    mode: u32,
) -> anyhow::Result<()> {
    let mut stream = fs.read_stream(src).await?;
    let mut pending = root.create_file(dst)?;

    while let Some(chunk) = stream.recv().await? {
        pending.file_mut().write_all(&chunk).await?;
    }

    pending.commit(mode).await?;
    Ok(())
}

/// Copy a sandbox file to a Windows host using streaming I/O.
#[cfg(windows)]
async fn copy_sandbox_file_to_local_windows(
    fs: &SandboxFsOps<'_>,
    src: &str,
    root: &host::CopyRoot,
    dst: &Path,
    mode: u32,
) -> anyhow::Result<()> {
    let mut stream = fs.read_stream(src).await?;
    let mut pending = root.create_file(dst)?;

    while let Some(chunk) = stream.recv().await? {
        pending.file_mut().write_all(&chunk).await?;
    }

    pending.commit(mode).await?;
    Ok(())
}

/// Copy a sandbox file into another sandbox using streaming I/O.
async fn copy_sandbox_file_to_sandbox(
    src_fs: &SandboxFsOps<'_>,
    src: &str,
    dst_fs: &SandboxFsOps<'_>,
    dst: &str,
) -> anyhow::Result<()> {
    let mut stream = src_fs.read_stream(src).await?;
    let sink = dst_fs.write_stream(dst).await?;

    while let Some(chunk) = stream.recv().await? {
        sink.write(&chunk).await?;
    }

    sink.close().await?;
    Ok(())
}

/// Resolve a sandbox destination using cp-style "existing directory means copy into it" behavior.
async fn sandbox_destination(
    fs: &SandboxFsOps<'_>,
    dst: &str,
    basename: &str,
) -> anyhow::Result<String> {
    if dst.ends_with('/') {
        return Ok(guest_join(dst, basename));
    }

    match fs.stat_with_follow(dst, false).await {
        Ok(metadata) if metadata.kind == FsEntryKind::Directory => Ok(guest_join(dst, basename)),
        _ => Ok(dst.to_string()),
    }
}

/// Resolve a local destination using cp-style "existing directory means copy into it" behavior.
async fn local_destination(dst: &Path, basename: &str) -> anyhow::Result<PathBuf> {
    match tokio::fs::symlink_metadata(dst).await {
        Ok(metadata) if metadata.is_dir() => Ok(dst.join(basename)),
        _ => Ok(dst.to_path_buf()),
    }
}

/// Set guest permission bits.
async fn set_guest_mode(
    fs: &SandboxFsOps<'_>,
    path: &str,
    mode: u32,
    follow_symlink: bool,
) -> anyhow::Result<()> {
    fs.set_stat(
        path,
        follow_symlink,
        FsSetAttrs {
            mode: Some(permission_bits(mode)),
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}

/// Keep only Unix permission bits from a mode value.
fn permission_bits(mode: u32) -> u32 {
    mode & 0o7777
}

/// Returns true when an endpoint explicitly looks like a host path.
fn is_explicit_local_path(value: &str) -> bool {
    microsandbox_utils::looks_like_local_path_text(value) || Path::new(value).is_absolute()
}

#[cfg(unix)]
fn local_mode(metadata: &std::fs::Metadata) -> u32 {
    metadata.permissions().mode()
}

#[cfg(windows)]
fn local_mode(metadata: &std::fs::Metadata) -> u32 {
    match (metadata.is_dir(), metadata.permissions().readonly()) {
        (true, true) => 0o555,
        (true, false) => 0o755,
        (false, true) => 0o444,
        (false, false) => 0o644,
    }
}

/// Return the final path component of a local path.
fn local_basename(path: &Path) -> anyhow::Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("cannot infer basename for {}", path.display()))
}

/// Return the final path component of a guest path.
fn guest_basename(path: &str) -> anyhow::Result<&str> {
    let name = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("cannot infer basename for {path}"))?;

    if matches!(name, "." | "..") || name.as_bytes().contains(&0) {
        anyhow::bail!("invalid guest path component `{name}`");
    }
    #[cfg(windows)]
    if !is_valid_windows_file_name(name) {
        anyhow::bail!("guest path component `{name}` is not a valid Windows file name");
    }

    Ok(name)
}

/// Return whether a guest component can be represented as a conventional Windows file name.
#[cfg(any(windows, test))]
fn is_valid_windows_file_name(name: &str) -> bool {
    if name
        .chars()
        .any(|character| character < ' ' || r#"<>:"\|?*"#.contains(character))
        || name.ends_with([' ', '.'])
    {
        return false;
    }

    let stem = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "COM¹"
            | "COM²"
            | "COM³"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "LPT¹"
            | "LPT²"
            | "LPT³"
    )
}

/// Join a guest parent path and child name.
fn guest_join(parent: &str, child: &str) -> String {
    if parent == "/" {
        format!("/{child}")
    } else if parent.ends_with('/') {
        format!("{parent}{child}")
    } else {
        format!("{parent}/{child}")
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sandbox_endpoint() {
        match Endpoint::parse("app:/tmp/file").unwrap() {
            Endpoint::Sandbox { name, path } => {
                assert_eq!(name, "app");
                assert_eq!(path, "/tmp/file");
            }
            other => panic!("expected sandbox endpoint, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_ambiguous_colon_endpoint() {
        let err = Endpoint::parse("file:name").unwrap_err();
        assert!(err.to_string().contains("ambiguous copy endpoint"));
    }

    #[test]
    fn parse_explicit_relative_colon_path_as_local() {
        match Endpoint::parse("./file:name").unwrap() {
            Endpoint::Local(path) => assert_eq!(path, PathBuf::from("./file:name")),
            other => panic!("expected local endpoint, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn parse_windows_drive_path_as_local() {
        match Endpoint::parse(r"C:\Users\Stephen\file.txt").unwrap() {
            Endpoint::Local(path) => assert_eq!(path, PathBuf::from(r"C:\Users\Stephen\file.txt")),
            other => panic!("expected local endpoint, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn relative_target_within_tree_resolves_under_root() {
        let dst = PathBuf::from("sub/link");
        let resolved = confine_symlink_target(&dst, "../file.txt").unwrap();
        assert_eq!(resolved, PathBuf::from("../file.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn relative_target_at_top_level_resolves_under_root() {
        let dst = PathBuf::from("link");
        let resolved = confine_symlink_target(&dst, "file.txt").unwrap();
        assert_eq!(resolved, PathBuf::from("file.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn absolute_guest_target_is_rerooted_under_destination() {
        // A guest-reported absolute path must never be honored as a real
        // host-absolute path; it is re-anchored at the copy root instead.
        let dst = PathBuf::from("link");
        let resolved = confine_symlink_target(&dst, "/Users/victim/.ssh/authorized_keys").unwrap();
        assert_eq!(resolved, PathBuf::from("Users/victim/.ssh/authorized_keys"));
    }

    #[cfg(unix)]
    #[test]
    fn absolute_guest_target_in_nested_directory_is_link_relative() {
        let dst = PathBuf::from("sub/link");
        let resolved = confine_symlink_target(&dst, "/etc/passwd").unwrap();
        assert_eq!(resolved, PathBuf::from("../etc/passwd"));
    }

    #[cfg(unix)]
    #[test]
    fn dotdot_traversal_escaping_root_is_rejected() {
        let dst = PathBuf::from("link");
        let err = confine_symlink_target(&dst, "../../../../etc/passwd").unwrap_err();
        assert!(err.to_string().contains("escapes the copy destination"));
    }

    #[cfg(unix)]
    #[test]
    fn dotdot_traversal_from_nested_dir_that_stays_within_root_is_allowed() {
        let dst = PathBuf::from("a/b/link");
        let resolved = confine_symlink_target(&dst, "../../sibling.txt").unwrap();
        assert_eq!(resolved, PathBuf::from("../../sibling.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn dotdot_traversal_from_nested_dir_that_exactly_escapes_root_is_rejected() {
        let dst = PathBuf::from("a/link");
        // Two levels up from `a/` is above the copy root.
        let err = confine_symlink_target(&dst, "../../outside.txt").unwrap_err();
        assert!(err.to_string().contains("escapes the copy destination"));
    }

    #[cfg(unix)]
    #[test]
    fn oversized_symlink_target_is_rejected_before_component_parsing() {
        let target = "a/".repeat(MAX_COPY_SYMLINK_TARGET_BYTES);
        let err = confine_symlink_target(Path::new("link"), &target).unwrap_err();
        assert!(err.to_string().contains("maximum"));
    }

    #[test]
    fn guest_basename_rejects_dot_components() {
        assert!(guest_basename("/out/.").is_err());
        assert!(guest_basename("/out/..").is_err());
    }

    #[test]
    fn windows_file_name_validation_rejects_reparse_sensitive_names() {
        assert!(is_valid_windows_file_name("ordinary.txt"));
        assert!(!is_valid_windows_file_name("payload:stream"));
        assert!(!is_valid_windows_file_name("..\\escape"));
        assert!(!is_valid_windows_file_name("CON.txt"));
        assert!(!is_valid_windows_file_name("LPT¹.log"));
        assert!(!is_valid_windows_file_name("trailing."));
    }
}
