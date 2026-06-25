//! `msb copy` command — copy files between the host and a sandbox.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::Args;
use futures::future::BoxFuture;
use microsandbox::sandbox::{FsEntryKind, FsMetadata, FsSetAttrs, SandboxFs};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
async fn copy_local_to_sandbox(fs: &SandboxFs<'_>, src: &Path, dst: &str) -> anyhow::Result<()> {
    let metadata = tokio::fs::symlink_metadata(src)
        .await
        .with_context(|| format!("stat {}", src.display()))?;
    let basename = local_basename(src)?;
    let dst = sandbox_destination(fs, dst, basename).await?;
    copy_local_entry_to_sandbox(fs, src.to_path_buf(), dst, metadata).await
}

/// Copy a sandbox path to the host.
async fn copy_sandbox_to_local(fs: &SandboxFs<'_>, src: &str, dst: &Path) -> anyhow::Result<()> {
    let metadata = fs
        .stat_with_follow(src, false)
        .await
        .with_context(|| format!("stat {src}"))?;
    let basename = guest_basename(src)?;
    let dst = local_destination(dst, basename).await?;
    copy_sandbox_entry_to_local(fs, src.to_string(), dst, metadata).await
}

/// Copy a sandbox path within the same sandbox.
async fn copy_sandbox_to_sandbox(fs: &SandboxFs<'_>, src: &str, dst: &str) -> anyhow::Result<()> {
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
    src_fs: &SandboxFs<'_>,
    src: &str,
    dst_fs: &SandboxFs<'_>,
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
    fs: &'a SandboxFs<'a>,
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

/// Recursively copy a sandbox entry to the host.
fn copy_sandbox_entry_to_local<'a>(
    fs: &'a SandboxFs<'a>,
    src: String,
    dst: PathBuf,
    metadata: FsMetadata,
) -> BoxFuture<'a, anyhow::Result<()>> {
    Box::pin(async move {
        match metadata.kind {
            FsEntryKind::Directory => {
                tokio::fs::create_dir_all(&dst)
                    .await
                    .with_context(|| format!("create directory {}", dst.display()))?;
                set_local_mode(&dst, metadata.mode).await?;

                for entry in fs.list(&src).await? {
                    let child_name = guest_basename(&entry.path)?;
                    let child_src = guest_join(&src, child_name);
                    let child_dst = dst.join(child_name);
                    let child_metadata = fs.stat_with_follow(&child_src, false).await?;
                    copy_sandbox_entry_to_local(fs, child_src, child_dst, child_metadata).await?;
                }
            }
            FsEntryKind::Symlink => {
                let target = fs.read_link(&src).await?;
                #[cfg(unix)]
                std::os::unix::fs::symlink(&target, &dst)
                    .with_context(|| format!("symlink {} -> {target}", dst.display()))?;
                #[cfg(windows)]
                {
                    let _ = target;
                    anyhow::bail!(
                        "copying sandbox symlinks to the Windows host is not supported yet"
                    );
                }
            }
            FsEntryKind::File => {
                copy_sandbox_file_to_local(fs, &src, &dst).await?;
                set_local_mode(&dst, metadata.mode).await?;
            }
            FsEntryKind::Other => {
                anyhow::bail!("unsupported file type: {src}");
            }
        }

        Ok(())
    })
}

/// Recursively copy a sandbox entry within the same sandbox.
fn copy_sandbox_entry_to_sandbox<'a>(
    fs: &'a SandboxFs<'a>,
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
    src_fs: &'a SandboxFs<'a>,
    src: String,
    dst_fs: &'a SandboxFs<'a>,
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
    fs: &SandboxFs<'_>,
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

/// Copy a sandbox file to the host using streaming I/O.
async fn copy_sandbox_file_to_local(
    fs: &SandboxFs<'_>,
    src: &str,
    dst: &Path,
) -> anyhow::Result<()> {
    let mut stream = fs.read_stream(src).await?;
    let mut file = tokio::fs::File::create(dst)
        .await
        .with_context(|| format!("create {}", dst.display()))?;

    while let Some(chunk) = stream.recv().await? {
        file.write_all(&chunk).await?;
    }

    file.flush().await?;
    Ok(())
}

/// Copy a sandbox file into another sandbox using streaming I/O.
async fn copy_sandbox_file_to_sandbox(
    src_fs: &SandboxFs<'_>,
    src: &str,
    dst_fs: &SandboxFs<'_>,
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
    fs: &SandboxFs<'_>,
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
    fs: &SandboxFs<'_>,
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

/// Set local permission bits.
async fn set_local_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(permission_bits(mode)))
            .await
            .with_context(|| format!("chmod {}", path.display()))?;
    }
    #[cfg(windows)]
    {
        let mut permissions = tokio::fs::metadata(path)
            .await
            .with_context(|| format!("stat {}", path.display()))?
            .permissions();
        permissions.set_readonly(permission_bits(mode) & 0o222 == 0);
        tokio::fs::set_permissions(path, permissions)
            .await
            .with_context(|| format!("set readonly bit on {}", path.display()))?;
    }
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
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("cannot infer basename for {path}"))
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
}
