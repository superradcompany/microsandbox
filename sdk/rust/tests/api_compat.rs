#[test]
fn rust_root_compat_exports_stay_available() {
    // Compile-time tripwire for public root exports restored after the
    // backend-routing refactor. The function items are not invoked.
    let _ = microsandbox::Image::get;
    let _ = microsandbox::Image::list;
    let _ = microsandbox::Image::inspect;
    let _ = microsandbox::Image::remove;
    let _ = microsandbox::Image::prune;
    let _ = microsandbox::all_sandbox_metrics;

    let _: Option<microsandbox::ImagePruneReport> = None;
    let _: Option<microsandbox::SandboxMetrics> = None;
}

#[test]
fn rust_config_compat_surface_stays_available() {
    // Ambient local config access and method-style path resolution are the
    // public shape; explicit free functions taking `&LocalConfig` are not.
    let _ = microsandbox::config::config;
    let _ = microsandbox::config::resolve_msb_path;
    let _ = microsandbox::config::resolve_libkrunfw_path;
    let _ = microsandbox::config::LocalConfig::resolve_msb_path;
    let _ = microsandbox::config::LocalConfig::resolve_libkrunfw_path;
}

#[cfg(feature = "ssh")]
#[test]
fn rust_ssh_compat_export_stays_available() {
    let _: Option<microsandbox::SandboxSshOps> = None;
}

#[allow(dead_code)]
async fn rust_sandbox_fs_handle_api_stays_available(
    fs: &microsandbox::sandbox::SandboxFsOps<'_>,
    entry: microsandbox::sandbox::FsEntry,
    metadata: microsandbox::sandbox::FsMetadata,
) -> microsandbox::MicrosandboxResult<()> {
    use microsandbox::sandbox::{FsHandle, FsOpenOptions, FsSetAttrs};

    let _: Option<FsHandle> = None;
    let file = fs.open_file("/tmp/file", FsOpenOptions::default()).await?;
    let dir = fs.open_dir("/tmp").await?;

    let _ = fs.read_handle(file, 0, None).await?;
    let mut read_stream = fs.read_handle_stream(file, 0, Some(1)).await?;
    let _ = read_stream.recv().await?;

    fs.write_handle(file, 0, b"hello").await?;
    let write_stream = fs.write_handle_stream(file, 0, None).await?;
    write_stream.close().await?;

    let _ = fs.read_dir_handle(dir, None).await?;
    let _ = fs.read_dir(dir, None).await?;

    let _ = fs.stat_handle(file).await?;
    let _ = fs.fstat(file).await?;
    fs.set_stat_handle(file, FsSetAttrs::default()).await?;
    fs.fset_stat(file, FsSetAttrs::default()).await?;

    let _ = fs.real_path(".").await?;
    fs.remove_empty_dir("/tmp/empty").await?;
    fs.close_handle(file).await?;
    fs.close_handle(dir).await?;

    let _ = (entry.uid, entry.gid, entry.accessed);
    let _ = (metadata.uid, metadata.gid, metadata.accessed);

    Ok(())
}
