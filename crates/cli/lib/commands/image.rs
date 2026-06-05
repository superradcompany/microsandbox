//! `msb image` command — manage OCI images.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::Instant;

use clap::{Args, Subcommand, ValueEnum};
use console::style;
use microsandbox::image::Image;
use microsandbox_image::{
    CachedImageMetadata, ImageArchiveFormat, ImageLoadOptions, ImageSaveConfig, ImageSaveLayer,
    ImageSaveRequest, Registry,
};

use crate::ui;

use super::pull;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Manage OCI images.
#[derive(Debug, Args)]
pub struct ImageArgs {
    /// Image subcommand.
    #[command(subcommand)]
    pub command: ImageCommands,
}

/// Image subcommands.
#[derive(Debug, Subcommand)]
pub enum ImageCommands {
    /// Download an image from a container registry.
    Pull(pull::PullArgs),

    /// List locally cached images.
    #[command(visible_alias = "ls")]
    List(ImageListArgs),

    /// Show detailed image information.
    Inspect(ImageInspectArgs),

    /// Load an image archive from tar.
    Load(ImageLoadArgs),

    /// Save one or more cached images to a tar archive.
    Save(ImageSaveArgs),

    /// Delete one or more cached images.
    #[command(visible_alias = "rm")]
    Remove(ImageRemoveArgs),

    /// Remove cached images not used by sandboxes.
    Prune(ImagePruneArgs),
}

/// Arguments for `msb image list`.
#[derive(Debug, Args)]
pub struct ImageListArgs {
    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,

    /// Show only image references.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Arguments for `msb image inspect`.
#[derive(Debug, Args)]
pub struct ImageInspectArgs {
    /// Image to inspect (e.g. python).
    pub reference: String,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,
}

/// Arguments for `msb image load`.
#[derive(Debug, Args)]
pub struct ImageLoadArgs {
    /// Read archive from a tar file instead of stdin.
    #[arg(short, long, value_name = "PATH")]
    pub input: Option<PathBuf>,

    /// Add a local image reference to the first imported image.
    #[arg(short, long, value_name = "REF")]
    pub tag: Vec<String>,

    /// Suppress output.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Arguments for `msb image save`.
#[derive(Debug, Args)]
pub struct ImageSaveArgs {
    /// Image reference(s) to save.
    #[arg(required = true)]
    pub references: Vec<String>,

    /// Archive format to write.
    #[arg(long, value_enum, default_value = "docker")]
    pub format: ImageSaveFormat,

    /// Write archive to a tar file instead of stdout.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Suppress output.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Archive format for `msb image save`.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ImageSaveFormat {
    /// Docker `docker save` compatible archive.
    Docker,
    /// OCI Image Layout archive.
    Oci,
}

/// Arguments for `msb image remove`.
#[derive(Debug, Args)]
pub struct ImageRemoveArgs {
    /// Image(s) to remove.
    #[arg(required = true)]
    pub references: Vec<String>,

    /// Remove even if the image is used by existing sandboxes.
    #[arg(short, long)]
    pub force: bool,

    /// Suppress output.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Arguments for `msb image prune`.
#[derive(Debug, Args)]
pub struct ImagePruneArgs {
    /// Do not prompt for confirmation.
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,

    /// Suppress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb image` command.
pub async fn run(args: ImageArgs) -> anyhow::Result<()> {
    match args.command {
        ImageCommands::Pull(args) => {
            run_pull_inner(
                args.reference,
                args.force,
                args.quiet,
                args.insecure,
                args.ca_certs,
                microsandbox_image::PullPolicy::IfMissing,
            )
            .await
        }
        ImageCommands::List(args) => run_list(args).await,
        ImageCommands::Inspect(args) => run_inspect(args).await,
        ImageCommands::Load(args) => run_load(args).await,
        ImageCommands::Save(args) => run_save(args).await,
        ImageCommands::Remove(args) => run_remove(args).await,
        ImageCommands::Prune(args) => run_prune(args).await,
    }
}

/// Execute `msb pull` (top-level alias).
pub async fn run_pull(args: pull::PullArgs) -> anyhow::Result<()> {
    run_pull_inner(
        args.reference,
        args.force,
        args.quiet,
        args.insecure,
        args.ca_certs,
        microsandbox_image::PullPolicy::IfMissing,
    )
    .await
}

/// Shared pull logic with DB persistence.
async fn run_pull_inner(
    reference: String,
    force: bool,
    quiet: bool,
    insecure: bool,
    cli_ca_certs: Option<String>,
    pull_policy: microsandbox_image::PullPolicy,
) -> anyhow::Result<()> {
    let start = Instant::now();

    let global = microsandbox::config::config();
    let cache = microsandbox_image::GlobalCache::new(&global.cache_dir())?;
    let platform = microsandbox_image::Platform::host_linux();
    let image_ref: microsandbox_image::Reference = reference
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid image reference: {e}"))?;

    let options = microsandbox_image::PullOptions { pull_policy, force };

    if let Some((result, metadata)) =
        microsandbox_image::Registry::pull_cached(&cache, &image_ref, &options)?
    {
        if let Err(e) = Image::persist(&reference, metadata).await {
            tracing::warn!(error = %e, "failed to persist image metadata to database");
        }

        if !quiet {
            eprintln!(
                "   {} {:<12} {}{}",
                style("✓").green(),
                "Pulled",
                reference,
                style(" (already cached)").dim()
            );
        }

        debug_assert!(result.cached);
        return Ok(());
    }

    let (progress, sender) = microsandbox_image::progress_channel();
    let display_reference = reference.clone();
    let (display_ready_tx, display_ready_rx) = mpsc::sync_channel(1);
    let display_thread = std::thread::spawn(move || -> anyhow::Result<()> {
        let mut display = if quiet {
            ui::PullProgressDisplay::quiet(&display_reference)
        } else {
            ui::PullProgressDisplay::new(&display_reference)
        };

        display.handle_event(microsandbox_image::PullProgress::Resolving {
            reference: Arc::<str>::from(display_reference.clone()),
        });

        let _ = display_ready_tx.send(());

        let mut receiver = progress.into_receiver();
        while let Some(event) = receiver.blocking_recv() {
            display.handle_event(event);
        }

        display.finish();
        Ok(())
    });

    let _ = display_ready_rx.recv();

    let auth = global.resolve_registry_auth(image_ref.registry())?;
    let mut ca_certs = global.resolve_ca_certs().await?;
    if let Some(path) = &cli_ca_certs {
        let data = tokio::fs::read(path)
            .await
            .map_err(|e| anyhow::anyhow!("failed to read CA certs from `{path}`: {e}"))?;
        ca_certs.push(data);
    }
    let mut insecure_registries = global.insecure_registries();
    if insecure {
        insecure_registries.push(image_ref.registry().to_string());
    }
    let registry = Registry::builder(platform, cache)
        .auth(auth)
        .extra_ca_certs(ca_certs)
        .add_insecure_registries(insecure_registries)
        .build()?;

    let task = registry.pull_with_sender(&image_ref, &options, sender);

    let result = match task.await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            let _ = display_thread.join();
            pull_failure_line(quiet, &reference);
            return Err(e.into());
        }
        Err(e) => {
            let _ = display_thread.join();
            pull_failure_line(quiet, &reference);
            return Err(anyhow::anyhow!("pull task panicked: {e}"));
        }
    };

    match display_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "failed to render pull progress");
        }
        Err(_) => {
            tracing::warn!("pull progress thread panicked");
        }
    }

    // Persist to database.
    let cache = microsandbox_image::GlobalCache::new(&global.cache_dir())?;
    match cache.read_image_metadata(&image_ref) {
        Ok(Some(metadata)) => {
            if let Err(e) = Image::persist(&reference, metadata).await {
                tracing::warn!(error = %e, "failed to persist image metadata to database");
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, "failed to read cached image metadata");
        }
    }

    if !quiet {
        let suffix = if result.cached {
            " (already cached)".to_string()
        } else {
            let elapsed = start.elapsed();
            if elapsed.as_millis() > 500 {
                format!(
                    " ({})",
                    microsandbox_utils::format::format_duration(elapsed)
                )
            } else {
                String::new()
            }
        };

        eprintln!(
            "   {} {:<12} {}{}",
            style("✓").green(),
            "Pulled",
            reference,
            style(suffix).dim()
        );
    }

    Ok(())
}

/// Pull an image if not already cached.
///
/// Used as a pre-flight check (e.g. before starting an OCI-backed sandbox).
/// When everything is cached, returns silently — no "already cached" line is
/// printed, because the caller already has its own UI (e.g. the Starting
/// spinner in `resolve_and_start`). Only falls through to the full pull UI
/// when there's actual work to do.
pub(crate) async fn pull_if_missing(reference: &str, quiet: bool) -> anyhow::Result<()> {
    // Local paths (directories, disk images) are not pullable.
    if reference.starts_with('.') || reference.starts_with('/') {
        return Ok(());
    }

    let global = microsandbox::config::config();
    let cache = microsandbox_image::GlobalCache::new(&global.cache_dir())?;
    let image_ref: microsandbox_image::Reference = reference
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid image reference: {e}"))?;
    let options = microsandbox_image::PullOptions {
        pull_policy: microsandbox_image::PullPolicy::IfMissing,
        force: false,
    };

    if let Some((_, metadata)) =
        microsandbox_image::Registry::pull_cached(&cache, &image_ref, &options)?
    {
        if let Err(e) = Image::persist(reference, metadata).await {
            tracing::warn!(error = %e, "failed to persist image metadata to database");
        }
        return Ok(());
    }

    run_pull_inner(
        reference.to_string(),
        false,
        quiet,
        false,
        None,
        microsandbox_image::PullPolicy::IfMissing,
    )
    .await
}

/// Execute `msb image list` / `msb images`.
pub async fn run_list(args: ImageListArgs) -> anyhow::Result<()> {
    let images = Image::list().await?;

    if args.format.as_deref() == Some("json") {
        let entries: Vec<serde_json::Value> = images
            .iter()
            .map(|img| {
                serde_json::json!({
                    "reference": img.reference(),
                    "digest": img.manifest_digest(),
                    "size_bytes": img.size_bytes(),
                    "architecture": img.architecture(),
                    "os": img.os(),
                    "layer_count": img.layer_count(),
                    "created_at": img.created_at().map(|dt| ui::format_json_datetime(&dt)),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if args.quiet {
        for img in &images {
            println!("{}", img.reference());
        }
        return Ok(());
    }

    if images.is_empty() {
        eprintln!("No images found.");
        return Ok(());
    }

    let mut table = ui::Table::new(&["REFERENCE", "DIGEST", "SIZE", "CREATED"]);

    for img in &images {
        let digest = img
            .manifest_digest()
            .map(truncate_digest)
            .unwrap_or_else(|| "-".to_string());
        let size = img
            .size_bytes()
            .map(format_bytes)
            .unwrap_or_else(|| "-".to_string());
        let created = img
            .created_at()
            .as_ref()
            .map(ui::format_datetime)
            .unwrap_or_else(|| "-".to_string());

        table.add_row(vec![img.reference().to_string(), digest, size, created]);
    }

    table.print();
    Ok(())
}

/// Execute `msb image inspect`.
pub async fn run_inspect(args: ImageInspectArgs) -> anyhow::Result<()> {
    let detail = Image::inspect(&args.reference).await?;

    if args.format.as_deref() == Some("json") {
        let layers_json: Vec<serde_json::Value> = detail
            .layers
            .iter()
            .map(|l| {
                serde_json::json!({
                    "diff_id": l.diff_id,
                    "blob_digest": l.blob_digest,
                    "media_type": l.media_type,
                    "compressed_size_bytes": l.compressed_size_bytes,
                    "erofs_size_bytes": l.erofs_size_bytes,
                    "position": l.position,
                })
            })
            .collect();

        let config_json = detail.config.as_ref().map(|c| {
            serde_json::json!({
                "digest": c.digest,
                "env": c.env,
                "cmd": c.cmd,
                "entrypoint": c.entrypoint,
                "working_dir": c.working_dir,
                "user": c.user,
                "labels": c.labels,
                "stop_signal": c.stop_signal,
            })
        });

        let json = serde_json::json!({
            "reference": detail.handle.reference(),
            "digest": detail.handle.manifest_digest(),
            "size_bytes": detail.handle.size_bytes(),
            "architecture": detail.handle.architecture(),
            "os": detail.handle.os(),
            "layer_count": detail.handle.layer_count(),
            "created_at": detail.handle.created_at().map(|dt| ui::format_json_datetime(&dt)),
            "config": config_json,
            "layers": layers_json,
        });

        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    // Default detail view.
    let h = &detail.handle;

    ui::detail_kv("Reference", h.reference());
    ui::detail_kv("Digest", h.manifest_digest().unwrap_or("-"));
    ui::detail_kv("Architecture", h.architecture().unwrap_or("-"));
    ui::detail_kv("OS", h.os().unwrap_or("-"));
    ui::detail_kv(
        "Size",
        &h.size_bytes()
            .map(format_bytes)
            .unwrap_or_else(|| "-".to_string()),
    );
    ui::detail_kv(
        "Created",
        &h.created_at()
            .as_ref()
            .map(ui::format_datetime)
            .unwrap_or_else(|| "-".to_string()),
    );

    if let Some(config) = &detail.config {
        ui::detail_header("Config");

        ui::detail_kv_indent(
            "Entrypoint",
            &config
                .entrypoint
                .as_ref()
                .map(|v| v.join(" "))
                .unwrap_or_else(|| "-".to_string()),
        );
        ui::detail_kv_indent(
            "Cmd",
            &config
                .cmd
                .as_ref()
                .map(|v| v.join(" "))
                .unwrap_or_else(|| "-".to_string()),
        );
        ui::detail_kv_indent("WorkingDir", config.working_dir.as_deref().unwrap_or("-"));
        ui::detail_kv_indent("User", config.user.as_deref().unwrap_or("-"));

        if !config.env.is_empty() {
            println!("  {}", style("Env:").dim());
            for var in &config.env {
                println!("    {var}");
            }
        }
    }

    if !detail.layers.is_empty() {
        ui::detail_header(&format!("Layers ({})", detail.layers.len()));
        for layer in &detail.layers {
            let size = layer
                .compressed_size_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "-".to_string());
            let media = layer.media_type.as_deref().unwrap_or("-");
            let short_digest = truncate_digest(&layer.blob_digest);
            println!(
                "  {:<4}{:<16}{:<10}{}",
                layer.position + 1,
                short_digest,
                size,
                media
            );
        }
    }

    Ok(())
}

/// Execute `msb image load` / `msb load`.
pub async fn run_load(args: ImageLoadArgs) -> anyhow::Result<()> {
    let global = microsandbox::config::config();
    let cache_dir = global.cache_dir();
    let temp_input;
    let input_path = if let Some(path) = args.input.as_ref() {
        path
    } else {
        temp_input = tempfile::NamedTempFile::new()?;
        let mut input = io::stdin().lock();
        let mut output = temp_input.reopen()?;
        io::copy(&mut input, &mut output)?;
        output.flush()?;
        temp_input.path()
    };

    let loaded = microsandbox_image::load_archive(
        &cache_dir,
        input_path,
        ImageLoadOptions {
            tags: args.tag.clone(),
        },
    )
    .await?;

    for image in &loaded {
        Image::persist(&image.reference, image.metadata.clone()).await?;
    }

    if !args.quiet {
        for image in &loaded {
            eprintln!(
                "   {} {:<12} {}",
                style("✓").green(),
                "Loaded",
                image.reference
            );
        }
    }

    Ok(())
}

/// Execute `msb image save` / `msb save`.
pub async fn run_save(args: ImageSaveArgs) -> anyhow::Result<()> {
    let global = microsandbox::config::config();
    let cache_dir = global.cache_dir();
    let cache = microsandbox_image::GlobalCache::new(&cache_dir)?;
    let mut requests = Vec::with_capacity(args.references.len());

    for reference in &args.references {
        let parsed: microsandbox_image::Reference = reference.parse()?;
        let metadata = cache
            .read_image_metadata(&parsed)?
            .ok_or_else(|| anyhow::anyhow!("image metadata not cached: {reference}"))?;
        let config = save_config_from_metadata(&metadata);
        let layers = metadata
            .layers
            .iter()
            .map(|layer| ImageSaveLayer {
                diff_id: layer.diff_id.clone(),
            })
            .collect();

        requests.push(ImageSaveRequest {
            reference: reference.clone(),
            config,
            raw_config_json: metadata.raw_config_json,
            layers,
        });
    }

    let temp_output;
    let output_path = if let Some(path) = args.output.as_ref() {
        path
    } else {
        temp_output = tempfile::NamedTempFile::new()?;
        temp_output.path()
    };
    let output_path_for_task = output_path.to_path_buf();
    let format = match args.format {
        ImageSaveFormat::Docker => ImageArchiveFormat::Docker,
        ImageSaveFormat::Oci => ImageArchiveFormat::Oci,
    };

    tokio::task::spawn_blocking(move || {
        let cache = microsandbox_image::GlobalCache::new(&cache_dir)?;
        microsandbox_image::save_archive(&cache, &output_path_for_task, &requests, format)
    })
    .await
    .map_err(|e| anyhow::anyhow!("save task panicked: {e}"))??;

    if args.output.is_none() {
        let mut file = std::fs::File::open(output_path)?;
        let mut stdout = io::stdout().lock();
        io::copy(&mut file, &mut stdout)?;
        stdout.flush()?;
    } else if !args.quiet {
        eprintln!(
            "   {} {:<12} {}",
            style("✓").green(),
            "Saved",
            output_path.display()
        );
    }

    Ok(())
}

/// Execute `msb image rm` / `msb rmi`.
pub async fn run_remove(args: ImageRemoveArgs) -> anyhow::Result<()> {
    let mut failed = false;

    for reference in &args.references {
        let spinner = if args.quiet {
            ui::Spinner::quiet()
        } else {
            ui::Spinner::start("Removing", reference)
        };

        match Image::remove(reference, args.force).await {
            Ok(()) => {
                spinner.finish_success("Removed");
            }
            Err(e) => {
                spinner.finish_clear();
                if !args.quiet {
                    ui::error(&format!("{e}"));
                }
                failed = true;
            }
        }
    }

    if failed {
        anyhow::bail!("some images failed to remove");
    }

    Ok(())
}

/// Execute `msb image prune`.
pub async fn run_prune(args: ImagePruneArgs) -> anyhow::Result<()> {
    if !args.yes {
        if !io::stdin().is_terminal() {
            anyhow::bail!("non-interactive terminal; use --yes to prune cached images");
        }

        eprint!("Remove all cached images not used by sandboxes? [y/N] ");
        io::stderr().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            if !args.quiet {
                eprintln!("Aborted.");
            }
            return Ok(());
        }
    }

    let report = Image::prune().await?;

    if args.format.as_deref() == Some("json") {
        let json = serde_json::json!({
            "image_refs_removed": report.image_refs_removed,
            "manifests_removed": report.manifests_removed,
            "layers_removed": report.layers_removed,
            "fsmeta_removed": report.fsmeta_removed,
            "vmdk_removed": report.vmdk_removed,
            "bytes_reclaimed": report.bytes_reclaimed,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    if args.quiet {
        return Ok(());
    }

    if report.image_refs_removed == 0
        && report.manifests_removed == 0
        && report.layers_removed == 0
        && report.fsmeta_removed == 0
        && report.vmdk_removed == 0
    {
        eprintln!("Nothing to prune.");
        return Ok(());
    }

    ui::success("Pruned", "image cache");
    ui::detail_kv_indent("Image refs", &report.image_refs_removed.to_string());
    ui::detail_kv_indent("Manifests", &report.manifests_removed.to_string());
    ui::detail_kv_indent("Layers", &report.layers_removed.to_string());

    if report.fsmeta_removed > 0 {
        ui::detail_kv_indent("Fsmeta", &report.fsmeta_removed.to_string());
    }

    if report.vmdk_removed > 0 {
        ui::detail_kv_indent("VMDK", &report.vmdk_removed.to_string());
    }

    if let Some(bytes) = report.bytes_reclaimed {
        ui::detail_kv_indent("Reclaimed", &format_bytes_u64(bytes));
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Format bytes as a human-readable string.
fn format_bytes(bytes: i64) -> String {
    microsandbox_utils::format::format_bytes(bytes.max(0) as u64)
}

/// Format bytes as a human-readable string.
fn format_bytes_u64(bytes: u64) -> String {
    microsandbox_utils::format::format_bytes(bytes)
}

/// Print the pull failure indicator line to stderr.
fn pull_failure_line(quiet: bool, reference: &str) {
    if !quiet {
        eprintln!("   {} {:<12} {}", style("✗").red(), "Pulling", reference);
    }
}

/// Truncate a digest to a short form (first 12 hex chars after algorithm prefix).
fn truncate_digest(digest: &str) -> String {
    if let Some(hex) = digest.strip_prefix("sha256:") {
        format!("sha256:{}", &hex[..hex.len().min(12)])
    } else {
        digest.chars().take(19).collect()
    }
}

fn save_config_from_metadata(metadata: &CachedImageMetadata) -> ImageSaveConfig {
    let (architecture, os) = raw_config_platform(&metadata.raw_config_json);

    ImageSaveConfig {
        architecture,
        os,
        env: metadata.config.env.clone(),
        entrypoint: metadata.config.entrypoint.clone(),
        cmd: metadata.config.cmd.clone(),
        working_dir: metadata.config.working_dir.clone(),
        user: metadata.config.user.clone(),
        labels: metadata
            .config
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    }
}

fn raw_config_platform(raw_config_json: &str) -> (Option<String>, Option<String>) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw_config_json) else {
        return (None, None);
    };

    let architecture = value
        .get("architecture")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    let os = value
        .get("os")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);

    (architecture, os)
}
