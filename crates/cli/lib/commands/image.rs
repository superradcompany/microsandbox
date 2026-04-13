//! `msb image` command — manage OCI images.

use std::sync::{Arc, mpsc};
use std::time::Instant;

use clap::{Args, Subcommand};
use console::style;
use microsandbox::image::Image;

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

    /// Delete one or more cached images.
    #[command(visible_alias = "rm")]
    Remove(ImageRemoveArgs),
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
                args.layer_mode.into(),
                args.quiet,
                microsandbox_image::PullPolicy::IfMissing,
            )
            .await
        }
        ImageCommands::List(args) => run_list(args).await,
        ImageCommands::Inspect(args) => run_inspect(args).await,
        ImageCommands::Remove(args) => run_remove(args).await,
    }
}

/// Execute `msb pull` (top-level alias).
pub async fn run_pull(args: pull::PullArgs) -> anyhow::Result<()> {
    run_pull_inner(
        args.reference,
        args.force,
        args.layer_mode.into(),
        args.quiet,
        microsandbox_image::PullPolicy::IfMissing,
    )
    .await
}

/// Shared pull logic with DB persistence.
async fn run_pull_inner(
    reference: String,
    force: bool,
    layer_mode: microsandbox_image::LayerMode,
    quiet: bool,
    pull_policy: microsandbox_image::PullPolicy,
) -> anyhow::Result<()> {
    let start = Instant::now();

    let global = microsandbox::config::config();
    let cache = microsandbox_image::GlobalCache::new(&global.cache_dir())?;
    let platform = microsandbox_image::Platform::host_linux();
    let image_ref: microsandbox_image::Reference = reference
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid image reference: {e}"))?;

    let options = microsandbox_image::PullOptions {
        pull_policy,
        force,
        layer_mode,
    };

    if let Some((result, metadata)) =
        microsandbox_image::Registry::pull_cached(&cache, &image_ref, &options)?
    {
        if let Err(e) = Image::persist(&reference, metadata, result.mode).await {
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

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build progress runtime: {e}"))?;

        let mut receiver = progress.into_receiver();
        let display = runtime.block_on(async move {
            while let Some(event) = receiver.recv().await {
                display.handle_event(event);
            }
            display
        });

        display.finish();
        Ok(())
    });

    let _ = display_ready_rx.recv();

    let auth = global.resolve_registry_auth(image_ref.registry())?;
    let registry = microsandbox_image::Registry::with_auth(platform, cache, auth)?;

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
            if let Err(e) = Image::persist(&reference, metadata, result.mode).await {
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
                format!(" ({})", ui::format_duration(elapsed))
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
/// Uses `PullPolicy::Missing` — skips the pull entirely when the image is
/// already in the local cache (no network call).  Returns `Ok(())` silently
/// if the reference is not a valid OCI image (e.g. a local directory path).
pub(crate) async fn pull_if_missing(reference: &str, quiet: bool) -> anyhow::Result<()> {
    // Local paths (directories, disk images) are not pullable.
    if reference.starts_with('.') || reference.starts_with('/') {
        return Ok(());
    }

    run_pull_inner(
        reference.to_string(),
        false,
        microsandbox_image::LayerMode::Layered,
        quiet,
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
                    "created_at": img.created_at().map(|dt| ui::format_datetime(&dt)),
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
            "created_at": detail.handle.created_at().map(|dt| ui::format_datetime(&dt)),
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
            println!("  {}", style("Env:").cyan());
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
                spinner.finish_error();
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

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Format bytes as a human-readable string.
fn format_bytes(bytes: i64) -> String {
    super::ui::format_bytes(bytes.max(0) as u64)
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
