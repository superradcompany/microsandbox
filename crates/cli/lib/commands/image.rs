//! `msb image` command — manage OCI images.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::Instant;

use clap::{Args, Subcommand, ValueEnum};
use console::style;
use microsandbox::config::RegistryOptions;
use microsandbox::image::Image;
use microsandbox_image::{ImageArchiveFormat, ImageLoadOptions, Registry};

use crate::ui::{self, OutputFormat};

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
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub format: Option<OutputFormat>,

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
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub format: Option<OutputFormat>,
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

    /// Path to a file listing OCI image references to exclude from pruning (one per line).
    /// Can be specified multiple times.
    #[arg(long = "exclude-from", value_name = "PATH")]
    pub exclude_from: Vec<PathBuf>,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub format: Option<OutputFormat>,

    /// Suppress output.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Optional settings supplied by callers that need more than the normal pull defaults.
#[derive(Default)]
struct PullOverrides {
    materialization: Option<pull::PullMaterialization>,
    explicit_auth: Option<microsandbox_image::RegistryAuth>,
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
                PullOverrides {
                    materialization: args.materialize,
                    ..PullOverrides::default()
                },
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
        PullOverrides {
            materialization: args.materialize,
            ..PullOverrides::default()
        },
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
    pull_overrides: PullOverrides,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let PullOverrides {
        materialization,
        explicit_auth,
    } = pull_overrides;

    let backend = crate::commands::common::resolve_local_backend()?;
    let backend = crate::commands::common::local_backend_ref(&backend)?;
    let backend_config = backend.config();
    let oci_defaults = &backend_config.sandbox_defaults.oci;
    let materialization = resolve_pull_materialization(materialization, oci_defaults)?;
    let cache = microsandbox_image::GlobalCache::new(&backend.cache_dir())?.operation();
    let platform = microsandbox_image::Platform::host_linux();
    let image_ref: microsandbox_image::Reference = reference
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid image reference: {e}"))?;

    let options = microsandbox_image::PullOptions {
        pull_policy,
        force,
        materialization: materialization.image_materialization(),
    };

    let has_explicit_auth = explicit_auth
        .as_ref()
        .is_some_and(|auth| !matches!(auth, microsandbox_image::RegistryAuth::Anonymous));

    if !has_explicit_auth
        && let Some((result, metadata)) =
            microsandbox_image::Registry::pull_cached_async(&cache, &image_ref, &options).await?
    {
        Image::persist(backend, &reference, metadata).await?;

        if !quiet {
            ui::success(
                "Pulled",
                &format!("{reference}{}", style(" (already cached)").dim()),
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

    let registry_options = RegistryOptions {
        ca_cert_files: cli_ca_certs.into_iter().map(Into::into).collect(),
        auth: explicit_auth,
        insecure,
        ..Default::default()
    };
    let config = backend
        .registry_config(image_ref.registry(), registry_options)
        .await?;
    let registry = Registry::builder(platform, cache)
        .auth(config.auth)
        .extra_ca_certs(config.ca_certs)
        .add_insecure_registries(config.insecure_registries)
        .build()?;

    let pulled = registry
        .pull_with_metadata(&image_ref, &options, Some(sender))
        .await;
    let (result, metadata) = match pulled {
        Ok(pulled) => pulled,
        Err(error) => {
            let _ = display_thread.join();
            pull_failure_line(quiet, &reference);
            return Err(error.into());
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

    // Keep the image operation alive while indexing the exact admitted generation.
    Image::persist(backend, &reference, metadata).await?;

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

        ui::success("Pulled", &format!("{reference}{}", style(suffix).dim()));
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
pub(crate) async fn pull_if_missing(
    reference: &str,
    quiet: bool,
    materialization: pull::PullMaterialization,
) -> anyhow::Result<()> {
    pull_if_missing_with_auth(reference, quiet, materialization, None).await
}

/// Repair the immutable layered backing for a stopped local sandbox.
pub(crate) async fn repair_pinned_root(
    reference: &str,
    digest: &str,
    quiet: bool,
) -> anyhow::Result<()> {
    let backend = crate::commands::common::resolve_local_backend()?;
    let local = crate::commands::common::local_backend_ref(&backend)?;
    let cache = microsandbox_image::GlobalCache::new(&local.cache_dir())?.operation();
    let original: microsandbox_image::Reference = reference.parse()?;
    let manifest: microsandbox_image::Digest = digest.parse()?;
    let pinned = microsandbox_image::Reference::with_digest(
        original.registry().to_owned(),
        original.repository().to_owned(),
        digest.to_owned(),
    );
    cache
        .lease_paths_async(vec![cache.fsmeta_erofs_path(&manifest)])
        .await?;
    let mut found_pinned_metadata = false;
    for reference in [&pinned, &original] {
        if let Some(metadata) = cache.read_image_metadata_async(reference).await?
            && metadata.manifest_digest == digest
        {
            found_pinned_metadata = true;
            let diff_ids = metadata
                .layers
                .iter()
                .map(|layer| layer.diff_id.parse())
                .collect::<Result<Vec<_>, _>>()?;
            if cache.is_vmdk_complete_for_layers(&manifest, &diff_ids) {
                return Ok(());
            }
            if cache.is_fsmeta_materialized(&manifest) && cache.all_layers_materialized(&diff_ids) {
                cache.rewrite_vmdk_async(&manifest, &diff_ids).await?;
                return Ok(());
            }
        }
    }
    if !found_pinned_metadata && cache.is_vmdk_complete(&manifest) {
        return Ok(());
    }

    // Query the exact upstream manifest if any backing layer needs to be recovered.
    run_pull_inner(
        pinned.whole(),
        false,
        quiet,
        false,
        None,
        microsandbox_image::PullPolicy::Always,
        PullOverrides {
            materialization: Some(pull::PullMaterialization::Layered),
            explicit_auth: None,
        },
    )
    .await?;
    let metadata = cache
        .read_image_metadata_async(&pinned)
        .await?
        .ok_or_else(|| anyhow::anyhow!("pinned image metadata missing after pull: {pinned}"))?;
    anyhow::ensure!(
        metadata.manifest_digest == digest,
        "registry returned a different manifest for {pinned}"
    );
    let layers = metadata
        .layers
        .iter()
        .map(|layer| layer.diff_id.parse())
        .collect::<Result<Vec<_>, _>>()?;
    if !cache.is_vmdk_complete_for_layers(&manifest, &layers) {
        cache.rewrite_vmdk_async(&manifest, &layers).await?;
    }
    anyhow::ensure!(
        cache.is_vmdk_complete_for_layers(&manifest, &layers),
        "incomplete OCI backing for {pinned}"
    );
    Ok(())
}

/// Pull an image if missing, honoring an explicit per-sandbox registry credential.
pub(crate) async fn pull_if_missing_with_auth(
    reference: &str,
    quiet: bool,
    materialization: pull::PullMaterialization,
    explicit_auth: Option<microsandbox_image::RegistryAuth>,
) -> anyhow::Result<()> {
    // Local paths (directories, disk images) are not pullable.
    if reference.starts_with('.') || reference.starts_with('/') {
        return Ok(());
    }

    let backend = crate::commands::common::resolve_local_backend()?;
    let local = crate::commands::common::local_backend_ref(&backend)?;
    let cache = microsandbox_image::GlobalCache::new(&local.cache_dir())?.operation();
    let image_ref: microsandbox_image::Reference = reference
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid image reference: {e}"))?;
    let options = microsandbox_image::PullOptions {
        pull_policy: microsandbox_image::PullPolicy::IfMissing,
        force: false,
        materialization: materialization.image_materialization(),
    };

    let has_explicit_auth = explicit_auth
        .as_ref()
        .is_some_and(|auth| !matches!(auth, microsandbox_image::RegistryAuth::Anonymous));

    if !has_explicit_auth
        && let Some((_, metadata)) =
            microsandbox_image::Registry::pull_cached_async(&cache, &image_ref, &options).await?
    {
        Image::persist(local, reference, metadata).await?;
        return Ok(());
    }

    run_pull_inner(
        reference.to_string(),
        false,
        quiet,
        false,
        None,
        microsandbox_image::PullPolicy::IfMissing,
        PullOverrides {
            materialization: Some(materialization),
            explicit_auth,
        },
    )
    .await
}

/// Execute `msb image list` / `msb images`.
pub async fn run_list(args: ImageListArgs) -> anyhow::Result<()> {
    let backend = crate::commands::common::resolve_local_backend()?;
    let local = crate::commands::common::local_backend_ref(&backend)?;
    let images = Image::list_local(local).await?;

    if args.format == Some(OutputFormat::Json) {
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
    let backend = crate::commands::common::resolve_local_backend()?;
    let local = crate::commands::common::local_backend_ref(&backend)?;
    let detail = Image::inspect_local(local, &args.reference).await?;

    if args.format == Some(OutputFormat::Json) {
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
    let backend = crate::commands::common::resolve_local_backend()?;
    let local = crate::commands::common::local_backend_ref(&backend)?;
    let cache_dir = local.cache_dir();
    // Start the progress display before reading the archive, so a piped
    // `docker save | msb load` shows activity while stdin is consumed.
    let quiet = args.quiet;
    let label = args
        .tag
        .first()
        .cloned()
        .or_else(|| {
            args.input
                .as_ref()
                .and_then(|p| p.file_name())
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "archive".to_string());
    let (progress, sender) = microsandbox_image::progress_channel();
    let (display_ready_tx, display_ready_rx) = mpsc::sync_channel(1);
    let display_thread = std::thread::spawn(move || -> anyhow::Result<()> {
        let mut display = ui::PullProgressDisplay::load(&label, quiet);
        let _ = display_ready_tx.send(());
        let mut receiver = progress.into_receiver();
        while let Some(event) = receiver.blocking_recv() {
            display.handle_event(event);
        }
        display.finish();
        Ok(())
    });
    let _ = display_ready_rx.recv();

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

    let cache_operation = microsandbox_image::GlobalCache::new(&cache_dir)?;
    let loaded = microsandbox_image::load_archive_with(
        &cache_operation,
        input_path,
        ImageLoadOptions {
            tags: args.tag.clone(),
            progress: Some(sender),
        },
        |image| async move {
            Image::persist(local, &image.reference, image.metadata)
                .await
                .map(|_| ())
                .map_err(|error| microsandbox_image::ImageError::Io(std::io::Error::other(error)))
        },
    )
    .await;

    match display_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(error = %error, "failed to render load progress"),
        Err(_) => tracing::warn!("load progress thread panicked"),
    }
    let loaded = loaded?;

    if !args.quiet {
        for image in &loaded {
            ui::success("Loaded", &image.reference);
        }
    }

    Ok(())
}

/// Execute `msb image save` / `msb save`.
pub async fn run_save(args: ImageSaveArgs) -> anyhow::Result<()> {
    let backend = crate::commands::common::resolve_local_backend()?;
    let local = crate::commands::common::local_backend_ref(&backend)?;

    let temp_output;
    let output_path = if let Some(path) = args.output.as_ref() {
        path
    } else {
        temp_output = tempfile::NamedTempFile::new()?;
        temp_output.path()
    };
    let format = match args.format {
        ImageSaveFormat::Docker => ImageArchiveFormat::Docker,
        ImageSaveFormat::Oci => ImageArchiveFormat::Oci,
    };

    Image::save_local(local, &args.references, output_path, format).await?;

    if args.output.is_none() {
        let mut file = std::fs::File::open(output_path)?;
        let mut stdout = io::stdout().lock();
        io::copy(&mut file, &mut stdout)?;
        stdout.flush()?;
    } else if !args.quiet {
        ui::success("Saved", &output_path.display().to_string());
    }

    Ok(())
}

/// Execute `msb image rm` / `msb rmi`.
pub async fn run_remove(args: ImageRemoveArgs) -> anyhow::Result<()> {
    let backend = crate::commands::common::resolve_local_backend()?;
    let local = crate::commands::common::local_backend_ref(&backend)?;
    let mut failed = false;

    for reference in &args.references {
        let spinner = if args.quiet {
            ui::Spinner::quiet()
        } else {
            ui::Spinner::start("Removing", reference)
        };

        match Image::remove_local(local, reference, args.force).await {
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
    let excluded_refs = load_exclude_from_files(&args.exclude_from)?;
    let backend = crate::commands::common::resolve_local_backend()?;
    let local = crate::commands::common::local_backend_ref(&backend)?;

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

    let report = Image::prune_local_with_keep(local, &excluded_refs).await?;

    if args.format == Some(OutputFormat::Json) {
        let json = serde_json::json!({
            "image_refs_removed": report.image_refs_removed,
            "manifests_removed": report.manifests_removed,
            "layers_removed": report.layers_removed,
            "fsmeta_removed": report.fsmeta_removed,
            "vmdk_removed": report.vmdk_removed,
            "bytes_reclaimed": report.bytes_reclaimed,
            "skipped_in_use": report.skipped_in_use,
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
        if report.skipped_in_use > 0 {
            eprintln!(
                "Nothing pruned; {} cache entries are in use.",
                report.skipped_in_use
            );
        } else {
            eprintln!("Nothing to prune.");
        }
        return Ok(());
    }

    ui::success("Pruned", "image cache");
    ui::detail_kv_indent("Skipped", &format!("{} in use", report.skipped_in_use));
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
        ui::failure("Pulling", reference);
    }
}

fn resolve_pull_materialization(
    requested: Option<pull::PullMaterialization>,
    defaults: &microsandbox::config::OciSandboxDefaults,
) -> anyhow::Result<pull::PullMaterialization> {
    if defaults.upper_size_mib.is_some() && defaults.root_disk.is_some() {
        anyhow::bail!(
            "sandbox_defaults.oci.root_disk and deprecated sandbox_defaults.oci.upper_size_mib are mutually exclusive"
        );
    }
    if matches!(
        defaults.root_disk,
        Some(microsandbox::sandbox::RootDisk::DiskImage { .. })
    ) {
        anyhow::bail!(
            "sandbox_defaults.oci.root_disk cannot be a shared disk-image; specify user-owned disk images per sandbox"
        );
    }

    Ok(requested.unwrap_or({
        if matches!(
            defaults.root_disk,
            Some(microsandbox::sandbox::RootDisk::Flat { .. })
        ) {
            pull::PullMaterialization::Flat
        } else {
            pull::PullMaterialization::Layered
        }
    }))
}

/// Load and validate OCI image references from one or more `--exclude-from` files.
fn load_exclude_from_files(paths: &[PathBuf]) -> anyhow::Result<Vec<String>> {
    let mut excluded_refs = Vec::new();
    for path in paths {
        let content = std::fs::read_to_string(path).map_err(|error| {
            anyhow::anyhow!(
                "failed to read --exclude-from file '{}': {error}",
                path.display()
            )
        })?;
        excluded_refs.extend(parse_exclude_from_file(&content, path)?);
    }
    Ok(excluded_refs)
}

/// Parse a line-oriented `--exclude-from` file, ignoring blank lines and `#`
/// comments, and normalizing each entry with the OCI reference parser.
fn parse_exclude_from_file(content: &str, path: &Path) -> anyhow::Result<Vec<String>> {
    let mut refs = Vec::new();
    for (index, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parsed: microsandbox_image::Reference = line.parse().map_err(|error| {
            anyhow::anyhow!(
                "invalid image reference in --exclude-from file '{}' at line {}: '{}': {error}",
                path.display(),
                index + 1,
                line
            )
        })?;
        refs.push(parsed.to_string());
    }
    Ok(refs)
}

/// Truncate a digest to a short form (first 12 hex chars after algorithm prefix).
fn truncate_digest(digest: &str) -> String {
    if let Some(hex) = digest.strip_prefix("sha256:") {
        format!("sha256:{}", &hex[..hex.len().min(12)])
    } else {
        digest.chars().take(19).collect()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pull_materialization_inherits_flat_only_when_not_explicit() {
        let defaults = microsandbox::config::OciSandboxDefaults {
            upper_size_mib: None,
            root_disk: Some(microsandbox::sandbox::RootDisk::Flat {
                size_mib: Some(8192),
                fstype: None,
                clone: microsandbox::sandbox::FlatClone::Auto,
            }),
        };

        assert_eq!(
            resolve_pull_materialization(None, &defaults).unwrap(),
            pull::PullMaterialization::Flat
        );
        assert_eq!(
            resolve_pull_materialization(Some(pull::PullMaterialization::Layered), &defaults)
                .unwrap(),
            pull::PullMaterialization::Layered
        );
    }

    #[test]
    fn parse_exclude_from_file_ignores_blank_lines_comments_and_whitespace() {
        let content = "\
            # Pre-warmed images\n\
            \n\
               \t  \n\
              alpine:3.20  \n\
              # Indented comment\n\
            \tpython:3.12-slim\r\n\
            ghcr.io/microsandbox/node:22\n\
        ";

        let parsed = parse_exclude_from_file(content, Path::new("exclude.txt")).unwrap();

        assert_eq!(
            parsed,
            vec![
                "docker.io/library/alpine:3.20",
                "docker.io/library/python:3.12-slim",
                "ghcr.io/microsandbox/node:22",
            ]
        );
    }

    #[test]
    fn parse_exclude_from_file_rejects_invalid_reference_with_line_number() {
        let content = "alpine:3.20\n\nINVALID:::REF!!!\n";
        let err = parse_exclude_from_file(content, Path::new("exclude.txt")).unwrap_err();
        let message = err.to_string();

        assert!(message.contains("exclude.txt"), "{message}");
        assert!(message.contains("line 3"), "{message}");
    }

    #[test]
    fn load_exclude_from_files_fails_on_missing_or_unreadable_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.txt");

        let err = load_exclude_from_files(std::slice::from_ref(&missing)).unwrap_err();
        assert!(
            err.to_string()
                .contains("failed to read --exclude-from file")
        );

        let dir_err = load_exclude_from_files(&[dir.path().to_path_buf()]).unwrap_err();
        assert!(
            dir_err
                .to_string()
                .contains("failed to read --exclude-from file")
        );
    }

    #[test]
    fn load_exclude_from_files_combines_multiple_files() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.txt");
        let second = dir.path().join("second.txt");
        std::fs::write(&first, "alpine:3.20\n").unwrap();
        std::fs::write(&second, "python:3.12-slim\n").unwrap();

        let loaded = load_exclude_from_files(&[first, second]).unwrap();
        assert_eq!(
            loaded,
            vec![
                "docker.io/library/alpine:3.20",
                "docker.io/library/python:3.12-slim",
            ]
        );
    }
}
