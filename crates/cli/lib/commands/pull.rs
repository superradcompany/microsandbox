//! `msb pull` command — pull an image from a registry.

use std::time::Instant;

use clap::Args;
use console::style;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Pull an image from a registry.
#[derive(Debug, Args)]
pub struct PullArgs {
    /// Image reference (e.g., python:3.11, ubuntu:22.04).
    pub reference: String,

    /// Force re-download and re-extract even if cached.
    #[arg(short, long)]
    pub force: bool,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb pull` command.
pub async fn run(args: PullArgs) -> anyhow::Result<()> {
    let start = Instant::now();

    let global = microsandbox::config::config();
    let cache = microsandbox_image::GlobalCache::new(&global.cache_dir())?;
    let platform = microsandbox_image::Platform::host_linux();
    let image_ref: microsandbox_image::Reference = args
        .reference
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid image reference: {e}"))?;

    let auth = global.resolve_registry_auth(image_ref.registry())?;
    let registry = microsandbox_image::Registry::with_auth(platform, cache, auth)?;

    let options = microsandbox_image::PullOptions {
        pull_policy: microsandbox_image::PullPolicy::Always,
        force: args.force,
        ..Default::default()
    };

    let (mut progress, task) = registry.pull_with_progress(&image_ref, &options);

    let mut display = if args.quiet {
        ui::PullProgressDisplay::quiet(&args.reference)
    } else {
        ui::PullProgressDisplay::new(&args.reference)
    };

    while let Some(event) = progress.recv().await {
        display.handle_event(event);
    }

    let result = match task.await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            display.finish();
            if !args.quiet {
                eprintln!(
                    "   {} {:<12} {}",
                    style("✗").red(),
                    "Pulling",
                    args.reference
                );
            }
            return Err(e.into());
        }
        Err(e) => {
            display.finish();
            if !args.quiet {
                eprintln!(
                    "   {} {:<12} {}",
                    style("✗").red(),
                    "Pulling",
                    args.reference
                );
            }
            return Err(anyhow::anyhow!("pull task panicked: {e}"));
        }
    };

    display.finish();

    if !args.quiet {
        let elapsed = start.elapsed();
        let duration = if elapsed.as_millis() > 500 {
            format!(" ({})", ui::format_duration(elapsed))
        } else {
            String::new()
        };

        eprintln!(
            "   {} {:<12} {}{}",
            style("✓").green(),
            "Pulled",
            args.reference,
            style(duration).dim()
        );

        if result.cached {
            eprintln!("   (already cached)");
        }
    }

    Ok(())
}
