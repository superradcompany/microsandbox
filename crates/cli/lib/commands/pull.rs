//! `msb pull` command — pull an image from a registry.

use clap::Args;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Pull an image from a registry.
#[derive(Debug, Args)]
pub struct PullArgs {
    /// Image reference (e.g., python:3.11, ubuntu:22.04).
    pub reference: String,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb pull` command.
pub async fn run(args: PullArgs) -> anyhow::Result<()> {
    let spinner = ui::Spinner::start("Pulling", &args.reference);

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
        ..Default::default()
    };

    match registry.pull(&image_ref, &options).await {
        Ok(result) => {
            spinner.finish_success("Pulled");
            if result.cached {
                eprintln!("   (already cached)");
            }
        }
        Err(e) => {
            spinner.finish_error();
            return Err(e.into());
        }
    }

    Ok(())
}
