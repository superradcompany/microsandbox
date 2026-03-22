//! `msb create` command — create and boot a fresh sandbox.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Create and boot a fresh sandbox (no workload launch).
#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Image reference (OCI image, directory, or disk image).
    pub image: String,

    /// Sandbox name. Auto-generated if not provided.
    #[arg(short, long)]
    pub name: Option<String>,

    /// Number of virtual CPUs.
    #[arg(short = 'c', long)]
    pub cpus: Option<u8>,

    /// Memory limit (e.g., 512M, 1G).
    #[arg(short, long)]
    pub memory: Option<String>,

    /// Volume mount (host:guest or name:guest). Can be repeated.
    #[arg(short, long)]
    pub volume: Vec<String>,

    /// Working directory inside sandbox.
    #[arg(short, long)]
    pub workdir: Option<String>,

    /// Default shell.
    #[arg(long)]
    pub shell: Option<String>,

    /// Environment variable (KEY=value). Can be repeated.
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Replace existing stopped sandbox with same name.
    #[arg(long)]
    pub force: bool,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb create` command.
pub async fn run(args: CreateArgs) -> anyhow::Result<()> {
    let is_named = args.name.is_some();
    let name = args.name.unwrap_or_else(ui::generate_name);

    let mut builder = Sandbox::builder(&name).image(args.image.as_str());

    if let Some(cpus) = args.cpus {
        builder = builder.cpus(cpus);
    }
    if let Some(ref mem) = args.memory {
        builder = builder.memory(ui::parse_size_mib(mem).map_err(anyhow::Error::msg)?);
    }
    if let Some(ref workdir) = args.workdir {
        builder = builder.workdir(workdir);
    }
    if let Some(ref shell) = args.shell {
        builder = builder.shell(shell);
    }
    if args.force {
        builder = builder.overwrite();
    }
    for env_str in &args.env {
        let (k, v) = ui::parse_env(env_str).map_err(anyhow::Error::msg)?;
        builder = builder.env(k, v);
    }
    for vol_str in &args.volume {
        builder = apply_volume(builder, vol_str)?;
    }

    let (mut progress, task) = builder.create_detached_with_pull_progress()?;
    let mut display = if args.quiet {
        ui::PullProgressDisplay::quiet(&args.image)
    } else {
        ui::PullProgressDisplay::new(&args.image)
    };

    while let Some(event) = progress.recv().await {
        display.handle_event(event);
    }

    match task.await {
        Ok(Ok(sandbox)) => {
            display.finish();
            sandbox.detach().await;
            // Print auto-generated name to stdout so it's scriptable.
            if !is_named {
                println!("{name}");
            }
        }
        Ok(Err(e)) => {
            display.finish();
            return Err(e.into());
        }
        Err(e) => {
            display.finish();
            return Err(anyhow::anyhow!("create task panicked: {e}"));
        }
    }

    Ok(())
}

/// Parse a volume spec and apply it to the builder.
pub fn apply_volume(
    builder: microsandbox::sandbox::SandboxBuilder,
    spec: &str,
) -> anyhow::Result<microsandbox::sandbox::SandboxBuilder> {
    let (source, guest) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("volume must be in format source:guest"))?;

    if source.starts_with('/') || source.starts_with("./") || source.starts_with("../") {
        Ok(builder.volume(guest, |m| m.bind(source)))
    } else {
        Ok(builder.volume(guest, |m| m.named(source)))
    }
}
